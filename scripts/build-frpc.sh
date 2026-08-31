#!/usr/bin/env bash
#
# Build frpc (the frp client) from pinned upstream source for every platform
# ShellPilot ships, and fold the results into resources/bin/manifest.json.
#
# Why build rather than download a release tarball: the manifest records a
# SHA-256 that the app verifies before every exec, so the bytes have to come
# from something we can reproduce. A downloaded archive would make the hash a
# record of "whatever was on the CDN that day".
#
# Why frp at all, and why this is licence-safe: frp is Apache-2.0, which places
# no obligation on ShellPilot beyond shipping the licence and NOTICE files —
# unlike OpenVPN, which is GPL-2.0 and is therefore deliberately NOT bundled
# (ShellPilot detects a system install instead). See docs/plans/vpn-tunnel-clients.md
# section 4.
set -euo pipefail

FRP_VERSION="${FRP_VERSION:-v0.71.0}"
FRP_REPO="https://github.com/fatedier/frp.git"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="$ROOT/resources/bin"
WORK="${FRP_WORKDIR:-$ROOT/.frp-build}"

# GOOS/GOARCH on the left, Node's platform-arch on the right. The right-hand
# names are what process.platform/process.arch produce and what
# electron-builder's ${platform}-${arch} macro expands to, so the lookup path
# is identical in a dev checkout and in a packaged app.
TARGETS=(
  "darwin amd64 darwin-x64"
  "darwin arm64 darwin-arm64"
  "linux amd64 linux-x64"
  "linux arm64 linux-arm64"
  "windows amd64 win32-x64"
  "windows arm64 win32-arm64"
)

command -v go >/dev/null 2>&1 || { echo "go toolchain not found" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git not found" >&2; exit 1; }

if [ ! -d "$WORK/frp/.git" ]; then
  echo "==> cloning frp $FRP_VERSION"
  mkdir -p "$WORK"
  git clone --depth 1 --branch "$FRP_VERSION" "$FRP_REPO" "$WORK/frp"
else
  echo "==> reusing $WORK/frp"
  git -C "$WORK/frp" fetch --depth 1 origin "$FRP_VERSION"
  git -C "$WORK/frp" checkout -q FETCH_HEAD
fi

SRC_SHA="$(git -C "$WORK/frp" rev-parse HEAD)"
echo "==> frp source $FRP_VERSION ($SRC_SHA)"

# frpc embeds its admin dashboard with `//go:embed dist`, and an embed pattern
# that matches nothing is a compile error — upstream builds those assets with a
# separate Vue toolchain and only ships them in release tarballs. ShellPilot
# drives frpc through its HTTP API (/api/*, /healthz), which is registered
# independently of the static asset routes, so the dashboard is dead weight
# here. A placeholder satisfies the embed without pulling a JS build into this
# script, and anyone who opens the dashboard by hand gets an explanation rather
# than a blank page.
if [ ! -f "$WORK/frp/web/frpc/dist/index.html" ]; then
  echo "==> stubbing the frpc dashboard assets"
  mkdir -p "$WORK/frp/web/frpc/dist"
  cat > "$WORK/frp/web/frpc/dist/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>frpc</title>
<p>This frpc was built by ShellPilot, which uses the frpc HTTP API and does not
build the dashboard assets. The API under /api and /healthz is unaffected.</p>
HTML
fi

# Fetch what the build needs before anything compiles, retrying the network.
#
# A CI run of this script died mid-download with
#
#   github.com/fatedier/yamux@v0.0.0-...: read
#   "https://proxy.golang.org/.../@v/....zip": stream error: INTERNAL_ERROR
#
# and passed unchanged on a re-run: proxy.golang.org dropped a stream. An
# ordinary network flake, and it would not be worth much here except that the
# release workflow runs this same script. A flake during a release is not a
# re-run — it is a failed build across three runners, a tag to delete and
# re-cut, and the draft releases from the half that succeeded to clean up.
#
# `go list -deps`, and not the two more obvious choices.
#
# Not `go build`, because a retry around a compile would run a genuine error
# three times and then report it as a network problem — a worse failure than
# the one being fixed. `go list` resolves and downloads without compiling, so
# there is no compile error for it to mistake.
#
# Not `go mod download` either, which was the first thing tried here and is
# wrong in a way worth recording: it resolves the whole module *graph*, so it
# demands more than the build does. In this very repo it fails while the build
# succeeds — frp's `gmsm` dependency requires `grpc@v1.31.0`, whose .mod file
# `go mod download` insists on reading even though nothing in frpc imports
# grpc. Prefetching with it would have enlarged the network surface this is
# meant to shrink, and broken builds that work today from a warm cache.
#
# Run once per target because imports are build-constraint sensitive: a package
# reached only under GOOS=windows is not in a linux resolution. Each pass after
# the first is served from the module cache and costs nothing.
#
# Duplicated in build-sidecar.sh rather than sourced from a shared file, and
# that is deliberate. The scripts in here are self-contained by convention —
# three of them, no `source` between them, each re-deriving its own paths and
# tool checks — and one function is not worth introducing the first sourcing
# relationship in the tree along with the path-resolution failure it brings.
# The case against duplication elsewhere in this repo was about a *rule* two
# copies could disagree on; this is mechanism, and a drifting copy costs
# nothing.
prefetch_modules() {
  local dir="$1"
  local pkg="$2"
  local t goos goarch nodedir attempt delay
  for t in "${TARGETS[@]}"; do
    read -r goos goarch nodedir <<<"$t"
    attempt=1
    delay=5
    while :; do
      # stdout is the package list and is not wanted; stderr is left alone, so
      # the last attempt's real error is the one that reaches the log.
      if ( cd "$dir" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
             go list -deps "$pkg" >/dev/null ); then
        break
      fi
      if [ "$attempt" -ge 3 ]; then
        echo "==> could not fetch modules for $goos/$goarch after 3 attempts" >&2
        return 1
      fi
      echo "==> module fetch for $goos/$goarch failed (attempt $attempt of 3); retrying in ${delay}s" >&2
      sleep "$delay"
      attempt=$((attempt + 1))
      delay=$((delay * 2))
    done
  done
}

prefetch_modules "$WORK/frp" ./cmd/frpc

mkdir -p "$OUT_ROOT"

for t in "${TARGETS[@]}"; do
  read -r goos goarch nodedir <<<"$t"
  exe=""
  [ "$goos" = "windows" ] && exe=".exe"
  dest="$OUT_ROOT/$nodedir"
  mkdir -p "$dest"
  echo "==> frpc $goos/$goarch -> $nodedir/frpc$exe"
  # CGO off keeps this a pure cross-compile with no per-platform toolchain, and
  # keeps the binary static so it does not pick up a host libc at runtime.
  # -trimpath and an empty -buildid make the output reproducible, which is what
  # makes the recorded hash meaningful.
  ( cd "$WORK/frp" && \
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath \
      -ldflags "-s -w -buildid= -X github.com/fatedier/frp/pkg/util/version.version=${FRP_VERSION#v}" \
      -o "$dest/frpc$exe" ./cmd/frpc )
done

# Upstream licence and attribution travel with the binaries: Apache-2.0 section
# 4 requires both the licence text and any NOTICE file to be distributed.
mkdir -p "$ROOT/resources/licenses/frp"
cp "$WORK/frp/LICENSE" "$ROOT/resources/licenses/frp/LICENSE"
# Written as an if rather than `[ -f x ] && cp` because under `set -e` the
# latter's exit status is the test's, and a release with no NOTICE file would
# then depend on a bash subtlety to not abort the build.
if [ -f "$WORK/frp/NOTICE" ]; then
  cp "$WORK/frp/NOTICE" "$ROOT/resources/licenses/frp/NOTICE"
fi
printf '%s\n' "frp $FRP_VERSION ($SRC_SHA)" > "$ROOT/resources/licenses/frp/VERSION"

echo "==> merging into manifest"
FRPC_VERSION="${FRP_VERSION#v}" node "$ROOT/scripts/update-bin-manifest.mjs" frpc

echo "done."
