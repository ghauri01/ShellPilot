#!/usr/bin/env bash
#
# Cross-compile shellpilot-netd, ShellPilot's userspace WireGuard sidecar, for
# every platform ShellPilot ships, and fold the results into
# resources/bin/manifest.json.
#
# The sidecar is our own code plus wireguard-go and gVisor netstack, all MIT /
# Apache-2.0 / BSD-3, so bundling it carries no obligation beyond preserving
# the notices. See docs/plans/vpn-tunnel-clients.md section 4 for why openvpn
# is deliberately NOT bundled the same way.
#
# CI must run this (and scripts/build-frpc.sh) BEFORE electron-builder.
# electron-builder.yml pulls resources/bin/${platform}-${arch} in through
# extraResources, and a missing directory is silent at package time — it only
# surfaces at runtime as every profile reporting `binary-missing`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/sidecar/netd"
OUT_ROOT="$ROOT/resources/bin"

# The sidecar version tracks the app version: they are released together and a
# mismatch between the two is a packaging bug, not a supported configuration.
VERSION="${SHELLPILOT_NETD_VERSION:-$(node -p "require('$ROOT/package.json').version" 2>/dev/null || echo '0.0.0-dev')}"
BUILD_SHA="${SHELLPILOT_NETD_SHA:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)}"

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

# Restrict to one target with e.g. `bash scripts/build-sidecar.sh darwin-arm64`.
# Handy while iterating; CI always builds all six.
if [ "$#" -gt 0 ]; then
  filtered=()
  for want in "$@"; do
    for t in "${TARGETS[@]}"; do
      # shellcheck disable=SC2086
      set -- $t
      [ "$3" = "$want" ] && filtered+=("$t")
    done
  done
  if [ "${#filtered[@]}" -eq 0 ]; then
    echo "no target matched: $*" >&2
    exit 2
  fi
  TARGETS=("${filtered[@]}")
  set --
fi

command -v go >/dev/null 2>&1 || { echo "go toolchain not found" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "node not found (needed to merge the manifest)" >&2; exit 1; }

echo "==> shellpilot-netd $VERSION ($BUILD_SHA)"
echo "==> $(go version)"

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
# Duplicated in build-frpc.sh rather than sourced from a shared file, and
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

# Before vet and test, not only before the build loop: those are the first
# commands here that reach the network, so a flake would hit them first.
prefetch_modules "$SRC" .

# Fail the build rather than ship something that does not compile or whose
# tests are red. A tunnel sidecar that panics has the app's network stack in
# its hands.
echo "==> vet + test"
( cd "$SRC" && go vet ./... && go test ./... )

mkdir -p "$OUT_ROOT"

for t in "${TARGETS[@]}"; do
  read -r goos goarch nodedir <<<"$t"
  exe=""
  [ "$goos" = "windows" ] && exe=".exe"
  dest="$OUT_ROOT/$nodedir"
  mkdir -p "$dest"
  echo "==> shellpilot-netd $goos/$goarch -> $nodedir/shellpilot-netd$exe"
  # CGO_ENABLED=0 is load-bearing, not a preference: it is what makes this a
  # pure cross-compile with no per-platform C toolchain, and what keeps the
  # binary from picking up a host libc at runtime. Nothing in the dependency
  # tree needs cgo — netstack is pure Go, which is the whole reason this
  # design needs no root.
  #
  # -trimpath and an empty -buildid make the output reproducible, which is
  # what makes the SHA-256 recorded in the manifest mean anything.
  ( cd "$SRC" && \
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath \
      -ldflags "-s -w -buildid= -X main.Version=$VERSION -X main.BuildSha=$BUILD_SHA" \
      -o "$dest/shellpilot-netd$exe" . )
done

# Upstream notices travel with the binaries. wireguard-go is MIT and gVisor is
# Apache-2.0; both require the notice to be reproduced in distributions.
mkdir -p "$ROOT/resources/licenses/shellpilot-netd"
{
  printf 'shellpilot-netd %s (%s)\n\n' "$VERSION" "$BUILD_SHA"
  printf 'Bundled Go dependencies, from sidecar/netd/go.mod:\n\n'
  ( cd "$SRC" && go list -m all 2>/dev/null | sed 's/^/  /' )
} > "$ROOT/resources/licenses/shellpilot-netd/VERSION"

# Smoke test: the host-platform binary must answer --version with parseable
# JSON on stdout, because that is exactly what the TypeScript probe() does
# before it will trust the binary with a key.
host_os="$(go env GOOS)"
host_arch="$(go env GOARCH)"
for t in "${TARGETS[@]}"; do
  read -r goos goarch nodedir <<<"$t"
  if [ "$goos" = "$host_os" ] && [ "$goarch" = "$host_arch" ]; then
    echo "==> smoke test $nodedir"
    "$OUT_ROOT/$nodedir/shellpilot-netd" --version | node -e '
      let s = ""
      process.stdin.on("data", (c) => (s += c))
      process.stdin.on("end", () => {
        const v = JSON.parse(s)
        if (!v.version || !v.goVersion) throw new Error("--version output is incomplete: " + s)
        console.log("    " + v.version + " / " + v.goVersion)
      })'
    break
  fi
done

echo "==> merging into manifest"
SHELLPILOT_NETD_VERSION="$VERSION" node "$ROOT/scripts/update-bin-manifest.mjs" shellpilot-netd

echo "done."
