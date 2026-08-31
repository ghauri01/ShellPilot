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

# Retries for every step below that reaches the network; see the file itself
# for why these are shared rather than duplicated.
. "$ROOT/scripts/lib/net-retry.sh"

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

# Before vet and test, not only before the build loop: those are the first
# commands here that reach the network.
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
