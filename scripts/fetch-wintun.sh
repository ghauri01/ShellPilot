#!/usr/bin/env bash
#
# Fetch the official Wintun redistributable and place wintun.dll beside the
# Windows tunnel engines, so WireGuard system mode on Windows needs nothing
# installed.
#
# This is the one shipped component that is *not* built from source, and it is
# the one shipped component that is *not* open source. Both facts are
# deliberate and both are forced by the same licence:
#
#   * Wintun's source is GPL-2.0, but the prebuilt DLLs from wintun.net carry a
#     separate "Prebuilt Binaries License" — proprietary, and the only terms
#     under which WireGuard LLC permits redistribution at all.
#   * Clause 3(a) of that licence forbids extracting from or modifying the
#     Software. So the DLL is copied out of the official ZIP untouched; it is
#     never rebuilt, repacked, stripped or signed by us.
#   * Clause 3(d) forbids redistribution "except insofar as the Software is
#     distributed alongside other software that uses the Software only via the
#     Permitted API" — the wintun.h interfaces. Both consumers here do exactly
#     that: shellpilot-netd through golang.zx2c4.com/wintun, and nothing else.
#   * Clause 3(c) requires its proprietary notices to travel with it, which is
#     why LICENSE.txt is copied into resources/licenses/wintun/ and ships.
#
# THIRD-PARTY-NOTICES.md states all of this in the open rather than filing it
# in a table, because ShellPilot is marketed as open source and this component
# is not.
#
# Why the hash is pinned rather than trusted: wintun.net is a CDN over HTTPS,
# which authenticates the host and nothing about the bytes. The DLL is signed
# by WireGuard LLC and Windows checks that at load time, but a build machine
# that fetched the wrong file would only find out on a user's machine. The
# recorded SHA-256 is of the ZIP as published — it was verified by hand against
# a download, and the licence text quoted above was read out of that same ZIP.
set -euo pipefail

WINTUN_VERSION="${WINTUN_VERSION:-0.14.1}"
WINTUN_URL="${WINTUN_URL:-https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip}"
WINTUN_SHA256="${WINTUN_SHA256:-07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="$ROOT/resources/bin"
LIC_ROOT="$ROOT/resources/licenses/wintun"
WORK="${WINTUN_WORKDIR:-$ROOT/.wintun-build}"

# Left of the arrow is the directory inside the ZIP, right is Node's
# platform-arch name — the same directory layout every other engine uses, so
# the DLL lands next to the executables that load it. That adjacency is the
# whole mechanism: both shellpilot-netd (via golang.zx2c4.com/wintun) and
# openvpn.exe load wintun.dll with LOAD_LIBRARY_SEARCH_APPLICATION_DIR, which
# searches the directory of the running .exe and System32 and nothing else. No
# PATH, no working directory — which is also why this is not a DLL-planting
# hazard.
#
# x86 and arm (32-bit) are in the ZIP and are not copied: ShellPilot ships no
# 32-bit Windows build.
TARGETS=(
  "amd64 win32-x64"
  "arm64 win32-arm64"
)

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }
command -v unzip >/dev/null 2>&1 || { echo "unzip not found" >&2; exit 1; }

mkdir -p "$WORK" "$LIC_ROOT"

ZIP="$WORK/wintun-${WINTUN_VERSION}.zip"
if [ ! -f "$ZIP" ]; then
  echo "==> fetching wintun ${WINTUN_VERSION}"
  curl -fsSL -o "$ZIP.part" "$WINTUN_URL"
  mv "$ZIP.part" "$ZIP"
fi

# Checked every run rather than only after a download: a cached ZIP in a reused
# workdir is precisely what an attacker with local write access would swap.
echo "==> verifying wintun zip"
if command -v shasum >/dev/null 2>&1; then
  echo "$WINTUN_SHA256  $ZIP" | shasum -a 256 -c - >/dev/null
else
  echo "$WINTUN_SHA256  $ZIP" | sha256sum -c - >/dev/null
fi

EXTRACT="$WORK/extract"
rm -rf "$EXTRACT"
mkdir -p "$EXTRACT"
unzip -q "$ZIP" -d "$EXTRACT"

for t in "${TARGETS[@]}"; do
  read -r zipdir nodedir <<<"$t"
  src="$EXTRACT/wintun/bin/$zipdir/wintun.dll"
  [ -f "$src" ] || { echo "wintun.dll for $zipdir is not in the archive" >&2; exit 1; }
  mkdir -p "$OUT_ROOT/$nodedir"
  echo "==> wintun $zipdir -> $nodedir/wintun.dll"
  # cp, not install/strip/sign. Clause 3(a): unmodified or not at all.
  cp "$src" "$OUT_ROOT/$nodedir/wintun.dll"
done

cp "$EXTRACT/wintun/LICENSE.txt" "$LIC_ROOT/LICENSE.txt"
{
  printf '%s\n' "wintun $WINTUN_VERSION (prebuilt, unmodified, from $WINTUN_URL)"
  printf '%s\n' "zip sha256 $WINTUN_SHA256"
  printf '%s\n' "Proprietary — see LICENSE.txt. Not open source, and not built from source."
} >"$LIC_ROOT/VERSION"

echo "==> merging into manifest"
WINTUN_DLL_VERSION="$WINTUN_VERSION" node "$ROOT/scripts/update-bin-manifest.mjs" wintun.dll

echo "done."
