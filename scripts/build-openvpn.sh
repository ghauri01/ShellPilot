#!/usr/bin/env bash
#
# Build OpenVPN from pinned upstream source for the platforms ShellPilot ships
# it on, and fold the results into resources/bin/manifest.json.
#
# Why bundle at all: until this script existed an OpenVPN profile could not
# connect until the user had installed OpenVPN themselves, which is a wall in
# front of a feature the app otherwise sets up for them.
#
# Why this is licence-safe, in one paragraph so nobody has to re-derive it:
# OpenVPN 2.x is GPL-2.0 with an OpenSSL linking exception. ShellPilot runs
# `openvpn` as a *separate process* and talks to it over its management socket
# — separate address space, no linking, no combined work. That is GPL-2.0 §2
# "mere aggregation", so ShellPilot stays MIT. What bundling *does* create is
# the GPL-2.0 §3 obligation on us as a distributor of GPL binaries: we must
# offer the corresponding source. That is why this script also writes a source
# tarball of the exact tree it built (see SRC_TARBALL below) — the release
# workflow uploads it as a release asset beside the installers.
#
# Why native builds rather than the six-target cross-compile build-frpc.sh
# does: frp is Go with CGO off, so one machine can emit every target. OpenVPN
# is C/autotools linked against OpenSSL, and there is no equivalent. So this
# script builds for the host platform only, and the release workflow runs it on
# each runner.
#
# Why OpenSSL is built from source here rather than linked against the host's:
# a Homebrew or distro libssl exists on the build machine, not on the user's.
# Static-linking a version we pinned is the only way the shipped binary means
# the same thing on every machine that runs it — and the only way the recorded
# SHA-256 describes something we chose rather than something the runner image
# happened to have that week.
#
# What the recorded hash is and is not. It is an exact description of the bytes
# this build produced, which is what `binaries.ts` checks before every exec —
# that is the property it exists for. It is *not* a reproducible-build claim:
# OpenVPN compiles `__DATE__` into its version banner and OpenSSL stamps its
# own build metadata, so two runs on different days give different bytes for
# the same source. Reproducing this build gets you an equivalent binary, not an
# identical one. The pinned tag, the pinned commit and the published source
# archive are what let someone check that the source is what we say it is;
# `build-frpc.sh` can promise more only because Go with `-trimpath -buildid=`
# is deterministic and C is not.
set -euo pipefail

# ---------------------------------------------------------------------- pins

# The tag, and the commit it must resolve to. A tag is a mutable pointer; the
# commit is not. Checking both means a re-pointed tag fails the build instead
# of silently changing what we ship.
OPENVPN_TAG="${OPENVPN_TAG:-v2.6.22}"
OPENVPN_EXPECT_COMMIT="${OPENVPN_EXPECT_COMMIT:-c9b790f5b9e8ebca5da38c22f479c31bb8d33686}"
OPENVPN_REPO="https://github.com/OpenVPN/openvpn.git"

# OpenSSL 3.5 is the current LTS line. Pinned by SHA-256 of the release
# tarball rather than by URL alone: the URL is a CDN, the hash is the bytes.
OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.8}"
OPENSSL_SHA256="${OPENSSL_SHA256:-a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2}"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="$ROOT/resources/bin"
LIC_ROOT="$ROOT/resources/licenses/openvpn"
WORK="${OPENVPN_WORKDIR:-$ROOT/.openvpn-build}"
# Not under resources/: this is the GPL §3 corresponding source, a release
# asset, and it has no business inside the installed app.
SRC_OUT="${OPENVPN_SRC_OUT:-$ROOT/.openvpn-src}"

# Windows is deliberately absent from every target list below, and it is not an
# oversight — see the "Windows" section of docs/VPN.md. OpenVPN's own default
# adapter on Windows is tap-windows6, a kernel driver we cannot install, and
# `--windows-driver wintun` does not rescue it: openvpn.exe never loads
# wintun.dll. It opens an adapter that already exists (tun.c
# `at_least_one_tap_win`), and creating a Wintun adapter needs
# `WintunCreateAdapter` from the DLL, which nothing in the OpenVPN tree calls.
# So a bundled openvpn.exe would fail on a clean machine, and the Windows
# system install — which brings both a driver and the Interactive Service — is
# still the only thing that works there.

# --------------------------------------------------------------- toolchain

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "$1 not found. $2" >&2
    exit 1
  }
}

# The platform check comes before the tool checks, so a Windows runner bows
# out cleanly instead of failing on a missing perl it was never going to use.
case "$(uname -s)" in
  Darwin) HOST_OS=darwin ;;
  Linux) HOST_OS=linux ;;
  *)
    # Not an error. `npm run build:engines` is one command on all three CI
    # runners, and the Windows one legitimately has no OpenVPN to build — see
    # the Windows note below. Exiting 1 here would fail the Windows release for
    # doing exactly the right thing. `verify-bin-manifest.mjs` is the check
    # that a platform is missing something it actually needs.
    echo "==> $(uname -s): ShellPilot does not bundle OpenVPN here; nothing to build."
    exit 0
    ;;
esac

need git 'Install git.'
need curl 'Install curl.'
need make 'Install make.'
need perl 'OpenSSL'"'"'s Configure is a Perl program.'
if [ "$HOST_OS" = darwin ]; then
  need autoreconf 'brew install autoconf automake libtool'
  # Apple ships a /usr/bin/libtool that is a static-library archiver and not
  # GNU libtool at all, so its presence proves nothing; autoreconf wants
  # glibtoolize, which only Homebrew's libtool provides.
  need glibtoolize 'brew install libtool'
else
  need autoreconf 'apt install autoconf automake libtool pkg-config'
  need libtoolize 'apt install libtool'
  # OpenVPN 2.6 requires libcap-ng on Linux and offers no way to opt out — the
  # check in configure.ac is unconditional for *-*-linux*, with no
  # --disable-capng to reach for. So it is a hard build dependency rather than
  # a choice, and saying so here beats a hundred lines of ./configure output
  # ending in a message about pkg-config.
  need pkg-config 'apt install pkg-config'
  pkg-config --exists libcap-ng || {
    echo "libcap-ng development files not found." >&2
    echo "  apt install libcap-ng-dev" >&2
    exit 1
  }
fi

# ------------------------------------------------------------------ targets
#
# `TARGETS` holds "<openssl-configure-target> <mach-o arch name, or - where
# there is no lipo step> <node platform-arch dir>" triples.
#
# macOS builds both arches from one runner and there is no cheat in it: the
# macOS SDK carries both slices, so OpenSSL is configured and compiled twice,
# the two static libraries are `lipo`'d together, OpenVPN is compiled once as a
# universal binary against them, and the result is thinned back into one file
# per arch. Every instruction in each output was compiled for that arch.
#
# Linux builds for the host arch only. Cross-compiling C against a foreign
# libc is a different problem from `GOARCH=arm64`, and the release only ships
# linux-x64.
if [ "$HOST_OS" = darwin ]; then
  TARGETS=(
    "darwin64-arm64-cc arm64 darwin-arm64"
    "darwin64-x86_64-cc x86_64 darwin-x64"
  )
  UNIVERSAL=1
  # Without this, clang stamps the runner's own OS version as the minimum and
  # the binary refuses to launch on anything older — a CI image bump would
  # silently drop support for macOS versions ShellPilot still runs on, and the
  # only symptom would be "binary-missing" on a user's Mac. Electron 43 itself
  # runs on macOS 11, so that is the floor.
  export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
else
  case "$(uname -m)" in
    x86_64) TARGETS=("linux-x86_64 - linux-x64") ;;
    aarch64 | arm64) TARGETS=("linux-aarch64 - linux-arm64") ;;
    *)
      echo "No OpenSSL configure target mapped for $(uname -m)." >&2
      exit 1
      ;;
  esac
  UNIVERSAL=0
fi

mkdir -p "$WORK" "$OUT_ROOT" "$LIC_ROOT" "$SRC_OUT"

# ------------------------------------------------------------------- openssl

TARBALL="$WORK/openssl-${OPENSSL_VERSION}.tar.gz"
if [ ! -f "$TARBALL" ]; then
  echo "==> fetching openssl ${OPENSSL_VERSION}"
  curl -fsSL -o "$TARBALL.part" "$OPENSSL_URL"
  mv "$TARBALL.part" "$TARBALL"
fi

# Verified every run, not only after a fresh download: a cached tarball in a
# reused workdir is exactly the thing an attacker would want to be able to
# swap.
echo "==> verifying openssl tarball"
if command -v shasum >/dev/null 2>&1; then
  echo "$OPENSSL_SHA256  $TARBALL" | shasum -a 256 -c - >/dev/null
else
  echo "$OPENSSL_SHA256  $TARBALL" | sha256sum -c - >/dev/null
fi

OPENSSL_SRC="$WORK/openssl-${OPENSSL_VERSION}"
if [ ! -d "$OPENSSL_SRC" ]; then
  echo "==> unpacking openssl"
  tar -xzf "$TARBALL" -C "$WORK"
fi

for t in "${TARGETS[@]}"; do
  read -r ssltarget _ nodedir <<<"$t"
  prefix="$WORK/openssl-out/$nodedir"
  # --libdir=lib below, so there is only one place to look — on a distro whose
  # default is lib64 this check would otherwise never hit and every run would
  # rebuild OpenSSL from scratch.
  if [ -f "$prefix/lib/libssl.a" ]; then
    echo "==> reusing openssl for $nodedir"
    continue
  fi
  echo "==> building openssl $ssltarget -> $nodedir"
  build="$WORK/openssl-build/$nodedir"
  rm -rf "$build"
  mkdir -p "$build"
  (
    cd "$build"
    # The `-arch` flag is not passed here: OpenSSL's darwin64-arm64 and
    # darwin64-x86_64 targets already carry their own, and Configure reads a
    # bare `arm64` on the command line as a second target rather than as an
    # argument to `-arch`.
    #
    # no-shared is the whole point — nothing for the user's machine to find at
    # runtime. The rest is build time we do not need to spend; none of it
    # removes an algorithm OpenVPN uses.
    perl "$OPENSSL_SRC/Configure" "$ssltarget" \
      --prefix="$prefix" --openssldir="$prefix/ssl" --libdir=lib \
      no-shared no-module no-tests no-docs no-apps no-legacy
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
    make install_sw
  )
done

if [ "$UNIVERSAL" = 1 ]; then
  echo "==> lipo'ing openssl into one universal tree"
  uni="$WORK/openssl-out/universal"
  rm -rf "$uni"
  mkdir -p "$uni/lib"
  # Headers come from the arm64 build. OpenSSL generates a couple of headers
  # (configuration.h, opensslv.h) at configure time, but the only per-target
  # value they carry is `bn_ops`, and both macOS targets declare the same one
  # (SIXTY_FOUR_BIT_LONG, Configurations/10-main.conf). If that ever diverged
  # the universal compile below would fail to build rather than silently ship
  # something wrong.
  cp -R "$WORK/openssl-out/darwin-arm64/include" "$uni/include"
  for lib in libssl.a libcrypto.a; do
    lipo -create \
      "$WORK/openssl-out/darwin-arm64/lib/$lib" \
      "$WORK/openssl-out/darwin-x64/lib/$lib" \
      -output "$uni/lib/$lib"
  done
fi

# ------------------------------------------------------------------- openvpn

SRC="$WORK/openvpn"
if [ ! -d "$SRC/.git" ]; then
  echo "==> cloning openvpn $OPENVPN_TAG"
  git clone --depth 1 --branch "$OPENVPN_TAG" "$OPENVPN_REPO" "$SRC"
else
  echo "==> reusing $SRC"
  git -C "$SRC" fetch --depth 1 origin "refs/tags/$OPENVPN_TAG:refs/tags/$OPENVPN_TAG" --force
  git -C "$SRC" checkout -q "refs/tags/$OPENVPN_TAG"
fi

SRC_SHA="$(git -C "$SRC" rev-parse HEAD^{commit})"
if [ "$SRC_SHA" != "$OPENVPN_EXPECT_COMMIT" ]; then
  echo "openvpn $OPENVPN_TAG resolves to $SRC_SHA, not the pinned $OPENVPN_EXPECT_COMMIT." >&2
  echo "The tag moved, or the clone is wrong. Refusing to build." >&2
  exit 1
fi
echo "==> openvpn source $OPENVPN_TAG ($SRC_SHA)"

# GPL-2.0 §3: as a distributor of these binaries we owe the corresponding
# source. `git archive` of the exact commit we are about to compile is that
# source, byte for byte, and the release workflow attaches it to the release.
# Written before the build so a failed compile still leaves the evidence of
# what was attempted.
SRC_TARBALL="$SRC_OUT/openvpn-${OPENVPN_TAG#v}-source.tar.gz"
echo "==> writing corresponding source to $SRC_TARBALL"
git -C "$SRC" archive --format=tar --prefix="openvpn-${OPENVPN_TAG#v}/" "$SRC_SHA" | gzip -9 -n >"$SRC_TARBALL"

if [ ! -f "$SRC/configure" ]; then
  echo "==> autoreconf"
  ( cd "$SRC" && autoreconf -fi )
fi

# What is switched off, and why each one:
#
#   lzo, lz4     compression inside a TLS tunnel is the VORACLE attack;
#                OpenVPN 2.6 disables it by default and ShellPilot's importer
#                strips `comp-lzo`/`compress` anyway. Removing the code
#                removes two more dependencies to pin.
#   plugins      `.ovpn` plugin directives are already rejected at import as
#                arbitrary code execution. A build that cannot load a plugin
#                cannot be talked into loading one.
#   pkcs11       needs a host PKCS#11 module; ShellPilot has no UI for one.
#   dco          the kernel data-channel-offload module. Bundling a userspace
#                binary that behaves differently depending on whether a kernel
#                module happens to be loaded is not a thing we can test.
#   selinux,
#   systemd      link against host libraries that may not exist on the user's
#                machine, which is the whole reason for the static build.
CONFIGURE_FLAGS=(
  --disable-lzo
  --disable-lz4
  --disable-plugins
  --disable-pkcs11
  --disable-dco
  --disable-selinux
  --disable-systemd
  --disable-debug
  --disable-dependency-tracking
)

# libcap-ng, linked statically where we can.
#
# We ship this binary inside a .deb and an AppImage. A .deb can declare a
# dependency; an AppImage carries no system libraries at all, so anything left
# dynamically linked has to already exist on the user's machine. libcap-ng is
# usually there and that is exactly the problem — "usually" is how a bundled
# binary fails for the minority who then have no idea why.
#
# The static archive is preferred for the same reason OpenSSL is linked
# statically a few lines above. If the distribution ships only the shared
# object we fall back to it rather than refusing to build, but say so, because
# the resulting binary is less portable than the one we intend to ship and the
# linkage check at the end of this script is what will catch it.
# Expanded at the call site as ${CAPNG_ARGS[@]+"${CAPNG_ARGS[@]}"} rather than
# "${CAPNG_ARGS[@]}". Under `set -u`, bash 3.2 treats an empty array's [@]
# expansion as an unbound variable, and bash 3.2 is what macOS ships — so the
# plain form built fine on Linux and failed every macOS release with
# "CAPNG_ARGS[@]: unbound variable". This array is empty on macOS by
# definition, which is exactly where the old bash is.
CAPNG_ARGS=()
if [ "$HOST_OS" != darwin ]; then
  capng_a="$(pkg-config --variable=libdir libcap-ng)/libcap-ng.a"
  if [ -f "$capng_a" ]; then
    CAPNG_ARGS=(LIBCAPNG_CFLAGS="$(pkg-config --cflags libcap-ng)" LIBCAPNG_LIBS="$capng_a")
  else
    echo "warning: no static libcap-ng at $capng_a; linking it dynamically" >&2
  fi
fi

build_openvpn() {
  local sslprefix="$1" archflags="$2" outdir="$3"
  rm -rf "$outdir"
  mkdir -p "$outdir"
  (
    cd "$outdir"
    "$SRC/configure" "${CONFIGURE_FLAGS[@]}" \
      OPENSSL_CFLAGS="-I$sslprefix/include" \
      OPENSSL_LIBS="$sslprefix/lib/libssl.a $sslprefix/lib/libcrypto.a" \
      ${CAPNG_ARGS[@]+"${CAPNG_ARGS[@]}"} \
      CFLAGS="-O2 $archflags" \
      LDFLAGS="$archflags"
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
  )
}

if [ "$UNIVERSAL" = 1 ]; then
  echo "==> building openvpn (universal arm64 + x86_64)"
  build_openvpn "$WORK/openssl-out/universal" "-arch arm64 -arch x86_64" "$WORK/openvpn-build/universal"
  for t in "${TARGETS[@]}"; do
    read -r _ arch nodedir <<<"$t"
    mkdir -p "$OUT_ROOT/$nodedir"
    echo "==> thinning openvpn -> $nodedir/openvpn"
    lipo -thin "$arch" "$WORK/openvpn-build/universal/src/openvpn/openvpn" \
      -output "$OUT_ROOT/$nodedir/openvpn"
    chmod 755 "$OUT_ROOT/$nodedir/openvpn"
  done
else
  for t in "${TARGETS[@]}"; do
    read -r _ _ nodedir <<<"$t"
    echo "==> building openvpn -> $nodedir/openvpn"
    build_openvpn "$WORK/openssl-out/$nodedir" "" "$WORK/openvpn-build/$nodedir"
    mkdir -p "$OUT_ROOT/$nodedir"
    cp "$WORK/openvpn-build/$nodedir/src/openvpn/openvpn" "$OUT_ROOT/$nodedir/openvpn"
    chmod 755 "$OUT_ROOT/$nodedir/openvpn"
  done
fi

# ------------------------------------------------------------ linkage check

# What does the binary we are about to ship actually need at run time?
#
# Until now nothing asked. The static OpenSSL link was asserted in a VERSION
# file and never verified against the artefact, and libcap-ng arrived as a hard
# Linux dependency without anyone noticing it would be dynamically linked. That
# is precisely the class of mistake that cannot fail on a build machine, which
# has every development package installed, and can only fail on a user's.
#
# So: enumerate the dynamic dependencies and refuse anything outside a baseline
# that every target system has by definition. libssl or libcap-ng appearing
# here means the static link silently did not happen.
check_linkage() {
  local bin="$1" bad=''

  if [ "$HOST_OS" = darwin ]; then
    # Everything under /usr/lib and /System is part of the OS on macOS. A
    # Homebrew path is the tell: that is a library the user does not have.
    bad="$(otool -L "$bin" | tail -n +2 | awk '{print $1}' \
      | grep -vE '^(/usr/lib/|/System/Library/)' || true)"
  else
    # glibc's own pieces plus the loader. Anything else is a bet on the user's
    # distribution. Note libcap-ng is deliberately NOT in this list.
    bad="$(ldd "$bin" | awk '{print $1}' \
      | grep -vE '^(linux-vdso\.so|/lib64/ld-linux|/lib/ld-linux|ld-linux|libc\.so|libm\.so|libdl\.so|libpthread\.so|librt\.so|libresolv\.so)' || true)"
  fi

  if [ -n "$bad" ]; then
    echo "==> $bin links libraries the user may not have:" >&2
    printf '      %s\n' $bad >&2
    echo "    Everything beyond libc must be linked statically; see the" >&2
    echo "    OPENSSL_LIBS and LIBCAPNG_LIBS arguments to configure." >&2
    return 1
  fi
  echo "==> $bin: no dynamic dependencies beyond the base system"
}

for t in "${TARGETS[@]}"; do
  read -r _ _ nodedir <<<"$t"
  # Only the slice matching this machine can be inspected: `ldd` and `otool -L`
  # read the binary that will run here, and a cross-built or thinned foreign
  # slice is not it.
  case "$nodedir" in
    *"-$(node -p 'process.arch' 2>/dev/null || echo unknown)")
      check_linkage "$OUT_ROOT/$nodedir/openvpn" ;;
  esac
done

# --------------------------------------------------------------- attribution

# GPL-2.0 §1 requires the licence to travel with the binary, and the OpenSSL
# linking exception in COPYRIGHT.GPL is the clause that makes the OpenSSL link
# lawful — so both ship, not just the first.
cp "$SRC/COPYING" "$LIC_ROOT/COPYING"
cp "$SRC/COPYRIGHT.GPL" "$LIC_ROOT/COPYRIGHT.GPL"
cp "$OPENSSL_SRC/LICENSE.txt" "$LIC_ROOT/OPENSSL-LICENSE.txt"
{
  printf '%s\n' "openvpn $OPENVPN_TAG ($SRC_SHA)"
  printf '%s\n' "statically linked against openssl $OPENSSL_VERSION"
  printf '%s\n' "corresponding source: openvpn-${OPENVPN_TAG#v}-source.tar.gz, attached to the ShellPilot release this binary shipped in"
} >"$LIC_ROOT/VERSION"

echo "==> merging into manifest"
OPENVPN_VERSION="${OPENVPN_TAG#v}" node "$ROOT/scripts/update-bin-manifest.mjs" openvpn

echo "done."
