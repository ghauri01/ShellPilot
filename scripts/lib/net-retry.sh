# Network steps that a release cannot afford to lose to a dropped connection.
#
# Sourced by build-frpc.sh, build-sidecar.sh, build-openvpn.sh and
# fetch-wintun.sh. Not executable on its own, and deliberately defines
# functions and nothing else, so sourcing it has no side effects.
#
# WHY THIS EXISTS
#
# A CI run of build-frpc.sh died mid-download with
#
#   github.com/fatedier/yamux@v0.0.0-...: read
#   "https://proxy.golang.org/.../@v/....zip": stream error: INTERNAL_ERROR
#
# and passed unchanged on a re-run. An ordinary network flake, and not worth
# much on its own — except that the release workflow runs these same scripts. A
# flake there is not a re-run: it is a failed build across three runners, a tag
# to delete and re-cut, and the draft releases from the half that succeeded to
# clean up first.
#
# Between them these four scripts clone two git repositories, fetch two tags,
# and download two archives before anything is compiled. Every one of those is
# the same bet on someone else's network staying up for the length of a
# release.
#
# WHY A SHARED FILE, HAVING ARGUED AGAINST ONE
#
# The retry landed first in two scripts, duplicated, on the reasoning that the
# scripts here are self-contained by convention and one small function did not
# justify the first `source` in the tree. That reasoning does not survive the
# real scope: four scripts need it, two of them need the clone wrapper as well,
# and that is roughly sixty duplicated lines whose copies would drift. The
# convention was worth keeping for one function and is not worth keeping for
# six operations across four files.
#
# Every caller derives ROOT the same way, from BASH_SOURCE, so `.
# "$ROOT/scripts/lib/net-retry.sh"` resolves wherever the script is run from.
#
# Written for bash 3.2, which is what macOS CI runs: no associative arrays, no
# `${var,,}`, no `local -n`, and nothing that expands an empty array.

# Run a command, and treat failure as possibly transient.
#
# Three attempts, backing off 5s then 10s. The output of the command is never
# captured or silenced: on the final attempt the underlying error is the only
# thing that explains what went wrong, and a retry that swallows what it
# retried is untriageable.
#
#   retry_network "cloning frp" git clone --depth 1 ...
#
# The first argument is a human description used in the progress lines; the
# rest is the command, run as-is. A shell function works here as well as a
# binary, which is how the wrappers below are retried.
retry_network() {
  local what="$1"
  shift
  local attempt=1
  local delay=5
  while :; do
    "$@" && return 0
    if [ "$attempt" -ge 3 ]; then
      echo "==> $what failed three times; giving up" >&2
      return 1
    fi
    echo "==> $what failed (attempt $attempt of 3); retrying in ${delay}s" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

# A shallow clone of one tag, safe to retry.
#
# The `rm -rf` is the whole point of the wrapper. A clone that dies partway
# leaves the destination behind, and git refuses to clone into a directory that
# is not empty — so a naive retry fails on the wreckage of the previous attempt
# rather than on the network, and reports a confusing "already exists" instead
# of the real error. Starting from nothing each time keeps every attempt
# identical to the first.
#
# Only ever called with a destination this script owns and created under its
# own work directory.
clone_pinned() {
  local dest="$1"
  local repo="$2"
  local ref="$3"
  rm -rf "$dest"
  git clone --depth 1 --branch "$ref" "$repo" "$dest"
}

# Fetch every module the build needs, before anything compiles.
#
# `go list -deps`, and not the two more obvious choices.
#
# Not `go build`: a retry around a compile would run a genuine error three
# times and then report it as a network problem, which is a worse failure than
# the one being fixed. `go list` resolves and downloads without compiling, so
# there is no compile error for it to mistake for a flake.
#
# Not `go mod download` either, which was tried first and is wrong in a way
# worth recording. It resolves the whole module *graph*, so it demands strictly
# more than the build does: in this repo it fails outright while the build
# succeeds, because frp's `gmsm` dependency requires `grpc@v1.31.0` and
# `go mod download` insists on reading that .mod even though nothing in frpc
# imports grpc. Prefetching with it would have enlarged the network surface
# this is meant to shrink and broken builds that work today from a warm cache.
#
# Run once per target because imports are build-constraint sensitive: a package
# reached only under GOOS=windows is not in a linux resolution. Every pass
# after the first is served from the module cache and costs nothing.
#
# Reads the caller's TARGETS array, which both Go callers define in the same
# "<goos> <goarch> <nodedir>" shape.
_go_list_deps() {
  ( cd "$1" && CGO_ENABLED=0 GOOS="$2" GOARCH="$3" go list -deps "$4" >/dev/null )
}

prefetch_modules() {
  local dir="$1"
  local pkg="$2"
  local t goos goarch nodedir
  for t in "${TARGETS[@]}"; do
    read -r goos goarch nodedir <<<"$t"
    retry_network "fetching modules for $goos/$goarch" \
      _go_list_deps "$dir" "$goos" "$goarch" "$pkg" || return 1
  done
}
