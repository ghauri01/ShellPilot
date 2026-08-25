#!/usr/bin/env bash
# Runs the built CLI directly, no npm install/publish needed.
# Usage: bin/shellpilot.sh claude | codex | run -- <command>
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$DIR/../out/cli/index.js" "$@"
