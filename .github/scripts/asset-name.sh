#!/usr/bin/env bash
# The release asset's identity, defined once. `asset-name.sh --triple` prints the target
# triple; `asset-name.sh <version>` prints the archive name for that version.
set -euo pipefail

triple=x86_64-pc-windows-msvc

case "${1:?--triple or a version required}" in
    --triple) printf '%s\n' "$triple" ;;
    *) printf 'ssh-broker-%s-%s.zip\n' "$1" "$triple" ;;
esac
