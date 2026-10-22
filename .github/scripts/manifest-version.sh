#!/usr/bin/env bash
# Print the version of the `ssh-broker` package in the manifest of the current directory.
set -euo pipefail

metadata="$(cargo metadata --no-deps --locked --format-version 1)"
version="$(jq -r '.packages[] | select(.name == "ssh-broker") | .version // empty' <<<"$metadata" | tr -d '\r')"
if [[ -z "$version" ]]; then
    echo "::error::the manifest has no package named ssh-broker with a version" >&2
    exit 1
fi

printf '%s\n' "$version"
