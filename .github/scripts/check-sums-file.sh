#!/usr/bin/env bash
# Succeed only when the sums file `$3` in directory `$1` is exactly the one line
# `<sha256 of $1/$2>  $2` that the release-asset workflow writes, for the executable `$2`.
#
# `sha256sum -c` verifies whatever files the sums file lists, so a sums file that names another
# file, or lists two, can pass it without saying anything about the executable. The hash is
# taken from the executable here and the whole file is compared to the line it would be written
# as. Git for Windows' `sha256sum` marks binary-mode entries with `*`, so the line is spelled
# out instead of being taken from `sha256sum`.
set -euo pipefail

dir="${1:?directory required}"
exe="${2:?executable name required}"
sums="${3:?sums file name required}"

hash="$(sha256sum "${dir}/${exe}" | cut -d ' ' -f 1)"

status=0
cmp -s <(printf '%s  %s\n' "$hash" "$exe") "${dir}/${sums}" || status=$?

case "$status" in
    0)
        echo "${sums} is the sum of ${exe}: ${hash}"
        ;;
    1)
        echo "::error::${sums} does not match ${exe}: it is not exactly the one line '${hash}  ${exe}'. It holds:"
        cat "${dir}/${sums}"
        exit 1
        ;;
    *)
        echo "::error::cmp failed (exit ${status}) while comparing ${dir}/${sums} with the sum of ${exe}"
        exit 1
        ;;
esac
