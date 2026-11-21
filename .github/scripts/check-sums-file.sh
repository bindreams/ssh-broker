#!/usr/bin/env bash
# Succeed only when the sums file `$3` in directory `$1` is exactly the one line
# `<sha256 of $1/$2>  $2` that the release-asset workflow writes, for the executable `$2`.
#
# `sha256sum -c` passes a sums file that names another file or lists two, saying nothing about
# the executable, so the hash is taken from the executable and the whole file compared to the
# exact line. The line is spelled out because Git for Windows' `sha256sum` marks binary-mode
# entries with `*`.
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
