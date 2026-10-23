#!/usr/bin/env bash
# Fail if the executable `$1` imports a DLL that is not on the allowlist of OS-shipped DLLs.
#
# ssh-broker.exe becomes sshd's DefaultShell on guests that may lack the VC++
# redistributable, so the C runtime has to be linked in (`+crt-static`). A dynamic import
# of the VC or UCRT runtime would make every SSH login fail there, with no fallback.
#
# An allowlist, not a denylist: a new dependency that drags in any other DLL fails here
# and gets looked at, instead of passing because nobody thought to forbid it.
#
# `check-imports.sh --names` classifies the DLL names on stdin (one per line) instead of
# reading an executable; it prints the names that are not allowed and exits 1 if there are any.
set -euo pipefail

# Baseline `api-ms-win-core-*` API sets resolve to the OS's own implementation, and are listed
# one by one. The `ext-ms-*` extension sets are not guaranteed on every Windows edition, so none
# is allowed. `ucrtbase`, `api-ms-win-crt-*` and the VC runtime are absent on purpose:
# `+crt-static` removes them.
allowed_names='api-ms-win-core-synch-l1-2-0|api-ms-win-core-winrt-error-l1-1-0|kernel32|kernelbase|ntdll|advapi32|ws2_32|crypt32|oleaut32|user32|ole32|shell32|bcrypt|secur32|userenv|wtsapi32|netapi32|shlwapi|rpcrt4|sspicli|ncrypt|iphlpapi|gdi32'

# Print the names on stdin that are not allowed. `grep` exits 1 when it selects nothing,
# which is the good case; any other non-zero exit is a failure.
disallowed() {
    local status=0
    grep -ivE "^(${allowed_names})\.dll\$" || status=$?
    if [[ "$status" -gt 1 ]]; then
        echo "::error::grep failed (exit ${status}) while classifying imports" >&2
        return "$status"
    fi
}

if [[ "${1:-}" == "--names" ]]; then
    bad="$(tr -d '\r' | sed '/^[[:space:]]*$/d' | disallowed)"
    if [[ -n "$bad" ]]; then
        echo "$bad"
        exit 1
    fi
    exit 0
fi

exe="${1:?path to the executable required}"

vswhere='C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe'
if [[ ! -f "$vswhere" ]]; then
    echo "::error::vswhere.exe not found at ${vswhere}" >&2
    exit 1
fi

status=0
found="$("$vswhere" -latest -products '*' \
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
    -find 'VC/Tools/MSVC/**/bin/Hostx64/x64/dumpbin.exe')" || status=$?
if [[ "$status" -ne 0 ]]; then
    echo "::error::vswhere.exe failed (exit ${status}) while looking for dumpbin.exe" >&2
    exit 1
fi
dumpbin="$(head -n 1 <<<"$found" | tr -d '\r')"
if [[ -z "$dumpbin" ]]; then
    echo "::error::dumpbin.exe not found through vswhere" >&2
    exit 1
fi

status=0
listing="$("$dumpbin" -nologo -dependents "$exe" 2>&1)" || status=$?
if [[ "$status" -ne 0 ]]; then
    echo "::error::dumpbin failed (exit ${status}) on ${exe}: ${listing}" >&2
    exit 1
fi

# Both the load-time and the delay-load dependencies are listed as indented `NAME.dll` lines.
status=0
dlls="$(tr -d '\r' <<<"$listing" | grep -iE '^[[:space:]]+[^[:space:]]+\.dll[[:space:]]*$' | tr -d ' \t')" || status=$?
if [[ "$status" -gt 1 ]]; then
    echo "::error::grep failed (exit ${status}) while parsing the dumpbin output for ${exe}" >&2
    exit 1
fi
if [[ -z "$dlls" ]]; then
    echo "::error::no imports parsed from dumpbin output for ${exe}" >&2
    exit 1
fi

echo "imports of ${exe}:"
echo "$dlls"

status=0
bad="$(bash "$0" --names <<<"$dlls")" || status=$?
case "$status" in
    0) ;;
    1)
        echo "::error::${exe} imports DLLs that are not on the allowlist of OS-shipped DLLs; a fresh Windows guest may not have them:" >&2
        echo "$bad" >&2
        exit 1
        ;;
    *)
        echo "::error::classifying the imports of ${exe} failed (exit ${status})" >&2
        exit 1
        ;;
esac
