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

# API sets resolve to the OS's own implementation, whatever Windows version is installed.
# `api-ms-win-crt-*` is the UCRT's API set and is deliberately absent: `+crt-static` removes it.
allowed_patterns='^(api-ms-win-core-|ext-ms-)'

# OS-shipped System32 DLLs. `ucrtbase` and the VC runtime are deliberately absent.
allowed_names='kernel32|kernelbase|ntdll|advapi32|ws2_32|crypt32|oleaut32|user32|ole32|shell32|bcrypt|secur32|userenv|wtsapi32|netapi32|shlwapi|rpcrt4|sspicli|ncrypt|iphlpapi|gdi32'

# Print the names on stdin that are not allowed.
disallowed() {
    grep -ivE "${allowed_patterns}|^(${allowed_names})\.dll\$" || true
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
dumpbin="$("$vswhere" -latest -products '*' \
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
    -find 'VC/Tools/MSVC/**/bin/Hostx64/x64/dumpbin.exe' | head -n 1 | tr -d '\r')"
if [[ -z "$dumpbin" ]]; then
    echo "::error::dumpbin.exe not found through vswhere" >&2
    exit 1
fi

# Both the load-time and the delay-load dependencies are listed as indented `NAME.dll` lines.
dlls="$("$dumpbin" -nologo -dependents "$exe" | tr -d '\r' | grep -iE '^[[:space:]]+[^[:space:]]+\.dll[[:space:]]*$' | tr -d ' \t')"
if [[ -z "$dlls" ]]; then
    echo "::error::no imports parsed from dumpbin output for $exe" >&2
    exit 1
fi

echo "imports of $exe:"
echo "$dlls"

if ! bad="$(bash "$0" --names <<<"$dlls")"; then
    echo "::error::$exe imports DLLs that are not on the allowlist of OS-shipped DLLs; a fresh Windows guest may not have them:" >&2
    echo "$bad" >&2
    exit 1
fi
