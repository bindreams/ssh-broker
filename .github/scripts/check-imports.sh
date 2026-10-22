#!/usr/bin/env bash
# Fail if the executable `$1` imports a DLL that a fresh Windows install does not ship.
#
# ssh-broker.exe becomes sshd's DefaultShell on guests that may lack the VC++
# redistributable, so the C runtime has to be linked in (`+crt-static`). A dynamic import
# of the VC or UCRT runtime would make every SSH login fail there, with no fallback.
set -euo pipefail

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

# Runtime families that are not part of a fresh Windows install (or that `+crt-static` removes).
forbidden='^(vcruntime|msvcp|msvcr|concrt|vcomp|vccorlib|ucrtbase|api-ms-win-crt-)'
if bad="$(grep -iE "$forbidden" <<<"$dlls")"; then
    echo "::error::$exe imports a runtime DLL a fresh Windows guest may not have:" >&2
    echo "$bad" >&2
    exit 1
fi
