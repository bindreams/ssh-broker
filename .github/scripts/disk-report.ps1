# Print the free space of the runner's drives and the size of what the tests fill them with, and list the profile of
# every test account that is left (a folder `sb*` in the users root or a profile-list entry for one), with its size.
# It does not fail on them: Task Scheduler and sshd logons leave a profile that the tests clear themselves (owner
# decision on the hive), and the sizes show a leak (CI round 14: 1.3 GB each filled the disk).
# Usage: disk-report.ps1 <label>. CI only; it changes nothing.
param([Parameter(Mandatory)][string]$Label)

$ErrorActionPreference = 'Continue'

function Get-TreeSizeGb([string]$Path) {
    if (-not (Test-Path $Path)) { return 'absent' }
    $bytes = (Get-ChildItem -LiteralPath $Path -Force -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    '{0:N2} GB' -f ($bytes / 1GB)
}

Write-Output "=== disk report: $Label ==="
Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Free } |
    ForEach-Object { '{0}: free {1:N2} GB, used {2:N2} GB' -f $_.Name, ($_.Free / 1GB), ($_.Used / 1GB) }

$places = @(
    (Join-Path (Get-Location).Path 'target'),
    "$env:USERPROFILE\.cargo",
    "$env:USERPROFILE\.rustup",
    $env:TEMP,
    'C:\Windows\SystemTemp',
    'C:\Windows\Temp',
    'C:\ProgramData'
)
foreach ($place in $places) { Write-Output ('{0}: {1}' -f $place, (Get-TreeSizeGb $place)) }

# The profiles the test accounts leave behind are folders of the users root named after the account (`sb...`).
$usersRoot = Split-Path -Parent $env:USERPROFILE
$prefix = Join-Path $usersRoot 'sb'
$profiles = Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'sb*' }
$count = @($profiles).Count
$total = 0
foreach ($profile in $profiles) {
    $total += (Get-ChildItem -LiteralPath $profile.FullName -Force -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
}
Write-Output ('{0}*: {1} folders, {2:N2} GB' -f $prefix, $count, ($total / 1GB))
$entries = @(
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath -like "$prefix*" })
Write-Output ('profile list entries under {0}*: {1}' -f $prefix, $entries.Count)

if ($count -ne 0 -or $entries.Count -ne 0) {
    Write-Output ('test account profiles are left after "{0}":' -f $Label)
    $profiles | ForEach-Object { Write-Output ('  folder {0}' -f $_.FullName) }
    $entries | ForEach-Object { Write-Output ('  profile list entry {0}' -f (Get-ItemProperty $_.PSPath).ProfileImagePath) }
}
