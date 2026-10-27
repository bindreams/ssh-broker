# Measure whether, and when, Windows unloads the hives of the test accounts that stay loaded after the tests
# (CI round 19: the product's `logout` ended everything it owns, and the hive of a Task Scheduler or sshd logon was
# still loaded 120 s later). Prints the logon sessions of the machine, then waits for each loaded `sb*` hive to
# unload and records when; then restarts the sshd service and records again which unloaded. Read-only except for
# the sshd restart. Always exits 0: the output is the result. CI only (the runner is discarded after the job).
# Usage: hive-unload-wait.ps1
$ErrorActionPreference = 'Continue'

# The longest the wait for Windows' own unload may take: an external event that may never happen.
$Bound = [TimeSpan]::FromMinutes(20)

Add-Type -Namespace Sb -Name Reg -MemberDefinition @'
[DllImport("advapi32.dll")]
public static extern int RegNotifyChangeKeyValue(System.IntPtr hKey, bool bWatchSubtree, uint dwNotifyFilter, System.IntPtr hEvent, bool fAsynchronous);
'@

$started = [DateTime]::UtcNow
function Stamp { '{0:HH:mm:ss}Z (+{1:N0} s)' -f [DateTime]::UtcNow, ([DateTime]::UtcNow - $started).TotalSeconds }

$LogonTypes = @{
    2 = 'Interactive'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'; 7 = 'Unlock'; 8 = 'NetworkCleartext'
    9 = 'NewCredentials'; 10 = 'RemoteInteractive'; 11 = 'CachedInteractive'
}

# The logon sessions LSA knows (Win32_LogonSession), with the account of each when it still resolves; the
# accounts of the tests are deleted, so theirs often do not. System sessions are left out.
function Show-LogonSessions([string]$When) {
    Write-Output "--- logon sessions $When, $(Stamp) ---"
    $owners = @{}
    Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | ForEach-Object {
        $owners[[string]$_.Dependent.LogonId] = '{0}\{1}' -f $_.Antecedent.Domain, $_.Antecedent.Name
    }
    $shown = 0
    $batch = 0
    foreach ($session in (Get-CimInstance Win32_LogonSession | Sort-Object StartTime)) {
        $owner = $owners[[string]$session.LogonId]
        if ($owner -match '^(NT AUTHORITY|Window Manager|Font Driver Host)\\') { continue }
        $type = $LogonTypes[[int]$session.LogonType]
        if (-not $type) { $type = "type $($session.LogonType)" }
        if ($session.LogonType -eq 4) { $batch++ }
        if (-not $owner) { $owner = '(account does not resolve)' }
        Write-Output ('  id {0} {1,-18} {2,-10} started {3:u} package {4}' -f $session.LogonId, $owner, $type, $session.StartTime, $session.AuthenticationPackage)
        $shown++
    }
    Write-Output "  $shown session(s) listed, of them $batch Batch"
}

# The subkey names of HKEY_USERS that are the hive (and classes hive) of an `sb*` test account: loaded, an
# S-1-5-21 SID, not the runner's own, and either with a profile under a folder `sb*` or with no profile-list entry.
function Get-TestHives {
    $own = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $names = [Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-[0-9-]+(_Classes)?$' }
    foreach ($name in $names) {
        $sid = $name -replace '_Classes$', ''
        if ($sid -eq $own) { continue }
        $path = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" `
                -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and (Split-Path -Leaf $path) -notlike 'sb*') { continue }
        $name
    }
}

function Show-ProfileList([string[]]$Names) {
    foreach ($sid in ($Names | ForEach-Object { $_ -replace '_Classes$', '' } | Sort-Object -Unique)) {
        $item = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue
        if ($item) {
            Write-Output ('  {0}: path {1}, RefCount {2}, State {3}, Flags {4}' -f $sid, $item.ProfileImagePath,
                $(if ($null -ne $item.RefCount) { $item.RefCount } else { 'absent' }),
                $(if ($null -ne $item.State) { $item.State } else { 'absent' }),
                $(if ($null -ne $item.Flags) { $item.Flags } else { 'absent' }))
        } else {
            Write-Output "  ${sid}: no profile-list entry"
        }
    }
}

$changed = New-Object System.Threading.ManualResetEvent $false

# Wait until every key of `$Names` has left HKEY_USERS, woken by a change of its subkeys, for at most `$Bound`.
# The notification is registered before the keys are looked at, so an unload between the two is not missed.
# Prints when each key unloaded (Write-Host, so the output stays apart from the return value); returns the keys
# that never did.
function Wait-Unloaded([string[]]$Names, [string]$Phase) {
    $hku = [Microsoft.Win32.Registry]::Users
    $remaining = New-Object System.Collections.Generic.List[string]
    $remaining.AddRange([string[]]$Names)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        [void]$changed.Reset()
        $status = [Sb.Reg]::RegNotifyChangeKeyValue($hku.Handle.DangerousGetHandle(), $false, 1, $changed.SafeWaitHandle.DangerousGetHandle(), $true)
        if ($status -ne 0) { throw "RegNotifyChangeKeyValue on HKEY_USERS failed with error $status" }
        $loaded = $hku.GetSubKeyNames()
        foreach ($name in @($remaining)) {
            if ($loaded -notcontains $name) {
                Write-Host ('  {0}: HKEY_USERS\{1} unloaded at {2}, {3:N0} s into this wait' -f $Phase, $name, (Stamp), $clock.Elapsed.TotalSeconds)
                [void]$remaining.Remove($name)
            }
        }
        if ($remaining.Count -eq 0) { break }
        $left = $Bound - $clock.Elapsed
        if ($left -le [TimeSpan]::Zero) { break }
        [void]$changed.WaitOne($left)
    }
    foreach ($name in $remaining) {
        Write-Host ('  {0}: HKEY_USERS\{1} did NOT unload within {2:N0} s ({3})' -f $Phase, $name, $clock.Elapsed.TotalSeconds, (Stamp))
    }
    $remaining.ToArray()
}

Write-Output "=== hive unload wait, started $(Stamp) ==="
Show-LogonSessions 'at the start'

$hives = @(Get-TestHives)
Write-Output "--- loaded hives of test accounts at the start: $($hives.Count) ---"
$hives | ForEach-Object { Write-Output "  HKEY_USERS\$_" }
Show-ProfileList $hives

$stuck = @()
if ($hives.Count -gt 0) {
    Write-Output "--- waiting for Windows to unload them (bound $($Bound.TotalMinutes) min) ---"
    $stuck = @(Wait-Unloaded $hives 'without any action')
}

if ($stuck.Count -gt 0) {
    Write-Output '--- restarting the sshd service ---'
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Output '  there is no sshd service on this machine'
    } else {
        Write-Output "  sshd was $($service.Status)"
        try {
            Restart-Service -Name sshd -Force -ErrorAction Stop
            Write-Output "  sshd restarted at $(Stamp), now $((Get-Service -Name sshd).Status)"
        } catch {
            Write-Output "  restarting sshd failed: $_"
        }
        $stuck = @(Wait-Unloaded $stuck 'after the sshd restart')
    }
}

Write-Output "--- result, $(Stamp) ---"
if ($hives.Count -eq 0) {
    Write-Output '  no hive of a test account was loaded at the start'
} elseif ($stuck.Count -eq 0) {
    Write-Output '  every hive that was loaded at the start unloaded'
} else {
    Write-Output "  never unloaded: $($stuck -join ', ')"
}
Show-LogonSessions 'at the end'
exit 0
