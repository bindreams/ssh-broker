# ssh-broker

Give a Windows SSH session the environment of a session you'd get by sitting at the machine.

## The problem

Log in over SSH with a key on Windows and you get a **network logon in session 0**. It authenticates you correctly, and then three things quietly do not work:

- **DPAPI fails for user-scope secrets.** A key-authenticated logon carries no credential material, so there is no user master key behind it, and `CryptUnprotectData` gets `ERROR_NO_SUCH_LOGON_SESSION`. Machine-scope blobs still work.
- **Your profile isn't loaded**, so environment and per-user state are not what your desktop session has.
- **Symlinks stop resolving.** The shell Windows OpenSSH spawns runs under the RedirectionGuard process mitigation, so traversing a reparse point created by a non-admin fails with `STATUS_UNTRUSTED_MOUNT_POINT`. In practice: every WinGet shim in `AppData\Local\Microsoft\WinGet\Links` — `fnm`, `uv`, `bun` — fails to launch.

RDP has none of these problems, and not because it is more trusted: the mitigation tracks which process spawned your shell, not how you authenticated. `explorer.exe` and `conhost.exe` do not carry it, and an interactive logon holds credential material.

## What this does

It relays your shell out of session 0 and into an interactive session that already exists.

```
ssh client ──▶ sshd ──▶ shim (DefaultShell) ──▶ AF_UNIX ──▶ agent (interactive session)
                                                                    │
                                                                    ▼
                                                        shell in a pseudoconsole
```

The **shim** is installed as sshd's `DefaultShell`, so every SSH session runs it instead of a shell. It forwards keystrokes, window resizes and mouse events to the **agent**, which lives in the interactive session and hosts your shell ([configurable](#shell-configuration)) — in a pseudoconsole for an interactive session or a command with a terminal, on redirected pipes for `ssh host "cmd"`. Output comes back the same way.

Because the shell is a child of the agent rather than of `sshd`, it inherits neither the network logon nor the RedirectionGuard mitigation. DPAPI works, the profile is loaded, and symlinks resolve — without disabling a security mitigation or storing a password anywhere. `verify` checks the session id and DPAPI, and reports symlink traversal — failing only on a confirmed block, since the unprivileged agent usually cannot create a link to test with. The profile follows from the interactive logon rather than being probed separately. Those checks run in a child the agent spawns, so if the relay stops delivering, `verify` reports that as a failed row and exits rather than hanging — `--probe-timeout <seconds>` adjusts how long it waits, and `0` waits indefinitely.

There is **one agent per logged-on user**, and each user's agent serves only that user. The logon task runs for every member of `BUILTIN\Users` and starts the agent in the session of whoever logs on; `apply` registers it without a password and starts one in each session that is already logged on. The shim connects to the socket of the account sshd authenticated, found from its own token's profile and from nothing else: there is no setting, flag or environment variable that points it at another account's agent. An administrator who SSHes in as `bob` gets bob's agent or a local shell, never another user's session.

The two halves talk over an AF_UNIX socket, `%LOCALAPPDATA%\ssh-broker\agent.sock` inside the user's own profile. Two ACLs protect it, and both grant Full Control to exactly that user, SYSTEM and Administrators:

- The socket **file's** ACL decides who can connect. Windows AF_UNIX has no peer credentials, and the folders above the socket are no barrier: every ordinary user holds the privilege that skips traverse checks, so a second user who knows the path reaches the file itself.
- The socket **folder's** ACL decides who can create, replace or delete the socket. Its entries are inheritable, so the socket, the lock files and the logs folder are born with the same set instead of the creating process's default ACL.

`bind` verifies the folder fail-closed before it binds, and the socket file right after, before it listens; a socket whose ACL cannot be proven is removed. The install directory `C:\ProgramData\ssh-broker`, which holds the exe the agent and the self-heal task run, is writable only by SYSTEM and Administrators (everyone else may read and execute), and `apply` verifies that fail-closed too. An install directory made by an earlier build is refused: inspect it, remove it, run `apply` again.

If a user is logged on in two sessions, the second session's agent waits and takes over when the first one's session ends, so the user keeps an agent for as long as they are logged on anywhere. A second agent in the same session exits at once.

`ssh-broker verify` reports on the account that runs it and no other; each user runs it for themselves. If its `socket reachable` row fails, run `ssh-broker agent` in your desktop session: the logon task discards the agent's stderr, and an error before the agent's log opens (`%LOCALAPPDATA%\ssh-broker\logs\agent.log`) is printed there and nowhere else. That includes a log that cannot be set up at all, such as a folder owned by someone else: the agent prints the cause there and keeps serving without a log. Its `log folder` row shows when that folder is missing or does not grant exactly you, SYSTEM and Administrators.

A profile path so long that the socket path would pass the 107-byte AF_UNIX limit (only possible with a relocated profile root) is refused with the reason: the socket stays inside the profile, because that is what keeps it private, and the shim fails open.

## Background sessions

A user with no session on the PC (nobody logged in at the console or over RDP) has no interactive session to relay into. An interactive SSH login then asks for the Windows password:

```
ssh-broker: <user> has no Windows session on this PC. Enter your Windows password to start one. (The password goes to Windows to sign you in; ssh-broker does not store it.) Press Ctrl+C for a plain shell.
```

The password is not echoed, goes to Windows (`CreateProcessWithLogonW`) and nowhere else, and is wiped from the buffers ssh-broker holds as soon as the call returns. Windows signs the account in and starts `ssh-broker agent --background` in a new logon session with a loaded profile; the login relays into it. The session has no desktop and lasts until the PC restarts or you run `logout`. If you sign in at the desktop afterwards, no second agent starts: the background session keeps serving.

Three ways out of the prompt, none of which starts a session:

- **Ctrl+C or Ctrl+D**, at any point while typing, gives the plain shell and a line that says what it lacks.
- **A wrong password** prints Windows' reason and gives the plain shell. There is one attempt per connection; reconnecting asks again. Windows' account lockout policy counts these like any other failed sign-in.
- **A login that cannot ask** (`ssh host cmd`, `scp`, `sftp`, `ssh -T`) never prompts. It runs as before, with one line on stderr that names `ssh -t` and `auto-login on`.

Enter on an empty line does not mean "plain shell": it says empty passwords are not supported yet (ssh-broker#45) and asks again.

### Starting one at boot: `auto-login`

`auto-login` stores your Windows password with Task Scheduler and registers a task that starts your background session at boot, so the session exists before anyone logs in and nobody types a password after a restart.

```
C:\ProgramData\ssh-broker\ssh-broker.exe auto-login on  [<account>]
C:\ProgramData\ssh-broker\ssh-broker.exe auto-login off [<account>]
```

Both need **an elevated administrator shell**, and take the account to act on (the account running the command by default). Task Scheduler refuses a boot trigger to any token that is not an elevated administrator's, for a standard user and for a non-elevated administrator alike. A shell that ssh-broker hosts is not elevated, so:

- at the PC, open an elevated prompt (one UAC prompt);
- over SSH as an administrator, run `ssh-broker.exe logout`, reconnect and press Ctrl+C at the password prompt for a plain shell: that shell runs under sshd's own token, which for an administrator may be elevated (to be confirmed against a real `sshd`);
- a standard user cannot run it alone: an administrator runs it for them and types their password.

`on` asks for the account's password, checks that Windows accepts it for a batch logon, registers the task, reads the registered task back and compares it with what it asked for (a mismatch deletes the task and fails), and starts the task once so the session begins now. The task runs the installed exe, in the administrator-only install directory, with the plain token, and its permissions let only SYSTEM and Administrators change it.

The account must hold **"Log on as a batch job"**. Administrators hold it by default; a standard account does not, and `on` refuses, naming the right: an administrator can grant it in Local Security Policy (User Rights Assignment). ssh-broker never changes machine policy.

`off` deletes the task, which deletes the stored password with it. A session that is running continues until `logout`. `on` and `off` take the lock `apply` takes (see Upgrading) for their steps, so neither runs in the middle of an `apply`, and an `apply` does not run in the middle of either: they wait for each other's steps. `on` first checks, changing nothing, that `apply` has installed the exe (otherwise it says to run `apply` first, before asking for anything and without creating the install directory), asks for the password, and only then takes the lock, so a prompt left open holds up nothing. `off` takes the lock only if there is an install directory that passes its check; if there is none, or it fails its check (so no `apply` can run), or the lock cannot be taken (an error such as a lock file with the wrong access; waiting for another holder is not one), it deletes the task without the lock, and in the last two cases prints a warning naming the reason or the cause. `verify` has an `auto-login task` row: it checks the task's definition and reports its last result, and says plainly that a failed logon is not recorded there, so a stale password or a missing batch right shows only as a session that did not start; you are then asked for the password again at the next login.

Windows' own auto-logon is a different, documented option: signing the user in at boot (Sysinternals Autologon, or `netplwiz` where it applies) gives a desktop session, and the logon task's desktop agent then serves. ssh-broker does not configure it; it stores the password as an LSA secret and leaves a signed-in desktop.

### Ending one

`ssh-broker logout` ends your background session: the agent, every shell it hosts and the processes they started. Run it with the installed exe's full path, `C:\ProgramData\ssh-broker\ssh-broker.exe logout`, because `apply` does not put the install directory on `PATH`. The usual place to type it is a shell the session itself gave you; the agent waits for the command to finish and print its reply before it ends anything, and your SSH connection then closes.

| Exit code | Meaning |
|---|---|
| 0 | The session ended. |
| 1 | You have no session to end (also when the session was ending already and is gone by the time `logout` connects again). |
| 2 | Your agent runs in your desktop session; signing out of Windows ends it. |
| 4 | Your agent could not be reached for another reason (access denied, a socket path that is too long): the message names it. |
| 254 | The agent closed two connections in a row without answering, which an agent of this version never does (it may be an older ssh-broker). |

A login that reaches the agent while it is ending gets no shell. It prints `ssh-broker: your background session is ending; reconnect in a moment.` and exits 255, the code ssh uses for a connection that failed, so a script cannot take it for the command's own failure.

A login the agent cannot serve for another reason also gets a line saying why, and ends the connection with a code that is not the command's: 255 when the agent could not start the shell or the command (`ssh-broker: the agent could not start the command: ...`), 254 when it could not read the request. A command whose connection ends before the agent says anything prints `ssh-broker: the agent ended before it answered; the command may or may not have run` and exits 255; it is never sent again. A login (or `logout`) whose connection is closed without an answer twice in a row prints `ssh-broker: the agent closed the connection twice without answering; it may be a different ssh-broker version` and exits 254. A connection that the agent cannot use, or whose handler failed, is answered with a line saying so and exits 255.

## Requirements

None beyond Windows with OpenSSH. The default shell is the system `cmd.exe`, which every Windows has. To use PowerShell Core (`pwsh`), install it and name it in the [shell configuration](#shell-configuration); stock Windows ships `powershell.exe` 5.1, which is a different binary.

## Shell configuration

ssh-broker starts the shell you choose, the way stock OpenSSH does: a login runs the shell, and `ssh host cmd` runs it with the command packed after its command option (`cmd.exe /c "cmd"`, `pwsh -c cmd`). The same happens when the shim fails open.

The configuration is read from the first of these that has a `shell` block, re-read for every session:

1. the user's `%XDG_CONFIG_HOME%\ssh-broker\config.yaml` (when that variable is an absolute path), else `%USERPROFILE%\.config\ssh-broker\config.yaml` (the profile is the account's own, not the variable);
2. the system's `C:\ProgramData\ssh-broker\config.yaml`;
3. the built-in `cmd.exe` of the system directory.

A `shell` block replaces the one below it as a whole. The canonical form, with every key:

```yaml
shell:
  start: [pwsh.exe]
  append:
    without-command: []
    with-command: [-c]
  escaping: msvc        # cmd | msvc
```

`shell: pwsh.exe` means `shell: {start: pwsh.exe}` means `shell: {start: [pwsh.exe]}`; a string is exactly one argument and is never split. A bare name is searched on the `PATH` of the process that starts the shell (the agent, for a relayed session), in order, with `.exe` added when the name has no extension; anything with a separator must be an absolute path. Nothing in `start` is expanded: `%VAR%` stays as written. Keys are kebab-case, and an unknown key is an error.

- `start`: the program and its leading arguments.
- `append.without-command`: added after `start` for a login (default: nothing).
- `append.with-command`: added after `start` for a command (default `/c` for the system `cmd.exe`, else `-c`).
- `escaping`: how the command follows. `cmd` wraps it in quotes and changes nothing else, as sshd does for `cmd.exe`. `msvc` makes it one argument in standard `CommandLineToArgvW` quoting, which any program that splits its line that way (PowerShell, most native programs) reads back exactly. Default `cmd` for the system `cmd.exe` (decided by the file, not the spelling of its path), else `msvc`. A command with a terminal (`ssh -t host cmd`) is appended as written, as OpenSSH does. Without a terminal, leading spaces, tabs, CRs and LFs of the command are dropped for `msvc` as well as for `cmd` (the one trim `CreateProcessW` needs, applied to both, so an `msvc` argument never starts with a line break); a command with a terminal keeps its leading line breaks.

A file or shell that cannot be used is never a lockout: the session runs the built-in `cmd.exe` after one warning on stderr that names the file and the value, not the next layer up. `ssh-broker verify` prints the effective block with where each value comes from, and fails its `shell config` row while a fallback is in effect.

`apply` creates the system file once, from the shell sshd used before ssh-broker, so sessions keep starting it: `DefaultShell` becomes `start`, `DefaultShellCommandOption` becomes `with-command` (split into words, as sshd pastes it into the line, so `/d /c` is two arguments), `DefaultShellArguments` becomes `without-command`, and `DefaultShellEscapeArguments` becomes `escaping` for a shell sshd treats as "other" (not `cmd`, PowerShell, bash, Cygwin or `ssh-shellhost`, which sshd escapes by its own rules). A value longer than sshd reads (16,383 characters) counts as not set, as it does for sshd; a `DefaultShell` that long is no shell. sshd reads the three string values as raw bytes whatever their registry type, and so does `apply`: a `REG_EXPAND_SZ` keeps its `%VAR%` text, as it does for sshd. Every `apply` removes `DefaultShellArguments` from the registry once `DefaultShell` is ssh-broker and the system file exists, since sshd would pass it to ssh-broker ahead of `-c`, and prints the value it removed; with no file to hold it, `apply` leaves the value and says so, and a later `apply` that finds the file removes it. If the removal fails, `apply` prints the value and the cause, and the next `apply` tries again. Only values that differ from what ssh-broker would do for that program are written. A `DefaultShell` that is a bare name is looked up as sshd does (the directory of the sshd service, the system directory, the Windows directory, then `PATH`) and the file found is what the config names, since a session searches `PATH` alone; when no file is found, `apply` prints every previous value so you can restore them. `apply` never rewrites the file, and writes nothing when the previous shell was ssh-broker, is not installed, or was never set.

## Limits worth knowing before you install it

- **A background session needs your password once.** If you have no session on the PC, an interactive login (`ssh -t`) asks for your Windows password and starts one (below). A login that cannot ask (a command, `scp`, `sftp`, or no terminal), and a login that declines, gets your configured shell in the plain session sshd made, without DPAPI, a loaded profile or symlink traversal. Only local accounts with a non-empty password are supported (ssh-broker#45).
- **Your session's background processes die with it.** When the session ends, everything it spawned is terminated — including a process that redirected its output to a file and never touched the session's pipes. There is no `nohup` equivalent here. This matches what stock Windows OpenSSH does; it is the opposite of Unix, where the session waits for pipe EOF.
- **The shim fails open.** If the agent is unreachable it runs your command locally and says why, rather than locking you out of the machine. That is deliberate: a broken broker must never cost you SSH access. The reason goes to stderr for `ssh host cmd`; for an interactive session it goes to the log in your own `%LOCALAPPDATA%\ssh-broker\logs` (the agent logs there too), because writing to stderr there would corrupt the terminal stream. The one exception is a reason that comes from your own setup, such as a profile path too long for a socket: that is printed to stderr in both modes, before the fallback shell starts. If the shim cannot set up its log (the folder belongs to someone else, say), it carries on without one; for `ssh host cmd` the fallback message then also says why there is no log, and in the other cases `verify`'s `log folder` row is where to look. The fallback runs the session through your configured shell, with the command packed as it would have been under the agent; if that shell cannot be used, the built-in `cmd.exe` runs after a warning on stderr.
- **Everything goes through the relay, including `sftp` and `scp`.** No command is *classified* and routed around it — the fail-open above is a different thing, running locally because the agent is unreachable rather than because of what the command is. Deciding what to route would mean classifying a command from a string the client chose — and sshd rewrites commands before the shim ever sees them. The relay carries arbitrary bytes unchanged in both directions (tested, and checked end to end by `verify`), so transfers work normally; running them locally would be faster, and that is a trade we take deliberately rather than guess at what a command is.
- **`apply` owns `DefaultShellEscapeArguments`.** It sets `HKLM\SOFTWARE\OpenSSH\DefaultShellEscapeArguments` to the DWORD 1 (sshd's default), before it registers the shim as `DefaultShell`, overwriting any other value, and `verify` fails if sshd would read it as off. Without a PTY, sshd passes the command to the shim in one of two encodings depending on that value. sshd reads the value once per session, when it starts, so a shim that read it later could disagree with the session it serves. The shim therefore always decodes the escaped form and reads no registry value; keeping the value at 1 is what keeps it right.

## Install

Releases carry `ssh-broker-<version>-x86_64-pc-windows-msvc.zip` (`ssh-broker.exe` and the license) and a `.sha256` file, with a build attestation on the zip. Verify before installing:

```sh
gh attestation verify ssh-broker-<version>-x86_64-pc-windows-msvc.zip -R bindreams/ssh-broker \
    --signer-workflow bindreams/ssh-broker/.github/workflows/release-asset.yaml \
    --source-ref refs/heads/main
sha256sum -c ssh-broker-<version>-x86_64-pc-windows-msvc.zip.sha256
```

Then extract it and, from an elevated prompt, run `ssh-broker.exe apply`. It installs the broker for every user: each user who logs on gets their own agent. `ssh-broker.exe verify` checks the result for the user who runs it. The executable is statically linked, so it needs no Visual C++ redistributable.

## Upgrading

An install that already uses ssh-broker has no previous shell for `apply` to carry, so after the upgrade to this version sessions start the built-in `cmd.exe`, not `pwsh`. If you want `pwsh`, add `shell: pwsh.exe` to the system or the user [shell configuration](#shell-configuration).

Run `apply` again from an elevated prompt with the newer build. A running agent holds the installed exe open, so when `apply` replaces the exe with a different build it first disables the logon task, so no logon starts an agent from the old exe meanwhile, stops every agent the task started and waits for each to exit, then enables the task again and starts one in each logged-on session (also if a later step fails). Their open SSH sessions end; users reconnect. An agent started by hand with `ssh-broker agent` is not stopped, and the shim of an SSH session that is still open holds the exe too (it is sshd's `DefaultShell`): if either still holds the exe, `apply` fails with a message saying so; find them with `tasklist /fi "imagename eq ssh-broker.exe"`, end them or close the sessions, and run `apply` again. If an agent does not exit after being stopped, `apply` fails naming its process id and starts no agent in that session; run `apply` again once the process has exited. A killed `apply` can leave the logon task disabled, which `verify` reports on its `agent task` row; a later `apply` enables it again once it is past its argument check, the check of the install directory, the check of the lock file and the wait described next, and the query of the registered agent task (one that fails earlier leaves the task as it was). An `apply` of the build that is already installed leaves agents alone. Only one `apply` runs at a time on a machine, for its whole run (a lock on `apply.lock` in the install directory, a file only SYSTEM and Administrators can open, so that no standard user can hold it; `apply` refuses a lock file with any other access and tells you to remove it); the boot self-heal is an `apply` too, and one that starts while another is running waits for it. `auto-login on` and `off` take the same lock and wait for it in the same way.

Background sessions are replaced the same way. Before it replaces the exe, `apply` disables every auto-login task, stops every user's auto-login session and ends every background session that no task owns (one the password prompt started), waiting for each process; after the copy it enables the auto-login tasks again and starts each one, also if a later step fails. A prompt-started session is not restarted: its user is asked for the password at the next login. Background sessions are found by the installed exe's file identity and told from a shim by their command line (`agent --background`), so an SSH session's shim is never ended by `apply`; it holds the exe until its session closes, and `apply` then fails with the message above.

The contract: an upgrade is expected to succeed, and nothing is guaranteed to be in a valid state while it runs. If it is interrupted (a killed `apply`, a power cut), run `apply` again: it repairs an incomplete state. Every `apply` that is past the checks listed above for enabling the logon task (the argument check, the check of the install directory, the check of the lock file and the wait, and the query of the registered agent task), including one of the build that is already installed, ends by enabling every auto-login task that is disabled and starting each enabled one that has no running session (it does not stop or restart a session that is running), as it already does for the logon task; an `apply` that fails one of those checks repairs nothing. So a task you disabled by hand in Task Scheduler is enabled again by the next `apply`; `auto-login off` is the way to turn auto-login off.

### From a single-user install

Earlier builds ran one agent for one configured account (`apply --user`, `config.toml`, a shared `C:\ProgramData\ssh-broker\s` socket directory). Run `apply` again from an elevated prompt: it stops that agent, deletes `config.toml` and the old socket directory, and replaces both tasks. The old agent's sessions end. The old `C:\ProgramData\ssh-broker\logs` stays on disk and may be deleted. `--user` is gone, because there is no target account any more; a leftover boot-time task that still passes it is accepted with a warning, so it can finish the repair.

## Status

Working and tested, but pre-1.0. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and test it, and how releases are made.

## License

[GPL-3.0](LICENSE.md)
