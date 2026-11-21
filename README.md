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

Because the shell is a child of the agent rather than of `sshd`, it inherits neither the network logon nor the RedirectionGuard mitigation. DPAPI works, the profile is loaded, and symlinks resolve — without disabling a security mitigation or storing a password anywhere. `doctor` checks the session id and DPAPI, the level a login gets (see [Elevated sessions](#elevated-sessions)), and whether a junction that a non-administrator made is followed, which is what RedirectionGuard refuses: it fails on a junction that is not. The profile follows from the interactive logon rather than being probed separately. Those checks run in a child the agent spawns, so if the relay stops delivering, `doctor` reports that as a failed row and exits rather than hanging — `--probe-timeout <seconds>` adjusts how long it waits for each probe (an administrator's elevated agent is probed twice, so `doctor` can take twice that), and `0` waits indefinitely.

There is **one agent per logged-on user**, and each user's agent serves only that user. The logon task runs for every member of `BUILTIN\Users` and starts the agent in the session of whoever logs on; `install` registers it without a password and starts one in each session that is already logged on. The shim connects to the socket of the account sshd authenticated, found from its own token's profile and from nothing else: there is no setting, flag or environment variable that points it at another account's agent. An administrator who SSHes in as `bob` gets bob's agent or a local shell, never another user's session.

The two halves talk over an AF_UNIX socket, `%LOCALAPPDATA%\ssh-broker\agent.sock` inside the user's own profile (`%LOCALAPPDATA%\ssh-broker-elevated\agent.sock` for an agent at High integrity, an administrator's: see [Elevated sessions](#elevated-sessions)). Two ACLs protect it, and both grant Full Control to exactly that user, SYSTEM and Administrators:

- The socket **file's** ACL decides who can connect. Windows AF_UNIX has no peer credentials, and the folders above the socket are no barrier: every ordinary user holds the privilege that skips traverse checks, so a second user who knows the path reaches the file itself.
- The socket **folder's** ACL decides who can create, replace or delete the socket. Its entries are inheritable, so the socket, the lock files and the logs folder are born with the same set instead of the creating process's default ACL.

`bind` verifies the folder fail-closed before it binds, and the socket file right after, before it listens; a socket whose ACL cannot be proven is removed. For an elevated agent both must also carry the High integrity label, or it does not bind. The install directory `C:\ProgramData\ssh-broker`, which holds the exe the agent runs, is writable only by SYSTEM and Administrators (everyone else may read and execute), and `install` verifies that fail-closed too. An install directory that is not the hardened one is refused: inspect it, remove it, run `install` again.

If a user is logged on in two sessions, the second session's agent waits and takes over when the first one's session ends, so the user keeps an agent for as long as they are logged on anywhere. A second agent in the same session exits at once.

`ssh-broker doctor` reports on the account that runs it and no other; each user runs it for themselves. If its `socket reachable` row fails, run `ssh-broker agent` in your desktop session (an administrator runs it from an elevated prompt: at an ordinary one the agent refuses to start and exits 68): the logon task discards the agent's stderr, and an error before the agent's log opens (`%LOCALAPPDATA%\ssh-broker\logs\agent.log`, under `ssh-broker-elevated` for an agent at High integrity) is printed there and nowhere else. That includes a log that cannot be set up at all, such as a folder owned by someone else: the agent prints the cause there and keeps serving without a log. Its `log folder` row shows when that folder is missing or does not grant exactly you, SYSTEM and Administrators. An administrator's `doctor` run below High fails the `socket reachable` row with the commands to run instead (see [`doctor`](#doctor)).

A profile path so long that the socket path would pass the 107-byte AF_UNIX limit (only possible with a relocated profile root) is refused with the reason: the socket stays inside the profile, because that is what keeps it private, and the shim fails open.

## Elevated sessions

An administrator's brokered session starts unelevated, as a prompt opened at the desktop does: `ssh host whoami /groups` shows Medium integrity, with Administrators deny-only. Two things raise it. The login can ask for an elevated session from the start with `SSH_BROKER_ELEVATION=always` (below): `whoami /groups` then shows High integrity, with Administrators enabled. And a program in an unelevated session can run one command elevated with [`ssh-broker elevate`](#ssh-broker-elevate). The same holds for an account whose token Windows splits without making it an administrator (a member of Backup Operators, say). A standard account's session has the only token it has, and `elevate` is refused there (see the limits).

The agent is elevated, and the shell it hosts inherits that only when the login asks for `always`: any other login gets the unelevated token described below. It is started elevated three ways: by the logon task (`HighestAvailable`: an administrator's full token, a standard account's only token), by the password prompt (a batch logon, which gives the full token) and by the `auto-login` task. An administrator's agent is never below High: one started at an ordinary prompt refuses to run and exits 68, so a login of an administrator meets an elevated agent or none.

**Two folders.** An agent at High integrity keeps its socket, lock files and logs in `%LOCALAPPDATA%\ssh-broker-elevated`; every other agent keeps them in `%LOCALAPPDATA%\ssh-broker`. The elevated folder is created with the High mandatory integrity label, and the agent binds only if the folder and the socket file carry it. Connecting to a socket needs write access to its file, and the label refuses write to a process below High, so an unelevated process of an administrator (a desktop program, an ordinary prompt, an unelevated session) cannot connect to the elevated agent's own socket whatever the socket's ACL says. An agent at High also keeps `request.sock` in `%LOCALAPPDATA%\ssh-broker`, and a process of the account below High can connect to it. It takes `logout` and `elevate` and no other request, and no session ever starts on it. If that folder cannot be used (it is wrongly owned, or held by another program), the agent still serves its sessions and has no request socket. An account that joins or leaves Administrators uses the other folder from its next login; each folder is created right and never repaired. An administrator's `ssh-broker` folder holds `request.sock` and the log of the account's unelevated shims; [Upgrading](#upgrading) says what to do with what an earlier version left in it.

### The level of a session

A session is unelevated unless the login's `SSH_BROKER_ELEVATION` says otherwise. The value is one of four words, in lower case and with no padding. What each does to the session and to `ssh-broker elevate` typed in it:

| Value | The session starts | `ssh-broker elevate` in it |
|---|---|---|
| `never` | unelevated | refused |
| `prompt` | unelevated | asks the person at the terminal first (the default) |
| `auto-approve` | unelevated | runs the command without a question |
| `always` | elevated | runs the command in the session itself, asking nobody |

A login that does not set the variable is given what `prompt` gives. A login that asks for `always` and cannot have it is refused before anything is started or asked for, with a sentence that names the variable (exit 255, nothing run): when its own token is below High, or is an administrator's with elevation removed, or its level cannot be read. A client configuration that sets `always` for every host therefore refuses every login to a machine where it cannot be had. A value that is none of the four words fails the login the same way, and so does a login that set `never`, `prompt` or `auto-approve` whose unelevated token cannot be made. Nothing on the SSH command line is interpreted.

**How to ask.** `ssh -o SetEnv=SSH_BROKER_ELEVATION=always host` asks for an elevated session. `SetEnv SSH_BROKER_ELEVATION=auto-approve` in a `Host` block of the client's configuration sets that value on every login to that host: its sessions are unelevated, and `ssh-broker elevate` in them runs without a question. sshd hands the variable to the session only if it accepts it, which `install` sets up (the `sshd accepts SSH_BROKER_ELEVATION` row of `doctor` says whether it does). One it does not accept is dropped without a word, and the session is unelevated. A server can pin a value instead: `SetEnv SSH_BROKER_ELEVATION=never` in `sshd_config`, globally or in a `Match` block, wins over what the client sends and needs no `AcceptEnv` (measured with the in-box sshd of Windows Server 2025). A program that runs commands over SSH and sometimes needs one of them elevated sets `auto-approve` and runs `ssh-broker elevate <command>` for that one, or asks `always` for the whole login.

**What an unelevated session is.** It runs at Medium integrity, with Administrators deny-only and the privileges UAC's filtered token has, in the agent's own logon session (the same profile, `HKCU` and DPAPI). It cannot write what only administrators can write, cannot open the agent's process for write and cannot connect to the agent's own socket; it reaches the agent only on `request.sock`, for `logout` and `elevate`. Every session of an agent has its own random id in `SSH_BROKER_SESSION`, which it can read. The id tells the agent which session a request is for and proves nothing. Windows calls it not elevated. Its token differs from the one UAC makes in two fields: its elevation type is the agent's (Full or Default, where UAC's says Limited), and file and registry virtualization is off, where UAC's has it on: a legacy program that writes under `Program Files` is refused here where UAC would redirect the write.

**What it is not.** An unelevated session is a convenience, not a confinement. A client can ask for `always` as it can leave it out, and the level does not restrict what the account or a key can do. An unelevated session is not separated from the account's elevated agent by anything ssh-broker promises: it shares the agent's logon session, which UAC's own pair of tokens does not. The gate on the socket means that a process of the account below High cannot take an elevated shell at will. It does not mean that such a process can never influence an elevated session: the account's own startup files (a PowerShell profile, say) run in every elevated shell, brokered or not.

`auto-approve` means what it says: in a login that asks for it, any program in the session can run a command elevated without a question. A server administrator who does not want that pins `prompt` or `never` with `SetEnv`.

A program of the account can connect to `request.sock`, as any program of a standard account can connect to its `agent.sock`. One that opens connections and sends nothing ties up its own account's agent and can delay its end by up to 30 seconds. Nothing guards against this.

**Windows' `sudo` and gsudo.** `ssh-broker elevate` asks on the SSH terminal and starts the command from the agent, which is already elevated, so it needs no desktop. gsudo 2.6.1 did not elevate in an unelevated brokered session of an administrator, measured on Windows Server 2025 in a background session (no desktop): it exited 999 and, with a terminal, printed `This operation requires an interactive window station`. Windows' own `sudo` was not on that machine. A session whose agent runs at the desktop, and a UAC that asks for consent, were not measured.

### `ssh-broker elevate`

```
ssh-broker elevate [--terminal] <command> [arguments]
```

Typed in a session that an agent hosts, it runs the command elevated. Where it runs depends on the session's level (the table above).

**Where it works.** In a shell that has a valid `SSH_BROKER_SESSION`, at any level: one that has none is refused, an elevated prompt at the desktop included. In a session below High it asks the account's agent on `request.sock`, and the agent starts the command with its own elevated token. At High (a session that asked for `always`) it starts the command itself, in place, on the console it has, and asks nobody; `--terminal` changes nothing there, and Ctrl+C and Ctrl+Break go to the command.

**What runs.** The line typed after `elevate`, as written, started directly: not through the configured shell. The program is a path (it contains `\`, `/` or `:`; a relative one is taken from the folder `elevate` was typed in) or a bare name searched on `PATH` only, with `.exe` added when the name has no extension. A shell built-in (`dir`) and a name that only `PATHEXT` completes (`npm` for `npm.cmd`) are not found and nothing runs: name the file (`npm.cmd`), or run it through the shell (`elevate cmd /c dir`). It starts in the folder `elevate` was typed in. When the agent starts it, its environment is the agent's, not the session shell's: a variable set in the session is not in it, and `SSH_BROKER_SESSION` is.

**Where its output and input go.** By default the command runs on pipes with its input closed, and `elevate` prints its output: stdout to stdout and stderr to stderr, in the session below the line that was typed, so it can be piped (`ssh-broker elevate whoami /groups | findstr Label`). Ctrl+C ends `elevate` and with it the command. With `--terminal`, which counts only as the first argument and needs a session with a terminal, the command gets a screen of its own, for a program that needs one (an elevated shell, an editor): it owns the screen while it runs and gets the keys typed meanwhile. When it ends the keys are the session's again and the session's screen is repainted; what the command showed is not kept. A command run with `--terminal` also ends with the session whose screen it holds. One elevation runs at a time in a session.

**Exit codes.**

| Exit code | Meaning |
|---|---|
| the command's | The command ran, and this is how it ended. It can equal 126 or 255: the line `elevate` prints on a refusal tells them apart. |
| 126 | The command was not run: a refusal (below), after a line that says why. |
| 255 | `elevate` cannot tell how the command ended: the agent ended before it answered (`ssh-broker: the agent ended before it answered; the command may or may not have run`), its answer could not be read, or the command ran and its end could not be read. A command is never sent a second time: the agent may have started it. |
| 2 | No command was given: `usage: ssh-broker elevate [--terminal] <command> [arguments]`. |

**What refuses it.** A refusal, by `elevate` itself or by the agent, is exit 126 after one line that starts with `ssh-broker: ` and says why (the table above has the other codes). The refusals a person can do something about, which are not all of them:

- Outside a session an agent hosts: `this shell is not hosted by ssh-broker, so nothing can be elevated from it (a session of an agent from before this version has no session id: end it and log in again).`
- A session whose account's agent runs below High (a standard account's): `elevate needs an account whose agent runs at High, and this account's agent does not.`
- `never`: `this login asked that nothing be elevated (SSH_BROKER_ELEVATION=never).`
- `prompt` in a session without a terminal, where there is nobody to ask: `this login asks before elevating, and this session has no terminal to ask on. Log in with ssh -t, or with SSH_BROKER_ELEVATION=auto-approve to run commands elevated without a question, or with SSH_BROKER_ELEVATION=always to run the whole session elevated.`
- `--terminal` in a session without a terminal: `--terminal needs a session with a terminal, and this one has none: log in with ssh -t, or leave out --terminal to run the command with its output here and its input closed.`
- A question answered with anything but yes: `running the command as administrator was not allowed, so nothing was run.`
- A session that ends while its question is open: `this session ended before the question was answered, so nothing was run.`
- A second elevation while one is asked or runs: `another elevation is in progress in this session.`
- A request for a session whose login asked for `always`, which can come only from a process below High somewhere else in the account (in the session itself `elevate` runs the command in place): `this session is already elevated: run the command in it.`
- An agent that is ending: `your background session is ending; reconnect in a moment.`
- A request the agent cannot read or serve, such as one from a client of another version or a command of 32,767 UTF-16 units or more: `the agent could not read the request: <cause>` or `the agent could not serve the request: <cause>`.
- A command that cannot be started, the program not found, the folder gone, this process's own level unreadable and an agent that cannot be reached included: `the command could not be started elevated: <cause>`.

### The question

In a session with a terminal, `prompt` asks the person before anything runs. The session's own shim, which sits under sshd, writes on the person's terminal. It resets the character attributes, the scroll region and the cursor's visibility, clears the screen, and shows:

```
ssh-broker: a program in this session asks to run as administrator:
    <command>
    in <folder>
Run it as administrator? [y/N]
```

`y` or `yes`, in any case, and Enter run the command. Anything else refuses, Enter alone and Ctrl+C included, with no second question for the same request. The command and the folder are shown as text: a control character, or a bidirectional or zero-width format character, is shown as an escape, and more than 400 characters of either are cut, with a note of how many there were. The agent holds the session's output while the question is open, so no program in the session can write into it. When the command starts, or the request is refused, the session's screen is repainted by giving its pseudoconsole its size again; a program that was running in it is not told to redraw. A command run with `--terminal` takes the screen straight from the question.

What the person typed or pasted before the question appeared goes on to the session and runs after it; nothing of the session's input is discarded for a question. The answer is the next line typed after the question appeared. A pasted line that is still on its way when the question appears can therefore answer it, and refuses it unless it is `y` or `yes`. Keys typed after the answer go to the command when it has a screen of its own (`--terminal`), and otherwise to the session. A question whose program has gone, or whose session has ended, is taken off the screen and nothing runs.

A process below High that asks to attach to the console of a process on the shim's console is refused by Windows (measured with the in-box sshd of Windows Server 2025), and what a program writes to its own output is not read as an answer. The question is a consent step, not a boundary: a program in the session can ask, and can write to the terminal before and after.

### `doctor`

The report begins with a line that names the version and this executable's path, `ssh-broker v<version> (<path>)` (the version alone when the path cannot be read); the line has no `[PASS]` or `[FAIL]` and judges nothing. The rows follow it.

For an agent at High (an administrator's elevated one, or that of an account Windows splits without making it an administrator) `doctor` runs two probes through the agent, first one that asks for `prompt`, the default level (an unelevated session) and then one that asks for `always`; an agent below High is probed once. The rows about the session a login gets (the session id, DPAPI, the bytes of the relay) are those of the first probe, since that is what a login at the default level gets. The session that the shim runs for a login that set nothing, when its unelevated token cannot be made (the limit "A login that does not set `SSH_BROKER_ELEVATION` can end elevated ..."), is not what `doctor` measures: there the probe is refused and `doctor` shows the refusal. The rows:

- `session`: passes when a login at the default level (`prompt`) gets Medium integrity with Administrators not enabled (deny-only, for an administrator); fails otherwise, saying what it got.
- `elevated session on request`: passes when a login that asks for `always` gets High integrity with Administrators enabled (not enabled, for an account that is not an administrator); fails otherwise. An administrator's agent below High, which can give no such session, fails it.
- `session privilege` (an agent below High, and only for a standard account at Medium integrity): passes.
- `junction (via agent)`: `doctor` names a directory under its own temp directory. The first probe makes a junction in it, so that a token below High made it (an agent below High has one probe, which makes and follows it), and the session that asked for `always` reads through it, since RedirectionGuard refuses only a junction a non-administrator made and follows one that the elevated process made itself. It fails on a junction that is refused, one that was made and not read, a directory that could not be made, a probe that did not report the outcome, and when no junction from below High could be made, saying why.
- Not tested: when the volume of the temp directory holds no junctions, the `junction (via agent)` row says so and does not fail.
- A probe that does not answer takes only its own rows with it: the other probe still runs and the rest of the report stands. A first probe that does not answer is the one row `parity probe (via agent)`, in place of the session id, DPAPI, session, junction and byte rows, with the row of the probe that asked for `always` beside it. A first probe that times out is not followed by a second, since the agent is not answering.
- `junction directory`: `doctor` removes the directory it named, whatever became of the probes. When it cannot, or a probe that did not answer may still create it, this row names the directory so that it can be deleted. It passes on purpose: a directory left in the temp folder does not make the installation wrong.
- `install directory on PATH` and `sshd accepts SSH_BROKER_ELEVATION`: whether the install directory is on the system `PATH`, and whether sshd accepts the variable (or sets it itself) and has read the files that say so. The second is judged only by an administrator's elevated `doctor`; a process that is not one passes it as not checked.

Run below High by an administrator (an unelevated session, or an ordinary prompt), `doctor` shows the local rows and runs no probe. In place of the rows about the agent it shows one failing row, `socket reachable`, which says `not checked below High: this account's agent serves elevated processes: run this from an elevated prompt or from an SSH login that asked for SSH_BROKER_ELEVATION=always, or run ssh-broker elevate ssh-broker doctor in an SSH session`, so it exits 1. `elevate` is refused outside a session an agent hosts, so at the desktop only an elevated prompt checks. `logout` works from any process of the account, when the agent's request socket is served; where it is not, `logout` says so and where to run it, or, when the plain folder is refused, names that folder and exits 4. If it could not check whether the account has an elevated session, its line says so.

The limits of elevated sessions are in [Limits worth knowing](#limits-worth-knowing-before-you-install-it).

## Background sessions

A user with no session on the PC (nobody logged in at the console or over RDP) has no interactive session to relay into. An interactive SSH login then asks for the Windows password:

```
ssh-broker: <user> has no Windows session on this PC. Enter your Windows password to start one. (The password goes to Windows to sign you in; ssh-broker does not store it.) Press Ctrl+C for a plain shell.
```

The password is not echoed, goes to Windows and nowhere else (`CreateProcessWithLogonW`; for an administrator `LogonUserW`, as a batch logon, which needs the account to hold "Log on as a batch job", as administrators do by default, and then `CreateProcessWithTokenW`, which needs the login to hold "Impersonate a client after authentication", as administrators do by default too), and is wiped from the buffers ssh-broker holds as soon as the call returns. Windows signs the account in and starts `ssh-broker agent --background` in a new logon session with a loaded profile; the login relays into it. The session has no desktop and lasts until the PC restarts or you run `logout`. If you sign in at the desktop afterwards, no second agent starts: the background session keeps serving.

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

Both need **an elevated administrator shell**, and take the account to act on (the account running the command by default). Task Scheduler refuses a boot trigger to any token that is not an elevated administrator's, for a standard user and for a non-elevated administrator alike. An administrator's SSH session is unelevated unless the login asks for `SSH_BROKER_ELEVATION=always`, so over SSH it runs from a login that does. Where a shell is not elevated (`whoami /groups` shows Medium integrity):

- at the PC, open an elevated prompt (one UAC prompt);
- a standard user cannot run it alone: an administrator runs it for them and types their password.

`on` asks for the account's password, checks that Windows accepts it for a batch logon, registers the task, reads the registered task back and compares it with what it asked for (a mismatch deletes the task and fails), and starts the task once so the session begins now. The task runs the installed exe, in the administrator-only install directory, and its permissions let only SYSTEM and Administrators change it.

The account must hold **"Log on as a batch job"**. Administrators hold it by default; a standard account does not, and `on` refuses, naming the right: an administrator can grant it in Local Security Policy (User Rights Assignment). ssh-broker never changes machine policy.

`off` deletes the task, which deletes the stored password with it. A session that is running continues until `logout`. `on` and `off` take the lock `install` takes (see Upgrading) for their steps, so neither runs in the middle of an `install`, and an `install` does not run in the middle of either: they wait for each other's steps. `on` first checks, changing nothing, that `install` has installed the exe (otherwise it says to run `install` first, before asking for anything and without creating the install directory), asks for the password, and only then takes the lock, so a prompt left open holds up nothing. `off` takes the lock only if there is an install directory that passes its check; if there is none, or it fails its check (so no `install` can run), or the lock cannot be taken (an error such as a lock file with the wrong access; waiting for another holder is not one), it deletes the task without the lock, and in the last two cases prints a warning naming the reason or the cause. `doctor` has an `auto-login task` row: it checks the task's definition and reports its last result, and says plainly that a failed logon is not recorded there, so a stale password or a missing batch right shows only as a session that did not start; you are then asked for the password again at the next login.

Windows' own auto-logon is a different, documented option: signing the user in at boot (Sysinternals Autologon, or `netplwiz` where it applies) gives a desktop session, and the logon task's desktop agent then serves. ssh-broker does not configure it; it stores the password as an LSA secret and leaves a signed-in desktop.

### Ending one

`ssh-broker logout` ends your background session: the agent, every shell it hosts and the processes they started. `ssh-broker logout` finds the exe by name where the session's `PATH` has the install directory ([Install](#install) says when that is); elsewhere type the full path, `C:\ProgramData\ssh-broker\ssh-broker.exe logout`. The usual place to type it is a shell the session itself gave you; the agent waits for the command to finish and print its reply before it ends anything, and your SSH connection then closes.

| Exit code | Meaning |
|---|---|
| 0 | The session ended. |
| 1 | You have no session to end, or none that this process can reach (the line says which, and where to run `logout` in the second case). Also when the session was ending already and is gone by the time `logout` connects again. |
| 2 | Your agent runs in your desktop session; signing out of Windows ends it. |
| 4 | Your agent could not be reached for another reason (access denied, a socket path that is too long): the message names it. |
| 254 | The agent closed two connections in a row without answering, which an agent of this version never does (it may be an older ssh-broker). |

When `ssh host ssh-broker logout` ends the session, the session that carries the command ends with it, and the ssh client can report 1 instead of 0; the line `logout` printed says what happened.

A login that reaches the agent while it is ending gets no shell. It prints `ssh-broker: your background session is ending; reconnect in a moment.` and exits 255, the code ssh uses for a connection that failed, so a script cannot take it for the command's own failure.

A login the agent cannot serve for another reason also gets a line saying why, and ends the connection with a code that is not the command's: 255 when the agent could not start the shell or the command (`ssh-broker: the agent could not start the command: ...`), 254 when it could not read the request. A command whose connection ends before the agent says anything prints `ssh-broker: the agent ended before it answered; the command may or may not have run` and exits 255; it is never sent again. A login (or `logout`) whose connection is closed without an answer twice in a row prints `ssh-broker: the agent closed the connection twice without answering; it may be a different ssh-broker version` and exits 254. A connection that the agent cannot use, or whose handler failed, is answered with a line saying so and exits 255.

## Requirements

None beyond Windows with OpenSSH. Inside your profile directory, `AppData`, `AppData\Local` and `ssh-broker` (`ssh-broker-elevated` for an elevated login; each with its `logs` folder) must be real folders, not junctions or symlinks: a link at one of them is refused, with the folder named. The profile directory itself, and anything above it (the folder of all profiles moved to another drive), may be a link, as it may for Windows. An `ssh-broker`, `ssh-broker-elevated` or `logs` folder whose owner or permissions are not exactly its own (for `ssh-broker-elevated`, also one without the High integrity label) is refused too, with the folder named and left as it is: remove it, and it is made again. The shim refuses a log file, or an `agent.lock` it looks at, that already existed with more than one name (a hard link to a file elsewhere): remove it. A login that finds its broker folder refused, or cannot open a folder on the way to it (access denied, for instance), is shown why and gets a plain shell, with no password prompt and no session started; a refused `logs` folder costs only the log. The default shell is the system `cmd.exe`, which every Windows has. To use PowerShell Core (`pwsh`), install it and name it in the [shell configuration](#shell-configuration); stock Windows ships `powershell.exe` 5.1, which is a different binary.

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

A file or shell that cannot be used is never a lockout: the session runs the built-in `cmd.exe` after one warning on stderr that names the file and the value, not the next layer up. `ssh-broker doctor` prints the effective block with where each value comes from, and fails its `shell config` row while a fallback is in effect.

A configured shell that ends with `0xC0000135` (`STATUS_DLL_NOT_FOUND`) gets one more warning, naming the file, the setting and the value: a DLL that the shell, or a program it ran last, needs was not found. It is printed in the session for an agent-hosted shell (with or without a terminal) and on stderr when the shim runs the shell itself.

`install` creates the system file once, from the shell sshd used before ssh-broker, so sessions keep starting it: `DefaultShell` becomes `start`, `DefaultShellCommandOption` becomes `with-command` (split into words, as sshd pastes it into the line, so `/d /c` is two arguments), `DefaultShellArguments` becomes `without-command`, and `DefaultShellEscapeArguments` becomes `escaping` for a shell sshd treats as "other" (not `cmd`, PowerShell, bash, Cygwin or `ssh-shellhost`, which sshd escapes by its own rules). A value longer than sshd reads (16,383 characters) counts as not set, as it does for sshd; a `DefaultShell` that long is no shell. sshd reads the three string values as raw bytes whatever their registry type, and so does `install`: a `REG_EXPAND_SZ` keeps its `%VAR%` text, as it does for sshd. Every `install` removes `DefaultShellArguments` from the registry once `DefaultShell` is ssh-broker and the system file is a regular file (a directory, or a link whose target is not a regular file, holds no config; a link to a regular file is a file), since sshd would pass it to ssh-broker ahead of `-c`. It prints the value before it removes it; with no file to hold it, or when it cannot tell whether there is one, `install` leaves the value and says so (the cause, when a check failed), and a later `install` that finds the file removes it. A value `install` cannot read is left too, and `install` says why: it never removes a value it has not shown. If the removal fails, `install` prints the value and the cause, and the next `install` tries again. Only values that differ from what ssh-broker would do for that program are written. A `DefaultShell` that is a bare name is looked up as sshd does (the directory of the sshd service, the system directory, the Windows directory, then `PATH`) and the file found is what the config names, since a session searches `PATH` alone; when no file is found, `install` prints every previous value. `install` never rewrites the file, and writes no config when the previous shell was ssh-broker, is not installed, or was never set. If a value of the previous shell cannot be read (the registry returns an error other than "not found" for it), `install` stops before it writes the registry and changes nothing there: it prints what could not be read and what could, and a later `install` goes ahead once the value is fixed, deleted, or readable. This stop is for a shell that is about to be replaced: when the previous `DefaultShell` is ssh-broker or not set, nothing can be lost, so `install` goes on.

### What the lines of `install` mean

On stdout `install` says what it is about to do before each step that can take a while (a line that ends in `...`), then one line for its sshd step ([below](#the-sshd-step-of-install)), and last that ssh-broker has been installed. Those lines need no gloss. It says nothing when it writes the config: the file is the record. Every other line is on stderr, begins with what it says and not with the name of the verb, and states what happened and the values involved; what to do is here. A warning can sit above the last line: an install that could not do a step it can go on without (the `PATH`, an agent in one session, an auto-login session, the config that carries the previous shell) still ends with it. Once `install` has replaced `DefaultShell`, the values a "does not carry" line prints (`DefaultShell`, `DefaultShellCommandOption`, `DefaultShellArguments`, escape arguments) are the only copy of the old setup. When the write fails (the last entry under "Other lines:" below), `DefaultShell` keeps its old value.

Every "does not carry" line reads `<reason>. This install does not carry the shell sshd used before into <config>. install replaces DefaultShell next. Previous values under HKLM\SOFTWARE\OpenSSH: ...`. The reason is one of:

- `<config> exists`: a file is there and is never rewritten. Add the printed values to it if the shell needs them.
- `<config> is not a file`: a directory, or a link whose target is not a regular file, is at the path. Remove it, then write the file from the printed values, or set the printed values back under `HKLM\SOFTWARE\OpenSSH`.
- `could not write <config>: <cause>`: fix the cause, then write the file from the printed values.
- `cannot tell whether <config> is a file: <cause>`: the check failed; fix what the cause names. Then, if a file is there, add the printed values to it (nothing is overwritten); if not, write the file from the printed values.
- `the shell sshd uses now (<shell>) cannot be used: <why>`: no such file was found where sshd looks. Do not copy the printed values into the config; a config that names it starts `cmd.exe` with a warning in every session. Install the shell or correct its path, or choose another and name it in the config.
- `cannot find the system directory to look for the shell in: <cause>`: the shell was not looked up. Check that it exists; if it does, write the file from the printed values, naming the shell by its full path.
- `the shell sshd uses now (<shell>) was decided to have nothing to carry`: a check inside `install` disagreed with another. Treat as `could not write`: write the file from the printed values.

Other lines:

- `cannot read where sshd runs from: <cause>`: the directory of sshd was not searched for the shell, so a bare name may be reported as not found, or a different file of that name found. Check that the shell the config names is the one you expect.
- `cannot tell whether <path> is the system cmd.exe: <cause>`: `install` took it as another program and compared the values with the defaults for one. The config it wrote may list `with-command` and `escaping` that the defaults for `cmd.exe` would give; they are correct, and may be deleted when the shell is the system `cmd.exe`.
- `cannot read the shell sshd uses now: <values> under HKLM\...` (`install` ends, `DefaultShell` not changed): fix the value or its permissions, or delete it, and run `install` again.
- `left DefaultShellArguments (<value>) ...: there is no <config>`, `... is not a file`, or `... <cause>` of a failed check: the value stays. Write the config (put the value in its `append.without-command` if the shell needs it), or remove what is at its path, or fix the check, and run `install` again; it removes the value once the file is a regular file.
- `left DefaultShellArguments under HKLM\...: it could not be read (<cause>)`: fix the value or its permissions, or delete it, and run `install` again.
- `removing DefaultShellArguments (<value>) from HKLM\...`: the value is deleted from the registry, and nothing more is said when that worked. If the shell needs it, put it in the config's `append.without-command`.
- `could not remove DefaultShellArguments (<value>) from HKLM\...: <cause>`: the value stays; the next `install` tries again.
- `<dir> was not added to the system PATH: <why>`: sessions do not find `ssh-broker` by name until it is; add the directory to the system `PATH` and `doctor`'s `install directory on PATH` row passes.
- `could not tell whether session <n> has a user, so no agent was started there: <why>`, `no agent was started in session <n>: its old agent (process <pid>) was stopped but has not been seen to exit; ...`, `could not start the agent in session <n>: <cause>` and `the logged-on sessions could not be listed: <cause>`: no agent was started in that session (or in any); the user logs off and on, or you run `install` again once the old agent has exited.
- `could not start the <name> task: <cause>` and `could not tell whether the <name> task is running, so it was not started: <cause>`: an auto-login session was not started; run `install` again, or start the task in Task Scheduler.
- A second failure that comes with the one `install` ends with (a task that could not be enabled again, beside a step that failed) is printed above that error, as it says it.
- A failed write of the `DefaultShell` values (`install` ends with `DefaultShell not changed` and the cause; `DefaultShellEscapeArguments` and `DefaultShellCommandOption` may have been written): fix the cause and run `install` again.

### The sshd step of `install`

`install` says one step line for it, on stdout, once the task that runs the step has been started:

```
Setting up sshd to accept SSH_BROKER_ELEVATION; sshd may be restarted, and a connection over SSH may drop now. What the step does is written to <the report's path>...
```

If the connection drops, the step still finishes (a task runs it, outside your session): the report, `C:\ProgramData\ssh-broker\install-sshd.log`, holds what the step does and can be read while it runs. When the step has ended, `install` says on stderr, with no prefix, each warning of the step. A warning says what the step could not do, or what is not as it should be afterwards; where there is something for you to do, the warning says it. A run that has nothing to change, or whose changes went well, says only the step line. Every line of the step, notes included (what it did and found: the restart of sshd, what it noticed first), is in the report; a warning's line there begins `warning: `, and every other line is a note. A report without its closing line (the task was ended before its step finished, or a line of the report could not be written) is printed whole, notes included, after a warning that says so: the lines are what the step had written, and `sc query sshd` says whether sshd runs.

Two warnings need more than they say:

- `sshd is not running ...` (sshd was stopped before the step, so it was not started): the files hold the change, and sshd reads it when it is started. Start it (`net start sshd`) when you want SSH.
- `sshd failed to start with SSH_BROKER_ELEVATION accepted (<why>); ...`: sshd could not start with the change this run made. The line says what became of the files and whether sshd runs now. `install` run again tries the same change, so find out why sshd could not start with it before you run `install` again: sshd's own events are in the log `OpenSSH/Operational` (`wevtutil qe OpenSSH/Operational /c:20 /rd:true /f:text`).

The lines the step writes inside its task say `ssh-broker install` where they mean this command again. The window you typed `install` in does not see the new `PATH`, so run the installed exe by its full path, `C:\ProgramData\ssh-broker\ssh-broker.exe`, until you open a new session. The other lines of `install` are in [What the lines of `install` mean](#what-the-lines-of-install-mean).

## Limits worth knowing before you install it

- **An elevated session's socket path is 9 bytes longer.** `ssh-broker-elevated` is 9 bytes longer than `ssh-broker`, so the longest profile path that works is 62 bytes for an elevated process and 71 for any other. A longer one is refused with the reason, as above.
- **A login that does not set `SSH_BROKER_ELEVATION` can end elevated, and runs without the agent.** If the agent cannot prepare its unelevated session (the token cannot be made, or its level cannot be read), the login is not refused and the agent hosts nothing: the shim runs the session itself, as a command and as a terminal session alike, like any session it runs when the agent is unreachable. It is unelevated where the shim can step its token down; otherwise it has the token sshd gave it, which for an administrator is elevated, and a line that says so and why. Either way it has no DPAPI and no loaded profile, and runs under RedirectionGuard. A program that must never run elevated sets `never`, `prompt` or `auto-approve`, and is refused instead when its session cannot be prepared.
- **`doctor`'s session rows need an elevated `doctor`.** A process of an administrator that is not elevated (an ordinary prompt, an unelevated session) shows the local rows, checks neither the agent's socket, folder and log folder nor the session rows, and says how to check: `ssh-broker doctor` from an elevated prompt or from an SSH login that asked for `SSH_BROKER_ELEVATION=always`, or `ssh-broker elevate ssh-broker doctor` in an SSH session. An account that Windows splits without making it an administrator gets no such line from `doctor`: its unelevated process looks in the plain folder and reports what is there, which is no agent. `logout` works from any level: it asks `request.sock` where it finds no agent; if that is not served either, it says so and where to run it. It does so for an administrator's unelevated process, and for an unelevated process of any account whose profile has an `ssh-broker-elevated` folder, which an agent at High made.
- **`elevate` needs an account whose agent runs at High.** An administrator's agent does, and so does that of an account Windows splits without making it an administrator (Backup Operators, say). A standard account's agent runs below High and keeps no request socket, so `elevate` in its session is refused with a sentence that says why. Nothing here raises a standard account's session.
- **An elevated command's output is the session's, and its input is closed.** A command run without `--terminal` has its input closed, so a program that reads it sees the end at once, and `elevate` prints its output in the session, where the session's programs can read it. Ctrl+C ends it and its processes at once, without giving them a chance to clean up. `--terminal` gives it a screen of its own, and what it drew is not kept when it ends.
- **A question is written over a full-screen program.** The question that `elevate` asks when a login set nothing or `prompt` is written on the person's terminal even while an editor or a pager owns it: it resets the terminal's attributes, scroll region and cursor visibility and clears the screen. When it ends the agent gives the session's pseudoconsole its size again so that it repaints, and the program is not told to redraw.
- **The input queue of a session with a terminal has no bound.** A client that keeps sending keys while it reads none of the session's output grows the agent's memory by what it sends. The stdin of a command on pipes keeps its bound.
- **Until sshd has read its configuration, only `elevate` raises privilege.** A login's `SSH_BROKER_ELEVATION` is dropped until sshd accepts it (`install` makes it, and `doctor`'s `sshd accepts SSH_BROKER_ELEVATION` row says whether it does), so every session is unelevated and `always` cannot be had. If the agent is then unreachable, an administrator's shell is the unelevated fail-open one, and `elevate` is refused in it as not hosted.
- **sshd must give an administrator the full token.** A login of an administrator whose token is below High (`whoami /groups` shows Medium integrity for an SSH login without ssh-broker) is told that it cannot reach the account's agent, which runs elevated, and gets the plain shell, with no password prompt and no wait for an agent (a login that asked for `SSH_BROKER_ELEVATION=always` is refused instead, since no level of such a token reaches an elevated session). No sshd is known to do this: OpenSSH for Windows 10.4p1 gives High for a password login and for a key login, and 9.5p2 for a key login.
- **A folder an unelevated process of the account made is refused.** A folder named `ssh-broker-elevated` that an unelevated process of the account made, or put in the place of the real one while no agent or shim held it, is refused like any folder that is not exactly right: the login is told the folder's path and what to do (remove it, and it is made again), and gets the plain shell. The account does this to itself and can undo it from any prompt of the account, since it owns what it made.
- **A password cannot always start an elevated session.** A login at High for which the password prompt cannot start an elevated agent gets no agent from the prompt, is told the cause, and gets the plain shell. There are two causes. The account may not log on as a batch job (the sentence `auto-login` uses). Or the login lacks "Impersonate a client after authentication", which starting a process with the batch-logon token needs: administrators hold it, and Backup Operators and the other groups that Windows splits do not, by default. Both are visible in Local Security Policy. The way out is a logon at the desktop, which starts the agent from the logon task (and, for the first cause, granting the right: ssh-broker never changes machine policy). For the second cause `auto-login` is a way out too: its session for a member of Backup Operators is elevated and serves that account's logins (measured with the in-box sshd on Windows Server 2025).
- **A program that holds the broker's folder open keeps a login from being brokered.** If another program has the broker's own folder (`ssh-broker` or `ssh-broker-elevated` under `AppData\Local`) open with the right to delete or rename it, or without letting others read it, when a login walks to it, that login is told which folder is held and that another program has it open in a way that keeps the broker from using it, and gets the plain shell. The next login, once that program has let go, is brokered again. The login does not retry. This holds for a standard account's folder too. Whether any program opens the folder so in passing is not measured.
- **A background session needs your password once.** If you have no session on the PC, an interactive login (`ssh -t`) asks for your Windows password and starts one (below). A login that cannot ask (a command, `scp`, `sftp`, or no terminal), and a login that declines, gets your configured shell in the plain session sshd made, without DPAPI, a loaded profile or symlink traversal. Only local accounts with a non-empty password are supported (ssh-broker#45).
- **Your session's background processes die with it.** When the session ends, everything it spawned is terminated — including a process that redirected its output to a file and never touched the session's pipes. There is no `nohup` equivalent here. This matches what stock Windows OpenSSH does; it is the opposite of Unix, where the session waits for pipe EOF.
- **The shim fails open.** If the agent is unreachable it runs your command locally and says why, rather than locking you out of the machine. That is deliberate: a broken broker must never cost you SSH access. The reason goes to stderr for `ssh host cmd`; for an interactive session it goes to the log in your own `%LOCALAPPDATA%\ssh-broker\logs` (`ssh-broker-elevated\logs` for an elevated login; the agent logs there too), because writing to stderr there would corrupt the terminal stream. The one exception is a reason that comes from your own setup, such as a profile path too long for a socket: that is printed to stderr in both modes, before the fallback shell starts. If the shim cannot set up its log (the folder belongs to someone else, say), it carries on without one; for `ssh host cmd` the fallback message then also says why there is no log, and in the other cases `doctor`'s `log folder` row is where to look. The fallback runs the session through your configured shell, with the command packed as it would have been under the agent; if that shell cannot be used, the built-in `cmd.exe` runs after a warning on stderr.
- **Everything goes through the relay, including `sftp` and `scp`.** No command is *classified* and routed around it — the fail-open above is a different thing, running locally because the agent is unreachable rather than because of what the command is. Deciding what to route would mean classifying a command from a string the client chose — and sshd rewrites commands before the shim ever sees them. The relay carries arbitrary bytes unchanged in both directions (tested, and checked end to end by `doctor`), so transfers work normally; running them locally would be faster, and that is a trade we take deliberately rather than guess at what a command is.
- **`install` owns `DefaultShellEscapeArguments`.** It sets `HKLM\SOFTWARE\OpenSSH\DefaultShellEscapeArguments` to the DWORD 1 (sshd's default), before it registers the shim as `DefaultShell`, overwriting any other value, and `doctor` fails if sshd would read it as off. Without a PTY, sshd passes the command to the shim in one of two encodings depending on that value. sshd reads the value once per session, when it starts, so a shim that read it later could disagree with the session it serves. The shim therefore always decodes the escaped form and reads no registry value; keeping the value at 1 is what keeps it right.
- **install makes sshd accept `SSH_BROKER_ELEVATION`.** It writes `sshd_config.d\10-ssh-broker.conf` (readable like sshd_config, and writable only by SYSTEM and Administrators), and adds `Include sshd_config.d/*.conf` above the first `Match` of sshd_config when sshd does not read that folder already. If `sshd_config.d` is there and is not exactly the folder install makes (one an administrator made by hand inherits other permissions), install leaves it alone and puts the line `AcceptEnv SSH_BROKER_ELEVATION` above the first `Match` of sshd_config instead.
- **install and doctor tell whether sshd has read its configuration by time, and install restarts sshd when it has not.** sshd reads its configuration only when it starts, and a running sshd cannot be asked what it accepts. So a change counts as read when the sshd service started after sshd_config, the folder sshd_config.d and every file in it last changed. When it has not, install restarts the service through the service manager: it sends the stop, waits until the service manager says stopped and the old sshd process has exited, starts the service, and waits until sshd listens on a TCP port or its process has exited (the service manager says running before sshd has read its configuration). It acts only on a state the service manager has said: a stopped sshd is not started (it reads the change when it is), a paused one or one whose state cannot be read is left as it is, and one that did not stop is not started again; where there is something to do, the line says it, and running `install` again restarts it. If sshd exits, or the service stops again, after a start the service manager accepted and before sshd listens, install puts back what it changed in this run and starts it again; if it is not running then, install says so and gives the command to start it at the PC. The waits have no time limit: a service that the service manager holds in a starting or stopping state, an sshd that neither listens nor exits, or an sshd that did not answer the stop in time (1053) and does not exit keeps install waiting. install prints the step's warnings when the step has ended, or the whole report when it has no closing line ([the sshd step of install](#the-sshd-step-of-install)); while it waits, the step's whole report can be read in `C:\ProgramData\ssh-broker\install-sshd.log`, whose lines show how far the step has got. To stop waiting, end the task `ssh-broker-install-sshd` (`schtasks /End /TN ssh-broker-install-sshd`), check sshd with `sc query sshd` (an sshd that the service manager says is running but that accepts no connection is restarted with `net stop sshd` and `net start sshd`), and run install again. When sshd_config or a file in sshd_config.d includes anything else, or a file's change time is ahead of the clock, whether sshd has read its configuration cannot be told: install restarts sshd to be sure, and doctor says it cannot be told (run install, or restart the sshd service). A clock set back between the two can hide a restart that is still needed: SSH_BROKER_ELEVATION is then dropped (sessions are unelevated) until sshd restarts. When the times cannot be read at all, install restarts sshd only if it changed a file in this run, and otherwise says to restart the sshd service.
- **An sshd service started with arguments is not configured.** If the sshd service's command line has arguments (`sshd.exe -f D:\conf\sshd_config`, say), install changes nothing of sshd's and says so, and doctor's row says it was not checked. Add `AcceptEnv SSH_BROKER_ELEVATION` above the first `Match` of the file sshd reads, and restart sshd.
- **install edits sshd_config and the system PATH as any installer does.** It reads each one, changes it, and writes it back whole. An edit that another program or person makes to either while install runs can be lost. Run install when nothing else is installing software or editing sshd's configuration.

## Install

Releases carry `ssh-broker-<version>-x86_64-pc-windows-msvc.zip` (`ssh-broker.exe` and the license) and a `.sha256` file, with a build attestation on the zip. Verify before installing:

```sh
gh attestation verify ssh-broker-<version>-x86_64-pc-windows-msvc.zip -R bindreams/ssh-broker \
    --signer-workflow bindreams/ssh-broker/.github/workflows/release-asset.yaml \
    --source-ref refs/heads/main
sha256sum -c ssh-broker-<version>-x86_64-pc-windows-msvc.zip.sha256
```

Then extract it and, from an elevated prompt, run `ssh-broker.exe install`. It installs the broker for every user: each user who logs on gets their own agent. `ssh-broker.exe doctor` checks the result for the user who runs it. Sessions start the shell that [Shell configuration](#shell-configuration) names: `cmd.exe` when nothing names another. `install` puts the install directory on the system `PATH`. An agent has the `PATH` of the environment it started in, and its sessions inherit it. The agent that the password prompt starts for an account that has none, after `install`, gives sessions that find `ssh-broker` by name, `ssh-broker elevate` included. An agent that was running keeps the `PATH` it started with until it starts again, as does one started by hand from a shell that was opened before `install`. The release executable has the C runtime linked in, so it needs no Visual C++ redistributable.

`install`'s last step makes sshd accept `SSH_BROKER_ELEVATION`. It runs as a Task Scheduler task, `ssh-broker-install-sshd`, as SYSTEM, so that it finishes, and sshd is running at its end, even if the connection that runs `install` ends while sshd restarts. `install` says one line for the step, waits for it and, when it has ended, prints the step's warnings, or the whole report when it has no closing line ([the sshd step of install](#the-sshd-step-of-install)); the step's whole report is kept in `C:\ProgramData\ssh-broker\install-sshd.log`, where it can be read while it runs. An `install` ended before it removes the task leaves it registered with no trigger; the next `install` replaces and removes it. An `install` started while an earlier one's step still runs waits for that step first.

## Upgrading

Run `install` again from an elevated prompt with the newer build. A running agent holds the installed exe open, so when `install` replaces the exe with a different build it first disables the logon task, so no logon starts an agent from the old exe meanwhile, stops every agent the task started and waits for each to exit, then enables the task again and starts one in each logged-on session (also if a later step fails). Their open SSH sessions end; users reconnect. An agent started by hand with `ssh-broker agent` is not stopped, and the shim of an SSH session that is still open holds the exe too (it is sshd's `DefaultShell`): if either still holds the exe, `install` fails with a message saying so; find them with `tasklist /fi "imagename eq ssh-broker.exe"`, end them or close the sessions, and run `install` again. If an agent does not exit after being stopped, `install` fails naming its process id and starts no agent in that session; run `install` again once the process has exited. A killed `install` can leave the logon task disabled, which `doctor` reports on its `agent task` row; a later `install` enables it again once it is past its argument check, the check of the install directory, the check of the lock file and the wait described next (one that fails earlier leaves the task as it was). An `install` of the build that is already installed leaves agents alone. Only one `install` runs at a time on a machine, for its whole run (a lock on `apply.lock` in the install directory, a file only SYSTEM and Administrators can open, so that no standard user can hold it; `install` refuses a lock file with any other access and tells you to remove it); an `install` that starts while another is running waits for it. `auto-login on` and `off` take the same lock and wait for it in the same way.

Run `install` from an elevated prompt at the PC. A brokered SSH login can run it only if it asked for `SSH_BROKER_ELEVATION=always`, and then only to repair the installed build: `install` of a different build stops the agent that hosts the session, ends it part-way, and must be run again at the PC.

Background sessions are replaced the same way. Before it replaces the exe, `install` disables every auto-login task, stops every user's auto-login session and ends every background session that no task owns (one the password prompt started), waiting for each process; after the copy it enables the auto-login tasks again and starts each one, also if a later step fails. A prompt-started session is not restarted: its user is asked for the password at the next login. Background sessions are found by the installed exe's file identity and told from a shim by their command line (`agent --background`), so an SSH session's shim is never ended by `install`; it holds the exe until its session closes, and `install` then fails with the message above.

The contract: an upgrade is expected to succeed, and nothing is guaranteed to be in a valid state while it runs. If it is interrupted (a killed `install`, a power cut), run `install` again: it repairs an incomplete state. Every `install` that is past the checks listed above for enabling the logon task (the argument check, the check of the install directory, the check of the lock file and the wait), including one of the build that is already installed, ends by enabling every auto-login task that is disabled and starting each enabled one that has no running session (it does not stop or restart a session that is running), as it already does for the logon task; an `install` that fails one of those checks repairs nothing. So a task you disabled by hand in Task Scheduler is enabled again by the next `install`; `auto-login off` is the way to turn auto-login off.

**From 0.1.0, the build before elevated sessions**, some steps are yours; nothing more is done for you:

- `apply` is now `install`, and `verify` is now `doctor`. A word the build does not know, an old `apply` or `verify` included, starts the shim. The system config file 0.1.0 wrote has a comment that names `ssh-broker apply` and `ssh-broker verify`, and `install` never rewrites that file: read them as `install` and `doctor`.
- Run the new build's `install`. A logon task that still says `LeastPrivilege` starts an administrator's agent below High, which refuses to run and exits 68; `install` registers the task as `HighestAvailable`, and `doctor` fails its `agent task` row until it does.
- An agent of the old version that is still running refuses the new shim, by name, until it is restarted. `install` restarts the agents the logon task and `auto-login` started; one you started by hand with `ssh-broker agent` is for you to stop and start again, and a session the password prompt started ends and asks for the password at the next login.
- Delete the `agent.sock` that 0.1.0 left in an administrator's `%LOCALAPPDATA%\ssh-broker` folder, and keep the folder: the elevated agent keeps `request.sock` in it (see [Elevated sessions](#elevated-sessions)). Where there is no `request.sock`, `elevate` takes a leftover `agent.sock` for an agent that runs below High, and says so.
- Run `doctor` with the installed exe, after `install`: `C:\ProgramData\ssh-broker\ssh-broker.exe doctor`.
- `install` now also makes sshd accept `SSH_BROKER_ELEVATION` and puts the install directory on the system `PATH`.

## Status

Working and tested, but pre-1.0. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and test it, and how releases are made.

## License

[GPL-3.0](LICENSE.md)
