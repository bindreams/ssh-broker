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

The **shim** is installed as sshd's `DefaultShell`, so every SSH session runs it instead of a shell. It forwards keystrokes, window resizes and mouse events to the **agent**, which lives in the interactive session and hosts the real shell — in a pseudoconsole for an interactive session, on redirected pipes for `ssh host "cmd"`. Output comes back the same way.

Because the shell is a child of the agent rather than of `sshd`, it inherits neither the network logon nor the RedirectionGuard mitigation. DPAPI works, the profile is loaded, and symlinks resolve — without disabling a security mitigation or storing a password anywhere. `verify` checks the session id and DPAPI, and reports symlink traversal — failing only on a confirmed block, since the unprivileged agent usually cannot create a link to test with. The profile follows from the interactive logon rather than being probed separately. Those checks run in a child the agent spawns, so if the relay stops delivering, `verify` reports that as a failed row and exits rather than hanging — `--probe-timeout <seconds>` adjusts how long it waits, and `0` waits indefinitely.

There is **one agent per logged-on user**, and each user's agent serves only that user. The logon task runs for every member of `BUILTIN\Users` and starts the agent in the session of whoever logs on; `apply` registers it without a password and starts one in each session that is already logged on. The shim connects to the socket of the account sshd authenticated, found from its own token's profile and from nothing else: there is no setting, flag or environment variable that points it at another account's agent. An administrator who SSHes in as `bob` gets bob's agent or a local shell, never another user's session.

The two halves talk over an AF_UNIX socket, `%LOCALAPPDATA%\ssh-broker\agent.sock` inside the user's own profile. Two ACLs protect it, and both grant Full Control to exactly that user, SYSTEM and Administrators:

- The socket **file's** ACL decides who can connect. Windows AF_UNIX has no peer credentials, and the folders above the socket are no barrier: every ordinary user holds the privilege that skips traverse checks, so a second user who knows the path reaches the file itself.
- The socket **folder's** ACL decides who can create, replace or delete the socket. Its entries are inheritable, so the socket, the lock file and the logs folder are born with the same set instead of the creating process's default ACL.

`bind` verifies the folder fail-closed before it binds, and the socket file right after, before it listens; a socket whose ACL cannot be proven is removed. The install directory `C:\ProgramData\ssh-broker`, which holds the exe the agent and the self-heal task run, is writable only by SYSTEM and Administrators (everyone else may read and execute), and `apply` verifies that fail-closed too. An install directory made by an earlier build is refused: inspect it, remove it, run `apply` again.

If a user is logged on in two sessions, the second session's agent waits and takes over when the first one's session ends, so the user keeps an agent for as long as they are logged on anywhere. A second agent in the same session exits at once.

`ssh-broker verify` reports on the account that runs it and no other; each user runs it for themselves. If its `socket reachable` row fails, run `ssh-broker agent` in your desktop session: the logon task discards the agent's stderr, and an error before the agent's log opens (`%LOCALAPPDATA%\ssh-broker\logs\agent.log`) is printed there and nowhere else.

## Requirements

**PowerShell Core (`pwsh`) must be installed.** Stock Windows ships `powershell.exe` 5.1, which is a different binary. `pwsh` is what the agent hosts for every interactive session — a configurable shell is not implemented — and what the shim falls back to when the agent is unreachable and there is no command to run. `ssh host "cmd"` does not involve a shell on either path: the relay and the fail-open both spawn the command directly, so pipes, redirection and `&&` are the client's business, not the server's. The Windows test suite also assumes `pwsh`.

## Limits worth knowing before you install it

- **A user with no interactive session gets a plain passthrough shell.** No design can conjure an interactive session without that user's credentials; this relays into one that already exists. If nobody is logged in at the console or over RDP, there is nothing to relay into.
- **Your session's background processes die with it.** When the session ends, everything it spawned is terminated — including a process that redirected its output to a file and never touched the session's pipes. There is no `nohup` equivalent here. This matches what stock Windows OpenSSH does; it is the opposite of Unix, where the session waits for pipe EOF.
- **The shim fails open.** If the agent is unreachable it runs your command locally and says why, rather than locking you out of the machine. That is deliberate: a broken broker must never cost you SSH access. The reason goes to stderr for `ssh host cmd`; for an interactive session it goes to the log in your own `%LOCALAPPDATA%\ssh-broker\logs` (the agent logs there too), because writing to stderr there would corrupt the terminal stream. The one exception is a reason that comes from your own setup, such as a profile path too long for a socket: that is printed to stderr in both modes, before the fallback shell starts. An interactive fallback launches `pwsh`, so it inherits the requirement above; `ssh host cmd` runs the command directly, with no shell in between.
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

## Upgrading from a single-user install

Earlier builds ran one agent for one configured account (`apply --user`, `config.toml`, a shared `C:\ProgramData\ssh-broker\s` socket directory). Run `apply` again from an elevated prompt: it stops that agent, deletes `config.toml` and the old socket directory, and replaces both tasks. The old agent's sessions end. The old `C:\ProgramData\ssh-broker\logs` stays on disk and may be deleted. `--user` is gone, because there is no target account any more; a leftover boot-time task that still passes it is accepted with a warning, so it can finish the repair.

A profile path so long that the socket path would pass the 107-byte AF_UNIX limit (only possible with a relocated profile root) is refused with the reason: the socket stays inside the profile, because that is what keeps it private, and the shim fails open.

## Status

Working and tested, but pre-1.0. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and test it, and how releases are made.

## License

[GPL-3.0](LICENSE.md)
