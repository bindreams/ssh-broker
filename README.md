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

Because the shell is a child of the agent rather than of `sshd`, it inherits neither the network logon nor the RedirectionGuard mitigation. DPAPI works, the profile is loaded, and symlinks resolve — without disabling a security mitigation or storing a password anywhere. `verify` checks the session id, DPAPI and symlink traversal; the profile follows from the interactive logon rather than being probed separately.

The two halves talk over an AF_UNIX socket whose directory grants Full Control to the agent's account, SYSTEM and Administrators and to nobody else — verified fail-closed on every bind.

## Requirements

**PowerShell Core (`pwsh`) must be installed.** Stock Windows ships `powershell.exe` 5.1, which is a different binary. `pwsh` is what the agent hosts for an interactive session when no shell is configured, and what the shim falls back to when the agent is unreachable — for `ssh host "cmd"` as well, since both paths share that fallback. The Windows test suite also assumes it.

## Limits worth knowing before you install it

- **A user with no interactive session gets a plain passthrough shell.** No design can conjure an interactive session without that user's credentials; this relays into one that already exists. If nobody is logged in at the console or over RDP, there is nothing to relay into.
- **Your session's background processes die with it.** When the session ends, everything it spawned is terminated — including a process that redirected its output to a file and never touched the session's pipes. There is no `nohup` equivalent here. This matches what stock Windows OpenSSH does; it is the opposite of Unix, where the session waits for pipe EOF.
- **The shim fails open.** If the agent is unreachable it runs a local shell and says why, rather than locking you out of the machine. That is deliberate: a broken broker must never cost you SSH access. The reason goes to stderr for `ssh host cmd`; for an interactive session it goes to the log under `C:\ProgramData\ssh-broker\logs`, because writing to stderr there would corrupt the terminal stream. The fallback launches `pwsh`, so it inherits the requirement above.
- **File transfers bypass the relay.** `sftp` and `scp` need raw binary stdio and gain nothing from session parity, so the shim runs them locally.

## Status

Working and tested, but pre-1.0 and not yet packaged for general installation. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and test it.

## License

[GPL-3.0](LICENSE.md)
