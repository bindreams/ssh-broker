# ssh-broker

Give a Windows SSH session the environment of a session you'd get by sitting at the machine.

## The problem

Log in over SSH with a key on Windows and you get a **network logon in session 0**. It authenticates you correctly, and then three things quietly do not work:

- **DPAPI fails.** A key-authenticated logon carries no credential material, so there is no master key behind it. Anything that decrypts stored secrets gets `ERROR_NO_SUCH_LOGON_SESSION`.
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

The **shim** is installed as sshd's `DefaultShell`, so every SSH session runs it instead of a shell. It forwards keystrokes, window resizes and mouse events to the **agent**, which lives in the interactive session and hosts the real shell inside a pseudoconsole. Output comes back the same way.

Because the shell is a child of the agent rather than of `sshd`, it inherits neither the network logon nor the RedirectionGuard mitigation. DPAPI works and the profile is loaded — both checked by `verify` — and symlink traversal follows from the same lineage, without disabling a security mitigation or storing a password anywhere.

The two halves talk over an AF_UNIX socket whose directory grants Full Control to the agent's account, SYSTEM and Administrators and to nobody else — verified fail-closed on every bind.

## Limits worth knowing before you install it

- **A user with no interactive session gets a plain passthrough shell.** No design can conjure an interactive session without that user's credentials; this relays into one that already exists. If nobody is logged in at the console or over RDP, there is nothing to relay into.
- **Your session's background processes die with it.** When the session ends, everything it spawned is terminated — including a process that redirected its output to a file and never touched the session's pipes. There is no `nohup` equivalent here. This matches what stock Windows OpenSSH does; it is the opposite of Unix, where the session waits for pipe EOF.
- **The shim fails open, provided PowerShell Core is installed.** If the agent is unreachable it runs a local shell and says why, rather than locking you out of the machine. The fallback currently launches `pwsh` unconditionally — which stock Windows does not ship — so on a host without PowerShell Core the fallback itself fails. The reason goes to stderr for `ssh host cmd`; for an interactive session it goes to the log under `C:\ProgramData\ssh-broker\logs`, because writing to stderr there would corrupt the terminal stream.
- **File transfers bypass the relay.** `sftp` and `scp` need raw binary stdio and gain nothing from session parity, so the shim runs them locally.

## Status

Working and tested, but pre-1.0 and not yet packaged for general installation. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and test it.

## License

[GPL-3.0](LICENSE.md)
