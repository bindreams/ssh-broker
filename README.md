# ssh-broker

Give a Windows SSH session the environment of a session you'd get by sitting at the machine.

## The problem

Log in over SSH with a key on Windows and you get a **network logon in session 0**. It authenticates you correctly, and then three things quietly do not work:

- **DPAPI fails.** A key-authenticated logon holds no credentials, so there is no real logon session behind it. Anything that decrypts stored secrets gets `ERROR_NO_SUCH_LOGON_SESSION`.
- **Your profile isn't loaded**, so environment and per-user state are not what your desktop session has.
- **Symlinks stop resolving.** Windows OpenSSH opts `sshd.exe` into the RedirectionGuard process mitigation, and the shell inherits it, so traversing a reparse point created by a non-admin fails with `STATUS_UNTRUSTED_MOUNT_POINT`. In practice: every WinGet shim in `AppData\Local\Microsoft\WinGet\Links` — `fnm`, `uv`, `bun` — fails to launch.

RDP has none of these problems. Not because it is more trusted — RedirectionGuard ignores the authentication method entirely — but by lineage: `explorer.exe` and `conhost.exe` were never opted into the mitigation, and an interactive logon holds credentials.

## What this does

It relays your shell out of session 0 and into an interactive session that already exists.

```
ssh client ──▶ sshd ──▶ shim (DefaultShell) ──▶ AF_UNIX ──▶ agent (interactive session)
                                                                    │
                                                                    ▼
                                                        shell in a pseudoconsole
```

The **shim** is installed as sshd's `DefaultShell`, so every SSH session runs it instead of a shell. It forwards keystrokes, window resizes and mouse events to the **agent**, which lives in the interactive session and hosts the real shell inside a pseudoconsole. Output comes back the same way.

Because the shell is a child of the agent rather than of `sshd`, it inherits neither the network logon nor the RedirectionGuard mitigation. DPAPI works, the profile is loaded, symlinks resolve — without disabling a security mitigation or storing a password anywhere.

The two halves talk over an AF_UNIX socket whose directory is locked to a single account, verified fail-closed on every bind.

## Limits worth knowing before you install it

- **A user with no interactive session gets a plain passthrough shell.** No design can conjure an interactive session without that user's credentials; this relays into one that already exists. If nobody is logged in at the console or over RDP, there is nothing to relay into.
- **The shim fails open.** If the agent is unreachable it runs a local shell and says why on stderr, rather than locking you out of the machine. That is deliberate: a broken broker must never cost you SSH access.
- **File transfers bypass the relay.** `sftp` and `scp` need raw binary stdio and gain nothing from session parity, so the shim runs them locally.

## Status

Working and tested, but pre-1.0 and not yet packaged for general installation. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build and run it.

## License

[GPL-3.0](LICENSE.md)
