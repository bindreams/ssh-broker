# ssh-broker — architecture map

Product overview and install: [README.md](README.md). Contributor reference — build, test,
invariants: [CONTRIBUTING.md](CONTRIBUTING.md). This file is the short orientation.

## What it is

One binary with a handful of entry points plus the hidden `verify-probe` and `console-fallback` children, dispatched by argv. The **shim** is sshd's `DefaultShell`
and is the default action; the **agent** runs in a user's interactive session (one per logged-on
user) and hosts the shell in a pseudoconsole (PTY) or on redirected pipes (`ssh host cmd`); the two
speak framed messages over an ACL-gated AF_UNIX socket in that user's profile. `apply` and
`verify` install and check that arrangement.

The point is lineage: a shell that is a child of the agent rather than of `sshd` inherits
neither the session-0 network logon nor the RedirectionGuard mitigation. `verify` establishes
the session id and DPAPI through an agent-spawned probe, and reports symlink traversal — a probe
that cannot create a link reports `Skipped` rather than failing, which is the usual outcome for
the unprivileged agent. The profile follows from the interactive logon and is not separately
checked.

## Where things live

| Module | Responsibility |
|---|---|
| `route` | argv → entry point. A known verb wins; anything else is the shim |
| `cmdline` | the raw command line and the exact `-c` command sshd sent (argv has lost its quotes) |
| `shell`, `shell/{config,layers,pack,windows}` | which shell a session starts and how its command is packed: the config file, the user/system/built-in layers, the spawn line; pure over a `Host`, one implementation for the agent and the shim |
| `shim`, `shim_pty` | the SSH side: console raw mode, input encoding, fail-open |
| `agent` | the interactive-session side: accept, handshake, relay threads, teardown |
| `conpty` | pseudoconsole host for the PTY path |
| `pipes` | redirected-pipe child for the EXEC path |
| `protocol` | frame codec, handshake, `FrameReader` |
| `relay` | transport-agnostic pumping; `PumpError` names which side failed |
| `winutil` | Windows RAII (`OwnedHandle`, `AttrList`), job containment, cosca→Win32 errors |
| `afunix`, `acl` | the socket, and the file and folder ACLs that are the security boundary |
| `socket_loc`, `userdir` | where a user's socket lives (from the token's profile, length-checked), and creating its private folder |
| `agent_lock` | one agent per session, one serving agent per user |
| `filelog` | the rolling log in the user's own folder |
| `fallback_file` | the owner-only file in the private folder that carries a fallback shell's notice and line to the hidden `console-fallback` verb |
| `vtinput` | Win32 `INPUT_RECORD` → VT sequences (pure, host-testable) |
| `provision` | `apply`/`verify`: DefaultShell, logon task, per-user socket rows, parity probes |
| `offer`, `offer/text` | the session offer as a pure state machine over injected I/O, and every line it shows |
| `secret`, `password_entry` | wiped password buffers, and the key-event state machine that fills one |
| `console_modes`, `console_prompt` | the console's raw mode as a guard; the password prompt on it, and why the shim has no agent |
| `shim_offer` | the shim's hook for a missing agent: the notice, or the prompt, the logon and the wait for the agent |
| `account`, `logon`, `socket_watch` | who the token is, the secondary-logon call that starts a background agent, and the folder and profile-list watch with which the shim learns the agent serves (no named kernel object) |
| `agent_background`, `agent/logout`, `logout` | the background agent's start checks and exit codes; ending a session, both sides |

## Invariants you must not break

Most are enforced by a prek hook; the ones marked *(review)* are not, and rest on reading the
diff. (No lint enforces any of these — `clippy.toml` is deliberately empty.) Full rationale in
[CONTRIBUTING.md](CONTRIBUTING.md#invariants).

- **No sleeping as synchronization**, and no arbitrary retry caps *(the retry half: review)*.
  Retrying a documented self-clearing condition is fine; inventing an attempt limit is not.
- **Tests fail loudly** — never skip on a missing dependency *(review)*.
- **Unit tests in a sibling `foo_tests.rs`**, never an inline `#[cfg(test)] mod`. The hook
  catches the inline form; that the sibling is wired up with `#[path]` is *(review)*.
- **No personal home paths** in tracked files; usernames and machine names *(review)*.
- **`acl::verify_dir_acl` and `acl::verify_file_acl` are exact-match and fail-closed.** Together they
  are the security boundary: the socket file's ACL decides who can connect, the folder's decides who
  can replace the socket. If either cannot be proven, refuse to bind.
- **The shim fails open on the relay path** *(review)*, through the configured shell (the built-in `cmd.exe` if that is unusable). A broken broker must
  not cost you SSH access. The security boundary never degrades — the ACL gate and the bind
  fail closed. Provisioning has best-effort steps of its own, marked where they occur.

## Two things that surprise people

**Clippy sees one `cfg` at a time.** Most of this crate is `cfg(windows)`, so a single local
run lints half of it. CI lints per-platform; use `cargo xwin clippy` for the other half.

**A sink failure is not a disconnect.** `PumpError` names which side failed: a sink failure is
local and says nothing about the peer — a relayed command closing its own stdin is routine.
Agent-side callers use `relay::pump_until_peer_gone`, which owns that distinction: it stops
delivering on a sink failure but keeps reading, so the peer's eventual disconnect is still
seen. Reach for it rather than `pump_decode` + `peer_gone()`; getting this wrong has both
killed live sessions and hung the agent. The shim is the deliberate exception — from where it
sits a broken sink is its own stdio, so it collapses every `PumpError` to exit 254.
