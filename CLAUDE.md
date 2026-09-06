# ssh-broker — architecture map

Product overview and install: [README.md](README.md). Contributor reference — build, test,
invariants: [CONTRIBUTING.md](CONTRIBUTING.md). This file is the short orientation.

## What it is

One binary with four entry points, dispatched by argv. The **shim** is sshd's `DefaultShell`
and is the default action; the **agent** runs in an interactive session and hosts the shell in
a pseudoconsole; the two speak framed messages over an ACL-gated AF_UNIX socket. `apply` and
`verify` install and check that arrangement.

The point is lineage: a shell that is a child of the agent rather than of `sshd` inherits
neither the session-0 network logon nor the RedirectionGuard mitigation, so DPAPI, the user
profile, and symlink traversal all work.

## Where things live

| Module | Responsibility |
|---|---|
| `route` | argv → entry point. A known verb wins; anything else is the shim |
| `shim`, `shim_pty` | the SSH side: console raw mode, input encoding, fail-open |
| `agent` | the interactive-session side: accept, handshake, relay threads, teardown |
| `conpty` | pseudoconsole host for the PTY path |
| `pipes` | redirected-pipe child for the EXEC path |
| `protocol` | frame codec, handshake, `FrameReader` |
| `relay` | transport-agnostic pumping; `PumpError` names which side failed |
| `afunix`, `acl` | the socket, and the ACL that is the security boundary |
| `vtinput` | Win32 `INPUT_RECORD` → VT sequences (pure, host-testable) |
| `provision` | `apply`/`verify`: DefaultShell, logon task, socket dir, parity probes |

## Invariants you must not break

Each is enforced by a hook, a lint, or a test. Full rationale in
[CONTRIBUTING.md](CONTRIBUTING.md#invariants).

- **No sleeping as synchronization**, and no arbitrary retry caps. Retrying a documented
  self-clearing condition is fine; inventing an attempt limit is not.
- **Tests fail loudly** — never skip on a missing dependency.
- **Unit tests in a sibling `foo_tests.rs`**, never an inline `#[cfg(test)] mod`.
- **No personal paths, usernames or machine names** in tracked files.
- **`acl::verify_dir_acl` is exact-match and fail-closed.** It is the whole security boundary;
  if it cannot prove the directory is safe, refuse to bind.
- **The shim fails open, and only the shim.** A broken broker must not cost you SSH access.
  Everywhere else fails closed.

## Two things that surprise people

**Clippy sees one `cfg` at a time.** Most of this crate is `cfg(windows)`, so a single local
run lints half of it. CI lints per-platform; use `cargo xwin clippy` for the other half.

**`pump_decode` distinguishes *which side* failed.** A sink failure is local and says nothing
about the peer — a relayed command closing its own stdin is routine. Only a transport or
protocol failure, or a clean EOF, means the far end is gone. Ask `PumpError::peer_gone()`
rather than treating every error alike; collapsing them has caused real bugs here.
