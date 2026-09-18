# Contributing to ssh-broker

What the tool does and why lives in [README.md](README.md). This file is the contributor
reference: how it is put together, how to build and test it, and the invariants that are not
negotiable.

## Architecture

One binary, four entry points plus a hidden `verify-probe` child, selected by argv
([`src/route.rs`](src/route.rs)). The shim is
the *default* action because `DefaultShell` is a bare path and cannot carry a subcommand: a
known verb in first position selects a subcommand, anything else is the shim.

| Verb | Module | Runs where |
|---|---|---|
| *(none)* or `-c "cmd"` | `shim`, `shim_pty` | the SSH session, as sshd's `DefaultShell` |
| `agent` | `agent` | the interactive session, started by a logon task |
| `apply` | `provision` | wherever an admin runs it; needs elevation |
| `verify` | `provision` | on the host itself, unelevated by design |
| `verify-probe` | `provision` | the child the **agent** spawns in its interactive session, driven through the relay by `verify` |

Supporting modules: `protocol` (frame codec and handshake), `relay` (transport-agnostic
pumping), `afunix` + `acl` (the socket and its security boundary), `conpty` (the pseudoconsole
host), `pipes` (the redirected-pipe EXEC child), `vtinput` (Win32 input records → VT),
`winutil` (Windows RAII guards, job containment, cosca→Win32 error conversion).

The functionality lives in the library rather than the binary so it is reachable from tests on
every host platform; `main.rs` is a thin dispatcher.

### The security boundary is the socket directory

The agent runs as a specific user and the shim runs as the authenticated SSH user. What keeps
one user out of another's session is the socket directory's ACL, not anything in this code.
`acl::verify_dir_acl` is therefore **exact-match and fail-closed**: it rejects an absent DACL,
a non-protected one, inherited ACEs, DENY entries, non-FullControl grants, extra grantees, and
an owner outside the allowed set. If it cannot prove the directory is safe, the agent refuses
to bind.

### Fail-open is deliberate, and never in the security boundary

If the shim cannot reach the agent it runs your command locally and reports why. A broken broker
must not cost you access to the machine. An *interactive* session falls back to a plain `pwsh`, so
that path inherits the project's PowerShell Core requirement; `ssh host "cmd"` instead runs the
command directly, with no shell in between to re-quote it — which is what keeps an `sftp` or `scp`
session landing here byte-clean. Either way the child is contained in a job object exactly as a
relayed one is, so failing open is not a way to outlive the session. This is the relay path's
deliberate degradation, and the security boundary never degrades — the ACL check above and the
bind both fail closed. Elsewhere the shim also prefers working over failing in smaller ways
(logging disables itself rather than aborting, for one), and provisioning has best-effort steps of
its own.

## Building and testing

Two targets. The host target runs the cross-platform logic; Windows runs everything.

```sh
cargo test                                          # host: pure logic
cargo clippy --locked --all-targets -- -D warnings  # host half of the codebase
cargo xwin check --target x86_64-pc-windows-msvc    # cross-compile check
```

`rust-toolchain.toml` pins the toolchain and declares the Windows target, so a fresh checkout
gets both without a separate `rustup target add`. The cross-compile line also needs
`cargo install cargo-xwin`, which the toolchain file cannot supply.

**Clippy only sees one `cfg` at a time**, and most of this crate is `cfg(windows)`. A single
run lints half the code. CI runs it per-platform for that reason; locally, `cargo xwin clippy`
covers the other half.

**CI is the Windows test bed.** The full suite — ACLs, AF_UNIX, pseudoconsoles, the registry —
runs on `windows-latest` on every PR. You do not need a Windows machine to change this project.

### Hooks

```sh
uv tool install prek && prek install
```

`prek run --all-files` also runs in CI, so the hooks gate everyone, not just people who
installed them. The three pattern hooks' regexes — and the `types`/`exclude` filters that
decide what those regexes ever see — are pinned by `scripts/prek_patterns_test.py`. A hook
that cannot fire is worse than no hook, and two earlier versions of these shipped regexes that
could not fire. `cargo-fmt` and `cargo-clippy` run commands rather than patterns, and nothing
pins their `types` filter.

Note that `prek run --all-files` only scans **git-tracked** files. An untracked probe passes
vacuously, which is a convincing way to believe a broken hook works.

## Invariants

Most are enforced by a prek hook rather than by good intentions. The ones marked below rest on
review instead. No lint enforces any of them: `clippy.toml` is deliberately empty.

**No sleeping as synchronization.** A sleep is a bet that some duration is long enough, and
that bet loses on a loaded runner. Teardown ordering uses real primitives: waking a parked
console read by injecting a record, closing a pseudoconsole to force EOF, joining threads.
Waiting on a genuinely external event is fine and normally uses an unbounded wait; a wait
carrying a numeric bound is not. A same-line `sleep-ok:` marker **and a reason** opts out — a bare
marker does not suppress. The hatch is not fixture-only: product code may carry one where the
reason is written down, and exactly one place does.

That place is [`provision::bounded`](src/provision/bounded.rs), and its justification is narrower
than "the network might swallow it". `verify` runs on this host and drives the agent over the
AF_UNIX socket **in-process** — there is no ssh client, no sshd and no separate shim in that path.
If the agent dies, the socket EOFs and the probe fails with no clock involved. The bound covers the
case that has no such primitive: the agent alive while its handler, or the session-1 probe child,
never produces output — a wedged LSASS blocking the child's DPAPI round trip, a hung filesystem
filter driver, or a deadlock of our own.

That last possibility is the uncomfortable one, and it is why the bound is confined to this one
command. Most ways `verify` can hang are OUR bugs, and a clock over a bug is precisely what this
rule exists to forbid. It is justified here because `verify` is a one-shot operator diagnostic
whose subject is a possibly-sick machine: hanging is the worst way to report one, and it throws
away the local rows already gathered. `--probe-timeout 0` keeps the true unbounded hang for anyone
debugging such a deadlock. Nothing else may take a bound on this argument.

**No arbitrary retry caps** *(review-enforced)*. Numeric bounds that are not retry caps are fine
and are explained where they occur — the agent task's `RestartOnFailure` `Count`, which the Task
Scheduler schema requires and cannot express as unbounded; `decode_output`'s fixed leading window
for sniffing UTF-16, a heuristic over a fixed input; the handle-writer queue's depth, which is
backpressure. Retrying a specific, self-clearing condition is fine —
`ErrorKind::Interrupted` is retried in place, because `Read::read` documents it as
non-fatal. Inventing a maximum attempt count is not.

**Tests fail loudly** *(review-enforced)*. Nothing skips on a missing dependency. A test that needs an environment
CI cannot provide is excluded by an explicit label the runner is told about, never by a runtime
early return.

**Unit tests live beside their module** as `foo_tests.rs`, linked with `#[path]`, never as an
inline `#[cfg(test)] mod`. The hook catches the inline form; that the sibling is actually wired
up with `#[path]` is *(review-enforced)*. Inline modules hide host-testable logic inside files that are
otherwise platform-gated — which is how `child_cwd`'s tests once became unreachable from the
macOS build.

**No personal home paths** in tracked files *(hook-enforced)*; no usernames or machine names
*(review)* — the hook matches home-directory shapes only, so a bare username or a hostname is
caught by reading the diff. This repo is public and its history had to be rewritten once to
scrub a hardcoded home directory out of every commit. `me` and `example` are the sanctioned
placeholders under `C:\Users\` or `/Users/`; `Public`, `Default` and `All Users` are allowed
as machine-independent Windows paths.

## Pull requests

Branch, PR, green CI, squash merge. The PR title becomes the commit subject on `main`, so it
follows Conventional Commits and is checked.

`--locked` is enforced in CI: a change that edits `Cargo.toml` without regenerating
`Cargo.lock` fails rather than silently resolving something else.
