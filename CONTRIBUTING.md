# Contributing to ssh-broker

What the tool does and why lives in [README.md](README.md). This file is the contributor
reference: how it is put together, how to build and test it, and the invariants that are not
negotiable.

## Architecture

One binary, four entry points plus the hidden `verify-probe` and `console-fallback` children, selected by argv
([`src/route.rs`](src/route.rs)). The shim is
the *default* action because `DefaultShell` is a bare path and cannot carry a subcommand: a
known verb in first position selects a subcommand, anything else is the shim.

| Verb | Module | Runs where |
|---|---|---|
| *(none)* or `-c "cmd"` | `shim`, `shim_pty` | the SSH session, as sshd's `DefaultShell` |
| `agent` | `agent` | a user's interactive session, one per logged-on user, started by a logon task for any member of `BUILTIN\Users` |
| `apply` | `provision` | wherever an admin runs it; needs elevation |
| `verify` | `provision` | on the host itself, as the account whose agent it asks: an administrator runs it elevated, and an unelevated one finds no agent and says why |
| `verify-probe` | `provision` | the child the **agent** spawns in its interactive session, driven through the relay by `verify` |
| `console-fallback [--login] <handle>` | `shim`, `shim_pty`, `handoff` | the fallback shell of a terminal session through the agent: reads a notice and a line from the pipe handle the agent gave it alone (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) until the agent closes its end, prints the notice on its pseudoconsole (which clears anything written ahead of it), starts the line there, exits with its code; it keeps through Ctrl+C for the shell, and when it cannot read the pipe it starts the built-in `cmd.exe` for a login (`--login`) and exits 255 for a command |

Supporting modules: `protocol` (frame codec and handshake), `relay` (transport-agnostic
pumping), `afunix` + `acl` (the socket and its security boundary), `socket_loc` + `userdir` (where a
user's socket lives, derived from the profile of the token), `agent_lock` (one agent per session, one
serving agent per user), `filelog` (the per-user log folder), `conpty` (the pseudoconsole
host), `pipes` (the redirected-pipe EXEC child), `vtinput` (Win32 input records → VT),
`winutil` (Windows RAII guards, job containment, cosca→Win32 error conversion, the process token and its checked information).

The functionality lives in the library rather than the binary so it is reachable from tests on
every host platform; `main.rs` is a thin dispatcher.

### The security boundary is the socket file and its folder

There is one agent per user, and its socket is `<profile>\AppData\Local\ssh-broker\agent.sock`;
for an agent at High integrity (an administrator's elevated one) it is
`<profile>\AppData\Local\ssh-broker-elevated\agent.sock`, a folder of its own (`socket_loc::Integrity`
says which: the shim and the agent each derive it from their own token's integrity level). The
shim runs as the authenticated SSH user and derives that path from its own token's profile
(`userdir`), never from the environment or an argument, so it cannot be pointed at another
account's agent. What keeps one user out of another's session is then two ACLs, not anything in
this code:

- The socket **file's** DACL decides who can `connect()`. Folder ACLs above it do not: every
  ordinary user holds `SeChangeNotifyPrivilege`, which skips traverse checks, so a second user who
  knows the path reaches the file itself.
- The socket **folder's** DACL decides who can create, replace or delete the socket.

Both must grant Full Control to exactly the user, SYSTEM and Administrators. The folder's ACEs are
inheritable so the socket, `agent.lock`, `sessions.lock` and `logs` are born with that set instead of the creating
token's default DACL; `tests/user_isolation_windows.rs` pins this with a creator whose default DACL
is world-accessible. `acl::verify_dir_acl` and `acl::verify_file_acl` are **exact-match and
fail-closed**: they reject an absent DACL, a non-protected folder DACL, DENY entries,
non-FullControl grants, extra grantees, and an owner outside the allowed set. `Listener::bind`
verifies the folder, binds, verifies the socket file, and only then listens; it removes a socket it
cannot prove. If it cannot prove the folder is safe, the agent refuses to bind.

`connect()` asks for write access to the socket file. That is why a process of the same user at
Low integrity (a sandboxed renderer) is refused although the DACL admits it: a file without an
integrity label is Medium, and the default no-write-up policy refuses a Low writer. The file has
no label unless one is set on it or inherited from any ancestor folder (the product leaves the
SACL unprotected). Only the user at Medium or above, an administrator or SYSTEM can set one, and
each of them can connect anyway; the product does not check for one.
`tests/user_isolation_windows.rs` pins the refusal and, with the file labelled Low, the connect.

The elevated folder uses that rule as its gate. It is created with the mandatory label
`S:(ML;OICI;NW;;;HI)` (High, no-write-up, inherited) in its creation descriptor, so the socket, the
locks and `logs` are born labelled, and a process of the account below High can neither connect nor
delete, rename or create beside the socket whatever the DACL says. `acl::verify_dir_acl` and
`acl::verify_file_acl` take the location's `Integrity` and for `High` require exactly that label as
part of "exactly private"; a folder without it is refused with the words of every other refusal and
is never labelled afterwards. An account that joins or leaves Administrators moves to the other
folder, each of which is created right and never repaired. `tests/user_isolation_windows.rs` pins
what a process below High is refused, and `tests/redirection_guard_windows.rs` pins the premise of
`verify`'s junction row (see the next section).

`userdir::open_socket_dir` (and `ensure_socket_dir` over it) reaches the folder by handle: it opens
the profile directory (opened following a link, see below), then `AppData`, `Local`,
`ssh-broker` and `logs`, each by name relative to the handle above it, with `FILE_OPEN_REPARSE_POINT`,
and refuses any whose handle is a reparse point. A process of the same account at lower integrity can
replace one of those names with a junction or symlink, and a path walk would follow it out of the
profile. Nothing below the profile directory is opened by path except `<profile>\AppData`, once, to
confirm it (below; `acl::private_dir`), and the log is
opened under the `logs` handle for the same reason (`filelog::daily`). A missing private folder is
created with its security descriptor given at creation. One that exists is verified through the
handle and never modified: if it is not a real directory with an owner in {user, SYSTEM,
Administrators} and exactly the private ACL, it is refused and left untouched, and removing it makes
it be created again. That is not a repair because a repair would re-ACL whatever a hard link inside
the folder names, and a handle opened before it stays open after it. The shim's opens of a log file
and of `agent.lock` refuse one that already existed with more than one name (a hard link to a file
elsewhere), as they refuse a link. A link at `AppData`,
`AppData\Local`, `ssh-broker` or `logs` is refused for every caller, a deliberate one included. A link at
the profile directory itself, or above it, is followed: its path is `ProfileImagePath`, and Windows
loads the profile through that same path, links included, so the broker uses the profile where the
operating system does and a layout that works today (a junction made for one profile, a profile that
is a mounted volume) keeps working. What that leaves: an account that replaces its own profile
directory with a link can make an elevated shim create, and never modify, an `ssh-broker` folder
(with `logs` and a log file) under another `AppData\Local`. That folder is then refused by its owner's
agent, with the folder named, and removing it restores them. A profile
path that would push the socket past the 107-byte AF_UNIX limit is an error, not a reason to use
another location (`socket_loc::SocketLocationError::TooLong`).

The walk holds the private folder, and confirms the path to it. `ssh-broker` is opened without
`FILE_SHARE_DELETE` (with `FILE_TRAVERSE`: sharing is judged only for an open that asks for data,
execute or delete access, so a handle with read-control and read-attributes alone holds nothing), and
`userdir::SocketDir` keeps it, and `logs`, for as long as it is held. While it is held nobody can
rename or remove it, and nobody can rename or remove `Local` or `AppData` either: Windows does not
rename a directory with an open descendant. `AppData` and `Local` are opened only to read their ACL
and attributes, sharing everything, which takes no part in a sharing check, so other programs use them
as usual. With the private folder held, the walk confirms the path to it in two steps. It opens `Local` as one
name relative to the `AppData` handle, not following a link, and refuses unless that is the `Local` the
walk went through (the same volume and 128-bit file id): `Local` is, now, a child of that `AppData`,
and with the private folder open inside it, it cannot leave. Then it opens `<profile>\AppData` by its
full path, the path `bind` and `connect` resolve, without following a link, and refuses unless that is
the `AppData` the walk went through. A process of the same account that renamed `Local` aside, or moved
it out of `AppData`, and put a link or a folder of its own in its place while the walk was opening it
is caught there, and after the check the location's path names the folders held. A folder that is gone
when it is confirmed is a refusal too, never "no folder yet". What may be written inside the folder, or to its
attributes, is decided by its ACL (and, for the elevated agent's folder, by its label), not by the hold.
This is a stated limit: if another program holds
the broker's own folder open in a way that keeps the broker from using it (with the right to delete
or rename it, or without letting others read it) when a walk opens it, the walk is refused with that
said (`offer::text::folder_held`): no retry, since a holder that never lets go would hang the login.
The next login, once the holder has let go, is brokered again.
There is one way to connect to an agent: `SocketDir::connect`, through the folders held
(`afunix::connect` is crate-private). A caller that connects walks first and keeps the `SocketDir`
over the connect; a shim connects only if its private folder was accepted. A test whose subject is
the connect itself by a bare path (an account the socket's ACL refuses, a stand-in socket) makes it
in `tests/common/raw_connect.rs`.

The agent's own operations in the folder (`Listener::bind`, the `agent_lock` locks, the `serving`
marker) name it by path, and the by-path contract rests on the hold above: the agent keeps its
`SocketDir` for its whole run, so while any of these runs nobody can rename, replace or remove the
folder, or `Local` or `AppData` above it, and the path names the folder held. That matters most for an
elevated agent, whose writes a redirection would otherwise pay. An administrator's agent is elevated,
started by the logon task (`HighestAvailable`), by the password prompt (a batch logon, pinned by
`an_administrators_shim_sees_the_elevated_agent_it_starts`) or by the `auto-login` task, and it refuses
to run with a filtered token (exit code 68). Inside its folder the label keeps a process of the account
below High from creating or changing anything; the hold keeps it from moving the folder itself.
The elevated shim looks at `agent.lock` through the
folder's handle and never creates it (`starting_agent`, `userdir::open_existing_socket_dir`); the
folder watch (`socket_watch`) stays by path, and neither it nor the connect, which goes through the
folders held, creates or writes anything.

The install directory is the other half of the boundary: the agent runs the exe in it, so a directory a standard user can write to is a privilege escalation. `apply` verifies it exactly and reads and writes nothing in it until that passes. Users can read what is in it, so a file in it that a user must not open (`apply.lock`: a byte-range lock needs only a read handle) gets its own protected DACL of SYSTEM and Administrators at creation, verified exactly (`acl::ensure_admin_only_file`).

### Fail-open is deliberate, and never in the security boundary

If the shim cannot reach the agent it runs your session locally and reports why. A broken broker
must not cost you access to the machine. The session runs through the configured shell, with the
command packed the way the agent would have packed it: both call `shell::plan`, the shim with its
own environment. If the configured shell cannot be used, the built-in `cmd.exe` runs after one
warning. The child is contained in a job object exactly as a relayed one is, so failing open is not
a way to outlive the session. This is the relay path's
deliberate degradation, and the security boundary never degrades — the ACL check above and the
bind both fail closed. Elsewhere the shim also prefers working over failing in smaller ways
(logging disables itself rather than aborting, for one), and provisioning has best-effort steps of
its own.

### What `verify`'s junction row proves

RedirectionGuard refuses to follow a link that a non-administrator made, and a process follows a link it
made itself, so a row that read through a link the probe made as an elevated process would pass whether or
not the mitigation is on. For an agent at High integrity `verify` therefore runs two probes through it
(`provision::probe_run`): first `verify-probe --make-junction <directory>` with `Privilege::Unelevated`, which
makes that directory with a junction in it by a token below High, then `verify-probe --follow <directory>` as
the account, which reads through it. `verify` names the directory itself, under its own temp directory with a
name unique to the run, before any probe runs, and removes it, through no link, whatever became of either
probe: no probe reports a path, because a path a process below High wrote is not one an elevated `verify`
acts on. The make-probe fails on a path that exists and never clears one. Each probe's outcome is a value
(`session_rows::ProbeOutcome`: answered, failed, timed out, not run) and `probe_run::run_at` returns them
all, so the rows are a pure function of what it found. A probe that fails is data, not an early return: the
default probe still runs (with a junction of its own, which proves nothing and is not judged), so only the
rows about the failed probe fail; a first probe that times out starts no second, and `verify` says that it
may still create the directory. A junction counts as made from below High only when the make-probe reports an
integrity below High and made the junction; otherwise the junction row fails with why. A junction needs no
privilege, but it needs a volume that holds reparse points: where the directory was made and the volume
refused the reparse point the state is `SymlinkState::Skipped`, which fails nothing and says on the row that
it was not tested and why; a directory that could not be made at all is `NotMade`, a junction refused with
error 448 is `Blocked`, and one that was made and not read is `Failed`, and all three fail. The probe's
stderr lines about the junction (`probe::JUNCTION_SAID`) reach the row. For an agent below High there is one probe, which makes and follows
its own. The probe's PROBE line also carries its own `elevation` and `integrity` (read by
`account::elevation_of` and `integrity_of`), which the `elevated session` and `unelevated session on request`
rows judge. The two probes and the two rows are keyed on the agent being at High (the level of the process
that runs `verify`, which is the level of the folder it asks; the default probe's own level for the rows),
not on `Elevation::Full`.
`tests/redirection_guard_windows.rs` measures the premise.

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

**No run of spaces inside a string literal.** A sentence written over several lines is joined with a
trailing `\`, which also drops the next line's indentation; joined any other way, the indentation
lands in the sentence. The hook rejects three or more spaces between two non-space characters inside
a literal on one line. A literal that needs the run (a table column, a command line under test) opts
out with a same-line `spaces-ok:` marker **and a reason**; a bare marker does not suppress. Raw
strings are skipped, and only the line with the literal's opening quote is read, so a run typed into
a later line of a sentence continued with `\` is not checked.

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

**The password has three sinks** *(review-enforced)*. It is read from the console (the shim's prompt, and
`auto-login on`'s) into a `SecretUnits` (`secret.rs`: fully initialised backing, wiped on drop and before a
growth frees the old store); the console's record buffer is wiped after every read. From there it goes only to
Windows, in these places:

- `CreateProcessWithLogonW`, to start a background session below High (`logon::start_background_agent`
  with `LogonKind::Interactive`), in a NUL-terminated copy that `Password::with_nul` wipes when the call
  returns;
- `LogonUserW(BATCH)`, the one call `logon::batch_logon` makes, in the same kind of wiped copy: to ask
  whether the account may log on as a batch job (`logon::check_batch_logon`, which drops the token) and, for
  a login at High, to make the token the elevated agent is started with (`LogonKind::Batch`, over
  `CreateProcessWithTokenW`, which takes that token and never the password);
- Task Scheduler's `RegisterTask`, which **stores** it in its credential store for `auto-login on`
  (`provision::password_variant`): a BSTR copy that is zeroed before it is freed. Task Scheduler's own copy
  and the RPC buffers that carry it are outside this process.

It never goes on a command line, into the environment, a file, a log, a `tracing` field, a `Debug` impl or an
error text. A new use of it is a new sink: review it as one.

**No personal home paths** in tracked files *(hook-enforced)*; no usernames or machine names
*(review)* — the hook matches home-directory shapes only, so a bare username or a hostname is
caught by reading the diff. This repo is public and its history had to be rewritten once to
scrub a hardcoded home directory out of every commit. `me` and `example` are the sanctioned
placeholders under `C:\Users\` or `/Users/`; `Public`, `Default` and `All Users` are allowed
as machine-independent Windows paths.

## Releasing

A release is two manual workflows, both taking the version (the `Cargo.toml` version, without `v`):

1. **Draft Release**, dispatched from `main`: tests the commit, builds and attests the Windows zip, creates draft `v<version>` with the zip and `.sha256`.
2. **Publish Release**, in the `Deploy` environment: re-verifies the draft against its commit on `main`, publishes it, and re-verifies the published zip.

`release-asset.yaml` also runs on pull requests that touch what goes into the asset, so packaging, the import check and the attestation are exercised before a release. `.github/scripts/check-imports.sh` fails the build if the exe imports a DLL outside its allowlist of OS-shipped ones; a new dependency that imports another system DLL is added to that allowlist.

`.cargo/config.toml` links the C runtime in (`+crt-static`) for every Windows MSVC target, so guests need no VC++ redistributable. Cargo reads it only from the working directory's ancestors (not via `--manifest-path`, a dependency or `cargo install`), and any `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`, even empty, replaces it. Only the release exe is checked.

Before the first publish, enable immutable releases on the repository and create the `Deploy` environment with deployment branches limited to `main`. It has no required reviewer; dispatching Publish Release is the decision to publish. Without immutable releases the final re-verification detects, but does not prevent, a draft asset being swapped in the moments before publishing.

## Pull requests

Branch, PR, green CI, squash merge. The PR title becomes the commit subject on `main`, so it
follows Conventional Commits and is checked.

`--locked` is enforced in CI: a change that edits `Cargo.toml` without regenerating
`Cargo.lock` fails rather than silently resolving something else.
