# Contributing to ssh-broker

What the tool does and why lives in [README.md](README.md). This file is the contributor
reference: how it is put together, how to build and test it, and the invariants that are not
negotiable.

## Architecture

One binary, the verbs in the table below, selected by argv ([`src/route.rs`](src/route.rs)). `install-sshd`,
`doctor-probe` and `console-fallback` are run by the product itself and not typed. The shim is
the *default* action because `DefaultShell` is a bare path and cannot carry a subcommand: a
known verb in first position selects a subcommand, anything else is the shim.

| Verb | Module | Runs where |
|---|---|---|
| *(none)* or `-c "cmd"` | `shim`, `shim_pty` | the SSH session, as sshd's `DefaultShell` |
| `agent` | `agent` | a user's interactive session, one per logged-on user, started by a logon task for any member of `BUILTIN\Users` |
| `install` | `provision` | wherever an admin runs it; needs elevation |
| `auto-login on\|off [<account>]` | `autologin` | wherever an elevated administrator runs it (`on` needs a terminal to ask for the password): stores the account's password with Task Scheduler and registers, or deletes, the boot task that starts its background session |
| `logout` | `logout`, `request`, `agent::logout` | a process of the account at any level: asks `agent.sock`, and below High `request.sock` where no agent is on the first, to end the account's background session |
| `elevate [--terminal] <command>` | `elevate`, `request`, `agent::{requests,elevation,link}` | a shell that an agent hosts: runs the command in place at High, and below High asks the agent on `request.sock`, which runs it with its own token once the session's `SSH_BROKER_ELEVATION` allows it |
| `doctor` | `provision` | on the host itself, as the account whose agent it asks: an administrator runs it elevated, and an unelevated one shows the local rows and the ways to check (an elevated prompt, an SSH login that asked for `always`, `ssh-broker elevate ssh-broker doctor` in an SSH session) |
| `install-sshd` | `provision`, `provision::sshd_task` | the hidden verb of the task `ssh-broker-install-sshd`, as SYSTEM: `install`'s sshd step (the drop-in, the `Include` and the restart of sshd), whose every line it writes to `install-sshd.log` in the install directory; `install` registers the task, starts it, waits for its instances and prints the report, so that the step finishes even if the `install` that started it is ended |
| `doctor-probe` | `provision` | the child the **agent** spawns in its interactive session, driven through the relay by `doctor` |
| `console-fallback [--login] <handle>` | `shim`, `shim_pty`, `handoff` | the fallback shell of a terminal session through the agent: reads a notice and a line from the pipe handle the agent gave it alone (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) until the agent closes its end, prints the notice on its pseudoconsole (which clears anything written ahead of it), starts the line there, exits with its code; it keeps through Ctrl+C for the shell, and when it cannot read the pipe it starts the built-in `cmd.exe` for a login (`--login`) and exits 255 for a command |

Supporting modules: `protocol` (frame codec and handshake), `relay` (transport-agnostic
pumping), `afunix` + `acl` (the socket and its security boundary), `socket_loc` + `userdir` (where a
user's socket lives, derived from the profile of the token), `agent_lock` (one agent per session, one
serving agent per user), `filelog` (the per-user log folder), `conpty` (the pseudoconsole
host), `pipes` (the redirected-pipe EXEC child), `vtinput` (Win32 input records → VT),
`winutil` (Windows RAII guards, job containment, cosca→Win32 error conversion, the process token and its checked information). The rest are in the table of [CLAUDE.md](CLAUDE.md#where-things-live).

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
is never labelled afterwards. `tests/user_isolation_windows.rs` pins
what a process below High is refused, and `tests/redirection_guard_windows.rs` pins the premise of
`doctor`'s junction row (see the next section).

An agent at High also binds `request.sock` in the plain folder, where neither the folder nor the file carries the
label, so a process of the account below High can connect to it: it is how an unelevated session reaches the agent.
It takes requests only (`logout`, and the `ElevationRequest` of `ssh-broker elevate`); a session handshake there is
answered with a sentence (`agent::requests::REQUESTS_ONLY`) and no session starts. **Everything on `request.sock` is
input from a lower level**; see `agent::requests`. The session id in a request says which session asks and is no credential. The agent
keeps its `SocketDir` of the plain folder for its whole run, as it keeps its own, so the by-path contract below holds
for `request.sock` too; a plain folder it cannot use costs it the request socket and nothing else. The socket is
served by the sessions' accept machinery and counted in the same tally, with no read bound of its own: a client that
connects and sends nothing holds a handler thread and can delay the agent's end by up to the drain's bound
(`agent::connections::DRAIN_BOUND`, 30 seconds). That is the contract the README states, not a defect to guard
against: the unelevated session is a consent step, not a boundary.

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

The install directory is the other half of the boundary: the agent runs the exe in it, so a directory a standard user can write to is a privilege escalation. `install` verifies it exactly and reads and writes nothing in it until that passes. Users can read what is in it, so a file in it that a user must not open (`apply.lock`, the lock of `install`: a byte-range lock needs only a read handle) gets its own protected DACL of SYSTEM and Administrators at creation, verified exactly (`acl::ensure_admin_only_file`).

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

### What `doctor`'s junction row proves

RedirectionGuard refuses to follow a link that a non-administrator made, and a process follows a link it
made itself, so a row that read through a link the probe made as an elevated process would pass whether or
not the mitigation is on. For an agent at High integrity `doctor` therefore runs two probes through it
(`provision::probe_run`): first `doctor-probe --make-junction <directory>` asking the agent for the default elevation policy
(`prompt`: an unelevated session), which makes that directory with a junction in it by a token below High, then
`doctor-probe --follow <directory>` asking for `always` (the account's own token), which reads through it. `doctor` names the directory of every junction itself, under its own temp directory with a
name unique to the run, before any probe runs, and removes it, through no link, whatever became of the
probes: no probe reports a path, because a path a process below High wrote is not one an elevated `doctor`
acts on. The make-probe fails on a path that exists and never clears one. Each probe's outcome is a value
(`session_rows::ProbeOutcome`: answered, failed, timed out, not run) and `probe_run::run_at` returns them
all, so the rows are a pure function of what it found. A probe that fails is data, not an early return: the
probe that asks for `always` still runs (given no junction), so only the rows about the failed probe fail. A junction
counts as made from below High only when the make-probe reports an integrity below High and a junction
that was made; otherwise the junction row fails with why, and a probe that reported no outcome is never read
as one that made a junction. A junction needs no privilege, but it needs a volume that holds reparse points,
which `link::make` asks the volume once the directory is made: a volume that holds none is
`SymlinkState::Skipped`, which fails nothing and says on the row that it was not tested; on a volume that
holds them every later failure is `NotMade` with its cause, a junction refused with error 448 is `Blocked`,
and one that was made and not read is `Failed`, and all three fail. The stderr lines of a probe about its
junction and about its own token (`probe::JUNCTION_SAID`, `probe::TOKEN_SAID`) reach the rows they explain.
For an agent below High there is one probe, which makes and follows the junction in the directory it is
given. The probe's PROBE line also carries its own `elevation` and `integrity` (read by
`account::elevation_of` and `integrity_of`), which the `session` and `elevated session on request` rows judge:
the first from the probe that asked for `prompt`, the default level, the second from the one that asked for `always`.
The session id, DPAPI and byte rows are the first probe's too, since that is the session a login gets
(`session_rows::Probes::session`; `Probes::elevated` is `None` for an agent below High, which refuses
`always`). The two probes and the two rows are keyed on the agent being at High (the level of the process
that runs `doctor`, which is the level of the folder it asks), not on `Elevation::Full`. A process below
High that is an administrator's runs no probe: `doctor` shows its local rows and one failing row, in place of the
rows about the agent's socket, that names the ways to check: an elevated prompt, an SSH login that asked for
`always`, and `elevate` in an SSH session (`offer::text::ELEVATED_AGENT_LOOKS_ELSEWHERE`, which `logout` says too,
and `CHECK_BELOW_HIGH_CLAUSE`).
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

Tests that need a real sshd, a local account or the machine's configuration are Elevated (CI only): make
`cargo test --no-run` compile them and let CI run them. `tests/sshd_config_windows.rs` takes the machine alone
(`ci-exclusive`).

Host tests of the pieces beside them: `agent::link` (whose output the connection carries, where the keys go),
`agent::requests`, `agent::elevation` (what each level allows), `consent_entry`, `console_prompt` (what is queued
when the question appears), and `provision::sshd_config` over a stand-in `SshdHost`.

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
than "the network might swallow it". `doctor` runs on this host and drives the agent over the
AF_UNIX socket **in-process** — there is no ssh client, no sshd and no separate shim in that path.
If the agent dies, the socket EOFs and the probe fails with no clock involved. The bound covers the
case that has no such primitive: the agent alive while its handler, or the session-1 probe child,
never produces output — a wedged LSASS blocking the child's DPAPI round trip, a hung filesystem
filter driver, or a deadlock of our own.

That last possibility is the uncomfortable one, and it is why the bound is confined to this one
command. Most ways `doctor` can hang are OUR bugs, and a clock over a bug is precisely what this
rule exists to forbid. It is justified here because `doctor` is a one-shot operator diagnostic
whose subject is a possibly-sick machine: hanging is the worst way to report one, and it throws
away the local rows already gathered. `--probe-timeout 0` keeps the true unbounded hang for anyone
debugging such a deadlock. Nothing else may take a bound on this argument.

**Product code reads, writes and accepts on an AF_UNIX socket only through `afunix`** *(review)*:
connections are non-blocking and one loop waits in slices of `RECHECK_EVERY` and retries (rationale: the
`afunix` module doc). A connection is one `Conn` handle; never duplicate it. No `SO_RCVTIMEO`, no raw
`socket2::Socket` I/O. A test holding a raw socket as the other end never waits for its END with a
blocking read: it waits for a frame, or reads through `afunix::split`.

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

**One rule decides a session's token** *(review)*. `account::step_down` turns what the login asked
(`SSH_BROKER_ELEVATION`) and the process's integrity into a token, none, or a refusal. The agent
(`UnelevatedToken::for_policy`), the shim's fail-open shell (`shim_pty`) and the shim's offer (`shim_offer::stance`)
all ask it; a second place that decides what a login gets is a defect.

**Nothing on the SSH command line is interpreted** *(review)*. The level of a login is the value of
`SSH_BROKER_ELEVATION` and nothing a client types as its command: no word, and no read of `SSH_ORIGINAL_COMMAND`
for one.

**Everything on `request.sock` is input from a lower level** *(review)*, and the socket takes requests only: see
"The security boundary is the socket file and its folder". A new kind of request that can end the agent ends it
through `agent::settled_end` and `finish_settled`, which are the one exit code of an agent whose end was decided.

**The consent is decided by a pure state machine** *(review)*. `consent_entry::ConsentEntry` takes key events and
says whether the answer allows; `console_prompt::ask_consent` does the console I/O around it, as `password_entry`
and the password prompt do. A change to what allows is a change to the state machine and its host tests, not to
the console code.

**`AcceptEnv` and `Include` edits go through the text-to-text function and `sshd -t`** *(review)*. `install` makes
a candidate of `sshd_config` with `sshd_config::with_line`, has `sshd -t` check it and `sshd -T` show the variable in
force, and only then renames it over the original (`sshd_config::configure`); the original is untouched on any
failure.

**No personal home paths** in tracked files *(hook-enforced)*; no usernames or machine names
*(review)* — the hook matches home-directory shapes only, so a bare username or a hostname is
caught by reading the diff. This repo is public and its history had to be rewritten once to
scrub a hardcoded home directory out of every commit. `me` and `example` are the sanctioned
placeholders under `C:\Users\` or `/Users/`; `Public`, `Default` and `All Users` are allowed
as machine-independent Windows paths.

## Releasing

A release is two manual workflows, both taking the version (the `Cargo.toml` version, without `v`):

1. **Draft Release**, dispatched from `main`: tests the commit, builds and attests the Windows exe, creates draft `v<version>` with the two assets: `ssh-broker-x86_64-pc-windows-msvc.exe` (no version in the name, so `releases/latest/download/<name>` is a stable link) and `SHA256SUMS`. `.github/scripts/asset-name.sh` is the one place that names them; the attestation's subject is the exe.
2. **Publish Release**, in the `Deploy` environment: re-verifies the draft against its commit on `main`, publishes it, and re-verifies the published exe.

`release-asset.yaml` also runs on pull requests that touch what goes into the asset, so the build, the import check and the attestation are exercised before a release. `.github/scripts/check-imports.sh` fails the build if the exe imports a DLL outside its allowlist of OS-shipped ones; a new dependency that imports another system DLL is added to that allowlist.

`.cargo/config.toml` links the C runtime in (`+crt-static`) for every Windows MSVC target, so guests need no VC++ redistributable. Cargo reads it only from the working directory's ancestors (not via `--manifest-path`, a dependency or `cargo install`), and any `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`, even empty, replaces it. Only the release exe is checked.

Before the first publish, enable immutable releases on the repository and create the `Deploy` environment with deployment branches limited to `main`. It has no required reviewer; dispatching Publish Release is the decision to publish. Without immutable releases the final re-verification detects, but does not prevent, a draft asset being swapped in the moments before publishing.

## Pull requests

Branch, PR, green CI, squash merge. The PR title becomes the commit subject on `main`, so it
follows Conventional Commits and is checked.

`--locked` is enforced in CI: a change that edits `Cargo.toml` without regenerating
`Cargo.lock` fails rather than silently resolving something else.
