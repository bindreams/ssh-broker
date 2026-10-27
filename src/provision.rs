//! provision: self-install (`apply`) and self-check (`verify`) — the DefaultShell values, the
//! agent logon task (one agent per logged-on user), the ONSTART self-heal task, and parity
//! probes (DPAPI/symlink/session) run THROUGH the invoking user's agent.
//!
//! The pure, host-tested logic lives in the submodules (registry/schtasks/probe/report); this root
//! holds the Windows orchestration. `apply` is ordered so a partial run never bricks SSH (the
//! DefaultShell registry flip is LAST, after the exe is proven present). It knows no user: each
//! agent makes and hardens its own socket directory in its own profile, so a SYSTEM-run
//! self-heal has nothing to resolve.

pub mod bounded;
#[cfg(windows)]
mod flow;
#[cfg(windows)]
pub(crate) mod layout;
#[cfg(windows)]
pub mod password_variant;
#[cfg(windows)]
pub(crate) mod pending_sessions;
pub mod probe;
#[cfg(windows)]
pub mod procwait;
pub mod registry;
pub mod report;
pub mod schtasks;
pub mod session_task;
#[cfg(windows)]
pub mod sessions;
#[cfg(windows)]
pub mod taskscheduler;
#[cfg(windows)]
pub(crate) mod user_rows;

/// `apply` subcommand: idempotently assert all desired state. Windows-only.
pub fn apply() -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::apply();
    #[cfg(not(windows))]
    anyhow::bail!("apply provisions a Windows host and runs only on Windows");
}

/// `verify` subcommand: local state checks + parity probes through the agent. Windows-only.
pub fn verify() -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::verify();
    #[cfg(not(windows))]
    anyhow::bail!("verify runs only on Windows");
}

/// `verify-probe`: the hidden child the agent spawns in session 1. Prints one PROBE line and
/// exits 0 (parity) / 1 (not). Never invoked directly by users.
pub fn verify_probe() -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::verify_probe();
    #[cfg(not(windows))]
    anyhow::bail!("verify-probe runs only on Windows");
}

/// Check the arguments after `apply`, returning the warnings to print.
///
/// `apply` takes none. The one exception is the removed `--user <name>`: an earlier build baked
/// it into the boot-time self-heal task, and during a half-done migration that task runs the new
/// exe with it. Refusing would leave the install unrepaired by the very task that exists to
/// repair it, so it is accepted, ignored, and reported.
pub fn check_apply_args(args: &[String]) -> anyhow::Result<Vec<String>> {
    let mut warnings = Vec::new();
    let mut rest = args.iter().peekable();
    while let Some(arg) = rest.next() {
        if arg == "--user" {
            // Its value is part of the flag, not an argument of its own.
            if rest.peek().is_some_and(|value| !value.starts_with('-')) {
                rest.next();
            }
            warnings.push(
                "apply: --user is ignored: ssh-broker runs one agent per logged-on user and has no target account"
                    .to_string(),
            );
        } else {
            anyhow::bail!("apply takes no arguments, got {arg:?}");
        }
    }
    Ok(warnings)
}

/// The directory `apply` installs into. The one place the path is written; [`layout::Layout`]
/// derives from it.
pub const BASE_DIR: &str = r"C:\ProgramData\ssh-broker";

/// The installed exe's file name.
pub const EXE_NAME: &str = "ssh-broker.exe";

/// The path `apply` installs the shim to and registers as `DefaultShell`.
pub fn canonical_exe() -> std::path::PathBuf {
    std::path::Path::new(BASE_DIR).join(EXE_NAME)
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod provision_tests;

#[cfg(windows)]
mod imp {
    use super::layout::{self, Layout};
    use super::{
        flow, pending_sessions, probe, procwait, registry, report, schtasks, session_task, sessions, taskscheduler,
        user_rows,
    };
    use crate::{afunix, shim};
    use anyhow::Context;
    use std::path::Path;

    /// Case-insensitive compare of a registry path string (quotes trimmed) to a path.
    fn eq_path(a: &str, b: &Path) -> bool {
        a.trim().trim_matches('"').eq_ignore_ascii_case(&b.to_string_lossy())
    }

    pub fn apply() -> anyhow::Result<()> {
        let layout = Layout::production();

        // 0. `apply` takes no arguments. A removed `--user` (still in an old self-heal task) is
        //    warned about and ignored.
        let args: Vec<String> = std::env::args().skip(2).collect();
        for warning in super::check_apply_args(&args)? {
            eprintln!("{warning}");
        }

        // 1. Install this exe to a STABLE path (see layout::prepare). Everything registers the
        //    canonical path: a temp path would brick SSH the instant it is deleted; the shim's
        //    fail-open can't help if sshd execs a missing binary. The install directory is gated
        //    first, so a planted one is never adopted, and a single-user install is replaced. A
        //    different build over an installed one stops every agent first (they hold the exe
        //    open) and waits for them to exit, with the logon task disabled so that no logon
        //    starts one from the old exe meanwhile. Every run from here ends by enabling the task, which
        //    also heals one an earlier, killed `apply` left disabled; the agents start again
        //    afterwards, even if a later step fails, except in a session whose old agent has not
        //    exited.
        let current = std::env::current_exe().context("current_exe")?;
        let registered_xml = schtasks::registered_xml(taskscheduler::task_xml(schtasks::AGENT_TASK))?;
        // The auto-login tasks that were enabled when the agents were stopped, to be enabled and
        // started again afterwards. It starts with the tasks an earlier `apply` that was killed
        // after disabling them still owes (the record is read only from a checked install directory).
        let owed = match layout::check_base(&layout) {
            Ok(base) => pending_sessions::load(&base.layout().pending_sessions_path())?,
            // Not ours yet: `prepare` makes it ours or refuses, and nothing in it is believed meanwhile.
            Err(_) => Vec::new(),
        };
        let enabled_sessions = std::cell::RefCell::new(owed);
        let exe = flow::run(
            || {
                taskscheduler::stop_instances(schtasks::AGENT_TASK, &layout.canonical_exe())?;
                stop_background_sessions(
                    &layout.canonical_exe(),
                    &layout.pending_sessions_path(),
                    &enabled_sessions,
                )
            },
            |stop_agents| {
                let exe = layout::prepare(&layout, &current, registered_xml.as_deref(), stop_agents)?;

                // 2. Register both tasks (idempotent /F).
                register_agent_task(&layout, &exe)?;
                register_selfheal_task(&exe)?;

                // 3. Write the escape flag and read it back at once, then flip the DefaultShell
                //    pair LAST and only to the validated canonical path; read that back too. sshd
                //    reads these once per session, so the shim cannot ask later which form sshd
                //    used: `apply` owns the flag (see `registry::desired_values`).
                registry::set_default_shell_under(registry::OPENSSH_KEY, &exe.to_string_lossy())
                    .context("write the DefaultShell values")?;
                let (shell, opt) = registry::read_default_shell_under(registry::OPENSSH_KEY)?;
                anyhow::ensure!(
                    eq_path(&shell, &exe) && opt == "-c",
                    "DefaultShell read-back mismatch (shell={shell:?}, opt={opt:?})"
                );
                Ok(exe)
            },
            agent_task_is_group_form,
            enable_agent_task,
            || {
                flow::resume_sessions(&enabled_sessions, |name| taskscheduler::set_enabled(name, true))?;
                // Every task is enabled again: nothing is owed any more. A directory that is not
                // ours is left alone: its file is not the one that was ignored at the start.
                match layout::check_base(&layout) {
                    Ok(base) => pending_sessions::store(&base.layout().pending_sessions_path(), &[]),
                    Err(_) => Ok(()),
                }
            },
            || flow::start_sessions(&enabled_sessions, taskscheduler::run_task),
            start_agents,
        )?;
        println!(
            "apply: ok — DefaultShell -> {}, agent + self-heal tasks installed",
            exe.display()
        );
        Ok(())
    }

    /// The background sessions' part of the stop that precedes replacing the exe: the auto-login
    /// tasks are disabled and their instances stopped, then every background agent left (the prompt
    /// path starts one without a task) is ended. A shim is never ended: it holds the exe only until
    /// its SSH session closes, and the copy reports it if it still does.
    fn stop_background_sessions(
        image: &Path,
        pending: &Path,
        enabled: &std::cell::RefCell<Vec<String>>,
    ) -> anyhow::Result<()> {
        flow::stop_sessions(
            taskscheduler::session_tasks,
            enabled,
            |names| pending_sessions::store(pending, names),
            |name| taskscheduler::stop_instances(name, image),
            || procwait::background_agents(image),
            |agent| agent.terminate(),
            |agents| procwait::wait_all_exited(&agents, procwait::EXIT_BOUND),
        )
        .context("stop the background sessions")
    }

    /// Whether the registered agent task is the group logon task, the form that can start an agent
    /// in any session. An older single-user task cannot, so a failed `apply` that stopped agents
    /// does not run it.
    ///
    /// A query that cannot be answered counts as "no": starting through a task of unknown form
    /// could start the single-user agent this migration is replacing.
    fn agent_task_is_group_form() -> bool {
        match taskscheduler::task_xml(schtasks::AGENT_TASK) {
            Ok(xml) => xml.is_some_and(|xml| schtasks::xml_is_group_logon_task(&xml)),
            Err(e) => {
                eprintln!("apply: not restarting the agents: {e:#}");
                false
            }
        }
    }

    /// Enable the agent task: undo the stop's disabling of it, and heal a task that an earlier
    /// `apply` left disabled by being killed. Registering the task afresh enables it too, but a
    /// failed `apply` may not have got that far.
    fn enable_agent_task() -> anyhow::Result<()> {
        taskscheduler::set_enabled(schtasks::AGENT_TASK, true).with_context(|| {
            format!(
                "could not enable the {} task again; no agent starts at a logon until it is",
                schtasks::AGENT_TASK
            )
        })
    }

    /// Step 4 of `apply`: start an agent in each session that already has a user, so nobody has to
    /// log off and on again (the logon trigger covers every later logon), and to bring back the
    /// agents step 1 stopped. An agent that is already running in its session exits at once, so
    /// this is safe to repeat. Best-effort: the install is complete without it, and a failed
    /// `apply` runs it too. A session whose old agent survived the stop is left alone: see
    /// [`flow::plan_start`].
    fn start_agents(survivors: &[procwait::Survivor]) {
        match sessions::interactive_sessions() {
            Ok(targets) => {
                for (id, why) in &targets.unknown {
                    eprintln!(
                        "apply: could not tell whether session {id} has a user, so no agent was started there: {why}"
                    );
                }
                let plan = flow::plan_start(&targets.ids, survivors);
                for (id, pids) in &plan.held {
                    eprintln!(
                        "apply: no agent was started in session {id}: its old agent (process {}) was stopped but has not been seen to exit; run apply again once it has exited",
                        pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
                    );
                }
                let mut started = 0usize;
                for id in &plan.start {
                    match taskscheduler::run_in_session(schtasks::AGENT_TASK, *id) {
                        Ok(()) => started += 1,
                        Err(e) => eprintln!("apply: could not start the agent in session {id}: {e:#}"),
                    }
                }
                println!(
                    "apply: started the agent in {started} of {} logged-on session(s)",
                    targets.total()
                );
            }
            Err(e) => eprintln!("apply: the logged-on sessions could not be listed: {e:#}"),
        }
    }

    fn register_agent_task(layout: &Layout, exe: &Path) -> anyhow::Result<()> {
        let xml = schtasks::agent_task_xml(&exe.to_string_lossy());
        let xml_path = layout.base.join("agent-task.xml");
        // schtasks /XML requires a UTF-16 file (a UTF-8 one is rejected).
        std::fs::write(&xml_path, schtasks::xml_file_bytes(&xml)).context("write agent task xml")?;
        run_schtasks(&schtasks::create_from_xml_argv(
            schtasks::AGENT_TASK,
            &xml_path.to_string_lossy(),
        ))
        .context("register agent task")?;
        Ok(())
    }

    fn register_selfheal_task(exe: &Path) -> anyhow::Result<()> {
        run_schtasks(&schtasks::selfheal_task_argv(&exe.to_string_lossy())).context("register self-heal task")?;
        Ok(())
    }

    /// Decode schtasks output, handling the UTF-16LE it can emit to a redirected pipe (BOM, or
    /// pervasive NUL bytes). Otherwise treat it as UTF-8/ASCII. The markers verify scans for
    /// (`<Task`, `InteractiveToken`) are ASCII either way, but decoding correctly avoids a
    /// NUL-interleaved false-fail.
    fn decode_output(bytes: &[u8]) -> String {
        let bom = bytes.starts_with(&[0xFF, 0xFE]);
        // A fixed window over a fixed input, not a cap on work: schtasks' UTF-16 output
        // interleaves NULs from the first byte, so a short prefix decides it. Counting the
        // whole buffer would say the same thing more slowly.
        let nul_heavy = bytes.iter().take(64).filter(|&&b| b == 0).count() > 8;
        if bom || nul_heavy {
            let start = if bom { 2 } else { 0 };
            // A trailing odd byte is dropped, as `chunks_exact` did: this decodes
            // schtasks' output defensively, not a length-checked wire format.
            let (pairs, _odd_tail) = bytes[start..].as_chunks::<2>();
            let u16s: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
            String::from_utf16_lossy(&u16s)
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    /// Run `schtasks` with the given args, erroring on a nonzero exit.
    fn run_schtasks(args: &[String]) -> anyhow::Result<String> {
        let out = std::process::Command::new("schtasks")
            .args(args)
            .output()
            .context("spawn schtasks")?;
        anyhow::ensure!(
            out.status.success(),
            "schtasks {:?} failed: {}",
            args,
            decode_output(&out.stderr).trim()
        );
        Ok(decode_output(&out.stdout))
    }

    // ── verify ─────────────────────────────────────────────────────────────────────

    pub fn verify() -> anyhow::Result<()> {
        let layout = Layout::production();
        let exe = layout.canonical_exe();
        let mut rows = Vec::new();

        // Local: the DefaultShell pair points at this exe (and the exe still exists).
        match registry::read_default_shell_under(registry::OPENSSH_KEY) {
            Ok((shell, opt)) => {
                let ok = eq_path(&shell, &exe) && opt == "-c" && exe.is_file();
                rows.push(report::Check::new(
                    "DefaultShell pair",
                    ok,
                    format!("shell={shell:?} opt={opt:?}"),
                ));
            }
            Err(e) => rows.push(report::Check::new("DefaultShell pair", false, e.to_string())),
        }

        // Local: the install directory is exactly the hardened one (only SYSTEM and Administrators
        // can write to it).
        let base = layout::check_base(&layout);
        rows.push(layout::install_dir_row(&base));

        // Local: sshd escapes the command, the only non-PTY form the shim decodes. sshd reads the
        // value once per session, so this is the one place it is checked.
        rows.push(registry::escape_arguments_check(registry::escape_arguments_under(
            registry::OPENSSH_KEY,
        )));

        // Local: the agent task is registered in its group form (any user, interactive session).
        rows.push(schtasks::agent_task_row(&taskscheduler::task_xml(schtasks::AGENT_TASK)));
        // Local: this account's auto-login task, if it has one (informational for everyone who has not
        // turned auto-login on, which passes).
        match crate::acl::Sid::current_user().and_then(|sid| sid.to_sddl()) {
            Ok(sid) => rows.push(session_task::task_row(
                &taskscheduler::task_state(&session_task::task_name(&sid)),
                &layout.canonical_exe().to_string_lossy(),
                &sid,
            )),
            Err(e) => rows.push(report::Check::new(
                "auto-login task",
                false,
                format!("could not tell who this is: {e:#}"),
            )),
        }
        // Informational: verify runs via the LeastPrivilege agent (non-elevated) and cannot
        // reliably query a SYSTEM-owned task, so this never gates verify (apply errors loudly
        // if registration fails, and the reboot self-heal is exercised in the Phase-8 test).
        rows.push(report::Check::new(
            "self-heal task (info)",
            true,
            match taskscheduler::task_xml(schtasks::SELFHEAL_TASK) {
                Ok(Some(_)) => "registered".to_string(),
                Ok(None) => "not registered".to_string(),
                Err(e) => format!("not queryable (needs elevation?): {e:#}"),
            },
        ));

        // Per user: this account's socket, its folder and file ACLs, and whether its agent
        // answers. `verify` reports on the account that runs it.
        let location = crate::userdir::current_socket_location();
        match crate::acl::Sid::current_user() {
            Ok(user) => {
                rows.push(user_rows::socket_location_row(&location));
                rows.push(user_rows::socket_dir_row(&location, &user));
                rows.push(user_rows::socket_file_row(&location, &user));
                rows.push(user_rows::log_folder_row(&location, &user));
            }
            Err(e) => rows.push(report::Check::new("socket location", false, format!("{e:#}"))),
        }
        rows.push(user_rows::socket_reachable_row(&location));
        rows.push(user_rows::other_users_row());

        // Through the agent: the real parity proof (run in session 1 by verify-probe). Bounded,
        // because the probe child blocks reading the upstream payload before it writes anything,
        // so an agent or session-1 child that wedges yields NO report at all — not even the local
        // rows already gathered above. See `provision::bounded` for why a clock here is the rule's
        // exception rather than a breach of it.
        //
        // Not a claim that this is the only wait that can hang: the `schtasks` queries above are
        // unbounded too, and a wedged Task Scheduler stalls `verify` just as thoroughly. That case
        // is simply not addressed here.
        // A malformed `--probe-timeout` errors rather than quietly applying the default, so the
        // operator who asked to wait indefinitely never silently gets 30s and a wrong diagnosis.
        let probe_timeout = super::bounded::probe_timeout_from_args(&std::env::args().collect::<Vec<_>>())?;
        // The probe runs the exe in the install directory, so an untrusted one never gets that far.
        match layout::run_if_trusted_base(&base, |trusted| {
            drive_probe_bounded(&trusted.layout().canonical_exe(), probe_timeout)
        }) {
            Ok((p, binary_ok)) => {
                // Parity = escaped session 0 (the limited network-logon session). The agent
                // need not be in THE active-console session — a box can have several
                // interactive sessions — and DPAPI/symlink below confirm it is a genuine one.
                rows.push(report::Check::new(
                    "interactive session (via agent)",
                    probe::is_genuine_session(p.session_id, p.logon_type),
                    format!(
                        "session_id={} (active console={}, logon type={})",
                        p.session_id,
                        probe::active_console_session(),
                        p.logon_type.map_or("unknown".to_string(), |t| t.to_string())
                    ),
                ));
                rows.push(report::Check::new("DPAPI (via agent)", p.dpapi_ok, String::new()));
                // Only a confirmed Blocked is a parity failure; Skipped (unprivileged,
                // untestable) does not fail verify.
                rows.push(report::Check::new(
                    "symlink (via agent)",
                    !p.symlink.is_failure(),
                    format!("{:?}", p.symlink),
                ));
                // Byte-transparency on the real path, in BOTH directions. Nothing is routed
                // around the relay any more, so "the relay carries arbitrary bytes unchanged" is
                // what makes scp/sftp work at all rather than a nicety — and the README says so.
                // These rows are what hold that claim honest end to end rather than in prose.
                // They are separate because a one-directional failure must name its direction:
                // client → child is the `scp`/`sftp put` upload, child → client the download.
                // Named for the transfer each direction carries. The previous names differed only
                // by two transposed words ("child to client" / "client to child") and read as
                // near-identical in the one place they appear side by side. (The formatter pads to
                // a MINIMUM width and truncates nothing — a sibling row already runs longer — so
                // length was never the problem; legibility was.)
                rows.push(report::Check::new(
                    "binary download (via agent)",
                    binary_ok,
                    if binary_ok {
                        String::new()
                    } else {
                        "the payload the child sent did not survive the relay byte for byte".into()
                    },
                ));
                // `detail()` distinguishes "the child reported a mismatch" from "the child never
                // reported at all" (an installed exe older than this check). Both FAIL — default-deny — but
                // they have different remedies, and claiming the payload was mangled when nothing
                // ever looked at it would be a diagnosis the code cannot support.
                rows.push(report::Check::new(
                    "binary upload (via agent)",
                    p.upstream.proven(),
                    p.upstream.detail(),
                ));
            }
            Err(e) => {
                rows.push(report::Check::new(
                    "parity probe (via agent)",
                    false,
                    format!("unavailable: {e}"),
                ));
            }
        }

        println!("{}", report::format_report(&rows));
        let code = report::verify_exit_code(&rows);
        if code != 0 {
            std::process::exit(code);
        }
        Ok(())
    }

    /// Drive the probe on a worker thread, giving up after `timeout`.
    ///
    /// The bound is here rather than around the child's stdin read for two reasons. It covers
    /// EVERY way the probe can fail to answer — a lost stdin-EOF marker, an agent that accepts the
    /// connection and then never replies, a child that dies mid-write — where bounding the read
    /// would cover only the first. And bounding a blocking `ReadFile` on a Windows pipe means
    /// overlapped I/O inside the child, where this is a thread and a channel.
    ///
    /// On expiry the error flows into the same `parity probe (via agent)` row that an unreachable
    /// agent produces, so `verify` still prints every local check and exits non-zero — instead of
    /// hanging with nothing on stdout, which is what it did before.
    fn drive_probe_bounded(
        exe: &Path,
        timeout: Option<std::time::Duration>,
    ) -> anyhow::Result<(probe::ProbeResult, bool)> {
        let (tx, rx) = std::sync::mpsc::channel();
        let exe = exe.to_path_buf();
        // The worker owns the whole relay conversation; on expiry it is left blocked on a socket
        // that is not delivering, and `verify` exits immediately after printing, which collects it.
        std::thread::spawn(move || {
            let _ = tx.send(drive_probe(&exe));
        });
        super::bounded::await_bounded(&rx, timeout)?
    }

    /// Drive `<exe> verify-probe` as an EXEC command THROUGH the agent (so it runs in session 1),
    /// parse the PROBE line it prints, and check whether its binary payload survived intact.
    ///
    /// The byte check reads the RAW stdout, before the lossy UTF-8 conversion the line parse
    /// needs: the payload is deliberately not valid UTF-8, so converting first would destroy the
    /// very property being measured. This is the end-to-end half of byte-transparency — a real
    /// child, real pipes, a real socket — which the in-memory relay tests cannot reach.
    fn drive_probe(exe: &Path) -> anyhow::Result<(probe::ProbeResult, bool)> {
        let sock = afunix::connect(&crate::userdir::current_socket_location()?.path).context("connect to agent")?;
        let (rx, tx) = afunix::split(sock)?;
        let cmd = format!("\"{}\" verify-probe", exe.display());
        let hs = shim::make_handshake(&Some(cmd), "xterm".into(), 80, 24);
        let mut out = Vec::new();
        let mut err = Vec::new();
        // Feed the SAME payload upstream that the child echoes downstream. Passing `io::empty()`
        // here left the client → child direction — the `sftp put` / `scp` upload direction —
        // completely unchecked, while the docs claimed `verify` covered both.
        let upstream = std::io::Cursor::new(probe::binary_probe_payload());
        let code = shim::run_exec_on(rx, tx, &hs, &mut out, &mut err, upstream)?;
        anyhow::ensure!(
            code != 254 && code != 255,
            "probe relay failed (code {code}; stderr={})",
            String::from_utf8_lossy(&err).trim()
        );
        let binary_ok = probe::binary_probe_ok(&out);
        let parsed = probe::parse_probe_line(&String::from_utf8_lossy(&out))?;
        Ok((parsed, binary_ok))
    }

    // ── verify-probe (runs in session 1, spawned by the agent) ───────────────────────

    pub fn verify_probe() -> anyhow::Result<()> {
        let sid = probe::current_session_id();
        let logon_type = probe::current_logon_type();
        let dpapi = probe::dpapi_roundtrip(b"ssh-broker-parity-probe");
        let symlink = probe::symlink_probe();
        // Read the UPSTREAM payload first. This direction — client → child — is the one an
        // `sftp put` / `scp` upload rides. The two directions are measured INDEPENDENTLY: the
        // downstream payload emitted below is a fixed write that carries nothing back about what
        // arrived here, so a corrupted upload surfaces ONLY as `upstream=fail` and never as a
        // downstream mismatch. The comparison itself lives in `probe::upstream_payload_ok` so it
        // is host-testable — this function is `cfg(windows)` and has no test module, so a
        // comparison written inline here could be mutated to `true` with the suite still green.
        let upstream_ok = match probe::upstream_payload_ok(&mut std::io::stdin()) {
            Ok(ok) => ok,
            Err(e) => {
                // Default-deny, but SAY WHY. Dropping this error with `.ok()` left a read failure
                // and a mangled payload reporting the identical `upstream=fail`, which
                // misdiagnoses a transport fault as a transparency fault. stderr is safe here:
                // the relay keeps it separate from the stdout the parent parses.
                eprintln!("ssh-broker: reading the upstream probe payload failed: {e}");
                false
            }
        };
        // One locked handle for both writes: `println!` would take its own lock, and the binary
        // payload must not interleave with the line that follows it.
        {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            probe::emit_binary_probe(&mut stdout).context("emit the binary-transparency payload")?;
            writeln!(
                stdout,
                "{}",
                probe::format_probe_line(sid, dpapi, symlink, upstream_ok, logon_type)
            )
            .context("write the PROBE line")?;
            stdout.flush().context("flush probe output")?;
        }
        // Parity gates: escaped session 0 AND a working DPAPI (proves a real user profile, the
        // thing session 0 lacks). A CONFIRMED symlink block also fails; a Skipped (unprivileged,
        // untestable) symlink does not. The active-console id is NOT required to match — a host
        // can have several interactive sessions; any non-0 one with DPAPI is parity.
        //
        // `upstream_ok` is deliberately NOT a gate here: it measures the RELAY, not the session,
        // and this child is the wrong place to judge it — exiting non-zero would report a
        // transport fault as a parity failure, and the parent could not tell the two apart. It
        // rides up in the PROBE line instead, where `verify` gates it as a row of its own.
        let pass = probe::is_genuine_session(sid, logon_type) && dpapi && !symlink.is_failure();
        if !pass {
            std::process::exit(1);
        }
        Ok(())
    }
}
