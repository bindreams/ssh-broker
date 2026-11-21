//! provision: self-install (`install`) and self-check (`doctor`) — the DefaultShell values, the
//! agent logon task (one agent per logged-on user), and parity probes (DPAPI/symlink/session) run
//! THROUGH the invoking user's agent.
//!
//! The pure, host-tested logic lives in the submodules (registry/schtasks/probe/report); this root
//! holds the Windows orchestration. `install` is ordered so a partial run never bricks SSH (the
//! DefaultShell registry flip is LAST, after the exe is proven present). It knows no user: each
//! agent makes and hardens its own socket directory in its own profile.

pub mod bounded;
#[cfg(windows)]
mod flow;
#[cfg(windows)]
pub mod handover;
#[cfg(windows)]
pub(crate) mod install_lock;
#[cfg(windows)]
pub(crate) mod layout;
#[cfg(windows)]
pub mod password_variant;
pub mod path_env;
pub mod probe;
#[cfg(windows)]
mod probe_run;
#[cfg(windows)]
pub mod procwait;
pub mod registry;
pub mod report;
pub mod schtasks;
#[cfg(windows)]
pub(crate) mod session_rows;
pub mod session_task;
#[cfg(windows)]
pub mod sessions;
pub mod sshd_config;
pub mod sshd_task;
#[cfg(windows)]
pub(crate) mod system_config;
#[cfg(windows)]
pub mod taskscheduler;
#[cfg(windows)]
pub(crate) mod user_rows;

/// `install` subcommand: idempotently assert all desired state. Windows-only.
pub fn install() -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::install();
    #[cfg(not(windows))]
    anyhow::bail!("install provisions a Windows host and runs only on Windows");
}

/// `install-sshd`: the hidden verb of the task `install` hands its sshd step to, which runs as SYSTEM: the step,
/// with each line it says written to the report that `install` prints. Never invoked directly by users.
pub fn install_sshd() -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::install_sshd();
    #[cfg(not(windows))]
    anyhow::bail!("install-sshd runs only on Windows");
}

/// `doctor` subcommand: local state checks + parity probes through the agent. Windows-only.
pub fn doctor() -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::doctor();
    #[cfg(not(windows))]
    anyhow::bail!("doctor runs only on Windows");
}

/// `doctor-probe`: the hidden child the agent spawns in session 1. Prints one PROBE line and
/// exits 0 (parity) / 1 (not). Never invoked directly by users.
pub fn doctor_probe(link: crate::route::ProbeLink) -> anyhow::Result<()> {
    #[cfg(windows)]
    return imp::doctor_probe(link);
    #[cfg(not(windows))]
    {
        let _ = link;
        anyhow::bail!("doctor-probe runs only on Windows");
    }
}

/// Check the arguments after `install`.
///
/// `install` takes none.
pub fn check_install_args(args: &[String]) -> anyhow::Result<()> {
    match args.first() {
        Some(arg) => anyhow::bail!("install takes no arguments, got {arg:?}"),
        None => Ok(()),
    }
}

/// The `doctor` row for the shell configuration: it passes when the configured (or built-in) shell is
/// in use, and fails when a fallback is, naming the file and the value.
pub fn shell_config_row(effective: &anyhow::Result<crate::shell::Effective>) -> report::Check {
    match effective {
        Ok(effective) => match &effective.problem {
            None => report::Check::new(
                "shell config",
                true,
                format!(
                    "{} ({})",
                    effective.program.display(),
                    match &effective.why.start {
                        crate::shell::Source::User(file) => format!("user: {}", file.display()),
                        crate::shell::Source::System(file) => format!("system: {}", file.display()),
                        _ => "built-in".to_string(),
                    }
                ),
            ),
            Some(problem) => report::Check::new("shell config", false, problem.describe()),
        },
        Err(e) => report::Check::new("shell config", false, format!("{e:#}")),
    }
}

/// The handshake `doctor` sends to run its probe through the agent: ssh-broker's own command, run as
/// it stands and not through the user's shell. `elevation` is what the probe asks the agent for, and
/// `link` what it does about the junction of the link row.
pub fn probe_handshake(
    exe: &std::path::Path,
    elevation: crate::protocol::ElevationPolicy,
    link: &crate::route::ProbeLink,
) -> crate::protocol::Handshake {
    use crate::route::ProbeLink;
    let command = format!("\"{}\" doctor-probe", exe.display());
    let command = match link {
        ProbeLink::NoJunction => command,
        ProbeLink::Make(dir) => format!("{command} --make-junction \"{dir}\""),
        ProbeLink::Follow(dir) => format!("{command} --follow \"{dir}\""),
    };
    crate::shim::make_handshake(
        &Some(command),
        false,
        crate::protocol::Launch::Direct,
        "xterm".into(),
        80,
        24,
        Some(elevation),
    )
}

/// This build's version. The one place it is read: every line that names it takes it from here.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The last line of an `install` that worked, and nothing follows it.
pub fn installed_line(version: &str) -> String {
    format!("ssh-broker v{version} has been installed!")
}

/// The directory `install` installs into. The one place the path is written; [`layout::Layout`]
/// derives from it.
pub const BASE_DIR: &str = r"C:\ProgramData\ssh-broker";

/// The installed exe's file name.
pub const EXE_NAME: &str = "ssh-broker.exe";

/// Whether sshd, given `shell` as the `DefaultShell`, runs ssh-broker's own exe: it compares the file
/// name as sshd's `CreateProcess` resolves it (`.exe` is appended to a name with no extension), so
/// `...\ssh-broker` is ssh-broker too. The one place `install` asks this.
pub fn is_ssh_broker(shell: &str) -> bool {
    crate::shell::program_file_name(shell).eq_ignore_ascii_case(EXE_NAME)
}

/// The path `install` installs the shim to and registers as `DefaultShell`.
pub fn canonical_exe() -> std::path::PathBuf {
    std::path::Path::new(BASE_DIR).join(EXE_NAME)
}

#[cfg(test)]
#[path = "provision_tests.rs"]
mod provision_tests;

#[cfg(windows)]
mod imp {
    use super::handover::{
        Handover, Say, Stream, hand_over, remove_arguments, replace_shell, say_to_console, show_to_console,
    };
    use super::layout::{self, Layout};
    use super::registry::SshdShell;
    use super::{
        flow, install_lock, path_env, probe, probe_run, procwait, registry, report, schtasks, session_rows,
        session_task, sessions, sshd_config, sshd_task, system_config, taskscheduler, user_rows,
    };
    use anyhow::Context;
    use std::path::{Path, PathBuf};

    /// Case-insensitive compare of a registry path string (quotes trimmed) to a path.
    fn eq_path(a: &str, b: &Path) -> bool {
        a.trim().trim_matches('"').eq_ignore_ascii_case(&b.to_string_lossy())
    }

    pub fn install() -> anyhow::Result<()> {
        let layout = Layout::production();

        // 0. `install` takes no arguments.
        let args: Vec<String> = std::env::args().skip(2).collect();
        super::check_install_args(&args)?;

        // 1. Install this exe to a STABLE path (see layout::prepare). Everything registers the
        //    canonical path: a temp path would brick SSH the instant it is deleted; the shim's
        //    fail-open can't help if sshd execs a missing binary. The install directory is gated
        //    first, so a planted one is never adopted. A different build over an installed one stops
        //    every agent first (they hold the exe open) and waits for them to exit, with the logon
        //    task and the auto-login tasks disabled so that nothing starts one from the old exe
        //    meanwhile. Every run from here that returns (one that a strict notice ends does not)
        //    ends by enabling those tasks and starting the auto-login ones that have no session
        //    (see `flow::repair_sessions`), which also heals what an earlier, killed `install` left;
        //    the agents start again afterwards, even if a later step fails, except in a session
        //    whose old agent has not exited.
        let current = std::env::current_exe().context("current_exe")?;
        // Every step line, warning and the last line goes through `flow::install_run`'s sink, which writes to the
        // console and ignores a stream that has closed (an `install` over an SSH connection that has gone), and the
        // last line comes after the sshd step. The two notices that are the only record of a value about to be
        // replaced or removed do not: they are written strictly (`show_to_console`), so that a write that fails ends
        // `install` before the value is touched.
        flow::install_run(
            &mut say_to_console,
            super::version(),
            |say| {
                // The install directory first: the lock file lives in it, and nothing is read from it or
                // written into it before it is proved ours. One `install` runs at a time, for its whole run,
                // and no `auto-login on|off` runs during it: a second `install` waits here, so it never stops
                // or starts what the first is working on. The lock is held to the end of `install_run`.
                let base = layout::ensure_base(&layout)?;
                let install_lock = flow::wait_for_lock(say, |waiting| {
                    install_lock::acquire(&layout.install_lock_path(), waiting)
                })?;
                // An earlier `install`'s sshd step is the rest of its run, and outlives its process: it is waited
                // for before this run touches anything.
                flow::wait_for_earlier_sshd_step(say, |waiting| {
                    taskscheduler::wait_for_instances(
                        schtasks::INSTALL_SSHD_TASK,
                        &layout.canonical_exe(),
                        procwait::Role::InstallSshd,
                        waiting,
                    )
                })?;
                let exe = flow::run(
                    say,
                    || {
                        taskscheduler::stop_instances(schtasks::AGENT_TASK, &layout.canonical_exe())?;
                        stop_background_sessions(&layout.canonical_exe())
                    },
                    |stop_agents, say| {
                        let exe = layout::prepare_in(&base, &current, say, stop_agents)?;

                        // 2. Register the agent task (idempotent /F).
                        register_agent_task(&layout, &exe)?;

                        // 3. Carry the previous sshd shell into the system config, while the registry still
                        //    holds it. Then write the escape flag and read it back at once, then flip the
                        //    DefaultShell pair LAST and only to the validated canonical path; read that back
                        //    too. sshd reads these once per session, so the shim cannot ask later which form
                        //    sshd used: `install` owns the flag (see `registry::desired_values`). A shell that
                        //    cannot be read in full stops `install` here, before any of it is written.
                        replace_shell(
                            || registry::read_sshd_shell_under(registry::OPENSSH_KEY),
                            |previous| carry_previous_shell(&base, previous, say),
                            |handover| {
                                registry::set_default_shell_under(registry::OPENSSH_KEY, &exe.to_string_lossy(), handover)
                                    .context("write DefaultShellEscapeArguments, DefaultShellCommandOption, DefaultShell (in that order)")
                            },
                        )?;
                        let (shell, opt) = registry::read_default_shell_under(registry::OPENSSH_KEY)?;
                        anyhow::ensure!(
                            eq_path(&shell, &exe) && opt == "-c",
                            "DefaultShell read-back mismatch (shell={shell:?}, opt={opt:?})"
                        );
                        remove_shell_arguments(&base.layout().system_config_path(), say);

                        // 4. The install directory on the system PATH, before any agent starts: an agent's
                        //    environment is fixed when it starts, and its sessions inherit it.
                        add_install_dir_to_path(say);
                        Ok(exe)
                    },
                    enable_agent_task,
                    repair_session_tasks,
                    start_agents,
                )?;
                Ok((exe, install_lock))
            },
            // 5. sshd accepts SSH_BROKER_ELEVATION. LAST: an sshd that has not read the change is
            //    restarted, and `install` run over SSH restarts the sshd that carries its own connection, so
            //    the step is the installed exe's task, which finishes even if this `install` is ended. It
            //    never fails `install`: the variable is a convenience, and `ssh-broker elevate` works
            //    without it.
            |(exe, _install_lock), say| sshd_task::hand_over_sshd_step(&layout, exe, say),
        )
    }

    /// `install-sshd`: see [`super::install_sshd`]. The step never fails; what fails is the report.
    pub fn install_sshd() -> anyhow::Result<()> {
        let report = Layout::production().install_sshd_report_path();
        sshd_task::write_report(&report, |say| {
            sshd_config::machine::configure_this_machine(say);
        })
    }

    /// Append the install directory to the machine's `PATH`, so that a session finds `ssh-broker` by name.
    /// The value keeps its registry type; see [`flow::add_install_dir_to_path`].
    fn add_install_dir_to_path(say: &mut Say<'_>) {
        flow::add_install_dir_to_path(
            say,
            super::BASE_DIR,
            &registry::read_system_path(),
            |text| {
                registry::expand_environment(text)
                    .map(|expanded| expanded.encode_utf16().count())
                    .map_err(|e| format!("{e:#}"))
            },
            registry::write_system_path,
            registry::broadcast_environment_change,
        );
    }

    /// Write the system config from the shell sshd runs now, if it is not ssh-broker and there is no
    /// config yet (see [`system_config`]). Must run before the registry is overwritten. The install is
    /// complete without the config, so a config that is not written does not fail `install`; the
    /// [`Handover`] it returns is what the flip takes. What `hand_over` prints then is the only record of the
    /// previous values: it is written strictly ([`show_to_console`]), and a write that fails ends `install`
    /// before the flip. `previous` is what the registry holds now.
    fn carry_previous_shell(base: &layout::TrustedBase<'_>, previous: &SshdShell, say: &mut Say<'_>) -> Handover {
        let config = base.layout().system_config_path();
        let config_is_file = system_config::config_is_file(&config);
        let host = crate::shell::WindowsHost;
        // The decision is made first, and the lookups it runs say what they cannot find out as they run. `decide`
        // takes them as `Fn`s, so the sink is shared through a cell, which ends with the block: nothing after the
        // decision holds the sink.
        let decision = {
            let say = std::cell::RefCell::new(&mut *say);
            // The file the shell resolves to, found as sshd finds it (a bare name is searched in sshd's own
            // directory, the system and Windows directories, then on `PATH`), so the identity check below
            // looks at that file and not at one of that name beside `install`. Looked up only when the
            // decision needs it, so that what cannot be read is not reported when it does not matter.
            let search = || {
                let image = registry::read_sshd_image_path().unwrap_or_else(|e| {
                    (say.borrow_mut())(Stream::Err, &system_config::sshd_location_unreadable(&format!("{e:#}")));
                    None
                });
                system_config::sshd_search_dirs(&host, image.as_deref())
                    .map_err(|e| format!("cannot find the system directory to look for the shell in: {e:#}"))
            };
            let find =
                |dirs: &[PathBuf], path: &Path| crate::shell::resolve_program_in(&host, dirs, &path.to_string_lossy());
            let is_system_cmd = |found: &Path| {
                use crate::shell::Host;
                host.is_system_cmd(found).unwrap_or_else(|e| {
                    (say.borrow_mut())(Stream::Err, &system_config::system_cmd_unknown(found, &e.to_string()));
                    false
                })
            };
            system_config::decide(previous, config_is_file, &search, &find, &is_system_cmd)
        };
        hand_over(
            &config,
            previous,
            decision,
            |block| system_config::create_once(base, block),
            &mut show_to_console,
        )
    }

    /// Remove `DefaultShellArguments` once `DefaultShell` is ssh-broker and `config` is a file: sshd would
    /// hand the arguments to ssh-broker ahead of `-c`, and the config is where they were carried (by the
    /// `install` that replaced the shell) or are not wanted. A value that cannot be read, or with no file known
    /// to hold it, is the only copy of the old setup: it is left, and said, for the next `install` (see
    /// [`system_config::plan_arguments`]). A removal prints the value before it deletes it
    /// ([`remove_arguments`]; the print is strict, see [`show_to_console`]), and a failed removal says so with the
    /// cause and `install` goes on.
    fn remove_shell_arguments(config: &Path, say: &mut Say<'_>) {
        let key = registry::OPENSSH_KEY;
        // Read on its own: another value that cannot be read does not make this one unreadable.
        let read = registry::read_shell_arguments_under(key).map_err(|e| format!("{e:#}"));
        remove_arguments(
            config,
            key,
            read,
            || system_config::config_is_file(config),
            |shown| registry::remove_shell_arguments_under(key, shown),
            say,
            &mut show_to_console,
        );
    }

    /// The background sessions' part of the stop that precedes replacing the exe: the auto-login
    /// tasks are disabled and their instances stopped, then every background agent left (the
    /// prompt path starts one without a task) is ended. A shim is never ended: it holds the exe only until
    /// its SSH session closes, and the copy reports it if it still does.
    fn stop_background_sessions(image: &Path) -> anyhow::Result<()> {
        flow::stop_sessions(
            taskscheduler::session_tasks,
            |name| taskscheduler::set_enabled(name, false),
            |name| taskscheduler::stop_instances(name, image),
            || procwait::background_agents(image),
            |agent| agent.terminate(),
            |agents| procwait::wait_all_exited(&agents, procwait::EXIT_BOUND),
        )
        .context("stop the background sessions")
    }

    /// Enable the agent task: undo the stop's disabling of it, and heal a task that an earlier
    /// `install` left disabled by being killed. Registering the task afresh enables it too, but a
    /// failed `install` may not have got that far.
    fn enable_agent_task() -> anyhow::Result<()> {
        taskscheduler::set_enabled(schtasks::AGENT_TASK, true).with_context(|| {
            format!(
                "could not enable the {} task again; no agent starts at a logon until it is",
                schtasks::AGENT_TASK
            )
        })
    }

    /// Enable every auto-login task that is disabled and start each one that has no session: undoes
    /// the stop's disabling, and repairs what an `install` that was killed (or a task disabled by hand)
    /// left. See [`flow::repair_sessions`].
    fn repair_session_tasks(say: &mut Say<'_>) -> anyhow::Result<()> {
        flow::repair_sessions(
            say,
            taskscheduler::session_tasks,
            |name| taskscheduler::set_enabled(name, true),
            taskscheduler::has_running_instance,
            taskscheduler::run_task,
        )
    }

    /// Step 4 of `install`: see [`flow::start_agents`].
    fn start_agents(survivors: &[procwait::Survivor], say: &mut Say<'_>) {
        flow::start_agents(
            say,
            sessions::interactive_sessions,
            |id| taskscheduler::run_in_session(schtasks::AGENT_TASK, id),
            survivors,
        );
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

    /// Decode schtasks output, handling the UTF-16LE it can emit to a redirected pipe (BOM, or
    /// pervasive NUL bytes). Otherwise treat it as UTF-8/ASCII. The markers doctor scans for
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

    // ── doctor ─────────────────────────────────────────────────────────────────────

    pub fn doctor() -> anyhow::Result<()> {
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

        // Local: the shell sessions start. A fallback to the built-in cmd.exe is a failure here: the
        // user's config says something that is not true.
        let effective = crate::shell::effective(&crate::shell::WindowsHost);
        rows.push(super::shell_config_row(&effective));

        // Local: the install directory is exactly the hardened one (only SYSTEM and Administrators
        // can write to it).
        let base = layout::check_base(&layout);
        rows.push(layout::install_dir_row(&base));

        // Local: the install directory is on the system PATH, so a session finds `ssh-broker` by name.
        rows.push(path_env::row(&registry::read_system_path(), super::BASE_DIR));

        // Local: sshd accepts SSH_BROKER_ELEVATION from clients, and has read the files that say so. `sshd -T`
        // reads sshd's host keys, so the row is judged only by an administrator's elevated `doctor` (see
        // `sshd_config::accepts_row`).
        let elevation = crate::account::elevation();
        rows.push(sshd_config::accepts_row(
            &elevation,
            sshd_config::machine::sshd_reading_this_machine,
        ));

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

        // Per user: this account's socket, its folder and file ACLs, and whether its agent
        // answers. `doctor` reports on the account that runs it.
        let location = crate::userdir::current_socket_location();
        let account_rows = user_rows::account_rows(&elevation);
        let filtered = matches!(account_rows, user_rows::AccountRows::Filtered);
        match (crate::acl::Sid::current_user(), account_rows) {
            (Ok(_), user_rows::AccountRows::Filtered) => {
                rows.push(user_rows::socket_location_row(&location));
                rows.push(user_rows::filtered_row());
            }
            (Ok(user), account_rows) => {
                if let user_rows::AccountRows::AgentAfter(unreadable) = account_rows {
                    rows.push(unreadable);
                }
                rows.push(user_rows::socket_location_row(&location));
                rows.push(user_rows::socket_dir_row(&location, &user));
                rows.push(user_rows::socket_file_row(&location, &user));
                rows.push(user_rows::log_folder_row(&location, &user));
                rows.push(user_rows::socket_reachable_row(&location, &user));
            }
            (Err(e), _) => {
                rows.push(report::Check::new("socket location", false, format!("{e:#}")));
                rows.push(report::Check::new("socket reachable", false, format!("{e:#}")));
            }
        }
        rows.push(user_rows::other_users_row());

        // Through the agent: the real parity proof (run in session 1 by doctor-probe). Bounded,
        // because the probe child blocks reading the upstream payload before it writes anything,
        // so an agent or session-1 child that wedges yields NO report at all — not even the local
        // rows already gathered above. See `provision::bounded` for why a clock here is the rule's
        // exception rather than a breach of it.
        //
        // Not a claim that this is the only wait that can hang: the `schtasks` queries above are
        // unbounded too, and a wedged Task Scheduler stalls `doctor` just as thoroughly. That case
        // is simply not addressed here.
        // A malformed `--probe-timeout` errors rather than quietly applying the default, so the
        // operator who asked to wait indefinitely never silently gets 30s and a wrong diagnosis.
        let probe_timeout = super::bounded::probe_timeout_from_args(&std::env::args().collect::<Vec<_>>())?;
        // An administrator's unelevated prompt cannot connect to the agent's own socket, and the row above names
        // the ways to check; a probe would only add a raw "connect to agent" failure beside that, so none is run.
        if !filtered {
            // The probe runs the exe in the install directory, so an untrusted one never gets that far.
            match layout::run_if_trusted_base(&base, |trusted| {
                probe_run::run(&trusted.layout().canonical_exe(), probe_timeout)
            }) {
                Ok(probes) => rows.extend(session_rows::parity_rows(&probes, probe::active_console_session())),
                Err(e) => rows.push(report::Check::new(
                    "parity probe (via agent)",
                    false,
                    format!("unavailable: {e:#}"),
                )),
            }
        }

        println!(
            "{}",
            report::format_report(super::version(), std::env::current_exe().ok().as_deref(), &rows)
        );
        if let Ok(effective) = &effective {
            println!("\n{}", crate::shell::render(effective));
        }
        let code = report::doctor_exit_code(&rows);
        if code != 0 {
            std::process::exit(code);
        }
        Ok(())
    }

    // ── doctor-probe (runs in session 1, spawned by the agent) ───────────────────────

    pub fn doctor_probe(link: crate::route::ProbeLink) -> anyhow::Result<()> {
        let sid = probe::current_session_id();
        let logon_type = probe::current_logon_type();
        let dpapi = probe::dpapi_roundtrip(b"ssh-broker-parity-probe");
        let symlink = probe::link::run(&link);
        let (elevation, integrity) = probe::current_token_facts();
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
            let result = probe::ProbeResult {
                session_id: sid,
                dpapi_ok: dpapi,
                symlink,
                upstream: if upstream_ok {
                    probe::UpstreamState::Ok
                } else {
                    probe::UpstreamState::Fail
                },
                logon_type,
                elevation,
                integrity,
            };
            writeln!(stdout, "{}", probe::format_probe_line(&result)).context("write the PROBE line")?;
            stdout.flush().context("flush probe output")?;
        }
        // Parity gates: escaped session 0 AND a working DPAPI (proves a real user profile, the
        // thing session 0 lacks). A junction that was not followed also fails. The active-console id is NOT required to match — a host
        // can have several interactive sessions; any non-0 one with DPAPI is parity.
        //
        // `upstream_ok` is deliberately NOT a gate here: it measures the RELAY, not the session,
        // and this child is the wrong place to judge it — exiting non-zero would report a
        // transport fault as a parity failure, and the parent could not tell the two apart. It
        // rides up in the PROBE line instead, where `doctor` gates it as a row of its own.
        let pass = probe::is_genuine_session(sid, logon_type)
            && dpapi
            && !symlink.is_some_and(probe::SymlinkState::is_failure);
        if !pass {
            std::process::exit(1);
        }
        Ok(())
    }
}
