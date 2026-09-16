//! provision: self-install (`apply`) and self-check (`verify`) — DefaultShell pair, the
//! session-1 agent logon task, the ONSTART self-heal task, the socket dir + ACL, and parity
//! probes (DPAPI/symlink/session) run THROUGH the agent.
//!
//! The pure, host-tested logic lives in the submodules (config/registry/schtasks/probe/report);
//! this root holds the Windows orchestration. `apply` is ordered so a partial run never bricks
//! SSH (the DefaultShell registry flip is LAST, after the socket dir is bindable and the exe is
//! proven present), and resolves the ACL grantee BY NAME so a SYSTEM-run self-heal grants the
//! same account the agent binds as.

pub mod config;
pub mod probe;
pub mod registry;
pub mod report;
pub mod schtasks;
pub mod sshd;

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

/// The install root. Single authority for the path so the shim, the socket dir and the logger
/// cannot drift apart — each previously carried its own copy of this literal.
pub fn base_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\ssh-broker")
}

/// Where `apply` persists the install config. Public because the SHIM reads it: routing a
/// transfer means matching sshd's declarations, which `apply` recorded here.
pub fn config_path() -> std::path::PathBuf {
    base_dir().join("config.toml")
}

#[cfg(windows)]
mod imp {
    use super::{base_dir, config, config_path, probe, registry, report, schtasks, sshd};
    use crate::{acl, afunix, shim};
    use anyhow::Context;
    use std::path::{Path, PathBuf};
    fn canonical_exe() -> PathBuf {
        base_dir().join("ssh-broker.exe")
    }

    /// The interactive user running `apply` (lowest-precedence fallback). Returns None for a
    /// service identity — `apply` may run as SYSTEM (the ONSTART self-heal), and the agent's
    /// ACL grantee must be the real auto-login user, NEVER SYSTEM (which would brick the bind
    /// gate). When this yields None under SYSTEM with no `--user`/config, resolution fails loudly.
    fn current_user_name() -> Option<String> {
        let name = std::env::var("USERNAME").ok()?;
        let upper = name.to_ascii_uppercase();
        if name.is_empty()
            || upper == "SYSTEM"
            || upper.ends_with('$') // machine account, e.g. MACHINE$
            || upper == "LOCAL SERVICE"
            || upper == "NETWORK SERVICE"
        {
            return None;
        }
        Some(name)
    }

    /// `--user <name>` from argv (baked into the SYSTEM ONSTART self-heal task's command).
    fn arg_user() -> Option<String> {
        let args: Vec<String> = std::env::args().collect();
        args.iter()
            .position(|a| a == "--user")
            .and_then(|i| args.get(i + 1))
            .filter(|s| !s.is_empty())
            .cloned()
    }

    /// Case-insensitive compare of a registry path string (quotes trimmed) to a path.
    fn eq_path(a: &str, b: &Path) -> bool {
        a.trim().trim_matches('"').eq_ignore_ascii_case(&b.to_string_lossy())
    }

    pub fn apply() -> anyhow::Result<()> {
        // 0. Install this exe to a STABLE path; everything registers the canonical path (a temp
        //    path would brick SSH the instant it is deleted — the shim's fail-open can't help if
        //    sshd execs a missing binary).
        let exe = install_self()?;

        // 1. Resolve the target account BY NAME (CLI --user > saved config > interactive user),
        //    failing loudly rather than ever guessing from a SYSTEM token.
        let saved = std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| config::Config::from_toml(&s).ok())
            .map(|c| c.target_user);
        let user =
            config::resolve_target_user(arg_user().as_deref(), saved.as_deref(), current_user_name().as_deref())?;
        let sid = acl::Sid::lookup(&user).with_context(|| format!("resolving SID for {user:?}"))?;

        // 2. Create + harden the socket dir (the agent's bind precondition) — fail-closed.
        let sdir = afunix::socket_dir();
        std::fs::create_dir_all(&sdir).context("create socket dir")?;
        std::fs::create_dir_all(base_dir().join("logs")).context("create logs dir")?;
        acl::harden_dir(&sdir, &sid).context("harden socket dir")?;
        anyhow::ensure!(
            acl::verify_dir_acl(&sdir, &sid).unwrap_or(false),
            "socket dir ACL did not verify after harden"
        );

        // 3. Persist config (records the account for the SYSTEM self-heal).
        let declared = read_declared_subsystems()?;
        write_config(&user, &declared)?;

        // 4. Register both tasks (idempotent /F).
        register_agent_task(&exe, &user)?;
        register_selfheal_task(&exe, &user)?;

        // 5. Flip the DefaultShell pair LAST and only to the validated canonical path; read back.
        registry::set_default_shell_under(registry::OPENSSH_KEY, &exe.to_string_lossy())
            .context("write DefaultShell pair")?;
        let (shell, opt) = registry::read_default_shell_under(registry::OPENSSH_KEY)?;
        anyhow::ensure!(
            eq_path(&shell, &exe) && opt == "-c",
            "DefaultShell read-back mismatch (shell={shell:?}, opt={opt:?})"
        );

        // 6. Start the agent now so no re-login is needed (the logon trigger covers the rest).
        if probe::active_console_session() != 0xFFFF_FFFF
            && let Err(e) = run_schtasks(&schtasks::run_task_argv(schtasks::AGENT_TASK))
        {
            eprintln!("apply: agent task registered but immediate start failed: {e}");
        }
        println!(
            "apply: ok — DefaultShell -> {}, agent + self-heal tasks installed for {user}",
            exe.display()
        );
        Ok(())
    }

    fn install_self() -> anyhow::Result<PathBuf> {
        let current = std::env::current_exe().context("current_exe")?;
        let canonical = canonical_exe();
        if current != canonical && !files_identical(&current, &canonical) {
            std::fs::create_dir_all(base_dir()).context("create base dir")?;
            if let Err(e) = std::fs::copy(&current, &canonical) {
                // A running agent holds the canonical exe open (sharing violation). Don't abort
                // the whole idempotent re-apply: if a canonical exe already exists, keep it and
                // repair the rest of the state (installing a NEW build needs the agent stopped).
                anyhow::ensure!(
                    canonical.is_file(),
                    "copy self to {} failed and no canonical exe exists: {e}",
                    canonical.display()
                );
                eprintln!(
                    "apply: could not update {} ({e}); using the existing exe \
                     — stop the agent to update the binary",
                    canonical.display()
                );
            }
        }
        anyhow::ensure!(canonical.is_file(), "canonical exe missing after install");
        Ok(canonical)
    }

    fn files_identical(a: &Path, b: &Path) -> bool {
        matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
    }

    /// Ask sshd for its own effective configuration and extract the `Subsystem` declarations.
    ///
    /// `sshd -T` prints the RESOLVED config: `dump_config` emits `subsystem <name> <args>`, where
    /// `<args>` is `subsystem_args` — the exact string sshd hands the login shell, i.e. the shim.
    /// Asking sshd avoids re-deriving it from `sshd_config`, which would mean reimplementing
    /// `argv_split` and `argv_assemble` and keeping both in step with upstream forever.
    ///
    /// Fails loudly rather than recording nothing. An empty list means "match nothing", so a
    /// half-provisioned install would look healthy while the matching this exists for never fired.
    fn read_declared_subsystems() -> anyhow::Result<Vec<sshd::Subsystem>> {
        // Normally on PATH via the OpenSSH feature, but PATH is not guaranteed for a SYSTEM-run
        // apply, so fall back to the canonical install location before giving up.
        const FALLBACK: &str = r"C:\Windows\System32\OpenSSH\sshd.exe";
        let mut last: Option<String> = None;
        for exe in ["sshd", FALLBACK] {
            match std::process::Command::new(exe).arg("-T").output() {
                Ok(out) if out.status.success() => return Ok(sshd::parse_subsystems(&decode_output(&out.stdout))),
                Ok(out) => last = Some(format!("`{exe} -T` failed: {}", decode_output(&out.stderr).trim())),
                Err(e) => last = Some(format!("could not run `{exe}`: {e}")),
            }
        }
        anyhow::bail!(
            "could not read sshd's effective configuration ({}); the shim routes transfers by \
             matching sshd's own Subsystem declarations, so provisioning cannot proceed without it",
            last.unwrap_or_else(|| "no attempt was made".into())
        )
    }

    fn write_config(user: &str, declared: &[sshd::Subsystem]) -> anyhow::Result<()> {
        let toml = config::Config {
            target_user: user.to_string(),
            declared_subsystems: declared.to_vec(),
        }
        .to_toml()?;
        // Direct overwrite: config.toml is read only by apply/verify, never concurrently with
        // this write, so atomicity buys nothing — and a plain write is reliably idempotent on
        // every re-apply (a temp+rename adds a Windows replace-semantics footgun for no gain).
        std::fs::write(config_path(), toml).context("write config")?;
        Ok(())
    }

    fn register_agent_task(exe: &Path, user: &str) -> anyhow::Result<()> {
        let xml = schtasks::agent_task_xml(&exe.to_string_lossy(), user);
        let xml_path = base_dir().join("agent-task.xml");
        // schtasks /XML requires a UTF-16 file (a UTF-8 one is rejected).
        std::fs::write(&xml_path, schtasks::xml_file_bytes(&xml)).context("write agent task xml")?;
        run_schtasks(&schtasks::create_from_xml_argv(
            schtasks::AGENT_TASK,
            &xml_path.to_string_lossy(),
        ))
        .context("register agent task")?;
        Ok(())
    }

    fn register_selfheal_task(exe: &Path, user: &str) -> anyhow::Result<()> {
        run_schtasks(&schtasks::selfheal_task_argv(&exe.to_string_lossy(), user)).context("register self-heal task")?;
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

    /// Run `schtasks` capturing (stdout, success) without erroring (for verify's queries).
    fn query_schtasks(args: &[String]) -> (String, bool) {
        match std::process::Command::new("schtasks").args(args).output() {
            Ok(o) => (decode_output(&o.stdout), o.status.success()),
            Err(_) => (String::new(), false),
        }
    }

    // ── verify ─────────────────────────────────────────────────────────────────────

    pub fn verify() -> anyhow::Result<()> {
        let exe = canonical_exe();
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

        // Local: the socket dir ACL verifies for the configured account (== the agent's grantee).
        let saved_cfg = std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| config::Config::from_toml(&s).ok());
        let saved_user = saved_cfg.as_ref().map(|c| c.target_user.clone());
        match &saved_user {
            Some(u) => {
                let ok = acl::Sid::lookup(u)
                    .and_then(|sid| acl::verify_dir_acl(&afunix::socket_dir(), &sid))
                    .unwrap_or(false);
                rows.push(report::Check::new("socket dir ACL", ok, format!("grantee={u}")));
            }
            None => rows.push(report::Check::new("socket dir ACL", false, "no config target_user")),
        }

        // Local: both tasks registered, and the agent task is InteractiveToken (session 1).
        let (agent_xml, agent_ok) = query_schtasks(&schtasks::query_task_argv(schtasks::AGENT_TASK));
        let registered = schtasks::parse_query_registered(&agent_xml, agent_ok);
        let interactive = schtasks::xml_has_interactive_token(&agent_xml);
        rows.push(report::Check::new(
            "agent task",
            registered && interactive,
            format!("registered={registered} interactive_token={interactive}"),
        ));
        // Informational: verify runs via the LeastPrivilege agent (non-elevated) and cannot
        // reliably query a SYSTEM-owned task, so this never gates verify (apply errors loudly
        // if registration fails, and the reboot self-heal is exercised in the Phase-8 test).
        let (_, heal_ok) = query_schtasks(&schtasks::query_task_argv(schtasks::SELFHEAL_TASK));
        rows.push(report::Check::new(
            "self-heal task (info)",
            true,
            if heal_ok {
                "registered"
            } else {
                "not queryable (needs elevation)"
            },
        ));

        // Local: the socket is reachable.
        let reachable = afunix::connect(&afunix::socket_path()).is_ok();
        rows.push(report::Check::new("socket reachable", reachable, String::new()));

        // Local: do the recorded Subsystem declarations still match what sshd reports?
        //
        // The shim runs a command locally only when it EXACTLY equals a declaration `apply`
        // recorded. Edit an `sshd_config` Subsystem line without re-running `apply` and the table
        // goes stale: the transfer stops matching and is relayed instead — still correct, since
        // the relay is byte-transparent, but slower and with nothing to say why. This row is what
        // says why.
        //
        // Informational when sshd cannot be asked. `verify` runs through the LeastPrivilege agent
        // and `sshd -T` generally needs elevation, so gating on it would paint every ordinary run
        // red. Same treatment as the self-heal task row above: reported with its reason, never
        // silently dropped.
        let recorded = saved_cfg.map(|c| c.declared_subsystems).unwrap_or_default();
        match read_declared_subsystems() {
            Ok(current) if current == recorded => rows.push(report::Check::new(
                "subsystem declarations",
                true,
                format!("{} declared, matching sshd", recorded.len()),
            )),
            Ok(current) => rows.push(report::Check::new(
                "subsystem declarations",
                false,
                format!(
                    "STALE — re-run apply (recorded {}, sshd now reports {})",
                    recorded.len(),
                    current.len()
                ),
            )),
            Err(e) => rows.push(report::Check::new(
                "subsystem declarations (info)",
                true,
                format!("recorded {}; could not re-check: {e}", recorded.len()),
            )),
        }

        // Through the agent: the real parity proof (run in session 1 by verify-probe).
        match drive_probe(&exe) {
            Ok((p, binary_ok)) => {
                // Parity = escaped session 0 (the limited network-logon session). The agent
                // need not be in THE active-console session — a box can have several
                // interactive sessions — and DPAPI/symlink below confirm it is a genuine one.
                rows.push(report::Check::new(
                    "interactive session (via agent)",
                    p.session_id != 0,
                    format!(
                        "session_id={} (active console={})",
                        p.session_id,
                        probe::active_console_session()
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
                // Byte-transparency on the real path. Transfers are routed around the relay on
                // the premise that relaying would not carry binary intact; this is the check
                // that holds that premise honest end to end, rather than in prose.
                rows.push(report::Check::new(
                    "binary transparency (via agent)",
                    binary_ok,
                    if binary_ok {
                        String::new()
                    } else {
                        "payload did not survive the relay byte for byte".into()
                    },
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

    /// Drive `<exe> verify-probe` as an EXEC command THROUGH the agent (so it runs in session 1),
    /// parse the PROBE line it prints, and check whether its binary payload survived intact.
    ///
    /// The byte check reads the RAW stdout, before the lossy UTF-8 conversion the line parse
    /// needs: the payload is deliberately not valid UTF-8, so converting first would destroy the
    /// very property being measured. This is the end-to-end half of byte-transparency — a real
    /// child, real pipes, a real socket — which the in-memory relay tests cannot reach.
    fn drive_probe(exe: &Path) -> anyhow::Result<(probe::ProbeResult, bool)> {
        let sock = afunix::connect(&afunix::socket_path()).context("connect to agent")?;
        let (rx, tx) = afunix::split(sock)?;
        let cmd = format!("\"{}\" verify-probe", exe.display());
        let hs = shim::make_handshake(&Some(cmd), "xterm".into(), 80, 24);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = shim::run_exec_on(rx, tx, &hs, &mut out, &mut err, std::io::empty())?;
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
        let dpapi = probe::dpapi_roundtrip(b"ssh-broker-parity-probe");
        let symlink = probe::symlink_probe();
        // One locked handle for both writes: `println!` would take its own lock, and the binary
        // payload must not interleave with the line that follows it.
        {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            probe::emit_binary_probe(&mut stdout).context("emit the binary-transparency payload")?;
            writeln!(stdout, "{}", probe::format_probe_line(sid, dpapi, symlink)).context("write the PROBE line")?;
            stdout.flush().context("flush probe output")?;
        }
        // Parity gates: escaped session 0 AND a working DPAPI (proves a real user profile, the
        // thing session 0 lacks). A CONFIRMED symlink block also fails; a Skipped (unprivileged,
        // untestable) symlink does not. The active-console id is NOT required to match — a host
        // can have several interactive sessions; any non-0 one with DPAPI is parity.
        let pass = sid != 0 && dpapi && !symlink.is_failure();
        if !pass {
            std::process::exit(1);
        }
        Ok(())
    }
}
