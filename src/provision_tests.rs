//! Host tests for `install`'s argument handling.
use super::*;
use crate::route::ProbeLink;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn check_install_args_accepts_no_arguments() {
    check_install_args(&[]).unwrap();
}

#[test]
fn check_install_args_refuses_any_argument() {
    let err = check_install_args(&args(&["--force"])).unwrap_err().to_string();
    assert!(err.contains("--force"), "{err}");
    let err = check_install_args(&args(&["--user", "someone"]))
        .unwrap_err()
        .to_string();
    assert!(err.contains("--user"), "{err}");
}

#[test]
fn the_installed_line_is_the_literal() {
    assert_eq!(installed_line("0.2.0"), "ssh-broker v0.2.0 has been installed!");
}

// The shell config row and the probe =====

use crate::shell::test_host::{TestHost, USER_CONFIG};

#[test]
fn the_shell_config_row_passes_with_the_program_and_its_origin() {
    let host = TestHost::new()
        .with_program("pwsh.exe", r"C:\p\pwsh.exe")
        .with_user_config("shell: pwsh.exe\n");
    let row = shell_config_row(&crate::shell::effective(&host));
    assert!(row.pass, "{}", row.detail);
    assert_eq!(row.name, "shell config");
    assert!(
        row.detail.contains(r"C:\p\pwsh.exe") && row.detail.contains(USER_CONFIG),
        "{}",
        row.detail
    );

    let built_in = shell_config_row(&crate::shell::effective(&TestHost::new()));
    assert!(
        built_in.pass && built_in.detail.contains("built-in"),
        "{}",
        built_in.detail
    );
}

#[test]
fn the_shell_config_row_fails_only_when_a_fallback_is_in_effect() {
    let broken = TestHost::new().with_user_config("shell: {strt: x}\n");
    let row = shell_config_row(&crate::shell::effective(&broken));
    assert!(!row.pass);
    assert!(
        row.detail.contains(USER_CONFIG) && row.detail.contains("strt"),
        "{}",
        row.detail
    );

    let missing = TestHost::new().with_user_config("shell: nonesuch.exe\n");
    let row = shell_config_row(&crate::shell::effective(&missing));
    assert!(!row.pass && row.detail.contains("nonesuch.exe"), "{}", row.detail);

    let mut nothing = TestHost::new();
    nothing.entries.clear();
    let row = shell_config_row(&crate::shell::effective(&nothing));
    assert!(!row.pass, "even the built-in cmd.exe is missing");
}

#[test]
fn the_probe_handshake_is_direct() {
    use crate::protocol::{Launch, Mode};
    let hs = probe_handshake(
        std::path::Path::new(r"C:\Program Files\ssh-broker\ssh-broker.exe"),
        crate::protocol::ElevationPolicy::Prompt,
        &ProbeLink::NoJunction,
    );
    assert_eq!(
        hs.launch,
        Launch::Direct,
        "the probe is ssh-broker's own, not a user command"
    );
    assert_eq!(hs.mode, Mode::Exec);
    assert_eq!(
        hs.command.as_deref(),
        Some(r#""C:\Program Files\ssh-broker\ssh-broker.exe" doctor-probe"#)
    );
}

/// The policy a probe asks for is in the handshake, which is all the agent goes by when it gives the probe's
/// child its token; the command is the same one the other probes run.
#[test]
fn probe_handshake_carries_the_policy_it_is_given() {
    use crate::protocol::ElevationPolicy;
    let exe = std::path::Path::new(r"C:\Program Files\ssh-broker\ssh-broker.exe");
    for elevation in [
        ElevationPolicy::Never,
        ElevationPolicy::Prompt,
        ElevationPolicy::AutoApprove,
        ElevationPolicy::Always,
    ] {
        assert_eq!(
            probe_handshake(exe, elevation, &ProbeLink::NoJunction).elevation,
            Some(elevation)
        );
    }
}

/// Each probe's command line names what it does about the junction. The directory to follow is quoted, so
/// a profile with a blank in its name reaches the probe as one argument.
#[test]
fn the_probe_handshake_names_the_junction_work() {
    use crate::protocol::ElevationPolicy;
    let exe = std::path::Path::new(r"C:\Program Files\ssh-broker\ssh-broker.exe");
    let command = |link: &ProbeLink| probe_handshake(exe, ElevationPolicy::Prompt, link).command.unwrap();
    let base = r#""C:\Program Files\ssh-broker\ssh-broker.exe" doctor-probe"#;

    assert_eq!(command(&ProbeLink::NoJunction), base);
    let dir = r"C:\Users\example user\AppData\Local\Temp\sb-junction-9-1";
    assert_eq!(
        command(&ProbeLink::Make(dir.into())),
        format!(r#"{base} --make-junction "{dir}""#)
    );
    assert_eq!(
        command(&ProbeLink::Follow(dir.into())),
        format!(r#"{base} --follow "{dir}""#)
    );
}
