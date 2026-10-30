//! Host tests for the config layers (pure; runs on any platform).

use std::path::PathBuf;

use super::{Origin, choose, user_config_path};
use crate::shell::test_host::{Entry, SYSTEM_CMD, SYSTEM_CONFIG, TestHost, USER_CONFIG};

fn start_of(chosen: &super::Chosen) -> Vec<String> {
    chosen.block.start.clone()
}

#[test]
fn no_files_means_the_built_in_cmd_exe() {
    let chosen = choose(&TestHost::new());
    assert_eq!(start_of(&chosen), [SYSTEM_CMD]);
    assert_eq!(chosen.origin, Origin::Default);
    assert_eq!(chosen.problem, None);
    assert_eq!(chosen.block.escaping, None);
}

#[test]
fn a_user_shell_replaces_the_system_block_whole() {
    let host = TestHost::new()
        .with_user_config("shell: pwsh.exe\n")
        .with_system_config("shell: {start: bash.exe, escaping: cmd, append: {with-command: [-x]}}\n");
    let chosen = choose(&host);
    assert_eq!(start_of(&chosen), ["pwsh.exe"]);
    assert_eq!(chosen.block.escaping, None);
    assert_eq!(chosen.block.with_command, None);
    assert_eq!(chosen.origin, Origin::User(PathBuf::from(USER_CONFIG)));
    // The system file is not even read: a broken one cannot matter.
    assert_eq!(host.read_log(), [PathBuf::from(USER_CONFIG)]);
}

#[test]
fn a_user_file_without_shell_uses_the_system_block() {
    for user in ["", "# nothing here\n"] {
        let host = TestHost::new()
            .with_user_config(user)
            .with_system_config("shell: pwsh.exe\n");
        let chosen = choose(&host);
        assert_eq!(start_of(&chosen), ["pwsh.exe"]);
        assert_eq!(chosen.origin, Origin::System(PathBuf::from(SYSTEM_CONFIG)));
        assert_eq!(chosen.problem, None);
    }
}

#[test]
fn the_system_block_is_used_when_there_is_no_user_file() {
    let chosen = choose(&TestHost::new().with_system_config("shell: pwsh.exe\n"));
    assert_eq!(start_of(&chosen), ["pwsh.exe"]);
    assert_eq!(chosen.origin, Origin::System(PathBuf::from(SYSTEM_CONFIG)));
}

#[test]
fn a_broken_user_file_falls_to_cmd_exe_not_to_the_system_layer() {
    let host = TestHost::new()
        .with_user_config("shell: {strt: pwsh.exe}\n")
        .with_system_config("shell: pwsh.exe\n");
    let chosen = choose(&host);
    assert_eq!(start_of(&chosen), [SYSTEM_CMD]);
    assert_eq!(chosen.origin, Origin::Default);
    let problem = chosen.problem.expect("a warning");
    assert_eq!(problem.file, PathBuf::from(USER_CONFIG));
    assert!(problem.reason.contains("strt"), "{}", problem.reason);
}

#[test]
fn a_broken_system_file_falls_to_cmd_exe_only_when_the_user_has_no_shell() {
    let host = TestHost::new().with_system_config("shell: [unclosed\n");
    let chosen = choose(&host);
    assert_eq!(start_of(&chosen), [SYSTEM_CMD]);
    assert_eq!(chosen.problem.expect("a warning").file, PathBuf::from(SYSTEM_CONFIG));

    let with_user_shell = TestHost::new()
        .with_user_config("shell: pwsh.exe\n")
        .with_system_config("shell: [unclosed\n");
    let chosen = choose(&with_user_shell);
    assert_eq!(start_of(&chosen), ["pwsh.exe"]);
    assert_eq!(chosen.problem, None);
}

#[test]
fn an_unreadable_path_is_broken() {
    for entry in [Entry::Dir, Entry::Unreadable("The process cannot access the file")] {
        let host = TestHost::new()
            .with_entry(USER_CONFIG, entry)
            .with_system_config("shell: pwsh.exe\n");
        let chosen = choose(&host);
        assert_eq!(start_of(&chosen), [SYSTEM_CMD]);
        let problem = chosen.problem.expect("a warning");
        assert_eq!(problem.file, PathBuf::from(USER_CONFIG));
        assert!(!problem.reason.is_empty());
    }
}

#[test]
fn bytes_that_are_not_text_are_broken_not_a_panic() {
    let chosen = choose(&TestHost::new().with_bytes(USER_CONFIG, b"\xFF\xFE\x00\xD8"));
    assert_eq!(start_of(&chosen), [SYSTEM_CMD]);
    assert!(chosen.problem.is_some());
}

#[test]
fn xdg_config_home_wins_only_when_absolute_and_non_empty() {
    let xdg = r"D:\cfg\ssh-broker\config.yaml";
    let host = TestHost::new().with_env("XDG_CONFIG_HOME", r"D:\cfg");
    assert_eq!(user_config_path(&host).unwrap(), PathBuf::from(xdg));
    let chosen = choose(&host.with_file(xdg, "shell: pwsh.exe\n"));
    assert_eq!(chosen.origin, Origin::User(PathBuf::from(xdg)));

    for ignored in ["", r"cfg", r".\cfg", r"\cfg", "C:cfg", "~"] {
        let host = TestHost::new().with_env("XDG_CONFIG_HOME", ignored);
        assert_eq!(
            user_config_path(&host).unwrap(),
            PathBuf::from(USER_CONFIG),
            "{ignored:?}"
        );
    }
    // Unset is the same as empty.
    assert_eq!(user_config_path(&TestHost::new()).unwrap(), PathBuf::from(USER_CONFIG));
}

#[test]
fn a_profile_with_spaces_and_non_ascii_names_the_right_file() {
    let profile = "D:\\Profiles\\Ünï cödé (work)";
    let mut host = TestHost::new();
    host.profile = Some(PathBuf::from(profile));
    let path = format!("{profile}\\.config\\ssh-broker\\config.yaml");
    assert_eq!(user_config_path(&host).unwrap(), PathBuf::from(&path));
    let chosen = choose(&host.with_file(&path, "shell: pwsh.exe\n"));
    assert_eq!(start_of(&chosen), ["pwsh.exe"]);
    assert_eq!(chosen.origin, Origin::User(PathBuf::from(path)));
}

#[test]
fn an_xdg_home_with_a_space_and_a_trailing_separator_names_the_right_file() {
    let host = TestHost::new().with_env("XDG_CONFIG_HOME", "D:\\My Config\\");
    assert_eq!(
        user_config_path(&host).unwrap(),
        PathBuf::from("D:\\My Config\\ssh-broker\\config.yaml")
    );
}

#[test]
fn no_profile_and_no_xdg_means_no_user_layer() {
    let mut host = TestHost::new().with_system_config("shell: pwsh.exe\n");
    host.profile = None;
    assert!(user_config_path(&host).is_err());
    let chosen = choose(&host);
    assert_eq!(start_of(&chosen), ["pwsh.exe"]);
    assert_eq!(chosen.problem, None);
}

#[test]
fn a_relocated_profile_without_the_default_name_is_honored() {
    // PROFILE is only the default: the token's profile is whatever the host says.
    let mut host = TestHost::new();
    host.profile = Some(PathBuf::from(r"E:\profiles\anna"));
    assert_eq!(
        user_config_path(&host).unwrap(),
        PathBuf::from(r"E:\profiles\anna\.config\ssh-broker\config.yaml")
    );
}

#[test]
fn the_notice_names_the_file_the_value_and_the_reason() {
    let problem = super::Problem {
        file: PathBuf::from(USER_CONFIG),
        value: Some("pwsh.exe".into()),
        reason: "not found on PATH".into(),
    };
    assert_eq!(
        problem.notice(),
        format!(
            "ssh-broker: cannot use the shell from {USER_CONFIG} (pwsh.exe): not found on PATH; using the built-in cmd.exe"
        )
    );
    let parse = super::Problem { value: None, ..problem };
    assert!(!parse.notice().contains("()"), "{}", parse.notice());
}
