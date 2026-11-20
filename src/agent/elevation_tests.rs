//! Tests for the agent's side of `elevate`: what a session's policy allows, and how a command is hosted. Real
//! commands (`cmd`, `findstr`) of this test's own, on pipes and pseudoconsoles; no socket to an agent.
use super::*;
use crate::offer::text;

/// A watch with no connection behind it: `on_hangup` is what the hang-up watcher's thread calls.
fn a_watch() -> RequestWatch {
    RequestWatch {
        link: Link::new(crate::agent::test_wire::Wire::default(), true, (80, 24), None),
        gone: ClientGone::default(),
        command: Mutex::new(None),
    }
}

/// An end for a command that counts how many times it was called.
fn counting_end() -> (Killer, Arc<std::sync::atomic::AtomicUsize>) {
    let ends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let end: Killer = {
        let ends = Arc::clone(&ends);
        Arc::new(move || {
            ends.fetch_add(1, Ordering::SeqCst);
        })
    };
    (end, ends)
}

/// The one watch covers the request from its question to its command: a hang-up while the command runs ends its tree.
#[test]
fn a_hang_up_while_the_command_runs_ends_its_tree() {
    let watch = a_watch();
    let (end, ends) = counting_end();
    watch.attach(end);
    assert_eq!(ends.load(Ordering::SeqCst), 0, "a client that is there ends nothing");
    assert!(!watch.is_gone());

    watch.on_hangup();
    assert!(watch.is_gone());
    assert_eq!(ends.load(Ordering::SeqCst), 1);
}

/// A hang-up that came before the command had a tree (the question's end, the start) ends it the moment it has one:
/// no window between the question and the command goes unwatched.
#[test]
fn a_hang_up_before_the_command_has_a_tree_ends_it_when_it_has() {
    let watch = a_watch();
    watch.on_hangup();
    assert!(watch.is_gone());

    let (end, ends) = counting_end();
    watch.attach(end);
    assert_eq!(ends.load(Ordering::SeqCst), 1, "ended at once, as it was attached");
}

/// The question shows the folder the command starts in: the request's, else the agent's own. When that cannot be
/// told, the question is refused with the cause and is never asked, with a blank folder.
#[test]
fn the_folder_shown_is_the_folder_the_command_starts_in_or_the_request_is_refused() {
    let named = Path::new(r"C:\work");
    assert_eq!(
        folder_shown(Some(named), || panic!("the agent's own folder is not asked")),
        Ok(r"C:\work".to_owned())
    );
    assert_eq!(
        folder_shown(None, || Ok(r"C:\agent".into())),
        Ok(r"C:\agent".to_owned())
    );
    let refusal = folder_shown(None, || Err(std::io::Error::other("the folder was removed")))
        .expect_err("a folder that cannot be told is no question");
    assert!(refusal.contains("the folder was removed"), "{refusal}");
    assert!(
        refusal.starts_with("ssh-broker: the command could not be started elevated"),
        "{refusal}"
    );
}

#[test]
fn decide_gives_never_refuse_auto_approve_run_always_refuse_already_elevated_prompt_ask_with_a_terminal() {
    for has_terminal in [true, false] {
        assert_eq!(
            decide(ElevationPolicy::Never, has_terminal, false),
            Verdict::Refuse(text::elevation_never())
        );
        assert_eq!(decide(ElevationPolicy::AutoApprove, has_terminal, false), Verdict::Run);
        assert_eq!(
            decide(ElevationPolicy::Always, has_terminal, false),
            Verdict::Refuse(text::elevation_already_elevated())
        );
    }
    assert_eq!(decide(ElevationPolicy::Prompt, true, false), Verdict::Ask);
}

/// There is nobody to ask in a session without a terminal, and the sentence says how to elevate there. `--terminal`
/// there is refused first, for the terminal it needs.
#[test]
fn decide_refuses_prompt_without_a_terminal_naming_the_variable_and_asks_with_one_whatever_the_command_wants() {
    assert_eq!(
        decide(ElevationPolicy::Prompt, false, false),
        Verdict::Refuse(text::elevation_no_terminal())
    );
    assert_eq!(
        decide(ElevationPolicy::Prompt, false, true),
        Verdict::Refuse(text::elevation_needs_a_terminal())
    );
    assert_eq!(decide(ElevationPolicy::Prompt, true, true), Verdict::Ask);
    let sentence = text::elevation_no_terminal();
    assert!(
        sentence.contains("SSH_BROKER_ELEVATION=always") && sentence.contains("SSH_BROKER_ELEVATION=auto-approve"),
        "{sentence}"
    );
}

#[test]
fn decide_refuses_a_command_that_wants_a_terminal_in_a_session_without_one_and_only_then() {
    assert_eq!(
        decide(ElevationPolicy::AutoApprove, false, true),
        Verdict::Refuse(text::elevation_needs_a_terminal())
    );
    assert_eq!(
        decide(ElevationPolicy::AutoApprove, true, true),
        Verdict::Run,
        "a session with a terminal gives it one"
    );
    // The login's own answer comes first: a `never` is not turned into a hint about `ssh -t`.
    assert_eq!(
        decide(ElevationPolicy::Never, false, true),
        Verdict::Refuse(text::elevation_never())
    );
    assert_eq!(
        decide(ElevationPolicy::Always, false, true),
        Verdict::Refuse(text::elevation_already_elevated())
    );
}
