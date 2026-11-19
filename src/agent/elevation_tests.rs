//! Tests for the agent's side of `elevate`: what a session's policy allows, and how a command is hosted. Real
//! commands (`cmd`, `findstr`) of this test's own, on pipes and pseudoconsoles; no socket to an agent.
use super::*;
use crate::offer::text;

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
