//! Tests for the agent's side of `elevate`: what a session's policy allows, and how a command is hosted. Real
//! commands (`cmd`, `findstr`) of this test's own, on pipes and pseudoconsoles; no socket to an agent.
use super::*;
use crate::offer::text;

#[test]
fn decide_gives_never_refuse_auto_approve_run_always_refuse_already_elevated_prompt_refuse_with_the_next_units_sentence()
 {
    for has_terminal in [true, false] {
        assert_eq!(
            decide(ElevationPolicy::Never, has_terminal),
            Verdict::Refuse(text::elevation_never())
        );
        assert_eq!(decide(ElevationPolicy::AutoApprove, has_terminal), Verdict::Run);
        assert_eq!(
            decide(ElevationPolicy::Always, has_terminal),
            Verdict::Refuse(text::elevation_already_elevated())
        );
        assert_eq!(
            decide(ElevationPolicy::Prompt, has_terminal),
            Verdict::Refuse(text::elevation_consent_not_built())
        );
    }
}
