use ::windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use super::piped_encoding;
use crate::cmdline::Encoding;

#[test]
fn a_readable_setting_picks_the_form_without_a_warning() {
    let on = piped_encoding(Ok(true));
    assert_eq!((on.encoding, on.warning), (Encoding::Escaped, None));
    let off = piped_encoding(Ok(false));
    assert_eq!((off.encoding, off.warning), (Encoding::Wrapped, None));
}

/// sshd keeps escaping on when it cannot read the value, so the shim assumes the same, and says
/// so: if the value is really 0, the command is then decoded as the wrong form.
#[test]
fn an_unreadable_setting_assumes_escaped_and_says_so() {
    let error = ::windows::core::Error::from(ERROR_ACCESS_DENIED.to_hresult());
    let detected = piped_encoding(Err(error));

    assert_eq!(detected.encoding, Encoding::Escaped);
    let warning = detected.warning.expect("an unreadable setting must be reported");
    assert!(warning.contains("DefaultShellEscapeArguments"), "{warning}");
    assert!(warning.contains("Access is denied"), "names the cause: {warning}");
    assert!(warning.contains("assum"), "names the assumption: {warning}");
}
