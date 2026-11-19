//! Tests for the ids the agent gives its sessions.
use super::*;

#[test]
fn an_id_is_32_hex_digits_that_parse_back_and_two_differ() {
    let (a, b) = (new_id().unwrap(), new_id().unwrap());
    assert_eq!(a.to_string().len(), 32);
    assert_eq!(SessionId::parse(&a.to_string()), Some(a));
    assert_ne!(a, b, "128 random bits do not repeat");
}
