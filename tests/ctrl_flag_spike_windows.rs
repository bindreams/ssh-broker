//! SPIKE, NOT FOR MERGE. Prints the "ignore Ctrl+C" setting of the test process and its ancestors.
#![cfg(windows)]

#[test]
fn the_test_process_chain() {
    println!("[test process] pid {}", std::process::id());
    print!("{}", ssh_broker::ctrl_flag_spike::chain(std::process::id()));
    ssh_broker::ctrl_flag_spike::record("test process");
}
