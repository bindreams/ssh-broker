//! ssh-broker entrypoint: dispatch argv to the library.
//!
//! Everything of substance lives in the library crate; this binary only decides which
//! entry point argv selects. See `lib.rs` for the architecture.

use ssh_broker::{Route, agent, cmdline, provision, route, shim};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let detected = cmdline::detect();
    match route(&args, &cmdline::current(), detected.encoding) {
        Route::Shim { exec } => shim::run(exec, detected.warning),
        Route::Agent => agent::run(),
        Route::Apply => provision::apply(),
        Route::Verify => provision::verify(),
        Route::VerifyProbe => provision::verify_probe(),
    }
}
