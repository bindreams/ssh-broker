//! Spike probe (Task 0 M6, never merged). `stdin_probe` reads its standard input to the end and prints
//! what it got on one line: the byte count, an FNV-1a hash and the read's error, if any.
//! `stdin_probe out` writes every byte value to standard output instead.

use std::io::{Read as _, Write as _};

fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
    })
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("out") {
        let all: Vec<u8> = (0..=255u8).collect();
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&all).expect("write");
        stdout.flush().expect("flush");
        return;
    }
    let mut data = Vec::new();
    let result = std::io::stdin().lock().read_to_end(&mut data);
    match result {
        Ok(_) => println!("stdin n={} fnv={:016x}", data.len(), fnv(&data)),
        Err(e) => println!(
            "stdin read-error kind={:?} os={:?} n={} fnv={:016x}",
            e.kind(),
            e.raw_os_error(),
            data.len(),
            fnv(&data)
        ),
    }
}
