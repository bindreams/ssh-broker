//! Unit tests for the `afunix` module.
use std::path::Path;

#[test]
fn unix_addr_accepts_a_normal_short_path() {
    assert!(super::unix_addr(Path::new("/tmp/ssh-broker/a.sock")).is_ok());
}

#[test]
fn unix_addr_rejects_an_overlong_path() {
    // sockaddr_un sun_path is ~108 bytes; a 200-char path must be rejected loudly.
    let long = format!("/tmp/{}.sock", "x".repeat(200));
    assert!(super::unix_addr(Path::new(&long)).is_err());
}

/// Create a short-pathed socket directory; on Windows, harden it so `bind`'s fail-closed
/// ACL gate is satisfied. Kept short because `sockaddr_un` paths are ~104-108 bytes.
fn setup_socket_dir(tag: &str) -> std::path::PathBuf {
    let base = if cfg!(windows) {
        std::env::temp_dir()
    } else {
        std::path::PathBuf::from("/tmp")
    };
    let dir = base.join(format!("sb-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(windows)]
    {
        let me = crate::acl::Sid::current_user().unwrap();
        crate::acl::harden_dir(&dir, &me).unwrap();
    }
    dir
}

#[test]
fn listen_connect_echo() {
    use std::io::{Read, Write};
    let dir = setup_socket_dir("echo");
    let sock_path = dir.join("s");

    let listener = super::Listener::bind(&sock_path).unwrap();
    let client = std::thread::spawn({
        let p = sock_path.clone();
        move || {
            let mut c = super::connect(&p).unwrap();
            c.write_all(b"hello").unwrap();
        }
    });

    let mut conn = listener.accept().unwrap();
    let mut buf = [0u8; 5];
    conn.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");

    client.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn split_halves_are_independent_and_shutdown_signals_eof() {
    use std::io::{Read, Write};
    let dir = setup_socket_dir("split");
    let sock_path = dir.join("s");
    let listener = super::Listener::bind(&sock_path).unwrap();

    let client = std::thread::spawn({
        let p = sock_path.clone();
        move || {
            let mut c = super::connect(&p).unwrap();
            c.write_all(b"req").unwrap();
            // read the server's reply until EOF (server shuts down its write half)
            let mut reply = Vec::new();
            c.read_to_end(&mut reply).unwrap();
            reply
        }
    });

    let server = listener.accept().unwrap();
    let (mut rx, mut tx) = super::split(server).unwrap();

    // The rx half receives the client's request...
    let mut buf = [0u8; 3];
    rx.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"req");

    // ...and the tx half sends a reply; shutdown_write FINs so the client's read_to_end ends.
    tx.write_all(b"reply").unwrap();
    tx.shutdown_write().unwrap();

    let reply = client.join().unwrap();
    assert_eq!(reply, b"reply");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_refuses_when_a_live_listener_holds_the_path() {
    let dir = setup_socket_dir("live");
    let p = dir.join("s");
    let _first = super::Listener::bind(&p).unwrap();
    assert!(
        super::Listener::bind(&p).is_err(),
        "binding over a live listener must fail (no hijack)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_reclaims_a_stale_socket_file() {
    let dir = setup_socket_dir("stale");
    let p = dir.join("s");
    drop(super::Listener::bind(&p).unwrap()); // listener closed; the socket file may linger
    // A fresh bind must reclaim the dead path rather than fail.
    let _second = super::Listener::bind(&p).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_refuses_an_unhardened_directory() {
    // No harden_dir -> the inherited/default DACL must fail the fail-closed gate.
    let dir = std::env::temp_dir().join(format!("sb-unhardened-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("s");
    assert!(
        super::Listener::bind(&p).is_err(),
        "bind must refuse a directory that is not locked down"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn production_socket_path_fits_sockaddr_un() {
    // The fixed production path must not overflow the sockaddr_un limit.
    assert!(super::unix_addr(&super::socket_path()).is_ok());
}

#[cfg(windows)]
#[test]
fn bound_listener_socket_is_not_inheritable() {
    let dir = setup_socket_dir("noinherit");
    let p = dir.join("s");
    let listener = super::Listener::bind(&p).unwrap();
    assert!(
        listener.inherit_flag_is_clear(),
        "the listening socket must not be inheritable (else children leak the ACL boundary)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
