//! Unit tests for the `afunix` module.
use std::path::Path;

#[test]
fn unix_addr_accepts_a_normal_short_path() {
    assert!(super::unix_addr(Path::new("/tmp/ssh-broker/a.sock")).is_ok());
}

#[test]
fn a_read_limit_is_rounded_up_to_whole_milliseconds_and_never_to_zero() {
    use std::time::Duration;
    for (limit, rounded) in [
        (Duration::ZERO, Duration::from_millis(1)),
        (Duration::from_nanos(1), Duration::from_millis(1)),
        (Duration::from_micros(500), Duration::from_millis(1)),
        (Duration::from_micros(999), Duration::from_millis(1)),
        (Duration::from_millis(1), Duration::from_millis(1)),
        (Duration::from_nanos(1_000_001), Duration::from_millis(2)),
        (Duration::from_micros(1500), Duration::from_millis(2)),
        (Duration::from_secs(30), Duration::from_secs(30)),
        (Duration::MAX, Duration::from_millis(u64::MAX)),
    ] {
        assert_eq!(super::whole_milliseconds_up(limit), rounded, "{limit:?}");
    }
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

#[cfg(windows)]
#[test]
fn a_connection_is_born_non_inheritable() {
    // Measures the OS: `accept_raw` is `accept` and nothing more. A listener made with
    // `WSA_FLAG_NO_HANDLE_INHERIT` yields sockets that are non-inheritable from the start, so no
    // child spawned by another thread can inherit one between `accept` and any later fix-up.
    let dir = setup_socket_dir("born");
    let p = dir.join("s");
    let listener = super::Listener::bind(&p).unwrap();
    let client = super::connect(&p).unwrap();
    let (accepted, _) = listener.sock.accept_raw().unwrap();
    assert!(
        !super::is_inheritable(&accepted).unwrap(),
        "an accepted socket of a no-inherit listener is inheritable at birth"
    );
    drop((accepted, client));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn an_accepted_connection_is_not_inheritable() {
    let dir = setup_socket_dir("accepted");
    let p = dir.join("s");
    let listener = super::Listener::bind(&p).unwrap();
    let _client = super::connect(&p).unwrap();
    let accepted = listener.accept().unwrap();
    assert!(!super::is_inheritable(&accepted).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn a_connection_that_arrives_inheritable_is_refused_not_fixed_up() {
    // Control: a socket made without the flag is inheritable, so the check can tell.
    let sock = socket2::Socket::new_raw(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    assert!(super::is_inheritable(&sock).unwrap(), "control: made without the flag");
    // Fixing it up afterwards would leave the window open for the whole life of the accept loop's
    // handoff; a connection that was ever inheritable is refused.
    let err = super::finish_accept(Ok(sock), super::harden_accepted).expect_err("must be refused");
    match err {
        super::AcceptError::Refused { cause, .. } => {
            assert!(format!("{cause:#}").contains("inheritable"), "{cause:#}")
        }
        other => panic!("{other:?}"),
    }
}

// the socket file's own ACL ----------------------------------------------------------------

#[cfg(windows)]
#[test]
fn bind_creates_a_socket_file_with_exactly_the_three_aces() {
    let dir = setup_socket_dir("file-acl");
    let p = dir.join("agent.sock");
    let _listener = super::Listener::bind(&p).unwrap();
    let me = crate::acl::Sid::current_user().unwrap();
    assert!(
        crate::acl::verify_file_acl(&p, &me).unwrap(),
        "the file is born with the directory's inheritable ACEs and nothing else"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_refuses_a_dir_that_is_widened_after_it_was_hardened() {
    let dir = setup_socket_dir("widened");
    let status = std::process::Command::new("icacls")
        .arg(&dir)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());
    let p = dir.join("agent.sock");
    let err = format!("{:#}", super::Listener::bind(&p).err().expect("must refuse"));
    assert!(err.contains("not locked down"), "{err}");
    assert!(!p.exists(), "nothing was bound");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_removes_the_socket_and_refuses_when_the_file_acl_does_not_verify() {
    let dir = setup_socket_dir("bad-file");
    let p = dir.join("agent.sock");
    let err = super::Listener::bind_with(&p, &|_| Ok(false))
        .err()
        .expect("must refuse");
    assert!(format!("{err:#}").contains("socket file"), "{err:#}");
    assert!(!p.exists(), "a socket whose ACL is unproven is not left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn bind_removes_the_socket_when_the_file_acl_cannot_be_read() {
    let dir = setup_socket_dir("unreadable-file");
    let p = dir.join("agent.sock");
    let result = super::Listener::bind_with(&p, &|_| anyhow::bail!("cannot read it"));
    assert!(result.is_err());
    assert!(!p.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bind_reports_a_live_listener_as_already_listening() {
    let dir = setup_socket_dir("already");
    let p = dir.join("s");
    let _first = super::Listener::bind(&p).unwrap();
    let err = super::Listener::bind(&p).err().expect("a live listener holds the path");
    assert!(
        err.downcast_ref::<super::AlreadyListening>().is_some(),
        "the caller must be able to tell this from a real failure: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn an_agent_that_takes_over_the_lock_reclaims_the_dead_agents_socket() {
    use crate::agent_lock::UserLock;
    let dir = setup_socket_dir("takeover");
    let sock = dir.join("agent.sock");
    let lock = dir.join("agent.lock");

    // The first agent serves under the lock and dies: lock released, socket file left behind.
    let first_lock = UserLock::try_acquire(&lock).unwrap().unwrap();
    drop(super::Listener::bind(&sock).unwrap());
    assert!(sock.exists(), "control: the dead agent left its socket file");
    drop(first_lock);

    // The second takes the lock, then binds over the stale file.
    let _second_lock = UserLock::acquire(&lock, || panic!("the lock was free")).unwrap();
    let _second = super::Listener::bind(&sock).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// accept errors -----

#[cfg(windows)]
fn raw(code: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(code)
}

#[cfg(windows)]
#[test]
fn a_connection_the_peer_dropped_while_queued_is_that_connections_loss() {
    // WSAECONNRESET and WSAECONNABORTED: the listener is fine; this one connection is gone.
    for code in [10054, 10053] {
        assert!(
            matches!(
                super::classify_accept_error(raw(code)),
                super::AcceptError::Connection(_)
            ),
            "{code}"
        );
    }
}

#[cfg(windows)]
#[test]
fn an_interruption_is_to_be_retried() {
    // WSAEINTR: a blocking call was cancelled; nothing was consumed and nothing is wrong.
    assert!(matches!(
        super::classify_accept_error(raw(10004)),
        super::AcceptError::Interrupted(_)
    ));
}

#[cfg(windows)]
#[test]
fn a_shortage_of_descriptors_or_buffers_is_exhaustion_and_keeps_its_code() {
    // WSAEMFILE and WSAENOBUFS clear only when something else lets go of a resource.
    for code in [10024, 10055] {
        match super::classify_accept_error(raw(code)) {
            super::AcceptError::Exhausted { code: got, .. } => assert_eq!(got, code),
            other => panic!("{code} classified as {other:?}"),
        }
    }
}

#[cfg(windows)]
#[test]
fn codes_a_blocking_listener_cannot_return_are_fatal_and_say_so() {
    // WSAEWOULDBLOCK needs a non-blocking socket and WSAEINPROGRESS a Winsock 1.1 blocking call in
    // progress; this listener is neither, so getting one means something is wrong with it.
    for code in [10035, 10036] {
        match super::classify_accept_error(raw(code)) {
            super::AcceptError::Fatal(e) => {
                let text = format!("{e:#}");
                assert!(text.contains(&code.to_string()), "{text}");
                assert!(text.contains("cannot return"), "{text}");
            }
            other => panic!("{code} classified as {other:?}"),
        }
    }
}

#[cfg(windows)]
#[test]
fn a_broken_listener_is_fatal() {
    // WSAEINVAL (not listening), WSAENOTSOCK, WSAENETDOWN, and a code Winsock does not document
    // for accept: none of them is a connection's fault or goes away by itself.
    for code in [10022, 10038, 10050, 99999] {
        assert!(
            matches!(super::classify_accept_error(raw(code)), super::AcceptError::Fatal(_)),
            "{code}"
        );
    }
}

#[cfg(windows)]
#[test]
fn an_accepted_connection_that_cannot_be_hardened_is_refused_not_fatal() {
    // The socket must not reach a child with its inherit flag set, so it is refused (and answered); the
    // listener has nothing wrong with it.
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    let err = super::finish_accept(Ok(sock), |_| anyhow::bail!("SetHandleInformation failed"))
        .expect_err("a connection that cannot be hardened is not handed out");
    match err {
        super::AcceptError::Refused { cause, .. } => {
            assert!(format!("{cause:#}").contains("SetHandleInformation"), "{cause:#}")
        }
        other => panic!("{other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn an_accepted_connection_that_hardens_is_handed_out() {
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).unwrap();
    assert!(super::finish_accept(Ok(sock), |_| Ok(())).is_ok());
}
