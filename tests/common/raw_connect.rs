//! A connect to an AF_UNIX socket by its bare path, for a test whose subject is the connect itself:
//! what the socket's ACL or an integrity level does to a process that is not the account's agent
//! client, or a stand-in socket that is no agent's. The product has no connect by path (it connects
//! through the folders it holds, `userdir::SocketDir::connect`), so a test that needs one makes it here.
#![allow(dead_code)]

use std::path::Path;

use socket2::{Domain, Socket, Type};
use ssh_broker::afunix;

/// Connect to the socket at `path`. The error is the OS's, as `afunix::connect` gave it.
pub fn raw_connect(path: &Path) -> anyhow::Result<Socket> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.connect(&afunix::unix_addr(path)?)?;
    Ok(socket)
}
