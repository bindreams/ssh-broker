//! provision::sshd_config::machine::listening — whether a process owns a TCP listening socket, read from the
//! kernel's socket table. No connection is made to anything: a listener is seen, not asked.

use std::mem::offset_of;

use anyhow::Context;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_LISTENER,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Whether the process `pid` owns a TCP socket in the listening state, on an IPv4 or an IPv6 address.
pub(super) fn listens(pid: u32) -> anyhow::Result<bool> {
    for (family, name) in [(AF_INET.0 as u32, "IPv4"), (AF_INET6.0 as u32, "IPv6")] {
        let owners = listener_owners(family).with_context(|| format!("read the {name} listening sockets"))?;
        if owners.contains(&pid) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The owning process id of every listening TCP socket of address family `family`. The table is asked for
/// again with the size the system names for as long as it answers that the buffer is too small: the table grows
/// and shrinks while it is read, and no number of attempts is the right one.
fn listener_owners(family: u32) -> anyhow::Result<Vec<u32>> {
    // `u32`s, so that the buffer is aligned as the table is.
    let mut buffer: Vec<u32> = Vec::new();
    let mut size = 0u32;
    loop {
        let table = (!buffer.is_empty()).then(|| buffer.as_mut_ptr().cast());
        // SAFETY: `table` is null, or the start of `buffer`, which holds at least `size` bytes; `size` is a local.
        let code = unsafe { GetExtendedTcpTable(table, &mut size, false, family, TCP_TABLE_OWNER_PID_LISTENER, 0) };
        if code == NO_ERROR.0 {
            break;
        }
        if code != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(std::io::Error::from_raw_os_error(code as i32)).context("GetExtendedTcpTable failed");
        }
        buffer.resize((size as usize).div_ceil(size_of::<u32>()), 0);
    }
    let table = buffer.as_ptr();
    // SAFETY: the call filled `buffer` with a `MIB_TCPTABLE_OWNER_PID` or a `MIB_TCP6TABLE_OWNER_PID` (by `family`):
    // a count, then that many rows, all inside `buffer`. The rows are reached from the pointer to the whole
    // buffer, for the table type declares room for one.
    Ok(unsafe {
        if family == AF_INET.0 as u32 {
            let count = (*table.cast::<MIB_TCPTABLE_OWNER_PID>()).dwNumEntries as usize;
            let rows = table
                .byte_add(offset_of!(MIB_TCPTABLE_OWNER_PID, table))
                .cast::<MIB_TCPROW_OWNER_PID>();
            std::slice::from_raw_parts(rows, count)
                .iter()
                .map(|row| row.dwOwningPid)
                .collect()
        } else {
            let count = (*table.cast::<MIB_TCP6TABLE_OWNER_PID>()).dwNumEntries as usize;
            let rows = table
                .byte_add(offset_of!(MIB_TCP6TABLE_OWNER_PID, table))
                .cast::<MIB_TCP6ROW_OWNER_PID>();
            std::slice::from_raw_parts(rows, count)
                .iter()
                .map(|row| row.dwOwningPid)
                .collect()
        }
    })
}

#[cfg(test)]
#[path = "listening_tests.rs"]
mod listening_tests;
