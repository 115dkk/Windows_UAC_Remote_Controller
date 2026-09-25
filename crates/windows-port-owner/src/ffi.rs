// SPDX-License-Identifier: GPL-2.0-or-later
//! The sole Windows FFI boundary. All table storage is initialized and aligned;
//! returned counts/lengths are checked before copying POD rows. Queries are
//! synchronous and retain no pointers. Owned process handles request only query
//! access, are noninheritable, and close on all exits. No privileges are enabled.

use crate::{ListenerOwner, PortOwnerError};
use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::AsRawSocket,
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE},
        NetworkManagement::IpHelper::{
            GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
        },
        Networking::WinSock::{
            AF_INET, AF_INET6, SO_EXCLUSIVEADDRUSE, SOCKET, SOCKET_ERROR, SOL_SOCKET,
            WSAGetLastError, setsockopt,
        },
        System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
    core::PWSTR,
};

const MAX_TABLE_BYTES: u32 = 8 * 1024 * 1024;
const TABLE_ATTEMPTS: usize = 4;

fn table(family: u32) -> Result<(Vec<u64>, usize), PortOwnerError> {
    let mut storage = vec![0_u64; 512];
    for _ in 0..TABLE_ATTEMPTS {
        let mut bytes = (storage.len() * size_of::<u64>()) as u32;
        // SAFETY: storage owns initialized, 8-byte-aligned writable bytes of the
        // supplied length. bytes is an exclusive live u32; neither pointer is
        // retained. family is AF_INET/AF_INET6 and the table class is PID_LISTENER.
        let code = unsafe {
            GetExtendedTcpTable(
                Some(storage.as_mut_ptr().cast()),
                &mut bytes,
                false,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if code == ERROR_INSUFFICIENT_BUFFER.0 {
            if bytes == 0 || bytes > MAX_TABLE_BYTES {
                return Err(PortOwnerError::InvalidTable);
            }
            storage.resize((bytes as usize).div_ceil(size_of::<u64>()), 0);
            continue;
        }
        if code != 0 {
            return Err(PortOwnerError::WindowsCall { code });
        }
        if bytes < size_of::<u32>() as u32 || bytes as usize > storage.len() * size_of::<u64>() {
            return Err(PortOwnerError::InvalidTable);
        }
        return Ok((storage, bytes as usize));
    }
    Err(PortOwnerError::WindowsCall {
        code: ERROR_INSUFFICIENT_BUFFER.0,
    })
}

pub(super) fn listener_owner(port: u16) -> Result<Option<ListenerOwner>, PortOwnerError> {
    for (family, offset, row_size) in [
        (
            AF_INET.0 as u32,
            offset_of!(MIB_TCPTABLE_OWNER_PID, table),
            size_of::<MIB_TCPROW_OWNER_PID>(),
        ),
        (
            AF_INET6.0 as u32,
            offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            size_of::<MIB_TCP6ROW_OWNER_PID>(),
        ),
    ] {
        let (storage, bytes) = table(family)?;
        // SAFETY: table checked at least four initialized bytes. The owned u64
        // allocation also satisfies u32 alignment; this copies the count only.
        let count = unsafe { storage.as_ptr().cast::<u32>().read() } as usize;
        if offset > bytes || count > (bytes - offset) / row_size {
            return Err(PortOwnerError::InvalidTable);
        }
        for index in 0..count {
            let at = offset + index * row_size;
            let (local_port, pid) = if family == AF_INET.0 as u32 {
                // SAFETY: at..at+row_size lies within the initialized table as
                // checked above. Windows' repr(C) row contains only integer POD;
                // read_unaligned copies it and never creates an aliased reference.
                let row = unsafe {
                    storage
                        .as_ptr()
                        .cast::<u8>()
                        .add(at)
                        .cast::<MIB_TCPROW_OWNER_PID>()
                        .read_unaligned()
                };
                (row.dwLocalPort, row.dwOwningPid)
            } else {
                // SAFETY: same checked byte range and POD-copy invariant as IPv4;
                // this query used AF_INET6 and the IPv6 owner-PID table layout.
                let row = unsafe {
                    storage
                        .as_ptr()
                        .cast::<u8>()
                        .add(at)
                        .cast::<MIB_TCP6ROW_OWNER_PID>()
                        .read_unaligned()
                };
                (row.dwLocalPort, row.dwOwningPid)
            };
            if u16::from_be(local_port as u16) == port && pid != std::process::id() {
                return Ok(Some(ListenerOwner {
                    pid,
                    image_name: image_name(pid),
                }));
            }
        }
    }
    Ok(None)
}

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the valid OpenProcess handle. No
        // borrowed pointer/query survives Drop and no other path closes it.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn image_name(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }
    // SAFETY: value arguments only; limited read-only query rights, no handle
    // inheritance, no privilege fallback. A successful handle gets a RAII owner.
    let process =
        Process(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?);
    let mut units = vec![0_u16; 32768];
    let mut length = units.len() as u32;
    // SAFETY: process stays open for the synchronous query; units is initialized
    // writable UTF-16 storage of length characters. Windows retains no pointers.
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(units.as_mut_ptr()),
            &mut length,
        )
    }
    .ok()?;
    let units = units.get(..length as usize)?;
    crate::name::sanitize(units)
}

pub(super) fn set_exclusive_address_use(socket: &socket2::Socket) -> io::Result<()> {
    let enabled = 1_i32.to_ne_bytes();
    // SAFETY: socket is borrowed and live for this synchronous option call;
    // enabled supplies exactly a native BOOL's initialized bytes. No ownership
    // transfer, retained pointers, bind, or privilege change occurs here.
    let result = unsafe {
        setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            Some(&enabled),
        )
    };
    if result == SOCKET_ERROR {
        // SAFETY: WSAGetLastError has no arguments and reads this thread's error
        // immediately after the failed Winsock call.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0));
    }
    Ok(())
}
