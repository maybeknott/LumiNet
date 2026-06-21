//! Windows ICMP implementation via iphlpapi.dll.
//!
//! Ported from: `ping/web/backend/scanner.py` — ctypes iphlpapi bindings
//!
//! Uses IcmpSendEcho2 with async events for non-blocking ICMP.
//! WaitForMultipleObjects polls up to 64 handles at once;
//! a rotating window strategy handles >64 in-flight pings.

#![cfg(windows)]
#![allow(dead_code)]

use crate::types::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::System::Threading::*;

// ─── ICMP Reply Structures ──────────────────────────────────────

/// Mirrors ICMP_ECHO_REPLY from Windows API.
///
/// Ported from scanner.py's ICMP_ECHO_REPLY ctypes.Structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IcmpEchoReply {
    pub address: u32,
    pub status: u32,
    pub round_trip_time: u32,
    pub data_size: u16,
    pub reserved: u16,
    pub data: *const u8,
    pub options: IpOptionInformation,
}

/// IP_OPTION_INFORMATION structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IpOptionInformation {
    pub ttl: u8,
    pub tos: u8,
    pub flags: u8,
    pub options_size: u8,
    pub options_data: *const u8,
}

/// ICMPv6 echo reply for IPv6 targets.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6EchoReply {
    pub address: Sockaddr6,
    pub status: u32,
    pub round_trip_time: u32,
}

/// IPv6 socket address.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Sockaddr6 {
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

// ─── Handle Management ──────────────────────────────────────────

/// Create an ICMP handle for IPv4.
pub fn icmp_create_file() -> LumiResult<HANDLE> {
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        return Err(LumiError::Network("IcmpCreateFile failed".to_string()));
    }
    Ok(handle)
}

/// Create an ICMPv6 handle for IPv6.
pub fn icmp6_create_file() -> LumiResult<HANDLE> {
    let handle = unsafe { Icmp6CreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        return Err(LumiError::Network("Icmp6CreateFile failed".to_string()));
    }
    Ok(handle)
}

/// Close an ICMP handle.
pub fn icmp_close_handle(handle: HANDLE) -> LumiResult<()> {
    let ok = unsafe { IcmpCloseHandle(handle) };
    if ok == 0 {
        return Err(LumiError::Network("IcmpCloseHandle failed".to_string()));
    }
    Ok(())
}

// ─── Async ICMP Send ────────────────────────────────────────────

/// Send an async ICMP echo request using IcmpSendEcho2.
pub fn send_icmp_async(
    handle: HANDLE,
    dest: Ipv4Addr,
    timeout_ms: u32,
    event: HANDLE,
    reply_buffer: &mut [u8],
) -> LumiResult<()> {
    let dest_addr = u32::from(dest).to_be();
    let payload = b"LumiNet";

    let ret = unsafe {
        IcmpSendEcho2(
            handle,
            event,
            None,
            std::ptr::null_mut(),
            dest_addr,
            payload.as_ptr() as *const std::ffi::c_void,
            payload.len() as u16,
            std::ptr::null_mut(),
            reply_buffer.as_mut_ptr() as *mut std::ffi::c_void,
            reply_buffer.len() as u32,
            timeout_ms,
        )
    };

    // IcmpSendEcho2 with an event returns 0 and sets ERROR_IO_PENDING for async
    if ret == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if err != windows_sys::Win32::Foundation::ERROR_IO_PENDING {
            return Err(LumiError::Network(format!(
                "IcmpSendEcho2 failed with error {}",
                err
            )));
        }
    }
    Ok(())
}

/// Send an async ICMPv6 echo request using Icmp6SendEcho2.
pub fn send_icmp6_async(
    handle: HANDLE,
    source: Ipv6Addr,
    dest: Ipv6Addr,
    timeout_ms: u32,
    event: HANDLE,
    reply_buffer: &mut [u8],
) -> LumiResult<()> {
    use std::mem;
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

    let mut src_addr: SOCKADDR_IN6 = unsafe { mem::zeroed() };
    src_addr.sin6_family = AF_INET6;
    src_addr.sin6_addr.u.Byte = source.octets();

    let mut dst_addr: SOCKADDR_IN6 = unsafe { mem::zeroed() };
    dst_addr.sin6_family = AF_INET6;
    dst_addr.sin6_addr.u.Byte = dest.octets();

    let payload = b"LumiNet";

    let ret = unsafe {
        Icmp6SendEcho2(
            handle,
            event,
            None,
            std::ptr::null_mut(),
            &src_addr as *const SOCKADDR_IN6 as *mut _,
            &dst_addr as *const SOCKADDR_IN6 as *mut _,
            payload.as_ptr() as *const std::ffi::c_void,
            payload.len() as u16,
            std::ptr::null_mut(),
            reply_buffer.as_mut_ptr() as *mut std::ffi::c_void,
            reply_buffer.len() as u32,
            timeout_ms,
        )
    };

    if ret == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if err != windows_sys::Win32::Foundation::ERROR_IO_PENDING {
            return Err(LumiError::Network(format!(
                "Icmp6SendEcho2 failed with error {}",
                err
            )));
        }
    }
    Ok(())
}

// ─── Completion Polling ─────────────────────────────────────────

/// Wait for multiple ICMP replies using WaitForMultipleObjects.
/// Returns indices of signaled events.
pub fn wait_for_replies(events: &[HANDLE], timeout_ms: u32) -> Vec<usize> {
    if events.is_empty() {
        return vec![];
    }

    // Windows limits WaitForMultipleObjects to MAXIMUM_WAIT_OBJECTS (64)
    const MAX_WAIT: usize = 64;
    let mut signaled = Vec::new();

    for chunk_start in (0..events.len()).step_by(MAX_WAIT) {
        let chunk_end = (chunk_start + MAX_WAIT).min(events.len());
        let chunk = &events[chunk_start..chunk_end];

        let ret = unsafe {
            WaitForMultipleObjects(
                chunk.len() as u32,
                chunk.as_ptr(),
                0, // bWaitAll = FALSE
                timeout_ms,
            )
        };

        const WAIT_OBJECT_0: u32 = 0;
        const WAIT_TIMEOUT: u32 = 0x00000102;
        const WAIT_FAILED: u32 = 0xFFFFFFFF;

        if ret == WAIT_TIMEOUT || ret == WAIT_FAILED {
            continue;
        }

        // ret is the index of the first signaled object
        let idx = (ret - WAIT_OBJECT_0) as usize;
        if idx < chunk.len() {
            signaled.push(chunk_start + idx);
        }
    }

    signaled
}

/// Parse an ICMP echo reply from a reply buffer.
pub fn parse_reply(buffer: &[u8]) -> LumiResult<IcmpEchoReply> {
    if buffer.len() < std::mem::size_of::<IcmpEchoReply>() {
        return Err(LumiError::Network(
            "ICMP reply buffer too small".to_string(),
        ));
    }
    let reply = unsafe { *(buffer.as_ptr() as *const IcmpEchoReply) };
    Ok(reply)
}

/// Parse an ICMPv6 echo reply from a reply buffer.
pub fn parse_reply6(buffer: &[u8]) -> LumiResult<Icmpv6EchoReply> {
    if buffer.len() < std::mem::size_of::<Icmpv6EchoReply>() {
        return Err(LumiError::Network(
            "ICMPv6 reply buffer too small".to_string(),
        ));
    }
    let reply = unsafe { *(buffer.as_ptr() as *const Icmpv6EchoReply) };
    Ok(reply)
}

// ─── ARP Resolution ─────────────────────────────────────────────

/// Resolve MAC address for an IPv4 address using SendARP.
pub fn send_arp(dest: Ipv4Addr) -> LumiResult<[u8; 6]> {
    let dest_ip = u32::from(dest).to_be();
    let mut mac_addr: u64 = 0;
    let mut mac_len: u32 = 6;

    let ret = unsafe {
        SendARP(
            dest_ip,
            0,
            &mut mac_addr as *mut u64 as *mut std::ffi::c_void,
            &mut mac_len,
        )
    };

    if ret != 0 {
        return Err(LumiError::Network(format!(
            "SendARP failed with error {}",
            ret
        )));
    }

    let bytes = mac_addr.to_le_bytes();
    Ok([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]])
}

/// Format MAC address bytes as colon-separated string.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

// ─── Event Handle Management ────────────────────────────────────

/// Create a manual-reset kernel event for async ICMP.
pub fn create_event() -> LumiResult<HANDLE> {
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(LumiError::Network("CreateEventW failed".to_string()));
    }
    Ok(handle)
}

/// Close a kernel event handle.
pub fn close_event(handle: HANDLE) -> LumiResult<()> {
    let ok = unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(LumiError::Network("CloseHandle failed".to_string()));
    }
    Ok(())
}

/// Reset an event to non-signaled state.
pub fn reset_event(handle: HANDLE) -> LumiResult<()> {
    let ok = unsafe { ResetEvent(handle) };
    if ok == 0 {
        return Err(LumiError::Network("ResetEvent failed".to_string()));
    }
    Ok(())
}
