//! # Unix ICMP Backend
//!
//! Cross-platform raw socket ICMP implementation for non-Windows targets.
//! Constructs ICMP echo request packets manually, sends them via raw sockets,
//! and parses the replies.
//!
//! This module is only compiled on non-Windows targets.

#![cfg(not(windows))]

use std::net::IpAddr;
use std::time::Duration;

/// Parsed ICMP echo reply (Unix variant).
#[derive(Debug, Clone)]
pub struct IcmpReply {
    pub address: IpAddr,
    pub status: u32,
    pub round_trip_time: u32,
    pub data_size: u16,
}

/// Creates a raw socket suitable for ICMP (v4) or ICMPv6 echo requests.
pub fn create_raw_socket(ipv6: bool) -> Result<i32, Box<dyn std::error::Error>> {
    use libc::{socket, AF_INET, AF_INET6, IPPROTO_ICMP, IPPROTO_ICMPV6, SOCK_RAW};
    let (domain, proto) = if ipv6 {
        (AF_INET6, IPPROTO_ICMPV6)
    } else {
        (AF_INET, IPPROTO_ICMP)
    };
    let fd = unsafe { socket(domain, SOCK_RAW, proto) };
    if fd < 0 {
        return Err(format!(
            "Failed to create raw socket (errno {}). Root/CAP_NET_RAW required.",
            unsafe { *libc::__errno_location() }
        )
        .into());
    }
    Ok(fd)
}

/// Sends an ICMP echo request on the given raw socket.
pub fn send_icmp_echo(
    socket: i32,
    dest: IpAddr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use libc::{c_void, sendto, sockaddr_in, AF_INET};
    use std::mem;

    let packet = build_icmp_packet(id, seq, payload);

    match dest {
        IpAddr::V4(ipv4) => {
            let addr = sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(ipv4).to_be(),
                },
                sin_zero: [0; 8],
            };
            let ret = unsafe {
                sendto(
                    socket,
                    packet.as_ptr() as *const c_void,
                    packet.len(),
                    0,
                    &addr as *const sockaddr_in as *const libc::sockaddr,
                    mem::size_of::<sockaddr_in>() as u32,
                )
            };
            if ret < 0 {
                return Err(format!("sendto failed with errno {}", unsafe {
                    *libc::__errno_location()
                })
                .into());
            }
        }
        IpAddr::V6(_) => {
            return Err("IPv6 ICMP not yet implemented on Unix".into());
        }
    }
    Ok(())
}

/// Receives an ICMP echo reply from the given raw socket.
pub fn recv_icmp_reply(socket: i32, timeout: u32) -> Result<IcmpReply, Box<dyn std::error::Error>> {
    use libc::{c_void, recvfrom, setsockopt, sockaddr_in, timeval, SOL_SOCKET, SO_RCVTIMEO};
    use std::mem;

    // Set receive timeout
    let tv = timeval {
        tv_sec: (timeout / 1000) as i64,
        tv_usec: ((timeout % 1000) * 1000) as i64,
    };
    unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &tv as *const timeval as *const c_void,
            mem::size_of::<timeval>() as u32,
        );
    }

    let mut buf = vec![0u8; 1500];
    let mut src_addr: sockaddr_in = unsafe { mem::zeroed() };
    let mut addr_len = mem::size_of::<sockaddr_in>() as u32;

    let n = unsafe {
        recvfrom(
            socket,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            0,
            &mut src_addr as *mut sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
        )
    };

    if n < 0 {
        return Err(format!("recvfrom failed with errno {}", unsafe {
            *libc::__errno_location()
        })
        .into());
    }

    buf.truncate(n as usize);
    parse_icmp_reply(&buf)
}

/// Builds a complete ICMP echo request packet.
pub fn build_icmp_packet(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + payload.len());
    // Type=8 (echo request), Code=0
    packet.push(8u8);
    packet.push(0u8);
    // Checksum placeholder
    packet.push(0u8);
    packet.push(0u8);
    // Identifier
    packet.push((id >> 8) as u8);
    packet.push((id & 0xFF) as u8);
    // Sequence number
    packet.push((seq >> 8) as u8);
    packet.push((seq & 0xFF) as u8);
    // Payload
    packet.extend_from_slice(payload);

    // Compute and fill checksum
    let cksum = checksum(&packet);
    packet[2] = (cksum >> 8) as u8;
    packet[3] = (cksum & 0xFF) as u8;

    packet
}

/// Parses a raw ICMP echo reply packet.
pub fn parse_icmp_reply(buf: &[u8]) -> Result<IcmpReply, Box<dyn std::error::Error>> {
    // IP header is typically 20 bytes; ICMP starts after
    if buf.len() < 28 {
        return Err("ICMP reply too short".into());
    }

    let ip_header_len = ((buf[0] & 0x0F) * 4) as usize;
    if buf.len() < ip_header_len + 8 {
        return Err("ICMP reply truncated".into());
    }

    let icmp = &buf[ip_header_len..];
    let icmp_type = icmp[0];
    // Type 0 = echo reply
    if icmp_type != 0 {
        return Err(format!("Not an ICMP echo reply (type={})", icmp_type).into());
    }

    // Extract source IP from IP header
    let src_ip = std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);

    Ok(IcmpReply {
        address: IpAddr::V4(src_ip),
        status: 0,
        round_trip_time: 0, // Caller measures RTT externally
        data_size: (buf.len() - ip_header_len - 8) as u16,
    })
}

/// Computes the Internet Checksum (RFC 1071).
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
