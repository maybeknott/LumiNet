//! # Raw TCP Packet Construction
//!
//! Provides structures to serialize raw TCP headers, primarily used
//! in custom stateless packet scanning probes and fake packet injection.

use std::net::IpAddr;

/// Represents a standard TCP Header (20 bytes).
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8, // e.g. 0x02 for SYN, 0x12 for SYN-ACK
    pub window: u16,
}

impl Default for TcpHeader {
    fn default() -> Self {
        Self {
            src_port: 49152,
            dst_port: 80,
            seq: 1000,
            ack: 0,
            flags: 0x02, // SYN
            window: 65535,
        }
    }
}

impl TcpHeader {
    /// Serializes the TCP header into its binary representation (20 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.seq.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.ack.to_be_bytes());
        bytes[12] = 0x50; // Data offset (5 words = 20 bytes), Reserved 0
        bytes[13] = self.flags;
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        // Checksum (offset 16..18) and Urgent pointer (offset 18..20) are left zero
        bytes
    }

    /// Computes a standard TCP checksum using a pseudo IPv4 header.
    pub fn calculate_checksum(&self, src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> u16 {
        let header_bytes = self.to_bytes();
        let mut pseudo_header = Vec::new();
        pseudo_header.extend_from_slice(&src_ip);
        pseudo_header.extend_from_slice(&dst_ip);
        pseudo_header.push(0); // Reserved byte
        pseudo_header.push(6); // Protocol: TCP (6)
        let total_len = (header_bytes.len() + payload.len()) as u16;
        pseudo_header.extend_from_slice(&total_len.to_be_bytes());

        // Accumulate pseudo header
        let mut sum = 0u32;
        for chunk in pseudo_header.chunks(2) {
            let val = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += val as u32;
        }

        // Accumulate TCP header (replacing checksum field with 0)
        for chunk in header_bytes.chunks(2) {
            if chunk.len() == 2 {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            } else {
                sum += u16::from_be_bytes([chunk[0], 0]) as u32;
            }
        }

        // Accumulate payload
        for chunk in payload.chunks(2) {
            let val = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += val as u32;
        }

        // Fold 32-bit sum to 16-bit
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }
}

/// Helper to get local IP address that would route to target IP.
fn get_local_ip(target: IpAddr) -> std::io::Result<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(std::net::SocketAddr::new(target, 1))?;
    Ok(socket.local_addr()?.ip())
}

/// Injects a spoofed fake TCP packet with a custom TTL to bypass DPI middleboxes.
pub fn send_fake_packet(
    target_ip: IpAddr,
    port: u16,
    ttl: u32,
    flags: u8,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let local_ip = get_local_ip(target_ip).unwrap_or_else(|_| {
        if target_ip.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        } else {
            IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        }
    });

    let domain = if target_ip.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::RAW, Some(socket2::Protocol::TCP))?;
    socket.set_ttl(ttl)?;

    let src_port = rand::random::<u16>().max(1024);
    let header = TcpHeader {
        src_port,
        dst_port: port,
        seq,
        ack,
        flags,
        window: 64240,
    };

    let src_bytes = match local_ip {
        IpAddr::V4(a) => a.octets(),
        _ => [127, 0, 0, 1],
    };
    let dst_bytes = match target_ip {
        IpAddr::V4(a) => a.octets(),
        _ => [127, 0, 0, 1],
    };

    let checksum = header.calculate_checksum(src_bytes, dst_bytes, payload);
    let mut header_bytes = header.to_bytes();
    header_bytes[16..18].copy_from_slice(&checksum.to_be_bytes());

    let mut packet = Vec::with_capacity(header_bytes.len() + payload.len());
    packet.extend_from_slice(&header_bytes);
    packet.extend_from_slice(payload);

    let target_addr = std::net::SocketAddr::new(target_ip, port);
    socket.send_to(&packet, &target_addr.into())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_header_serialization() {
        let header = TcpHeader {
            src_port: 1234,
            dst_port: 80,
            seq: 100,
            ack: 50,
            flags: 0x02,
            window: 8192,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 1234);
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 80);
        assert_eq!(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]), 100);
        assert_eq!(u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]), 50);
        assert_eq!(bytes[13], 0x02);
        assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 8192);
    }
}
