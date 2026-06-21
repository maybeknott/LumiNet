//! # Stateless TCP SYN Prober
//!
//! Implements a stateless packet probing socket interface to send raw SYN packets
//! and check connection states asynchronously.

use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::SocketAddr;

/// Manages a stateless raw socket for sending custom TCP packets.
pub struct StatelessProber {
    socket: Socket,
}

impl StatelessProber {
    /// Creates a new StatelessProber instance.
    pub fn new() -> std::io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// Sends a raw TCP packet payload to the designated target address.
    pub fn send_probe(&self, target: SocketAddr, packet: &[u8]) -> std::io::Result<()> {
        self.socket.send_to(packet, &target.into())?;
        Ok(())
    }

    /// Receives a response packet from the raw socket connection.
    pub fn recv_response(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        // Safe cast from &mut [u8] to &mut [MaybeUninit<u8>]
        let maybe_uninit_buf = unsafe {
            &mut *(buf as *mut [u8] as *mut [MaybeUninit<u8>])
        };

        let (n, addr) = self.socket.recv_from(maybe_uninit_buf)?;
        let std_addr = addr.as_socket().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid socket address format")
        })?;
        Ok((n, std_addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_stateless_prober_creation() {
        // Creating raw sockets typically requires elevated OS permissions (e.g. root or Admin).
        // We test creation, and if it fails due to permission errors, we skip gracefully.
        match StatelessProber::new() {
            Ok(prober) => {
                let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
                let dummy_packet = vec![0u8; 20];
                let _ = prober.send_probe(target, &dummy_packet);
            }
            Err(e) => {
                // Ignore permission denied or unsupported protocol errors on unprivileged test environments
                println!("StatelessProber skip (expected on non-admin environments): {}", e);
            }
        }
    }
}
