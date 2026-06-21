//! # SOCKS Evasion Utilities
//!
//! TCP segment splitting obfuscation ported from `MasterHttpRelayVPN-RUST`
//! to bypass deep packet inspection (DPI) signature classifiers.

use std::io::Write;
use std::net::TcpStream;

/// Writes a data buffer to a TCP stream using segment splitting with a delay
/// to evade deep packet inspection sensors that check the first few bytes.
pub fn write_with_evasion(stream: &mut TcpStream, data: &[u8], offset: usize) -> std::io::Result<()> {
    if data.len() > offset && offset > 0 {
        // Split write buffer into two segments with a slight delay
        stream.write_all(&data[0..offset])?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        stream.write_all(&data[offset..])?;
    } else {
        stream.write_all(data)?;
    }
    Ok(())
}
