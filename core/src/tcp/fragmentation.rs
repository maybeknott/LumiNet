//! # TCP Segment Fragmentation Writer
//!
//! Splices and writes TCP payloads across multiple small segments
//! with brief delays to desynchronize DPI pattern detection.

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// Wraps a standard TcpStream to write fragmented data segments.
pub struct FragmentedWriter<'a> {
    stream: &'a mut TcpStream,
    min_size: usize,
    max_size: usize,
    delay: Duration,
}

impl<'a> FragmentedWriter<'a> {
    /// Creates a new FragmentedWriter.
    pub fn new(stream: &'a mut TcpStream, min_size: usize, max_size: usize, delay_ms: u64) -> Self {
        let min_size = if min_size == 0 { 1 } else { min_size };
        let max_size = if max_size < min_size { min_size } else { max_size };
        Self {
            stream,
            min_size,
            max_size,
            delay: Duration::from_millis(delay_ms),
        }
    }

    /// Writes the payload using fragmented TCP segment splits and brief delays.
    pub fn write_fragmented(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut offset = 0;
        let mut rng_val = 137u32; // simple deterministic generator for LCG range fallback

        while offset < buf.len() {
            // Determine random chunk size between min_size and max_size
            let range = (self.max_size - self.min_size) + 1;
            rng_val = rng_val.wrapping_mul(1103515245).wrapping_add(12345);
            let size_offset = (rng_val as usize) % range;
            let chunk_size = self.min_size + size_offset;

            let limit = std::cmp::min(buf.len() - offset, chunk_size);
            self.stream.write_all(&buf[offset..offset + limit])?;
            self.stream.flush()?;
            
            offset += limit;

            // Pause if there is more data to send
            if offset < buf.len() && !self.delay.is_zero() {
                std::thread::sleep(self.delay);
            }
        }

        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;

    #[test]
    fn test_fragmented_write() {
        // Bind to localhost port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            conn.read_to_end(&mut buf).unwrap();
            buf
        });

        // Client connects and drops within block scope
        {
            let mut client = TcpStream::connect(server_addr).unwrap();
            let mut writer = FragmentedWriter::new(&mut client, 2, 5, 2);
            let payload = b"Hello fragmented TCP world!";
            let written = writer.write_fragmented(payload).unwrap();
            assert_eq!(written, payload.len());
        } // client is dropped here, closing the socket and sending EOF to the server thread

        let received = handle.join().unwrap();
        assert_eq!(received, b"Hello fragmented TCP world!");
    }
}
