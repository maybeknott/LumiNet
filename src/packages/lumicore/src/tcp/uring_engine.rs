#[cfg(target_os = "linux")]
use tokio_uring::net::TcpStream;

pub struct UringTcpEngine {
    #[allow(dead_code)] // reserved for io_uring ring depth configuration
    ring_depth: u32,
}

impl UringTcpEngine {
    pub fn new(ring_depth: u32) -> Self {
        Self { ring_depth }
    }

    #[cfg(target_os = "linux")]
    pub async fn transfer(
        &self,
        local: TcpStream,
        remote: TcpStream,
    ) -> Result<(), std::io::Error> {
        async fn copy_direction(
            source: &TcpStream,
            destination: &TcpStream,
        ) -> Result<(), std::io::Error> {
            let mut buf = vec![0u8; 16384];
            loop {
                let (read_result, returned_buf) = source.read(buf).await;
                let n = read_result?;
                if n == 0 {
                    return Ok(());
                }

                let outbound = returned_buf[..n].to_vec();
                let (write_result, _outbound) = destination.write_all(outbound).await;
                write_result?;
                buf = returned_buf;
            }
        }

        // tokio-uring TcpStream is intentionally not clonable. Drive both
        // borrowed directions concurrently in the same io_uring task rather
        // than spawning ownership-duplicating Tokio tasks.
        tokio::try_join!(
            copy_direction(&local, &remote),
            copy_direction(&remote, &local),
        )?;
        Ok(())
    }
}
