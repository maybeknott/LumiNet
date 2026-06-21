//! # TCP Prober
//!
//! TCP connection probing ported from `network-lab/lab-scanner.py`'s
//! `tcp_connect`. Supports individual probes, batch connections, full port
//! scans, and service banner grabbing.

use crate::types::{PortResult, ProbeResult, ScanConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Helper to get current epoch timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Probes a single TCP endpoint by attempting a full TCP handshake.
///
/// # Arguments
/// * `target` — Target hostname or IP address.
/// * `port` — TCP port number.
/// * `timeout_ms` — Connection timeout in milliseconds.
///
/// # Returns
/// A [`ProbeResult`] indicating success/failure and connection latency.
pub async fn tcp_connect(
    target: &str,
    port: u16,
    timeout_ms: u32,
) -> Result<ProbeResult, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let addr_str = format!("{}:{}", target, port);

    // Resolve address asynchronously
    let ip = match tokio::net::lookup_host(&addr_str).await?.next() {
        Some(socket_addr) => socket_addr.ip(),
        None => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "Failed to resolve target hostname",
            )));
        }
    };

    let socket_addr = std::net::SocketAddr::new(ip, port);
    let domain = if ip.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_nonblocking(true)?;

    // Set keepalive options to detect dead connections rapidly
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(10))
        .with_interval(Duration::from_secs(2));
    let _ = socket.set_tcp_keepalive(&keepalive);

    // Connect to target address
    match socket.connect(&socket_addr.into()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(err) => return Err(Box::new(err)),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let tokio_stream = TcpStream::from_std(std_stream)?;

    // Wait for the connection to become writable
    let result = timeout(
        Duration::from_millis(timeout_ms as u64),
        tokio_stream.writable(),
    )
    .await;

    let latency = start.elapsed().as_secs_f64() * 1000.0;
    let timestamp = current_timestamp();

    match result {
        Ok(Ok(())) => {
            let sock_ref = socket2::SockRef::from(&tokio_stream);
            match sock_ref.take_error() {
                Ok(None) => Ok(ProbeResult {
                    target: target.to_string(),
                    ip: Some(ip),
                    port: Some(port),
                    success: true,
                    latency_ms: latency,
                    error: None,
                    error_code: None,
                    timestamp,
                    metadata: HashMap::new(),
                }),
                Ok(Some(err)) => Ok(ProbeResult {
                    target: target.to_string(),
                    ip: Some(ip),
                    port: Some(port),
                    success: false,
                    latency_ms: latency,
                    error: Some(err.to_string()),
                    error_code: Some("CONNECTION_FAILED".to_string()),
                    timestamp,
                    metadata: HashMap::new(),
                }),
                Err(err) => Ok(ProbeResult {
                    target: target.to_string(),
                    ip: Some(ip),
                    port: Some(port),
                    success: false,
                    latency_ms: latency,
                    error: Some(err.to_string()),
                    error_code: Some("SOCKET_ERROR".to_string()),
                    timestamp,
                    metadata: HashMap::new(),
                }),
            }
        }
        Ok(Err(err)) => Ok(ProbeResult {
            target: target.to_string(),
            ip: Some(ip),
            port: Some(port),
            success: false,
            latency_ms: latency,
            error: Some(err.to_string()),
            error_code: Some("CONNECTION_FAILED".to_string()),
            timestamp,
            metadata: HashMap::new(),
        }),
        Err(_) => Ok(ProbeResult {
            target: target.to_string(),
            ip: Some(ip),
            port: Some(port),
            success: false,
            latency_ms: latency,
            error: Some("Connection timed out".to_string()),
            error_code: Some("TIMEOUT".to_string()),
            timestamp,
            metadata: HashMap::new(),
        }),
    }
}

/// Probes multiple TCP endpoints concurrently.
///
/// # Arguments
/// * `targets` — List of `(host, port)` pairs to probe.
/// * `config` — Scan configuration (timeout, concurrency, rate limit).
pub async fn tcp_connect_batch(
    mut targets: Vec<(String, u16)>,
    config: ScanConfig,
) -> Vec<ProbeResult> {
    if config.shuffle {
        let len = targets.len();
        if len > 1 {
            let br = crate::cidr::BlackRock::new(len as u64, config.shuffle_seed, 4);
            let mut shuffled_targets = Vec::with_capacity(len);
            for i in 0..len {
                let shuffled_idx = br.shuffle(i as u64) as usize;
                shuffled_targets.push(std::mem::take(&mut targets[shuffled_idx]));
            }
            targets = shuffled_targets;
        }
    }
    let sem = Arc::new(Semaphore::new(config.max_concurrent as usize));
    let timeout_ms = config.timeout_ms;
    let mut tasks = Vec::new();

    for (target, port) in targets {
        if target.is_empty() {
            continue;
        }
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            match tcp_connect(&target, port, timeout_ms).await {
                Ok(res) => res,
                Err(err) => ProbeResult {
                    target,
                    ip: None,
                    port: Some(port),
                    success: false,
                    latency_ms: 0.0,
                    error: Some(err.to_string()),
                    error_code: Some("RESOLUTION_FAILED".to_string()),
                    timestamp: current_timestamp(),
                    metadata: HashMap::new(),
                },
            }
        }));
    }

    let mut results = Vec::new();
    for res in futures::future::join_all(tasks).await.into_iter().flatten() {
        results.push(res);
    }
    results
}

/// Performs a port scan against a single target across multiple ports.
///
/// # Arguments
/// * `target` — Target hostname or IP address.
/// * `ports` — List of ports to scan.
/// * `config` — Scan configuration.
///
/// # Returns
/// A [`PortResult`] for each port indicating open/closed status and latency.
pub async fn port_scan(target: &str, mut ports: Vec<u16>, config: ScanConfig) -> Vec<PortResult> {
    if config.shuffle {
        let len = ports.len();
        if len > 1 {
            let br = crate::cidr::BlackRock::new(len as u64, config.shuffle_seed, 4);
            let mut shuffled_ports = Vec::with_capacity(len);
            for i in 0..len {
                let shuffled_idx = br.shuffle(i as u64) as usize;
                shuffled_ports.push(ports[shuffled_idx]);
            }
            ports = shuffled_ports;
        }
    }
    let sem = Arc::new(Semaphore::new(config.max_concurrent as usize));
    let timeout_ms = config.timeout_ms;
    let target_str = target.to_string();

    let mut tasks = Vec::new();
    for port in ports {
        let sem = Arc::clone(&sem);
        let target_str = target_str.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            let start = Instant::now();
            let res = tcp_connect(&target_str, port, timeout_ms).await;
            let latency = start.elapsed().as_secs_f64() * 1000.0;

            match res {
                Ok(probe) => PortResult {
                    ip: probe.ip.map(|i| i.to_string()).unwrap_or_default(),
                    port,
                    open: probe.success,
                    protocol: "tcp".to_string(),
                    service: None,
                    latency_ms: probe.latency_ms,
                    banner: None,
                },
                Err(err) => PortResult {
                    ip: String::new(),
                    port,
                    open: false,
                    protocol: "tcp".to_string(),
                    service: None,
                    latency_ms: latency,
                    banner: Some(err.to_string()),
                },
            }
        }));
    }

    let mut results = Vec::new();
    for res in futures::future::join_all(tasks).await.into_iter().flatten() {
        results.push(res);
    }
    results
}

/// Attempts to grab a service banner from an open TCP port.
///
/// Connects to the target, optionally sends a probe string, and reads
/// whatever the server sends back within the timeout.
///
/// # Arguments
/// * `target` — Target hostname or IP address.
/// * `port` — TCP port number.
/// * `timeout_ms` — Read timeout in milliseconds.
pub async fn banner_grab(
    target: &str,
    port: u16,
    timeout_ms: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", target, port);
    let connect_future = TcpStream::connect(&addr);
    let mut stream = timeout(Duration::from_millis(timeout_ms as u64), connect_future).await??;

    // Optional: send a line feed to trigger a response if the server is quiet (e.g. HTTP, SMTP)
    let _ = stream.write_all(b"\r\n\r\n").await;

    let mut buffer = vec![0u8; 1024];
    let read_future = stream.read(&mut buffer);
    let bytes_read = timeout(Duration::from_millis(timeout_ms as u64), read_future).await??;

    if bytes_read == 0 {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Server closed connection with no banner response",
        )));
    }

    let banner = String::from_utf8_lossy(&buffer[..bytes_read])
        .trim()
        .to_string();
    Ok(banner)
}
