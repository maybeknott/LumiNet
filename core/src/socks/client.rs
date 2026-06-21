//! # SOCKS5 / HTTP Proxy Client
//!
//! SOCKS5 handshake probing and tunneling ported from
//! `network-lab/lab-scanner.py`'s `socks5_handshake`. Also supports
//! HTTP CONNECT proxy probing and local proxy auto-discovery.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::types::ProbeResult;

/// Information about a discovered local proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDiscovery {
    /// Proxy listen address (usually `127.0.0.1` or `[::1]`).
    pub address: String,
    /// Proxy listen port.
    pub port: u16,
    /// Detected proxy protocol (`"socks5"`, `"http"`, `"https"`).
    pub protocol: String,
    /// Handshake latency in milliseconds.
    pub latency_ms: f64,
}

fn current_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Performs a SOCKS5 handshake probe without connecting to a destination.
pub async fn socks5_handshake(
    proxy: &str,
    port: u16,
    timeout_ms: u32,
) -> Result<ProbeResult, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", proxy, port);
    let start = Instant::now();

    let connect = TcpStream::connect(&addr);
    let mut stream = timeout(Duration::from_millis(timeout_ms as u64), connect).await??;

    // SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut resp = [0u8; 2];
    timeout(
        Duration::from_millis(timeout_ms as u64),
        stream.read_exact(&mut resp),
    )
    .await??;

    let latency = start.elapsed().as_secs_f64() * 1000.0;

    // VER=5, METHOD=0 (no auth) or METHOD=2 (username/password)
    let success = resp[0] == 0x05 && (resp[1] == 0x00 || resp[1] == 0x02);

    let mut meta = HashMap::new();
    meta.insert("socks_version".to_string(), format!("{}", resp[0]));
    meta.insert("auth_method".to_string(), format!("{}", resp[1]));

    Ok(ProbeResult {
        target: addr,
        ip: None,
        port: Some(port),
        success,
        latency_ms: latency,
        error: if success {
            None
        } else {
            Some(format!("Unexpected SOCKS5 response: {:?}", resp))
        },
        error_code: if success {
            None
        } else {
            Some("SOCKS5_HANDSHAKE_FAILED".to_string())
        },
        timestamp: current_ts(),
        metadata: meta,
    })
}

/// Establishes a full SOCKS5 tunnel to a destination through the proxy.
pub async fn socks5_connect(
    proxy: &str,
    port: u16,
    dest_host: &str,
    dest_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", proxy, port);
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;

    // Greeting
    timeout(Duration::from_secs(5), stream.write_all(&[0x05, 0x01, 0x00])).await??;
    let mut resp = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut resp)).await??;
    if resp[0] != 0x05 || resp[1] != 0x00 {
        return Err(format!("SOCKS5 auth negotiation failed: {:?}", resp).into());
    }

    // CONNECT request
    let host_bytes = dest_host.as_bytes();
    let mut req = vec![
        0x05, // VER
        0x01, // CMD = CONNECT
        0x00, // RSV
        0x03, // ATYP = domain name
        host_bytes.len() as u8,
    ];
    req.extend_from_slice(host_bytes);
    req.push((dest_port >> 8) as u8);
    req.push((dest_port & 0xFF) as u8);
    timeout(Duration::from_secs(5), stream.write_all(&req)).await??;

    // Read response
    let mut reply = [0u8; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await??;
    if reply[1] != 0x00 {
        return Err(format!("SOCKS5 CONNECT failed with code: {}", reply[1]).into());
    }

    // Skip the bound address
    match reply[3] {
        0x01 => {
            let mut _addr = [0u8; 6];
            timeout(Duration::from_secs(5), stream.read_exact(&mut _addr)).await??;
        }
        0x03 => {
            let mut len = [0u8; 1];
            timeout(Duration::from_secs(5), stream.read_exact(&mut len)).await??;
            let mut _addr = vec![0u8; len[0] as usize + 2];
            timeout(Duration::from_secs(5), stream.read_exact(&mut _addr)).await??;
        }
        0x04 => {
            let mut _addr = [0u8; 18];
            timeout(Duration::from_secs(5), stream.read_exact(&mut _addr)).await??;
        }
        _ => {}
    }

    Ok(stream)
}

/// Probes an HTTP CONNECT proxy by sending a CONNECT request.
pub async fn http_proxy_connect(
    proxy: &str,
    port: u16,
    dest: &str,
    timeout_ms: u32,
) -> Result<ProbeResult, Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", proxy, port);
    let start = Instant::now();

    let connect = TcpStream::connect(&addr);
    let mut stream = timeout(Duration::from_millis(timeout_ms as u64), connect).await??;

    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\n\r\n",
        dest, dest
    );
    stream.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 256];
    let n = timeout(
        Duration::from_millis(timeout_ms as u64),
        stream.read(&mut buf),
    )
    .await??;
    let latency = start.elapsed().as_secs_f64() * 1000.0;

    let response = String::from_utf8_lossy(&buf[..n]);
    let success = response.contains("200");

    Ok(ProbeResult {
        target: addr,
        ip: None,
        port: Some(port),
        success,
        latency_ms: latency,
        error: if success {
            None
        } else {
            Some(format!(
                "HTTP CONNECT failed: {}",
                response.lines().next().unwrap_or("")
            ))
        },
        error_code: if success {
            None
        } else {
            Some("HTTP_CONNECT_FAILED".to_string())
        },
        timestamp: current_ts(),
        metadata: HashMap::new(),
    })
}

/// Discovers local proxy services by probing common proxy ports on localhost.
pub async fn discover_local_proxies(ports: Vec<u16>) -> Vec<ProxyDiscovery> {
    let mut discovered = Vec::new();

    for port in ports {
        // Try SOCKS5
        if let Ok(result) = socks5_handshake("127.0.0.1", port, 500).await {
            if result.success {
                discovered.push(ProxyDiscovery {
                    address: "127.0.0.1".to_string(),
                    port,
                    protocol: "socks5".to_string(),
                    latency_ms: result.latency_ms,
                });
                continue;
            }
        }

        // Try HTTP CONNECT
        if let Ok(result) = http_proxy_connect("127.0.0.1", port, "example.com:80", 500).await {
            if result.success {
                discovered.push(ProxyDiscovery {
                    address: "127.0.0.1".to_string(),
                    port,
                    protocol: "http".to_string(),
                    latency_ms: result.latency_ms,
                });
            }
        }
    }

    discovered
}
