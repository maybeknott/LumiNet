//! # DNS over UDP
//!
//! Traditional DNS resolution over UDP port 53. Supports single queries,
//! batch resolution, and DNS server benchmarking.

use crate::dns::packet::{build_query, parse_response, TYPE_A};
use crate::types::DnsRecord;
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Result of probing a single DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerResult {
    /// DNS server address (IP or hostname).
    pub server: String,
    /// Query latency in milliseconds.
    pub latency_ms: f64,
    /// Whether the query was successful.
    pub success: bool,
    /// Records returned by the server (if successful).
    pub records: Vec<DnsRecord>,
    /// Error message (if the query failed).
    pub error: Option<String>,
}

/// Resolves a single DNS query over UDP.
pub async fn resolve(
    server: &str,
    domain: &str,
    record_type: u16,
    timeout_ms: u32,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let server_addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{}:53", server)
    };

    let txid: u16 = rand::random();
    let query = build_query(domain, record_type, txid);

    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    
    tokio::time::timeout(
        Duration::from_millis(timeout_ms as u64),
        socket.send_to(&query, &server_addr)
    ).await??;

    let mut buf = vec![0u8; 512];
    let (len, _) = tokio::time::timeout(
        Duration::from_millis(timeout_ms as u64),
        socket.recv_from(&mut buf)
    ).await??;
    
    buf.truncate(len);

    // Verify transaction ID to prevent spoofing and ensure response matches the query
    if buf.len() >= 2 {
        let resp_txid = u16::from_be_bytes([buf[0], buf[1]]);
        if resp_txid != txid {
            return Err(format!("DNS Transaction ID mismatch: expected {}, got {}", txid, resp_txid).into());
        }
    } else {
        return Err("DNS response too short to verify Transaction ID".into());
    }

    let records = parse_response(&buf)?;
    Ok(records)
}

/// Resolves multiple domains against the same DNS server concurrently.
pub async fn resolve_batch(
    server: &str,
    domains: Vec<String>,
    record_type: u16,
) -> Vec<Result<Vec<DnsRecord>, Box<dyn std::error::Error>>> {
    let server = server.to_string();
    let futures: Vec<_> = domains
        .into_iter()
        .map(|domain| {
            let srv = server.clone();
            async move { resolve(&srv, &domain, record_type, 3000).await }
        })
        .collect();
    join_all(futures).await
}

/// Benchmarks multiple DNS servers by resolving a test domain on each.
pub async fn scan_dns_servers(servers: Vec<String>, test_domain: &str) -> Vec<DnsServerResult> {
    let test_domain = test_domain.to_string();
    let futures: Vec<_> = servers
        .into_iter()
        .map(|server| {
            let domain = test_domain.clone();
            async move {
                let start = Instant::now();
                match resolve(&server, &domain, TYPE_A, 3000).await {
                    Ok(records) => DnsServerResult {
                        server,
                        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                        success: true,
                        records,
                        error: None,
                    },
                    Err(e) => DnsServerResult {
                        server,
                        latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                        success: false,
                        records: vec![],
                        error: Some(e.to_string()),
                    },
                }
            }
        })
        .collect();
    join_all(futures).await
}
