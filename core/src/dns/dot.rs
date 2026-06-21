//! # DNS over TLS (DoT)
//!
//! DNS resolution over TLS (port 853) for encrypted DNS queries to
//! well-known DoT-capable resolvers.

use crate::dns::packet::{build_query, parse_response};
use crate::types::DnsRecord;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

/// Well-known DNS-over-TLS server endpoints as `(host, port)` tuples.
pub const DOT_SERVERS: &[(&str, u16)] = &[
    ("1.1.1.1", 853),
    ("1.0.0.1", 853),
    ("8.8.8.8", 853),
    ("8.8.4.4", 853),
    ("9.9.9.9", 853),
    ("149.112.112.112", 853),
    ("dns.adguard.com", 853),
    ("dot.xfinity.com", 853),
];

/// Resolves a DNS query using DNS-over-TLS.
pub async fn resolve_dot(
    server: &str,
    port: u16,
    domain: &str,
    record_type: u16,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let server = server.to_string();
    let domain = domain.to_string();

    // Run blocking TLS I/O on the blocking thread pool
    let result = tokio::task::spawn_blocking(move || -> Result<Vec<DnsRecord>, String> {
        let txid: u16 = rand::random();
        let query = build_query(&domain, record_type, txid);

        // Prefix with 2-byte length (TCP DNS wire format)
        let mut msg = Vec::with_capacity(2 + query.len());
        msg.push((query.len() >> 8) as u8);
        msg.push((query.len() & 0xFF) as u8);
        msg.extend_from_slice(&query);

        let addr = format!("{}:{}", server, port);
        use std::net::ToSocketAddrs;
        let addrs = addr.to_socket_addrs()
            .map_err(|e| format!("invalid address/hostname: {}", e))?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err("no socket address resolved".to_string());
        }

        let tcp = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;

        // Build rustls client config trusting webpki roots
        // Build rustls client config trusting webpki roots
        static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
        let config = CONFIG.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            )
        });

        let server_name: rustls::pki_types::ServerName<'static> =
            rustls::pki_types::ServerName::try_from(server.clone())
                .map_err(|_| format!("invalid server name: {}", server))?;

        let mut conn =
            rustls::ClientConnection::new(config.clone(), server_name).map_err(|e| e.to_string())?;
        let mut tcp2 = tcp.try_clone().map_err(|e| e.to_string())?;
        let mut tls_stream = rustls::Stream::new(&mut conn, &mut tcp2);

        tls_stream.write_all(&msg).map_err(|e| e.to_string())?;
        tls_stream.flush().map_err(|e| e.to_string())?;

        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        tls_stream
            .read_exact(&mut len_buf)
            .map_err(|e| e.to_string())?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tls_stream
            .read_exact(&mut resp_buf)
            .map_err(|e| e.to_string())?;

        parse_response(&resp_buf).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("task join error: {}", e))?;

    result.map_err(Box::<dyn std::error::Error>::from)
}
