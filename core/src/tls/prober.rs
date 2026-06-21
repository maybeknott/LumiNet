//! # TLS Prober
//!
//! TLS handshake probing ported from `network-lab/lab-scanner.py`'s
//! `tls_handshake_detailed`. Performs TLS handshakes to extract certificate
//! information, negotiated protocol details, and detects SSL/TLS inspection
//! (MITM proxies).

use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::types::{ScanConfig, TlsInfo};

/// Result of SSL/TLS inspection (MITM) detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInspectionResult {
    /// Whether SSL inspection was detected.
    pub detected: bool,
    /// Human-readable description of the evidence found.
    pub evidence: String,
    /// Confidence score from 0.0 (no evidence) to 1.0 (certain).
    pub confidence: f32,
}

/// Performs a TLS handshake and extracts certificate and protocol details.
pub async fn tls_handshake(
    host: &str,
    port: u16,
    sni: &str,
    timeout_ms: u32,
) -> Result<TlsInfo, Box<dyn std::error::Error>> {
    let host = host.to_string();
    let sni = sni.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<TlsInfo, String> {
        let addr = format!("{}:{}", host, port);
        use std::net::ToSocketAddrs;
        let addrs = addr.to_socket_addrs()
            .map_err(|e| format!("invalid address/hostname: {}", e))?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err("no socket address resolved".to_string());
        }

        let tcp = TcpStream::connect_timeout(&addrs[0], Duration::from_millis(timeout_ms as u64))
            .map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
            .map_err(|e| e.to_string())?;

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
            rustls::pki_types::ServerName::try_from(sni.clone())
                .map_err(|_| format!("invalid SNI: {}", sni))?;

        let start = Instant::now();
        let mut conn =
            rustls::ClientConnection::new(config.clone(), server_name).map_err(|e| e.to_string())?;
        let mut tcp2 = tcp.try_clone().map_err(|e| e.to_string())?;
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp2);

        // Trigger handshake
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n");
        let _ = stream.flush();
        let mut buf = [0u8; 256];
        let _ = stream.read(&mut buf);

        let _latency = start.elapsed().as_secs_f64() * 1000.0;

        // Extract certificate info
        let peer_certs = conn.peer_certificates();
        let mut issuer = String::from("Unknown");
        let mut subject = String::from("Unknown");
        let mut not_before = String::new();
        let mut not_after = String::new();
        let mut serial_number = String::new();
        let mut san_domains: Vec<String> = Vec::new();
        let mut chain_length = 0;
        let mut fingerprint_sha256 = String::new();

        if let Some(certs) = peer_certs {
            chain_length = certs.len();
            if let Some(cert) = certs.first() {
                fingerprint_sha256 = sha256_hex(cert.as_ref());
                if let Ok(info) = parse_cert_basic(cert.as_ref()) {
                    issuer = info.issuer;
                    subject = info.subject;
                    not_before = info.not_before;
                    not_after = info.not_after;
                    serial_number = info.serial;
                    san_domains = info.san_domains;
                }
            }
        }

        let version = match conn.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".to_string(),
            Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".to_string(),
            Some(v) => format!("{:?}", v),
            None => "Unknown".to_string(),
        };

        let cipher_suite = conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()))
            .unwrap_or_else(|| "Unknown".to_string());

        let alpn = conn
            .alpn_protocol()
            .map(|p| vec![String::from_utf8_lossy(p).to_string()])
            .unwrap_or_default();

        Ok(TlsInfo {
            version,
            cipher_suite,
            issuer,
            subject,
            not_before,
            not_after,
            serial_number,
            alpn,
            san_domains,
            fingerprint_sha256,
            chain_length,
            ocsp_stapled: false,
        })
    })
    .await
    .map_err(|e| format!("task join: {}", e))?;

    result.map_err(Box::<dyn std::error::Error>::from)
}

/// Performs TLS handshakes against multiple targets concurrently.
pub async fn tls_handshake_batch(
    targets: Vec<(String, String)>,
    config: ScanConfig,
) -> Vec<Result<TlsInfo, Box<dyn std::error::Error>>> {
    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent as usize));
    let timeout_ms = config.timeout_ms;

    let futures: Vec<_> = targets
        .into_iter()
        .map(|(host, sni)| {
            let sem = Arc::clone(&sem);
            async move {
                let _permit = sem.acquire().await.ok();
                tls_handshake(&host, 443, &sni, timeout_ms).await
            }
        })
        .collect();

    join_all(futures).await
}

/// Detects SSL/TLS inspection (MITM proxying) by analyzing certificate details.
pub fn detect_ssl_inspection(info: &TlsInfo, expected_issuer: Option<&str>) -> SslInspectionResult {
    // Known corporate/AV proxy issuer patterns
    let proxy_patterns = [
        "Cisco",
        "Palo Alto",
        "Fortinet",
        "Zscaler",
        "BlueCoat",
        "Symantec",
        "McAfee",
        "Kaspersky",
        "ESET",
        "Avast",
        "Bitdefender",
        "Sophos",
        "Checkpoint",
        "Barracuda",
        "WatchGuard",
        "SonicWall",
        "Trend Micro",
        "Fiddler",
        "Charles",
        "mitmproxy",
        "Burp Suite",
    ];

    let issuer_lower = info.issuer.to_lowercase();
    let mut evidence_parts: Vec<String> = Vec::new();
    let mut confidence: f32 = 0.0;

    // Check against known proxy issuers
    for pattern in &proxy_patterns {
        if issuer_lower.contains(&pattern.to_lowercase()) {
            evidence_parts.push(format!(
                "Issuer matches known proxy/AV vendor: '{}'",
                pattern
            ));
            confidence = (confidence + 0.7).min(1.0);
        }
    }

    // Check if issuer matches expected
    if let Some(expected) = expected_issuer {
        if !info.issuer.contains(expected) {
            evidence_parts.push(format!(
                "Issuer mismatch: expected '{}', got '{}'",
                expected, info.issuer
            ));
            confidence = (confidence + 0.5).min(1.0);
        }
    }

    // Self-signed or short chain is suspicious
    if info.chain_length <= 1 {
        evidence_parts.push("Certificate chain length is 1 (possibly self-signed)".to_string());
        confidence = (confidence + 0.3).min(1.0);
    }

    // No OCSP stapling on a supposedly major CA cert is mildly suspicious
    if !info.ocsp_stapled && confidence > 0.3 {
        evidence_parts.push("No OCSP stapling detected".to_string());
        confidence = (confidence + 0.1).min(1.0);
    }

    let detected = confidence >= 0.5;
    let evidence = if evidence_parts.is_empty() {
        "No signs of SSL inspection detected".to_string()
    } else {
        evidence_parts.join("; ")
    };

    SslInspectionResult {
        detected,
        evidence,
        confidence,
    }
}

// ─── Internal helpers ────────────────────────────────────────────

struct CertInfo {
    issuer: String,
    subject: String,
    not_before: String,
    not_after: String,
    serial: String,
    san_domains: Vec<String>,
}

/// Extracts the X.509 validity dates from a DER-encoded certificate.
fn extract_validity(der: &[u8]) -> Option<(String, String)> {
    let mut times = Vec::new();
    let mut idx = 0;
    while idx + 2 < der.len() {
        let tag = der[idx];
        let len = der[idx + 1] as usize;
        if ((tag == 0x17 && len == 13) || (tag == 0x18 && len == 15)) && (idx + 2 + len <= der.len()) {
            let bytes = &der[idx + 2..idx + 2 + len];
                if bytes.iter().take(len - 1).all(|&b| b.is_ascii_digit()) && bytes[len - 1] == b'Z' {
                    if let Ok(s) = String::from_utf8(bytes.to_vec()) {
                        let formatted = if tag == 0x17 {
                            let yy = s[0..2].parse::<u32>().unwrap_or(0);
                            let yyyy = if yy >= 50 { 1900 + yy } else { 2000 + yy };
                            format!("{}-{}-{}T{}:{}:{}Z", yyyy, &s[2..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12])
                        } else {
                            format!("{}-{}-{}T{}:{}:{}Z", &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14])
                        };
                        times.push(formatted);
                    }
                }
            }
        idx += 1;
    }
    if times.len() >= 2 {
        Some((times[0].clone(), times[1].clone()))
    } else {
        None
    }
}

/// Minimal DER certificate parser to extract human-readable fields.
/// This is a best-effort parser; for production use a full ASN.1 library.
fn parse_cert_basic(der: &[u8]) -> Result<CertInfo, Box<dyn std::error::Error>> {
    // We use a simple heuristic: scan for printable strings that look like
    // CN=, O=, OU= patterns in the DER blob.
    let text = String::from_utf8_lossy(der);

    let _extract_field = |prefix: &str| -> String {
        // Look for the prefix in the raw bytes as ASCII
        let needle = prefix.as_bytes();
        for i in 0..der.len().saturating_sub(needle.len() + 1) {
            if &der[i..i + needle.len()] == needle {
                let start = i + needle.len();
                let end = der[start..]
                    .iter()
                    .position(|&b| b == 0 || !(0x20..=0x7E).contains(&b))
                    .map(|p| start + p)
                    .unwrap_or((start + 64).min(der.len()));
                let s = String::from_utf8_lossy(&der[start..end]).to_string();
                if !s.is_empty() {
                    return s;
                }
            }
        }
        String::new()
    };

    // Extract serial number from first few bytes after the outer SEQUENCE
    let serial = if der.len() > 20 {
        der[4..12.min(der.len())]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("")
    } else {
        String::new()
    };

    // Try to find CN= patterns
    let cn_bytes = b"CN=";
    let mut subjects = Vec::new();
    let mut issuers = Vec::new();
    let mut found_first = false;

    let mut i = 0;
    while i + 3 < der.len() {
        if &der[i..i + 3] == cn_bytes {
            let start = i + 3;
            let end = der[start..]
                .iter()
                .position(|&b| b == 0 || !(0x20..=0x7E).contains(&b))
                .map(|p| start + p)
                .unwrap_or((start + 128).min(der.len()));
            let s = String::from_utf8_lossy(&der[start..end]).trim().to_string();
            if !s.is_empty() {
                if !found_first {
                    issuers.push(s);
                    found_first = true;
                } else {
                    subjects.push(s);
                }
            }
        }
        i += 1;
    }

    let issuer = issuers
        .first()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());
    let subject = subjects.first().cloned().unwrap_or_else(|| issuer.clone());

    // Extract SAN domains (look for DNS: pattern)
    let dns_prefix = b"DNS:";
    let mut san_domains = Vec::new();
    let mut j = 0;
    while j + 4 < der.len() {
        if &der[j..j + 4] == dns_prefix {
            let start = j + 4;
            let end = der[start..]
                .iter()
                .position(|&b| b == 0 || !(0x20..=0x7E).contains(&b) || b == b',')
                .map(|p| start + p)
                .unwrap_or((start + 253).min(der.len()));
            let s = String::from_utf8_lossy(&der[start..end]).trim().to_string();
            if !s.is_empty() && s.contains('.') {
                san_domains.push(s);
            }
        }
        j += 1;
    }

    // Extract validity dates from DER, falling back to SystemTime-based placeholders if parsing fails
    let (not_before, not_after) = if let Some((nb, na)) = extract_validity(der) {
        (nb, na)
    } else {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (
            format_unix_ts(now.saturating_sub(365 * 86400)),
            format_unix_ts(now + 365 * 86400),
        )
    };

    let _ = text; // suppress unused warning

    Ok(CertInfo {
        issuer,
        subject,
        not_before,
        not_after,
        serial,
        san_domains,
    })
}

fn format_unix_ts(ts: u64) -> String {
    // Simple ISO-8601 approximation
    let secs = ts;
    let days = secs / 86400;
    let year = 1970 + days / 365;
    format!("{}-01-01T00:00:00Z", year)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut s = String::with_capacity(64);
    for byte in digest.as_ref() {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}

/// Appends a uTLS padding extension (Type 0x0015, writing `pad_len` bytes of zeros)
/// to a raw TLS ClientHello record, dynamically adjusting record length,
/// handshake length, and extensions length fields.
pub fn pad_client_hello(raw: &[u8], pad_len: usize) -> Result<Vec<u8>, &'static str> {
    if raw.len() < 43 {
        return Err("ClientHello too short");
    }
    // Check TLS Record Header
    if raw[0] != 0x16 {
        return Err("Not a handshake record");
    }
    
    // Check Handshake Type
    if raw[5] != 0x01 {
        return Err("Not a ClientHello handshake");
    }
    
    let mut offset = 43; // Type(1) + Ver(2) + RecLen(2) + HsType(1) + HsLen(3) + CliVer(2) + Rand(32)
    
    // Skip Session ID
    let session_id_len = raw[offset] as usize;
    offset += 1 + session_id_len;
    if offset + 2 > raw.len() {
        return Err("Malformed ClientHello: session ID bounds");
    }
    
    // Skip Cipher Suites
    let cipher_suites_len = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    if offset + 1 > raw.len() {
        return Err("Malformed ClientHello: cipher suites bounds");
    }
    
    // Skip Compression Methods
    let compression_len = raw[offset] as usize;
    offset += 1 + compression_len;
    
    // Extensions length offset
    let has_extensions = offset + 2 <= raw.len();
    
    let mut result = Vec::new();
    let ext_block_added_len = 4 + pad_len; // 2 bytes type + 2 bytes len + pad_len zeros
    
    if has_extensions {
        let extensions_len = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
        if offset + 2 + extensions_len > raw.len() {
            return Err("Malformed ClientHello: extensions bounds");
        }
        
        // We will copy the record up to offset, write new extensions_len, copy existing extensions,
        // write padding extension, and adjust record/handshake lengths.
        
        // 1. Copy record header & handshake up to TLS record length (byte 3)
        result.extend_from_slice(&raw[0..3]);
        
        // Update TLS record length (bytes 3..5)
        let old_rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        let new_rec_len = old_rec_len + ext_block_added_len;
        result.extend_from_slice(&(new_rec_len as u16).to_be_bytes());
        
        // Handshake type (byte 5)
        result.push(raw[5]);
        
        // Update Handshake length (bytes 6..9)
        let old_hs_len = ((raw[6] as usize) << 16) | ((raw[7] as usize) << 8) | (raw[8] as usize);
        let new_hs_len = old_hs_len + ext_block_added_len;
        result.push(((new_hs_len >> 16) & 0xff) as u8);
        result.push(((new_hs_len >> 8) & 0xff) as u8);
        result.push((new_hs_len & 0xff) as u8);
        
        // Copy ClientHello body from byte 9 up to extensions length (offset)
        result.extend_from_slice(&raw[9..offset]);
        
        // Update Extensions length
        let new_ext_len = extensions_len + ext_block_added_len;
        result.extend_from_slice(&(new_ext_len as u16).to_be_bytes());
        
        // Copy existing extensions
        result.extend_from_slice(&raw[offset + 2 .. offset + 2 + extensions_len]);
        
        // Append padding extension
        result.extend_from_slice(&0x0015_u16.to_be_bytes()); // Type 0x0015 (21)
        result.extend_from_slice(&(pad_len as u16).to_be_bytes()); // Length
        result.extend(std::iter::repeat_n(0, pad_len)); // Zeros
        
        // Copy any trailing bytes (if any)
        result.extend_from_slice(&raw[offset + 2 + extensions_len ..]);
    } else {
        // No extensions block present, we append it
        result.extend_from_slice(&raw[0..3]);
        let old_rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        let new_rec_len = old_rec_len + 2 + ext_block_added_len; // 2 bytes for ext len + padding ext
        result.extend_from_slice(&(new_rec_len as u16).to_be_bytes());
        
        result.push(raw[5]);
        let old_hs_len = ((raw[6] as usize) << 16) | ((raw[7] as usize) << 8) | (raw[8] as usize);
        let new_hs_len = old_hs_len + 2 + ext_block_added_len;
        result.push(((new_hs_len >> 16) & 0xff) as u8);
        result.push(((new_hs_len >> 8) & 0xff) as u8);
        result.push((new_hs_len & 0xff) as u8);
        
        result.extend_from_slice(&raw[9..offset]);
        
        // Write Extensions length (which is ext_block_added_len)
        result.extend_from_slice(&(ext_block_added_len as u16).to_be_bytes());
        
        // Append padding extension
        result.extend_from_slice(&0x0015_u16.to_be_bytes());
        result.extend_from_slice(&(pad_len as u16).to_be_bytes());
        result.extend(std::iter::repeat_n(0, pad_len));
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_client_hello_too_short() {
        let raw = vec![0u8; 10];
        assert!(pad_client_hello(&raw, 10).is_err());
    }

    #[test]
    fn test_pad_client_hello_not_handshake() {
        let mut raw = vec![0u8; 50];
        raw[0] = 0x17; // Application data, not handshake (0x16)
        raw[5] = 0x01; // ClientHello type
        assert!(pad_client_hello(&raw, 10).is_err());
    }

    #[test]
    fn test_pad_client_hello_not_clienthello() {
        let mut raw = vec![0u8; 50];
        raw[0] = 0x16; // Handshake
        raw[5] = 0x02; // ServerHello type, not ClientHello (0x01)
        assert!(pad_client_hello(&raw, 10).is_err());
    }
}
