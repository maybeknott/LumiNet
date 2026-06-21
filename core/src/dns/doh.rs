//! # DNS over HTTPS (DoH)
//!
//! DNS resolution via HTTPS using the RFC 8484 wire format and the
//! JSON API variants offered by major providers.

use crate::dns::packet::{build_query, parse_response};
use crate::types::DnsRecord;
use std::sync::OnceLock;

/// Well-known DNS-over-HTTPS endpoint URLs.
pub const DOH_ENDPOINTS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://dns.nextdns.io/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://dns.adguard.com/dns-query",
    "https://doh.mullvad.net/dns-query",
    "https://dns.controld.com/dns-query",
];

/// Resolves a domain using DNS-over-HTTPS (wire format, RFC 8484).
pub async fn resolve_doh(
    url: &str,
    domain: &str,
    record_type: &str,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let rtype: u16 = match record_type.to_uppercase().as_str() {
        "A" => crate::dns::packet::TYPE_A,
        "AAAA" => crate::dns::packet::TYPE_AAAA,
        "CNAME" => crate::dns::packet::TYPE_CNAME,
        "MX" => crate::dns::packet::TYPE_MX,
        "NS" => crate::dns::packet::TYPE_NS,
        "TXT" => crate::dns::packet::TYPE_TXT,
        "SOA" => crate::dns::packet::TYPE_SOA,
        "PTR" => crate::dns::packet::TYPE_PTR,
        "HTTPS" => crate::dns::packet::TYPE_HTTPS,
        _ => crate::dns::packet::TYPE_A,
    };

    let txid: u16 = rand::random();
    let query_bytes = build_query(domain, rtype, txid);

    // Encode as base64url without padding for GET request
    let b64 = base64_url_encode(&query_bytes);
    let get_url = format!("{}?dns={}", url, b64);

    let client = reqwest_client()?;
    let resp = client
        .get(&get_url)
        .header("Accept", "application/dns-message")
        .send()
        .await?;

    let bytes = resp.bytes().await?;
    let records = parse_response(&bytes)?;
    Ok(records)
}

/// Resolves a domain using the JSON API variant of DNS-over-HTTPS.
pub async fn resolve_doh_json(
    url: &str,
    domain: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let get_url = format!("{}?name={}&type=A", url, domain);
    let client = reqwest_client()?;
    let resp = client
        .get(&get_url)
        .header("Accept", "application/dns-json")
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    Ok(json)
}

fn base64_url_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let url_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let _ = b64_chars; // suppress warning
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        let indices = [
            (b0 >> 2) & 0x3F,
            ((b0 << 4) | (b1 >> 4)) & 0x3F,
            ((b1 << 2) | (b2 >> 6)) & 0x3F,
            b2 & 0x3F,
        ];
        let count = chunk.len() + 1;
        for &idx in &indices[..count] {
            let _ = write!(s, "{}", url_chars[idx] as char);
        }
    }
    s
}

fn reqwest_client() -> Result<&'static reqwest::Client, Box<dyn std::error::Error>> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to initialize reqwest Client")
    });
    Ok(client)
}
