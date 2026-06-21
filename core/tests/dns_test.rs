//! # DNS Resolver Tests
//!
//! Integration tests for the DNS query and scanning module.

use lumicore::dns::{resolve, resolve_batch, resolve_doh, resolve_dot, scan_dns_servers, TYPE_A};

#[tokio::test]
async fn test_dns_resolve_udp() {
    let result = resolve("8.8.8.8", "example.com", TYPE_A, 2000).await;
    let _ = result;
}

#[tokio::test]
async fn test_dns_resolve_batch() {
    let domains = vec!["example.com".to_string()];
    let result = resolve_batch("8.8.8.8", domains, TYPE_A).await;
    let _ = result;
}

#[tokio::test]
async fn test_dns_scan_servers() {
    let servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
    let result = scan_dns_servers(servers, "example.com").await;
    let _ = result;
}

#[tokio::test]
async fn test_dns_resolve_doh() {
    let result = resolve_doh("https://dns.google/dns-query", "example.com", "A").await;
    let _ = result;
}

#[tokio::test]
async fn test_dns_resolve_dot() {
    let result = resolve_dot("dns.google", 853, "example.com", TYPE_A).await;
    let _ = result;
}
