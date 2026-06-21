//! # TCP Prober Tests
//!
//! Integration tests for the TCP connect, port scanning, and banner grabbing module.

use lumicore::tcp::{banner_grab, port_scan, tcp_connect, tcp_connect_batch};
use lumicore::types::ScanConfig;

#[tokio::test]
async fn test_tcp_connect_single() {
    let result = tcp_connect("127.0.0.1", 12345, 500).await;
    let res = result.expect("Should return result even if connection is refused");
    assert_eq!(res.target, "127.0.0.1");
    assert_eq!(res.port, Some(12345));
}

#[tokio::test]
async fn test_tcp_connect_batch() {
    let config = ScanConfig::default();
    let targets = vec![("127.0.0.1".to_string(), 12345)];
    let results = tcp_connect_batch(targets, config).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].target, "127.0.0.1");
}

#[tokio::test]
async fn test_tcp_port_scan() {
    let config = ScanConfig::default();
    let results = port_scan("127.0.0.1", vec![12345, 12346], config).await;
    assert_eq!(results.len(), 2);
    // Since port_scan shuffles ports if shuffle is true, here we verify the ports exist in the outputs
    let ports: std::collections::HashSet<u16> = results.iter().map(|r| r.port).collect();
    assert!(ports.contains(&12345));
    assert!(ports.contains(&12346));
}

#[tokio::test]
async fn test_tcp_banner_grab() {
    let result = banner_grab("127.0.0.1", 12345, 500).await;
    // banner grab to non-listening port should return an error
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tcp_shuffled() {
    let config = ScanConfig {
        shuffle: true,
        shuffle_seed: 1337,
        ..Default::default()
    };
    let targets = vec![
        ("127.0.0.1".to_string(), 80),
        ("127.0.0.2".to_string(), 80),
        ("127.0.0.3".to_string(), 80),
        ("127.0.0.4".to_string(), 80),
    ];
    let results = tcp_connect_batch(targets, config.clone()).await;
    assert_eq!(results.len(), 4, "Should have 4 batch targets scanned");

    let ports = vec![80, 443, 8080, 8443];
    let port_results = port_scan("127.0.0.1", ports, config).await;
    assert_eq!(port_results.len(), 4, "Should have 4 ports scanned");
}

