//! # ICMP Scanner Tests
//!
//! Integration tests for the ICMP network scanning module.

use lumicore::icmp::{calibrate_rate, IcmpScanner};
use lumicore::types::ScanConfig;
use std::net::IpAddr;

#[tokio::test]
async fn test_icmp_scan_single() {
    let config = ScanConfig::default();
    let scanner = IcmpScanner::new(config);
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let result = scanner.scan_targets(vec![target]).await;
    let results = result.expect("Should scan single target successfully");
    assert_eq!(results.len(), 1, "Should have exactly one target in results");
    assert_eq!(results[0].target, target.to_string(), "Target string matches");
}

#[tokio::test]
async fn test_icmp_scan_cidr() {
    let config = ScanConfig::default();
    let scanner = IcmpScanner::new(config);
    let result = scanner.scan_cidr("127.0.0.1/32").await;
    let results = result.expect("Should scan CIDR successfully");
    assert_eq!(results.len(), 1, "CIDR scan should yield exactly one result");
    assert_eq!(results[0].target, "127.0.0.1", "Target matches expanded CIDR");
}

#[tokio::test]
async fn test_icmp_calibration() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let result = calibrate_rate(target, 10, 100, 10, 2).await;
    let best_rate = result.expect("Should calibrate rate successfully");
    assert!(best_rate >= 10, "Best rate should be at least min_rate");
}

#[tokio::test]
async fn test_icmp_scan_shuffled() {
    let config = ScanConfig {
        shuffle: true,
        shuffle_seed: 42,
        ..Default::default()
    };
    let scanner = IcmpScanner::new(config);
    // Expand a range that has multiple IPs, e.g. a loopback subnetwork 127.0.0.0/30 (4 IPs)
    let result = scanner.scan_cidr("127.0.0.0/30").await;
    let results = result.expect("Should scan CIDR with shuffling successfully");
    assert_eq!(results.len(), 4, "Should have exactly 4 targets");
}


