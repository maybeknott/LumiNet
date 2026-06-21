//! # WireGuard Prober Tests
//!
//! Integration tests for the WireGuard handshake prober.

use lumicore::wg::WgProber;

#[tokio::test]
async fn test_wg_probe_standard() {
    let prober = WgProber::new("127.0.0.1".to_string(), 51820, 1000, None);
    let result = prober.probe().await;
    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.ip, "127.0.0.1");
    assert_eq!(res.port, 51820);
}

#[tokio::test]
async fn test_wg_probe_padded() {
    let prober = WgProber::new("127.0.0.1".to_string(), 51820, 1000, Some(64));
    let result = prober.probe().await;
    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.ip, "127.0.0.1");
    assert_eq!(res.port, 51820);
}
