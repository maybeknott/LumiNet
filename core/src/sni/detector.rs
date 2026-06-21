//! # SNI Blocking Detector
//!
//! Detects SNI-based TLS blocking by comparing handshake results across
//! a set of domains. Connection resets, timeouts, and certificate mismatches
//! on specific domains (while others succeed) indicate SNI filtering.

use crate::types::{ScanConfig, SniResult};
use futures::future::join_all;
use std::sync::Arc;

/// Classification of an SNI detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniClassification {
    Allowed,
    Blocked,
    Timeout,
    Inconclusive,
}

/// Well-known test domains used for SNI blocking detection.
pub const TEST_DOMAINS: &[&str] = &[
    "cloudflare.com",
    "fastly.com",
    "akamai.com",
    "cdn.jsdelivr.net",
    "google.com",
    "bing.com",
    "duckduckgo.com",
    "twitter.com",
    "facebook.com",
    "instagram.com",
    "reddit.com",
    "linkedin.com",
    "telegram.org",
    "signal.org",
    "whatsapp.com",
    "discord.com",
    "youtube.com",
    "twitch.tv",
    "netflix.com",
    "github.com",
    "gitlab.com",
    "stackoverflow.com",
    "protonvpn.com",
    "mullvad.net",
    "torproject.org",
    "wireguard.com",
    "bbc.com",
    "reuters.com",
];

/// Detects SNI-based blocking across a list of domains.
pub async fn detect_sni_blocking(domains: Vec<String>, config: ScanConfig) -> Vec<SniResult> {
    let domains_to_test: Vec<String> = if domains.is_empty() {
        TEST_DOMAINS.iter().map(|s| s.to_string()).collect()
    } else {
        domains
    };

    let sem = Arc::new(tokio::sync::Semaphore::new(config.max_concurrent as usize));
    let timeout_ms = config.timeout_ms;

    let futures: Vec<_> = domains_to_test
        .into_iter()
        .map(|domain| {
            let sem = Arc::clone(&sem);
            async move {
                let _permit = sem.acquire().await.ok();
                probe_sni_domain(&domain, timeout_ms).await
            }
        })
        .collect();

    join_all(futures).await
}

/// Probes a single domain for SNI blocking.
async fn probe_sni_domain(domain: &str, timeout_ms: u32) -> SniResult {
    match crate::tls::tls_handshake(domain, 443, domain, timeout_ms).await {
        Ok(tls_info) => SniResult {
            domain: domain.to_string(),
            blocked: false,
            tls_success: true,
            tls_info: Some(tls_info),
            error: None,
            evidence: "TLS handshake succeeded — SNI not blocked".to_string(),
            confidence: 0.95,
        },
        Err(e) => {
            let err_str = e.to_string();
            let (blocked, evidence, confidence) = classify_error(&err_str);
            SniResult {
                domain: domain.to_string(),
                blocked,
                tls_success: false,
                tls_info: None,
                error: Some(err_str),
                evidence,
                confidence,
            }
        }
    }
}

/// Classifies an error string into blocking evidence.
fn classify_error(err: &str) -> (bool, String, f32) {
    let lower = err.to_lowercase();
    if lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("forcibly closed")
    {
        (
            true,
            format!(
                "Connection actively reset — likely SNI-based blocking: {}",
                err
            ),
            0.85,
        )
    } else if lower.contains("timed out") || lower.contains("timeout") || lower.contains("deadline")
    {
        (
            false,
            format!(
                "Connection timed out — possible passive blocking or unreachable: {}",
                err
            ),
            0.5,
        )
    } else if lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake")
    {
        (
            false,
            format!("TLS error (not necessarily SNI blocking): {}", err),
            0.3,
        )
    } else {
        (false, format!("Inconclusive error: {}", err), 0.2)
    }
}

/// Classifies a single [`SniResult`] into a [`SniClassification`].
pub fn classify_sni_result(result: &SniResult) -> SniClassification {
    if result.tls_success {
        return SniClassification::Allowed;
    }

    if let Some(err) = &result.error {
        let lower = err.to_lowercase();
        if lower.contains("connection reset")
            || lower.contains("connection refused")
            || lower.contains("forcibly closed")
        {
            return SniClassification::Blocked;
        }
        if lower.contains("timed out") || lower.contains("timeout") || lower.contains("deadline") {
            return SniClassification::Timeout;
        }
    }

    SniClassification::Inconclusive
}
