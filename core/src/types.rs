//! Shared types used across all LumiCore modules.
//!
//! These types form the data contract between the Rust engine and the Go
//! server via the FFI layer. All types derive Serialize/Deserialize for
//! JSON transport through C strings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

// ─── Probe Results ───────────────────────────────────────────────

/// Result of a single network probe (ICMP, TCP, SOCKS5, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub target: String,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub success: bool,
    pub latency_ms: f64,
    pub error: Option<String>,
    pub error_code: Option<String>,
    pub timestamp: u64,
    pub metadata: HashMap<String, String>,
}

/// Progress of a running scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub total: u64,
    pub completed: u64,
    pub alive: u64,
    pub failed: u64,
    pub elapsed_ms: u64,
    pub rate_pps: f64,
    pub estimated_remaining_ms: u64,
}

// ─── DNS ─────────────────────────────────────────────────────────

/// A single DNS resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub class: String,
}

/// Result of a DNS server probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerResult {
    pub server: String,
    pub protocol: String, // "udp", "doh", "dot"
    pub latency_ms: f64,
    pub success: bool,
    pub records: Vec<DnsRecord>,
    pub error: Option<String>,
}

// ─── TLS ─────────────────────────────────────────────────────────

/// TLS handshake information extracted from a connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub cipher_suite: String,
    pub issuer: String,
    pub subject: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
    pub alpn: Vec<String>,
    pub san_domains: Vec<String>,
    pub fingerprint_sha256: String,
    pub chain_length: usize,
    pub ocsp_stapled: bool,
}

/// SSL inspection detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslInspectionResult {
    pub detected: bool,
    pub evidence: String,
    pub confidence: f32,
    pub expected_issuer: Option<String>,
    pub actual_issuer: String,
}

// ─── Ports ───────────────────────────────────────────────────────

/// Result of a port scan probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub ip: String,
    pub port: u16,
    pub open: bool,
    pub protocol: String, // "tcp", "udp"
    pub service: Option<String>,
    pub latency_ms: f64,
    pub banner: Option<String>,
}

// ─── Speed ───────────────────────────────────────────────────────

/// Speed test measurement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedResult {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub bytes_transferred: u64,
    pub duration_ms: u64,
    pub server: String,
}

/// Latency measurement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyResult {
    pub target: String,
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub median_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub samples: u32,
}

// ─── SNI ─────────────────────────────────────────────────────────

/// SNI blocking detection result for a single domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniResult {
    pub domain: String,
    pub blocked: bool,
    pub tls_success: bool,
    pub tls_info: Option<TlsInfo>,
    pub error: Option<String>,
    pub evidence: String,
    pub confidence: f32,
}

// ─── Proxy Discovery ─────────────────────────────────────────────

/// Result of local proxy discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDiscovery {
    pub address: String,
    pub port: u16,
    pub protocol: String, // "socks5", "http", "https"
    pub latency_ms: f64,
    pub authenticated: bool,
}

// ─── HTTP ────────────────────────────────────────────────────────

/// HTTP response from a probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProbeResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub latency_ms: f64,
    pub content_length: u64,
    pub redirected: bool,
    pub final_url: String,
}

/// Captive portal detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaptivePortalResult {
    Open,
    CaptiveRedirect { redirect_url: String },
    ModifiedContent { evidence: String },
    Inconclusive { reason: String },
}

// ─── WireGuard ───────────────────────────────────────────────────

/// WireGuard handshake probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgProbeResult {
    pub ip: String,
    pub port: u16,
    pub success: bool,
    pub latency_ms: f64,
    pub response_type: String,
    pub error: Option<String>,
}

// ─── Configuration ───────────────────────────────────────────────

/// Configuration for a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub timeout_ms: u32,
    pub max_concurrent: u32,
    pub rate_limit_pps: u32,
    pub retry_count: u8,
    pub adaptive_rate: bool,
    pub ipv6: bool,
    #[serde(default)]
    pub shuffle: bool,
    #[serde(default)]
    pub shuffle_seed: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 2000,
            max_concurrent: 256,
            rate_limit_pps: 1000,
            retry_count: 1,
            adaptive_rate: true,
            ipv6: false,
            shuffle: false,
            shuffle_seed: 0,
        }
    }
}


// ─── Errors ──────────────────────────────────────────────────────

/// Core error type for all LumiCore operations.
#[derive(Debug, thiserror::Error)]
pub enum LumiError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Timeout after {0}ms")]
    Timeout(u32),
    #[error("DNS resolution failed: {0}")]
    DnsError(String),
    #[error("TLS handshake failed: {0}")]
    TlsError(String),
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Cancelled")]
    Cancelled,
}

pub type LumiResult<T> = Result<T, LumiError>;
