//! # HTTP Prober
//!
//! HTTP GET/HEAD probing with proxy support and captive portal detection.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Response from an HTTP probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as key-value pairs.
    pub headers: HashMap<String, String>,
    /// Response body bytes.
    #[serde(with = "serde_bytes_compat")]
    pub body: Vec<u8>,
    /// Total request latency in milliseconds.
    pub latency_ms: f64,
    /// Content-Length header value (or actual body length).
    pub content_length: u64,
}

/// Result of captive portal detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaptivePortalResult {
    /// Network is open — no captive portal detected.
    Open,
    /// Captive portal detected via HTTP redirect.
    CaptiveRedirect {
        /// The URL the portal redirects to.
        url: String,
    },
    /// Content was modified in transit (possible injection).
    ModifiedContent,
    /// Detection was inconclusive.
    Inconclusive,
}

/// Performs an HTTP GET request.
pub async fn http_get(
    url: &str,
    timeout_ms: u32,
    proxy: Option<&str>,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    http_get_impl(url, timeout_ms, proxy, true).await
}

/// Performs an HTTP GET request with optional redirect following.
pub async fn http_get_impl(
    url: &str,
    timeout_ms: u32,
    proxy: Option<&str>,
    follow_redirects: bool,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let start = Instant::now();

    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(5)
    } else {
        reqwest::redirect::Policy::none()
    };

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms as u64))
        .redirect(redirect_policy);

    if let Some(proxy_url) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
    }

    let client = builder.build()?;
    let resp = client.get(url).send().await?;

    let status = resp.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in resp.headers() {
        headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
    }

    let body = resp.bytes().await?.to_vec();
    let content_length = body.len() as u64;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(HttpResponse {
        status,
        headers,
        body,
        latency_ms,
        content_length,
    })
}

/// Performs an HTTP HEAD request (headers only, no body).
pub async fn http_head(
    url: &str,
    timeout_ms: u32,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms as u64))
        .build()?;

    let resp = client.head(url).send().await?;
    let status = resp.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in resp.headers() {
        headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
    }
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(HttpResponse {
        status,
        headers,
        body: vec![],
        latency_ms,
        content_length,
    })
}

/// Detects whether the current network has a captive portal.
pub async fn detect_captive_portal(timeout_ms: u32) -> CaptivePortalResult {
    // Well-known captive portal detection endpoints
    let check_urls = [
        (
            "http://connectivitycheck.gstatic.com/generate_204",
            204u16,
            "",
        ),
        (
            "http://www.msftconnecttest.com/connecttest.txt",
            200,
            "Microsoft Connect Test",
        ),
        (
            "http://captive.apple.com/hotspot-detect.html",
            200,
            "<HTML><HEAD><TITLE>Success</TITLE>",
        ),
    ];

    for (url, expected_status, expected_body) in &check_urls {
        match http_get_impl(url, timeout_ms, None, false).await {
            Ok(resp) => {
                if resp.status != *expected_status {
                    // Redirected to a different status — likely captive portal
                    if resp.status == 302 || resp.status == 301 || resp.status == 307 {
                        let redirect_url = resp
                            .headers
                            .get("location")
                            .cloned()
                            .unwrap_or_else(|| url.to_string());
                        return CaptivePortalResult::CaptiveRedirect { url: redirect_url };
                    }
                    return CaptivePortalResult::Inconclusive;
                }
                if !expected_body.is_empty() {
                    let body_str = String::from_utf8_lossy(&resp.body);
                    if !body_str.contains(expected_body) {
                        return CaptivePortalResult::ModifiedContent;
                    }
                }
                return CaptivePortalResult::Open;
            }
            Err(_) => continue,
        }
    }

    CaptivePortalResult::Inconclusive
}

/// Serde helper for Vec<u8> serialization (base64 in JSON).
mod serde_bytes_compat {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(s)
    }
}
