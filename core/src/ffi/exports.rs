#![allow(clippy::missing_safety_doc)]
//! # C FFI Exported Functions
//!
//! CGO-compatible export functions for the Go host application.
//! All functions accept JSON strings for config/input and return JSON results.

use super::{c_str_to_str, str_to_c_char};
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::os::raw::c_char;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// Gets or initializes a shared multi-threaded Tokio runtime for FFI operations.
fn get_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime")
    })
}

// ─── Input Structs for FFI ────────────────────────────────────────

#[derive(Deserialize)]
struct IcmpScanInput {
    targets: Vec<String>,
    config: Option<ScanConfig>,
}

#[derive(Deserialize)]
struct TcpProbeInput {
    target: String,
    port: u16,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct PortScanInput {
    target: String,
    ports: Vec<u16>,
    config: Option<ScanConfig>,
}

#[derive(Deserialize)]
struct DnsScanInput {
    server: String,
    domain: String,
    record_type: String,
    protocol: Option<String>,
    timeout_ms: Option<u32>,
}

#[derive(Deserialize)]
struct TlsProbeInput {
    target: String,
    port: u16,
    timeout_ms: u32,
    sni: Option<String>,
}

#[derive(Deserialize)]
struct Socks5ProbeInput {
    proxy_addr: String,
    #[allow(dead_code)]
    target: String,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct HttpProbeInput {
    url: String,
    timeout_ms: u32,
    proxy: Option<String>,
}

#[derive(Deserialize)]
struct SniDetectInput {
    domain: String,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct SpeedTestInput {
    server_url: String,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct CidrExpandInput {
    cidr: String,
}

#[derive(Deserialize)]
struct WgProbeInput {
    ip: String,
    port: u16,
    timeout_ms: u32,
    padding_len: Option<u32>,
    decoy_count: Option<u32>,
}

// ─── FFI Export Implementations ───────────────────────────────────

/// Wrapper for ICMP scanning.
///
/// Input JSON: `{"targets": ["192.168.1.1"], "config": <ScanConfig>}`
/// Output JSON: `{"results": [<ProbeResult>]}`
#[no_mangle]
pub unsafe extern "C" fn scan_icmp_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: IcmpScanInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let config = input.config.unwrap_or_default();
            let scanner = crate::icmp::IcmpScanner::new(config);

            let mut parsed_targets = Vec::new();
            for t in input.targets {
                if let Ok(ips) = crate::cidr::expand_cidr(&t) {
                    parsed_targets.extend(ips);
                } else if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                    parsed_targets.push(ip);
                }
            }

            scanner.scan_targets(parsed_targets).await
        });

        let json_res = match res {
            Ok(results) => serde_json::to_string(&results)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for TCP probing.
///
/// Input JSON: `{"target": "127.0.0.1", "port": 80, "timeout_ms": 1000}`
#[no_mangle]
pub unsafe extern "C" fn probe_tcp_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: TcpProbeInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            crate::tcp::tcp_connect(&input.target, input.port, input.timeout_ms).await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for Port scanning.
///
/// Input JSON: `{"target": "127.0.0.1", "ports": [80, 443], "config": <ScanConfig>}`
#[no_mangle]
pub unsafe extern "C" fn scan_ports_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: PortScanInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let config = input.config.unwrap_or_default();
            crate::tcp::port_scan(&input.target, input.ports, config).await
        });

        let json_res =
            serde_json::to_string(&res).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for DNS scanning.
///
/// Input JSON: `{"server": "8.8.8.8", "domain": "example.com", "record_type": "A", "protocol": "udp", "timeout_ms": 3000}`
#[no_mangle]
pub unsafe extern "C" fn scan_dns_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: DnsScanInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res: Result<DnsServerResult, String> = rt.block_on(async {
            let rtype = match input.record_type.to_uppercase().as_str() {
                "A" => crate::dns::TYPE_A,
                "AAAA" => crate::dns::TYPE_AAAA,
                "CNAME" => crate::dns::TYPE_CNAME,
                "MX" => crate::dns::TYPE_MX,
                "NS" => crate::dns::TYPE_NS,
                "TXT" => crate::dns::TYPE_TXT,
                "SOA" => crate::dns::TYPE_SOA,
                "PTR" => crate::dns::TYPE_PTR,
                "HTTPS" => crate::dns::TYPE_HTTPS,
                _ => crate::dns::TYPE_A,
            };

            let protocol = input.protocol.as_deref().unwrap_or("udp");
            let timeout = input.timeout_ms.unwrap_or(3000);
            let start = std::time::Instant::now();

            let dns_res = match protocol.to_lowercase().as_str() {
                "doh" | "https" => {
                    match crate::dns::resolve_doh(&input.server, &input.domain, &input.record_type).await {
                        Ok(records) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "doh".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: true,
                            records,
                            error: None,
                        }),
                        Err(e) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "doh".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: false,
                            records: vec![],
                            error: Some(e.to_string()),
                        })
                    }
                }
                "dot" | "tls" => {
                    let port = if input.server.contains(':') {
                        let parts: Vec<&str> = input.server.split(':').collect();
                        parts.last().unwrap().parse().unwrap_or(853)
                    } else {
                        853
                    };
                    let host = if input.server.contains(':') {
                        let parts: Vec<&str> = input.server.split(':').collect();
                        parts[0].to_string()
                    } else {
                        input.server.clone()
                    };
                    match crate::dns::resolve_dot(&host, port, &input.domain, rtype).await {
                        Ok(records) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "dot".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: true,
                            records,
                            error: None,
                        }),
                        Err(e) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "dot".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: false,
                            records: vec![],
                            error: Some(e.to_string()),
                        })
                    }
                }
                _ => {
                    if input.server.starts_with("https://") {
                        match crate::dns::resolve_doh(&input.server, &input.domain, &input.record_type).await {
                            Ok(records) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "doh".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: true,
                                records,
                                error: None,
                            }),
                            Err(e) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "doh".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: false,
                                records: vec![],
                                error: Some(e.to_string()),
                            })
                        }
                    } else {
                        match crate::dns::resolve(&input.server, &input.domain, rtype, timeout).await {
                            Ok(records) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "udp".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: true,
                                records,
                                error: None,
                            }),
                            Err(e) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "udp".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: false,
                                records: vec![],
                                error: Some(e.to_string()),
                            })
                        }
                    }
                }
            };
            dns_res
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for TLS probing.
///
/// Input JSON: `{"target": "example.com", "port": 443, "timeout_ms": 2000}`
#[no_mangle]
pub unsafe extern "C" fn probe_tls_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: TlsProbeInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let sni = input.sni.as_deref().unwrap_or(&input.target);
            crate::tls::tls_handshake(&input.target, input.port, sni, input.timeout_ms).await
        });

        let json_res = match res {
            Ok(result) => {
                serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
            }
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for SOCKS5 probing.
///
/// Input JSON: `{"proxy_addr": "127.0.0.1:1080", "target": "example.com:80", "timeout_ms": 2000}`
#[no_mangle]
pub unsafe extern "C" fn probe_socks5_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: Socks5ProbeInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            // Parse proxy_addr as host:port
            let parts: Vec<&str> = input.proxy_addr.rsplitn(2, ':').collect();
            let (proxy_host, proxy_port) = if parts.len() == 2 {
                let port: u16 = parts[0].parse().unwrap_or(1080);
                (parts[1].to_string(), port)
            } else {
                (input.proxy_addr.clone(), 1080u16)
            };
            crate::socks::socks5_handshake(&proxy_host, proxy_port, input.timeout_ms).await
        });

        let json_res = match res {
            Ok(result) => {
                serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
            }
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for HTTP client probing.
///
/// Input JSON: `{"url": "http://example.com", "timeout_ms": 2000, "proxy": null}`
#[no_mangle]
pub unsafe extern "C" fn probe_http_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: HttpProbeInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let proxy = input.proxy.as_deref();
            match crate::http::http_get(&input.url, input.timeout_ms, proxy).await {
                Ok(resp) => {
                    let body_preview =
                        String::from_utf8_lossy(&resp.body[..resp.body.len().min(512)]).to_string();
                    let response = HttpProbeResponse {
                        status_code: resp.status,
                        headers: resp.headers,
                        body_preview,
                        latency_ms: resp.latency_ms,
                        content_length: resp.content_length,
                        redirected: false,
                        final_url: input.url.clone(),
                    };
                    Ok::<HttpProbeResponse, String>(response)
                }
                Err(e) => Err(e.to_string()),
            }
        });

        let json_res = match res {
            Ok(result) => {
                serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
            }
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for SNI detection.
///
/// Input JSON: `{"domain": "blocked.com", "timeout_ms": 2000}`
#[no_mangle]
pub unsafe extern "C" fn detect_sni_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: SniDetectInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let config = crate::types::ScanConfig {
                timeout_ms: input.timeout_ms,
                max_concurrent: 1,
                rate_limit_pps: 100,
                retry_count: 1,
                adaptive_rate: false,
                ipv6: false,
                shuffle: false,
                shuffle_seed: 0,
            };
            let results = crate::sni::detect_sni_blocking(vec![input.domain], config).await;
            results
                .into_iter()
                .next()
                .ok_or_else(|| "No result".to_string())
        });

        let json_res = match res {
            Ok(result) => {
                serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
            }
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for Speed testing.
///
/// Input JSON: `{"server_url": "http://speedtest.example.com", "timeout_ms": 5000}`
#[no_mangle]
pub unsafe extern "C" fn test_speed_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: SpeedTestInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let tester = crate::speed::SpeedTester::new(input.server_url, input.timeout_ms);
            tester.run_test().await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for CIDR expansion.
///
/// Input JSON: `{"cidr": "192.168.1.0/24"}`
#[no_mangle]
pub unsafe extern "C" fn expand_cidr_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: CidrExpandInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let res = crate::cidr::expand_cidr(&input.cidr);

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

/// Wrapper for WireGuard probing.
///
/// Input JSON: `{"ip": "10.0.0.1", "port": 51820, "timeout_ms": 2000}`
#[no_mangle]
pub unsafe extern "C" fn probe_wg_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: WgProbeInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            let prober = if let Some(decoys) = input.decoy_count {
                crate::wg::WgProber::new_with_decoys(input.ip, input.port, input.timeout_ms, input.padding_len, decoys)
            } else {
                crate::wg::WgProber::new(input.ip, input.port, input.timeout_ms, input.padding_len)
            };
            prober.probe().await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

#[derive(Deserialize)]
struct CaptivePortalInput {
    timeout_ms: u32,
}

/// Wrapper for captive portal detection.
///
/// Input JSON: `{"timeout_ms": 3000}`
#[no_mangle]
pub unsafe extern "C" fn detect_captive_portal_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: CaptivePortalInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let rt = get_runtime();
        let res = rt.block_on(async {
            crate::http::detect_captive_portal(input.timeout_ms).await
        });

        let json_res = serde_json::to_string(&res)
            .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

#[derive(Deserialize)]
struct PadClientHelloInput {
    raw_hex: String,
    pad_len: usize,
}

#[derive(Serialize)]
struct PadClientHelloResult {
    padded_hex: Option<String>,
    success: bool,
    error: Option<String>,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Hex string must have an even length".to_string());
    }
    let mut res = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for i in (0..s.len()).step_by(2) {
        let high = chars[i].to_digit(16).ok_or_else(|| "Invalid hex digit".to_string())? as u8;
        let low = chars[i+1].to_digit(16).ok_or_else(|| "Invalid hex digit".to_string())? as u8;
        res.push((high << 4) | low);
    }
    Ok(res)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Wrapper for ClientHello padding.
///
/// Input JSON: `{"raw_hex": "160301...", "pad_len": 500}`
#[no_mangle]
pub unsafe extern "C" fn pad_client_hello_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: PadClientHelloInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let raw_bytes = match hex_decode(&input.raw_hex) {
            Ok(b) => b,
            Err(e) => {
                let res = PadClientHelloResult {
                    padded_hex: None,
                    success: false,
                    error: Some(e),
                };
                return str_to_c_char(&serde_json::to_string(&res).unwrap());
            }
        };

        let res = match crate::tls::pad_client_hello(&raw_bytes, input.pad_len) {
            Ok(padded) => PadClientHelloResult {
                padded_hex: Some(hex_encode(&padded)),
                success: true,
                error: None,
            },
            Err(e) => PadClientHelloResult {
                padded_hex: None,
                success: false,
                error: Some(e.to_string()),
            },
        };

        let json_res = serde_json::to_string(&res).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}

#[derive(Deserialize)]
struct FakePacketInput {
    target_ip: String,
    port: u16,
    ttl: u32,
    flags: Option<u8>,
    seq: Option<u32>,
    ack: Option<u32>,
    payload_hex: String,
}

/// Wrapper for raw fake TCP packet injection.
///
/// Input JSON: `{"target_ip": "192.0.2.1", "port": 443, "ttl": 4, "flags": 24, "payload_hex": "160301..."}`
#[no_mangle]
pub unsafe extern "C" fn inject_fake_packet_ffi(input_json: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(|| {
        let input_str = c_str_to_str(input_json);
        let input: FakePacketInput = match serde_json::from_str(input_str) {
            Ok(inp) => inp,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid JSON: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let target_ip = match input.target_ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid IP: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let payload = match hex_decode(&input.payload_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid Hex payload: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let flags = input.flags.unwrap_or(0x18); // Default to PSH|ACK
        let seq = input.seq.unwrap_or_else(|| rand::random::<u32>());
        let ack = input.ack.unwrap_or(0);

        let res = crate::tcp::send_fake_packet(
            target_ip,
            input.port,
            input.ttl,
            flags,
            seq,
            ack,
            &payload,
        );

        let json_res = match res {
            Ok(_) => "{\"success\":true}".to_string(),
            Err(e) => format!("{{\"success\":false,\"error\":\"{:?}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
    .unwrap_or_else(|_| str_to_c_char("{\"error\":\"Internal Rust Panic\"}"))
}
