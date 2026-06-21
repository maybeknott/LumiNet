//! # WireGuard Prober
//!
//! Implements a low-level UDP-based WireGuard handshake probe. Sends a correctly formatted
//! 148-byte Handshake Initiation packet and waits for a Handshake Response (type 2) or any UDP activity.

use crate::types::{LumiError, LumiResult, WgProbeResult};
use rand::RngCore;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Prober for verifying WireGuard endpoint status.
pub struct WgProber {
    ip: String,
    port: u16,
    timeout_ms: u32,
    padding_len: Option<u32>,
    num_decoys: u32,
}

impl WgProber {
    /// Creates a new WireGuard prober for the specified target.
    ///
    /// # Arguments
    /// * `ip` — IP address of the WireGuard endpoint.
    /// * `port` — UDP port of the WireGuard endpoint.
    /// * `timeout_ms` — Timeout in milliseconds.
    /// * `padding_len` — Optional extra random padding bytes.
    pub fn new(ip: String, port: u16, timeout_ms: u32, padding_len: Option<u32>) -> Self {
        Self {
            ip,
            port,
            timeout_ms,
            padding_len,
            num_decoys: 0,
        }
    }

    /// Creates a new WireGuard prober with decoy packet configuration.
    pub fn new_with_decoys(
        ip: String,
        port: u16,
        timeout_ms: u32,
        padding_len: Option<u32>,
        num_decoys: u32,
    ) -> Self {
        Self {
            ip,
            port,
            timeout_ms,
            padding_len,
            num_decoys,
        }
    }

    /// Probes the WireGuard endpoint by sending optionally decoy packets and then
    /// an initiation packet and waiting for a handshake response.
    pub async fn probe(&self) -> LumiResult<WgProbeResult> {
        let addr = format!("{}:{}", self.ip, self.port);
        let start = Instant::now();

        // 1. Bind local UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                return Err(LumiError::Network(format!(
                    "Failed to bind local UDP socket: {}",
                    e
                )))
            }
        };

        // 2. Connect UDP socket to target
        if let Err(e) = socket.connect(&addr).await {
            return Err(LumiError::Network(format!(
                "Failed to connect UDP socket to {}: {}",
                addr, e
            )));
        }

        let mut rng = rand::thread_rng();

        // 3. Send UDP decoy packets if configured
        for _ in 0..self.num_decoys {
            use rand::Rng;
            let packet_size = rng.gen_range(10..40);
            let mut decoy_packet = vec![0u8; packet_size];
            rng.fill_bytes(&mut decoy_packet);

            if let Err(e) = socket.send(&decoy_packet).await {
                return Err(LumiError::Network(format!(
                    "Failed to send UDP decoy packet: {}",
                    e
                )));
            }

            // Sleep with random jitter between 50 and 200 milliseconds
            let jitter_ms = rng.gen_range(50..200);
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
        }

        // 4. Construct a syntactically correct WireGuard Handshake Initiation packet (148 + pad bytes)
        let pad = self.padding_len.unwrap_or(0) as usize;
        let mut packet = vec![0u8; 148 + pad];

        // Message Type: 1 (Handshake Initiation)
        packet[0] = 1;
        // Reserved: 3 bytes (all zero)

        // Sender Index (random 4 bytes)
        rng.fill_bytes(&mut packet[4..8]);

        // Ephemeral Public Key (random 32 bytes)
        rng.fill_bytes(&mut packet[8..40]);

        // Encrypted Static Public Key (random 48 bytes)
        rng.fill_bytes(&mut packet[40..88]);

        // Encrypted Timestamp (random 28 bytes)
        rng.fill_bytes(&mut packet[88..116]);

        // MAC1 & MAC2: 16 bytes each
        rng.fill_bytes(&mut packet[116..148]);

        // If padding is active, randomize the trailing padding bytes
        if pad > 0 {
            rng.fill_bytes(&mut packet[148..148 + pad]);
        }

        // 5. Send packet
        if let Err(e) = socket.send(&packet).await {
            return Err(LumiError::Network(format!(
                "Failed to send UDP packet: {}",
                e
            )));
        }

        // 6. Receive response (expecting handshake response, type 2, length 92 bytes)
        let mut response_buf = vec![0u8; 1500];
        let recv_future = socket.recv(&mut response_buf);

        let result = timeout(Duration::from_millis(self.timeout_ms as u64), recv_future).await;

        let latency = start.elapsed().as_secs_f64() * 1000.0;

        match result {
            Ok(Ok(bytes_received)) => {
                if bytes_received >= 4 {
                    let msg_type = response_buf[0];
                    let response_type = match msg_type {
                        2 => "Handshake Response".to_string(),
                        3 => "Cookie Reply".to_string(),
                        4 => "Data Transport".to_string(),
                        _ => format!("UDP Response (Type {})", msg_type),
                    };

                    Ok(WgProbeResult {
                        ip: self.ip.clone(),
                        port: self.port,
                        success: true,
                        latency_ms: latency,
                        response_type,
                        error: None,
                    })
                } else {
                    Ok(WgProbeResult {
                        ip: self.ip.clone(),
                        port: self.port,
                        success: true,
                        latency_ms: latency,
                        response_type: "UDP Small Response".to_string(),
                        error: None,
                    })
                }
            }
            Ok(Err(err)) => Ok(WgProbeResult {
                ip: self.ip.clone(),
                port: self.port,
                success: false,
                latency_ms: latency,
                response_type: "None".to_string(),
                error: Some(err.to_string()),
            }),
            Err(_) => {
                // Timeout is normal since WireGuard silently drops packets with invalid MAC1
                // We'll mark it as successful if we are doing a broad simulation fallback or keep it false
                Ok(WgProbeResult {
                    ip: self.ip.clone(),
                    port: self.port,
                    success: false,
                    latency_ms: latency,
                    response_type: "Timeout".to_string(),
                    error: Some("Handshake timeout (silently dropped or offline)".to_string()),
                })
            }
        }
    }
}
