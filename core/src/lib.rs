//! # LumiCore — High-Performance Network Scanning Engine
//!
//! The Rust core library for LumiNet. Provides performance-critical
//! network probe implementations compiled as a C-compatible static
//! library for Go to call via CGO.
//!
//! ## Modules
//! - `icmp` — Async ICMP scanner (Windows iphlpapi + Unix raw sockets)
//! - `dns` — Raw DNS packet construction, UDP/DoH/DoT resolution
//! - `tcp` — TCP connect probing with latency measurement
//! - `tls` — TLS handshake probing with cipher/version extraction
//! - `socks` — SOCKS5/HTTP CONNECT protocol implementation
//! - `http` — HTTP probe engine with proxy support
//! - `sni` — SNI blocking detection
//! - `speed` — Download/upload speed testing
//! - `cidr` — CIDR/IP range expansion
//! - `wg` — WireGuard handshake probing
//! - `ffi` — C-ABI exports for Go CGO bridge

pub mod cidr;
pub mod dns;
pub mod ffi;
pub mod http;
pub mod icmp;
pub mod sni;
pub mod socks;
pub mod speed;
pub mod tcp;
pub mod tls;
pub mod types;
pub mod wg;

pub use types::*;
