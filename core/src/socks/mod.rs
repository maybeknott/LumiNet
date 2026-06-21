//! # SOCKS / Proxy Module
//!
//! SOCKS5 and HTTP CONNECT proxy client and discovery.

mod client;
mod evasion;

pub use client::{
    discover_local_proxies, http_proxy_connect, socks5_connect, socks5_handshake, ProxyDiscovery,
};
pub use evasion::write_with_evasion;
