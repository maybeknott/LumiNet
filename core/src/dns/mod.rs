//! # DNS Module
//!
//! DNS resolution with support for multiple transports: plain UDP (port 53),
//! DNS-over-HTTPS (DoH), and DNS-over-TLS (DoT). Includes hand-crafted DNS
//! packet building and parsing for minimal dependencies and full control.

mod doh;
mod dot;
mod packet;
mod udp;

pub use doh::{resolve_doh, resolve_doh_json, DOH_ENDPOINTS};
pub use dot::{resolve_dot, DOT_SERVERS};
pub use packet::{
    build_query, decode_domain_name, encode_domain_name, parse_response, CLASS_IN, TYPE_A,
    TYPE_AAAA, TYPE_CNAME, TYPE_MX, TYPE_NS, TYPE_PTR, TYPE_SOA, TYPE_TXT, TYPE_HTTPS,
};
pub use udp::{resolve, resolve_batch, scan_dns_servers, DnsServerResult};
