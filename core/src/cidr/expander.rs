//! # CIDR Expander
//!
//! Parses and expands CIDR blocks and IP ranges into list of individual IP addresses.

use crate::types::{LumiError, LumiResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Expander for CIDR blocks and IP ranges.
pub struct CidrExpander;

impl CidrExpander {
    /// Parses a CIDR block or IP range string and returns all contained IP addresses.
    ///
    /// Supports:
    /// - Individual IPs: `192.168.1.1`
    /// - IPv4 CIDR: `192.168.1.0/24`
    /// - IPv6 CIDR: `2001:db8::/120`
    /// - IPv4 full range: `192.168.1.5-192.168.1.15`
    /// - IPv4 suffix range: `192.168.1.5-15`
    ///
    /// # Arguments
    /// * `cidr` — The CIDR block or range.
    pub fn expand(cidr: &str) -> LumiResult<Vec<IpAddr>> {
        let cidr = cidr.trim();

        if cidr.is_empty() {
            return Err(LumiError::InvalidTarget(
                "Empty IP range target".to_string(),
            ));
        }

        // 1. Check for CIDR format (contains '/')
        if cidr.contains('/') {
            return Self::expand_cidr_block(cidr);
        }

        // 2. Check for range format (contains '-')
        if cidr.contains('-') {
            return Self::expand_dash_range(cidr);
        }

        // 3. Otherwise treat as a single IP address
        match IpAddr::from_str(cidr) {
            Ok(ip) => Ok(vec![ip]),
            Err(_) => Err(LumiError::InvalidTarget(format!(
                "Invalid IP address format: '{}'",
                cidr
            ))),
        }
    }

    /// Expands a CIDR block e.g., "192.168.1.0/24"
    fn expand_cidr_block(cidr: &str) -> LumiResult<Vec<IpAddr>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(LumiError::InvalidTarget(format!(
                "Invalid CIDR syntax: {}",
                cidr
            )));
        }

        let base_ip = IpAddr::from_str(parts[0])
            .map_err(|e| LumiError::InvalidTarget(format!("Invalid base IP: {}", e)))?;
        let prefix_len = u32::from_str(parts[1])
            .map_err(|e| LumiError::InvalidTarget(format!("Invalid prefix length: {}", e)))?;

        match base_ip {
            IpAddr::V4(ipv4) => {
                if prefix_len > 32 {
                    return Err(LumiError::InvalidTarget(
                        "IPv4 prefix length cannot exceed 32".to_string(),
                    ));
                }

                // Protect against out-of-memory errors for massive networks
                if prefix_len < 16 {
                    return Err(LumiError::InvalidTarget(format!(
                        "Prefix length /{} is too large to expand. Minimum prefix is /16 (65,536 IPs).",
                        prefix_len
                    )));
                }

                let ip_u32 = u32::from(ipv4);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let network = ip_u32 & mask;
                let num_hosts = 1u32 << (32 - prefix_len);

                let mut ips = Vec::with_capacity(num_hosts as usize);
                for i in 0..num_hosts {
                    let host_ip = network + i;
                    ips.push(IpAddr::V4(Ipv4Addr::from(host_ip)));
                }
                Ok(ips)
            }
            IpAddr::V6(ipv6) => {
                if prefix_len > 128 {
                    return Err(LumiError::InvalidTarget(
                        "IPv6 prefix length cannot exceed 128".to_string(),
                    ));
                }

                // For IPv6, we limit expansion to small subnets to prevent memory exhaustion.
                if prefix_len < 120 {
                    return Err(LumiError::InvalidTarget(format!(
                        "IPv6 prefix /{} is too large to expand. Minimum prefix is /120 (256 IPs).",
                        prefix_len
                    )));
                }

                let ip_u128 = u128::from(ipv6);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let network = ip_u128 & mask;
                let num_hosts = 1u128 << (128 - prefix_len);

                let mut ips = Vec::with_capacity(num_hosts as usize);
                for i in 0..num_hosts {
                    let host_ip = network + i;
                    ips.push(IpAddr::V6(Ipv6Addr::from(host_ip)));
                }
                Ok(ips)
            }
        }
    }

    /// Expands a dash range, e.g., "192.168.1.5-15" or "192.168.1.5-192.168.1.15"
    fn expand_dash_range(range_str: &str) -> LumiResult<Vec<IpAddr>> {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() != 2 {
            return Err(LumiError::InvalidTarget(format!(
                "Invalid range format: '{}'",
                range_str
            )));
        }

        let start_str = parts[0].trim();
        let end_str = parts[1].trim();

        let start_ip = Ipv4Addr::from_str(start_str).map_err(|_| {
            LumiError::InvalidTarget(format!(
                "Range start must be a valid IPv4 address: '{}'",
                start_str
            ))
        })?;

        let end_ip = if let Ok(ip) = Ipv4Addr::from_str(end_str) {
            ip
        } else {
            // Suffix range format e.g. "192.168.1.5-15"
            let last_octet = u8::from_str(end_str).map_err(|_| {
                LumiError::InvalidTarget(format!("Invalid range suffix octet: '{}'", end_str))
            })?;

            let octets = start_ip.octets();
            Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
        };

        let start_u32 = u32::from(start_ip);
        let end_u32 = u32::from(end_ip);

        if start_u32 > end_u32 {
            return Err(LumiError::InvalidTarget(format!(
                "Start IP ({}) is greater than end IP ({}) in range",
                start_ip, end_ip
            )));
        }

        let range_size = end_u32 - start_u32 + 1;
        if range_size > 65536 {
            return Err(LumiError::InvalidTarget(format!(
                "IP range size of {} is too large. Maximum allowed is 65536.",
                range_size
            )));
        }

        let mut ips = Vec::with_capacity(range_size as usize);
        for ip in start_u32..=end_u32 {
            ips.push(IpAddr::V4(Ipv4Addr::from(ip)));
        }
        Ok(ips)
    }
}

/// Helper function to quickly expand a CIDR string.
///
/// # Arguments
/// * `cidr` — The CIDR block or range (e.g. "192.168.1.0/24").
pub fn expand_cidr(cidr: &str) -> LumiResult<Vec<IpAddr>> {
    CidrExpander::expand(cidr)
}
