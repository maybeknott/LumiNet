//! # DNS Packet Builder & Parser
//!
//! Hand-crafted DNS packet construction and parsing, ported from
//! `network-lab/lab-scanner.py`. Builds raw DNS query packets and parses
//! response packets without relying on external DNS libraries for the wire format.

use crate::types::DnsRecord;

// ── DNS Record Type Constants ──────────────────────────────────────────────

/// DNS A record (IPv4 address).
pub const TYPE_A: u16 = 1;
/// DNS NS record (authoritative name server).
pub const TYPE_NS: u16 = 2;
/// DNS CNAME record (canonical name alias).
pub const TYPE_CNAME: u16 = 5;
/// DNS SOA record (start of authority).
pub const TYPE_SOA: u16 = 6;
/// DNS PTR record (pointer / reverse lookup).
pub const TYPE_PTR: u16 = 12;
/// DNS MX record (mail exchange).
pub const TYPE_MX: u16 = 15;
/// DNS TXT record (text).
pub const TYPE_TXT: u16 = 16;
/// DNS AAAA record (IPv6 address).
pub const TYPE_AAAA: u16 = 28;
/// DNS HTTPS record (SVCB/HTTPS bindings).
pub const TYPE_HTTPS: u16 = 65;


/// DNS IN (Internet) class.
pub const CLASS_IN: u16 = 1;

/// Builds a raw DNS query packet.
///
/// Constructs a standards-compliant DNS query with the given domain name,
/// record type, and transaction ID. The packet includes the 12-byte header,
/// the question section, and uses recursion desired (RD) flag.
///
/// # Arguments
/// * `domain` — The domain name to query (e.g., `"example.com"`).
/// * `record_type` — DNS record type (use the `TYPE_*` constants).
/// * `transaction_id` — A 16-bit transaction identifier for matching replies.
///
/// # Returns
/// The raw DNS query packet as a byte vector.
pub fn build_query(domain: &str, record_type: u16, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Header: transaction ID
    packet.push((transaction_id >> 8) as u8);
    packet.push((transaction_id & 0xFF) as u8);
    // Flags: standard query, recursion desired
    packet.push(0x01);
    packet.push(0x00);
    // QDCOUNT = 1
    packet.push(0x00);
    packet.push(0x01);
    // ANCOUNT = 0
    packet.push(0x00);
    packet.push(0x00);
    // NSCOUNT = 0
    packet.push(0x00);
    packet.push(0x00);
    // ARCOUNT = 0
    packet.push(0x00);
    packet.push(0x00);

    // Question section: encoded domain name
    packet.extend_from_slice(&encode_domain_name(domain));

    // QTYPE
    packet.push((record_type >> 8) as u8);
    packet.push((record_type & 0xFF) as u8);
    // QCLASS = IN
    packet.push((CLASS_IN >> 8) as u8);
    packet.push((CLASS_IN & 0xFF) as u8);

    packet
}

/// Parses a raw DNS response packet into structured [`DnsRecord`]s.
///
/// Handles label compression pointers, multiple answer records, and all
/// supported record types.
///
/// # Arguments
/// * `buf` — The raw DNS response bytes.
///
/// # Returns
/// A vector of parsed DNS records from the answer section.
pub fn parse_response(buf: &[u8]) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    if buf.len() < 12 {
        return Err("DNS response too short".into());
    }

    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return Ok(vec![]);
    }

    // Skip the question section
    let mut offset = 12usize;
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    for _ in 0..qdcount {
        let (_, consumed) = decode_domain_name(buf, offset)?;
        offset += consumed;
        offset += 4; // QTYPE + QCLASS
    }

    let mut records = Vec::new();
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        let (name, consumed) = decode_domain_name(buf, offset)?;
        offset += consumed;

        if offset + 10 > buf.len() {
            break;
        }

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        let rdata = &buf[offset..offset + rdlength];
        offset += rdlength;

        let class_str = if rclass == CLASS_IN {
            "IN".to_string()
        } else {
            format!("{}", rclass)
        };

        let (type_str, value) = match rtype {
            TYPE_A if rdlength == 4 => (
                "A".to_string(),
                format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
            ),
            TYPE_AAAA if rdlength == 16 => {
                let groups: Vec<String> = rdata
                    .chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                ("AAAA".to_string(), groups.join(":"))
            }
            TYPE_CNAME | TYPE_NS | TYPE_PTR => {
                let type_name = match rtype {
                    TYPE_CNAME => "CNAME",
                    TYPE_NS => "NS",
                    TYPE_PTR => "PTR",
                    _ => "UNKNOWN",
                };
                let (cname, _) = decode_domain_name(buf, offset - rdlength)?;
                (type_name.to_string(), cname)
            }
            TYPE_MX if rdlength >= 3 => {
                let (mx_host, _) = decode_domain_name(buf, offset - rdlength + 2)?;
                ("MX".to_string(), mx_host)
            }
            TYPE_TXT => {
                let mut txt = String::new();
                let mut i = 0;
                while i < rdlength {
                    let len = rdata[i] as usize;
                    i += 1;
                    if i + len <= rdlength {
                        txt.push_str(&String::from_utf8_lossy(&rdata[i..i + len]));
                    }
                    i += len;
                }
                ("TXT".to_string(), txt)
            }
            TYPE_SOA => {
                let (mname, _) = decode_domain_name(buf, offset - rdlength)?;
                ("SOA".to_string(), mname)
            }
            TYPE_HTTPS => {
                let has_ech = rdata.windows(2).any(|w| w == [0, 5]);
                let priority = if rdata.len() >= 2 {
                    u16::from_be_bytes([rdata[0], rdata[1]])
                } else {
                    0
                };
                let suffix = if has_ech { " [ECH Supported]" } else { "" };
                (
                    "HTTPS".to_string(),
                    format!("Priority: {}, Data: {}{}", priority, hex::encode(&rdata[2..]), suffix),
                )
            }
            _ => (format!("TYPE{}", rtype), hex::encode(rdata)),
        };

        records.push(DnsRecord {
            name,
            record_type: type_str,
            value,
            ttl,
            class: class_str,
        });
    }

    Ok(records)
}

/// Minimal hex encoding helper (avoids adding a dep just for this).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Encodes a domain name into DNS wire format (label-length encoding).
///
/// For example, `"example.com"` becomes `\x07example\x03com\x00`.
///
/// # Arguments
/// * `domain` — The domain name to encode.
pub fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        encoded.push(bytes.len() as u8);
        encoded.extend_from_slice(bytes);
    }
    encoded.push(0); // root label
    encoded
}

pub fn decode_domain_name(
    buf: &[u8],
    offset: usize,
) -> Result<(String, usize), Box<dyn std::error::Error>> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut bytes_consumed = 0;
    let mut jump_count = 0;

    loop {
        if pos >= buf.len() {
            return Err("DNS name decode: offset out of bounds".into());
        }

        let byte = buf[pos];

        if byte == 0 {
            if !jumped {
                bytes_consumed = pos - offset + 1;
            }
            break;
        } else if byte & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= buf.len() {
                return Err("DNS name decode: truncated pointer".into());
            }
            if !jumped {
                bytes_consumed = pos - offset + 2;
            }
            let ptr = (((byte & 0x3F) as usize) << 8) | buf[pos + 1] as usize;
            pos = ptr;
            jumped = true;
            jump_count += 1;
            if jump_count > 20 {
                return Err("DNS name decode: too many compression pointers (loop?)".into());
            }
        } else {
            let len = byte as usize;
            pos += 1;
            if pos + len > buf.len() {
                return Err("DNS name decode: label extends beyond buffer".into());
            }
            labels.push(String::from_utf8_lossy(&buf[pos..pos + len]).to_string());
            pos += len;
        }
    }

    Ok((labels.join("."), bytes_consumed))
}
