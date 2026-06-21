//! # SNI Spoofing TLS Handshake Builder
//!
//! Generates raw TLS ClientHello handshake byte packets containing custom SNI extensions.

/// Builds a raw TLS ClientHello packet with a spoofed SNI Server Name string.
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut packet = vec![
        0x16, 0x03, 0x01, // Record header: Handshake, TLS 1.0 (legacy record version)
        0x00, 0x00,       // Record length placeholder (offsets 3..5)
        0x01,             // Handshake type: ClientHello (1)
        0x00, 0x00, 0x00, // Handshake length placeholder (offsets 6..9)
        0x03, 0x03,       // Handshake version: TLS 1.2 (0x0303)
    ];

    // Client random (32 bytes)
    packet.extend_from_slice(&[0u8; 32]);

    // Session ID length (0)
    packet.push(0x00);

    // Cipher suites length (2 bytes, 2 ciphers = 4 bytes)
    // We add TLS_AES_128_GCM_SHA256 (0x1301) and TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    packet.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0xc0, 0x2f]);

    // Compression methods length (1), null compression (0)
    packet.extend_from_slice(&[0x01, 0x00]);

    // Extensions section start
    let mut extensions = Vec::new();

    // Add Server Name Indication (SNI) extension
    let sni_bytes = sni.as_bytes();
    let name_len = sni_bytes.len() as u16;
    let list_len = name_len + 3; // name_len + 1 (name type) + 2 (name length)
    let ext_len = list_len + 2;  // list_len + 2 (list length)

    // Extension type: Server Name (0x0000)
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&ext_len.to_be_bytes());
    extensions.extend_from_slice(&list_len.to_be_bytes());
    extensions.push(0x00); // Server name type: host_name (0)
    extensions.extend_from_slice(&name_len.to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    // Append extensions length to packet
    let ext_section_len = extensions.len() as u16;
    packet.extend_from_slice(&ext_section_len.to_be_bytes());
    packet.extend_from_slice(&extensions);

    // Update length headers
    let total_len = packet.len();
    
    // Update Handshake length (total length minus record header 5 bytes minus handshake header 4 bytes)
    let hs_len = (total_len - 9) as u32;
    let hs_len_bytes = hs_len.to_be_bytes();
    packet[6] = hs_len_bytes[1];
    packet[7] = hs_len_bytes[2];
    packet[8] = hs_len_bytes[3];

    // Update Record length (total length minus record header 5 bytes)
    let rec_len = (total_len - 5) as u16;
    let rec_len_bytes = rec_len.to_be_bytes();
    packet[3] = rec_len_bytes[0];
    packet[4] = rec_len_bytes[1];

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_client_hello() {
        let packet = build_client_hello("example.com");
        assert!(packet.len() > 40);
        // Verify TLS record header fields
        assert_eq!(packet[0], 0x16); // Handshake record type
        assert_eq!(packet[1], 0x03); // Version major
        assert_eq!(packet[2], 0x01); // Version minor
        assert_eq!(packet[5], 0x01); // Handshake ClientHello type
    }
}
