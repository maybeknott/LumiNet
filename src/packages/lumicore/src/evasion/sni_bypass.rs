//! # SNI Bypass
//!
//! Outbound TLS client hello hooking and fake decoy SNI packet injection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
#[cfg(target_os = "windows")]
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SniBypassConfig {
    pub enabled: bool,
    pub decoy_sni: String,
    pub filter: String,
}

impl Default for SniBypassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            decoy_sni: "microsoft.com".to_string(),
            filter: "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0".to_string(),
        }
    }
}

pub struct SniBypassEngine {
    running: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl Default for SniBypassEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SniBypassEngine {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn start(&mut self, config: SniBypassConfig) -> Result<(), String> {
        if !config.enabled {
            return Ok(());
        }
        Err("WinDivert SNI Bypass is only supported on Windows".to_string())
    }

    #[cfg(target_os = "windows")]
    pub fn start(&mut self, config: SniBypassConfig) -> Result<(), String> {
        if !config.enabled {
            return Ok(());
        }
        if !crate::evasion::sni_spoof::is_valid_sni_hostname(&config.decoy_sni) {
            return Err("invalid decoy SNI: expected a bounded ASCII DNS hostname".to_string());
        }

        if self.running.load(Ordering::SeqCst) {
            return Err("Engine already running".to_string());
        }

        self.running.store(true, Ordering::SeqCst);
        let running_clone = self.running.clone();

        let handle = thread::spawn(move || {
            if let Err(e) = run_divert_loop(config, running_clone) {
                log::error!("WinDivert loop error: {}", e);
            }
        });

        self.thread_handle = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(target_os = "windows")]
mod win_impl {
    use super::*;
    use std::ffi::c_void;

    // WinDivert structures
    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    pub struct DIVERT_ADDRESS {
        pub timestamp: u64,
        pub if_idx: u32,
        pub sub_if_idx: u32,
        pub direction: u8,
        pub bits: u8,
        pub reserved: [u8; 62],
    }

    type DivertOpenFn = unsafe extern "system" fn(
        filter: *const u8,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> *mut c_void;
    type DivertRecvFn = unsafe extern "system" fn(
        handle: *mut c_void,
        packet: *mut u8,
        packet_len: u32,
        read_len: *mut u32,
        addr: *mut DIVERT_ADDRESS,
    ) -> i32;
    type DivertSendFn = unsafe extern "system" fn(
        handle: *mut c_void,
        packet: *const u8,
        packet_len: u32,
        write_len: *mut u32,
        addr: *const DIVERT_ADDRESS,
    ) -> i32;
    type DivertCloseFn = unsafe extern "system" fn(handle: *mut c_void) -> i32;
    type DivertHelperCalcChecksumsFn = unsafe extern "system" fn(
        packet: *mut u8,
        packet_len: u32,
        addr: *mut DIVERT_ADDRESS,
        flags: u64,
    ) -> i32;

    struct WinDivertDll {
        _lib: *mut c_void,
        open: DivertOpenFn,
        recv: DivertRecvFn,
        send: DivertSendFn,
        close: DivertCloseFn,
        calc_checksums: DivertHelperCalcChecksumsFn,
    }

    extern "system" {
        fn LoadLibraryA(lpLibFileName: *const u8) -> *mut c_void;
        fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
        fn FreeLibrary(hLibModule: *mut c_void) -> i32;
    }

    impl WinDivertDll {
        fn load() -> Result<Self, String> {
            unsafe {
                let lib = LoadLibraryA(c"WinDivert.dll".as_ptr().cast());
                if lib.is_null() {
                    return Err("Failed to load WinDivert.dll".to_string());
                }

                let open_ptr = GetProcAddress(lib, c"DivertOpen".as_ptr().cast());
                let recv_ptr = GetProcAddress(lib, c"DivertRecv".as_ptr().cast());
                let send_ptr = GetProcAddress(lib, c"DivertSend".as_ptr().cast());
                let close_ptr = GetProcAddress(lib, c"DivertClose".as_ptr().cast());
                let calc_ptr = GetProcAddress(lib, c"DivertHelperCalcChecksums".as_ptr().cast());

                if open_ptr.is_null()
                    || recv_ptr.is_null()
                    || send_ptr.is_null()
                    || close_ptr.is_null()
                    || calc_ptr.is_null()
                {
                    FreeLibrary(lib);
                    return Err("Failed to find WinDivert functions".to_string());
                }

                Ok(Self {
                    _lib: lib,
                    open: std::mem::transmute::<*mut c_void, DivertOpenFn>(open_ptr),
                    recv: std::mem::transmute::<*mut c_void, DivertRecvFn>(recv_ptr),
                    send: std::mem::transmute::<*mut c_void, DivertSendFn>(send_ptr),
                    close: std::mem::transmute::<*mut c_void, DivertCloseFn>(close_ptr),
                    calc_checksums: std::mem::transmute::<*mut c_void, DivertHelperCalcChecksumsFn>(
                        calc_ptr,
                    ),
                })
            }
        }
    }

    pub fn run_divert_loop(
        config: SniBypassConfig,
        running: Arc<AtomicBool>,
    ) -> Result<(), String> {
        let dll = WinDivertDll::load()?;
        let filter_c = format!("{}\0", config.filter);

        let handle = unsafe { (dll.open)(filter_c.as_ptr(), 0, 0, 0) };
        if handle.is_null() {
            return Err("Failed to open WinDivert handle".to_string());
        }

        let mut packet_buf = vec![0u8; 65535];
        let mut addr = DIVERT_ADDRESS {
            timestamp: 0,
            if_idx: 0,
            sub_if_idx: 0,
            direction: 0,
            bits: 0,
            reserved: [0; 62],
        };

        while running.load(Ordering::SeqCst) {
            let mut read_len = 0u32;
            let success = unsafe {
                (dll.recv)(
                    handle,
                    packet_buf.as_mut_ptr(),
                    packet_buf.len() as u32,
                    &mut read_len,
                    &mut addr,
                )
            };

            if success == 0 {
                thread::sleep(Duration::from_millis(10));
                continue;
            }

            let raw_packet = &packet_buf[..read_len as usize];

            // If it's a TLS ClientHello, we inject the fake packet first
            if is_tls_client_hello(raw_packet) {
                if let Some(fake_pkt) =
                    build_fake_packet(raw_packet, &config.decoy_sni, &dll, &mut addr)
                {
                    let mut written = 0u32;
                    unsafe {
                        (dll.send)(
                            handle,
                            fake_pkt.as_ptr(),
                            fake_pkt.len() as u32,
                            &mut written,
                            &addr,
                        );
                    }
                }
            }

            // Forward the original packet
            let mut written = 0u32;
            unsafe {
                (dll.send)(
                    handle,
                    raw_packet.as_ptr(),
                    raw_packet.len() as u32,
                    &mut written,
                    &addr,
                );
            }
        }

        unsafe {
            (dll.close)(handle);
        }
        Ok(())
    }

    fn is_tls_client_hello(packet: &[u8]) -> bool {
        // Simple TCP/TLS parser helper
        if packet.len() < 40 {
            return false;
        }
        let ip_version = packet[0] >> 4;
        let ip_hdr_len = if ip_version == 4 {
            (packet[0] & 0x0F) as usize * 4
        } else {
            40 // IPv6 header length (we don't fully support IPv6 parse here, but just return false)
        };

        if packet.len() < ip_hdr_len + 20 {
            return false;
        }

        let tcp_hdr_len = ((packet[ip_hdr_len + 12] >> 4) as usize) * 4;
        let payload_offset = ip_hdr_len + tcp_hdr_len;

        if packet.len() < payload_offset + 6 {
            return false;
        }

        let payload = &packet[payload_offset..];
        // TLS Handshake (0x16) and ClientHello (0x01)
        payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
    }

    fn build_fake_packet(
        orig: &[u8],
        decoy_sni: &str,
        dll: &WinDivertDll,
        addr: &mut DIVERT_ADDRESS,
    ) -> Option<Vec<u8>> {
        let ip_version = orig[0] >> 4;
        if ip_version != 4 {
            return None; // IPv4 only for simpler packet fabrication
        }

        let ip_hdr_len = (orig[0] & 0x0F) as usize * 4;
        if ip_hdr_len < 20 || orig.len() < ip_hdr_len + 20 {
            return None;
        }
        let tcp_hdr_len = ((orig[ip_hdr_len + 12] >> 4) as usize) * 4;
        if tcp_hdr_len < 20 || orig.len() < ip_hdr_len + tcp_hdr_len {
            return None;
        }

        // Build fake clienthello payload
        let fake_hello = crate::evasion::sni_spoof::build_fake_clienthello(
            decoy_sni,
            crate::evasion::BrowserFingerprint::Chrome120,
        );

        let new_len = ip_hdr_len + tcp_hdr_len + fake_hello.len();
        let mut fake_pkt = vec![0u8; new_len];

        // Copy IP + TCP headers from original
        fake_pkt[..ip_hdr_len + tcp_hdr_len].copy_from_slice(&orig[..ip_hdr_len + tcp_hdr_len]);

        // Copy fake TLS ClientHello payload
        fake_pkt[ip_hdr_len + tcp_hdr_len..].copy_from_slice(&fake_hello);

        // Update IPv4 Total Length
        let total_len = fake_pkt.len() as u16;
        fake_pkt[2] = (total_len >> 8) as u8;
        fake_pkt[3] = (total_len & 0xFF) as u8;

        // The intercepted real ClientHello starts at ISN+1. Place the entire
        // decoy immediately before that receive window so the server treats it
        // as old data while passive DPI can still observe the ClientHello.
        let real_seq = u32::from_be_bytes([
            fake_pkt[ip_hdr_len + 4],
            fake_pkt[ip_hdr_len + 5],
            fake_pkt[ip_hdr_len + 6],
            fake_pkt[ip_hdr_len + 7],
        ]);
        let fake_seq = crate::evasion::sni_spoof::compute_fake_seq_from_next(
            real_seq,
            fake_hello.len(),
        );
        fake_pkt[ip_hdr_len + 4..ip_hdr_len + 8].copy_from_slice(&fake_seq.to_be_bytes());

        // Zero checksums before calc
        fake_pkt[10] = 0; // IP checksum
        fake_pkt[11] = 0;
        fake_pkt[ip_hdr_len + 16] = 0; // TCP checksum
        fake_pkt[ip_hdr_len + 17] = 0;

        // Recalculate checksums using WinDivert helper
        unsafe {
            (dll.calc_checksums)(fake_pkt.as_mut_ptr(), fake_pkt.len() as u32, addr, 0);
        }

        Some(fake_pkt)
    }
}

#[cfg(target_os = "windows")]
use win_impl::run_divert_loop;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_bypass_config() {
        let config = SniBypassConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.decoy_sni, "microsoft.com");
    }

    #[test]
    fn test_engine_init() {
        let mut engine = SniBypassEngine::new();
        let config = SniBypassConfig::default();
        let res = engine.start(config);
        assert!(res.is_ok());
        engine.stop();
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn enabled_engine_fails_closed_on_unsupported_platforms() {
        let mut engine = SniBypassEngine::new();
        let config = SniBypassConfig {
            enabled: true,
            ..SniBypassConfig::default()
        };
        let err = engine.start(config).expect_err("enabled WinDivert bypass must fail closed");
        assert!(err.contains("only supported on Windows"));
    }
}
