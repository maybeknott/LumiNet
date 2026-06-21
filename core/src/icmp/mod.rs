//! ICMP scanning engine — async, cross-platform.
//!
//! Ported from ping/scanner.py's AsyncIcmpScanner which uses Windows
//! iphlpapi (IcmpSendEcho2 with async events and WaitForMultipleObjects).
//!
//! Platform abstraction:
//! - Windows: iphlpapi.dll (IcmpSendEcho2, Icmp6SendEcho2, SendARP)
//! - Unix: Raw ICMP sockets (requires CAP_NET_RAW or root)

mod scanner;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use scanner::*;
