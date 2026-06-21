//! # TLS Module
//!
//! TLS handshake probing, certificate inspection, and SSL inspection detection.

pub mod cert_installer;
pub mod mitm;
mod prober;

pub use prober::{detect_ssl_inspection, tls_handshake, tls_handshake_batch, SslInspectionResult, pad_client_hello};
pub use mitm::MitmCertManager;
