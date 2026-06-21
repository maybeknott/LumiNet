//! # HTTP Module
//!
//! HTTP probing engine with proxy support, captive portal detection,
//! and header inspection capabilities.

mod prober;

pub use prober::{detect_captive_portal, http_get, http_head, CaptivePortalResult, HttpResponse};
