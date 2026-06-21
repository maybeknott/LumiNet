//! # C FFI Layer
//!
//! Provides C-compatible ABI exports for integration with the Go backend via CGO.
//! All functions take C-style inputs (e.g. `*const c_char`) and return JSON serialized strings.

pub mod exports;

#[cfg(target_os = "android")]
pub mod android_jni;

#[cfg(target_os = "ios")]
pub mod ios_ffi;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Helper to convert a raw C string to a Rust str.
///
/// # Safety
/// This function is unsafe as it dereferences raw pointers.
pub unsafe fn c_str_to_str<'a>(c_str: *const c_char) -> &'a str {
    if c_str.is_null() {
        ""
    } else {
        CStr::from_ptr(c_str).to_str().unwrap_or("")
    }
}

/// Helper to convert a Rust string/JSON into a raw C string.
/// The caller is responsible for freeing this memory using `free_string`.
pub fn str_to_c_char(s: &str) -> *mut c_char {
    let c_str = CString::new(s)
        .unwrap_or_else(|_| CString::new("{\"error\":\"CString conversion failed\"}").unwrap());
    c_str.into_raw()
}

/// Frees a string that was allocated by Rust and passed to C.
///
/// # Safety
/// This function must only be called with a pointer returned by Rust FFI.
#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}
