# 🦀 Rust Core Architecture & Technical Manual

This document provides a technical guide to the performance-critical scanning and diagnostic core located under `core/`. It details module structures, memory boundaries, threading models, and low-level evasion algorithms.

---

## 1. Directory & Module Mapping

The Rust core is compiled into a C-compatible static library (`liblumicore.a`) linked by the Go orchestration server.

```
core/
├── Cargo.toml                    # Rust crate dependencies and features
├── cbindgen.toml                  # cbindgen configurations for C header generation
├── src/
│   ├── lib.rs                    # Crate entry point
│   ├── ffi/
│   │   ├── mod.rs                # FFI module definition
│   │   ├── exports.rs            # Cgo-exported C ABI functions
│   │   └── types.rs              # C-compatible structs and serialized types
│   ├── scan/
│   │   ├── mod.rs                # Scanning orchestrator
│   │   ├── icmp/
│   │   │   └── scanner.rs        # Concurrent ICMP scanner (Winsock2 / raw sockets)
│   │   ├── tcp/
│   │   │   └── prober.rs         # Concurrent TCP connector and banner parser
│   │   ├── dns/
│   │   │   └── mod.rs            # DNS record harvester and DoH/DoT auditor
│   │   ├── tls/
│   │   │   └── prober.rs         # TLS ClientHello SNI reachability prober
│   │   └── wg/
│   │   │   └── prober.rs         # WireGuard padded UDP handshake prober
│   ├── cidr/
│   │   ├── mod.rs                # CIDR parser and validator
│   │   └── blackrock.rs          # Stateless index permutation shuffler
│   └── platform/
│       ├── mod.rs                # Trait abstractions for low-level socket APIs
│       ├── windows.rs            # Windows raw socket (Winsock2) implementation
│       └── linux.rs              # Linux standard raw socket implementation
└── tests/
    └── integration_tests.rs      # Integration tests covering scan components
```

---

## 2. Go-Rust FFI Interface Boundary

All complex data arrays and configuration payloads cross the FFI boundary as JSON-serialized strings.

```
       Go Server Caller                         Rust Core FFI Receiver
              │                                           │
  1. Serializes request struct to JSON                     │
  2. Calls `scan_icmp_ffi(cInput)` ───────────────────────►│
                                                          │ 3. Parses JSON config
                                                          │ 4. Executes Tokio async task
                                                          │ 5. Returns `const char*` pointer
  6. Copies pointer memory to Go heap ◄───────────────────┤
  7. Calls `free_string(cPointer)` ──────────────────────►│
                                                          │ 8. Drops Rust pointer allocation
```

### 2.1 JSON Schema Interfaces

#### ICMP Scan Input Configurations (JSON Passed from Go)
```json
{
  "target_cidr": "192.168.1.0/24",
  "concurrency": 200,
  "timeout_ms": 1500
}
```

#### ICMP Scan Output Result (JSON Returned to Go)
```json
{
  "status_code": 0,
  "message": "Scan complete",
  "data": {
    "scanned_hosts": 256,
    "active_hosts": [
      { "ip": "192.168.1.1", "rtt_ms": 1.2 },
      { "ip": "192.168.1.15", "rtt_ms": 2.4 }
    ]
  }
}
```

### 2.2 Memory Management & Pointer Conversions
To pass string results safely across the FFI boundary without memory leaks:
* **Memory Allocation:** Rust allocates string results on its own heap using `CString::into_raw`.
* **Go Copying:** Go reads the returned pointer memory block using `C.GoString` (which deep-copies the raw bytes to the Go garbage-collected heap).
* **Deallocation:** Go dispatches a cleanup command to release the Rust-allocated memory. Rust reconstructs the raw pointer into a `CString` instance, which is then dropped and deallocated.

```rust
// Rust FFI String Allocations & Cleanup
#[no_mangle]
pub extern "C" fn scan_icmp_ffi(config_ptr: *const c_char) -> *const c_char {
    if config_ptr.is_null() {
        return std::ptr::null();
    }
    
    // Convert incoming C string pointer to borrowed Rust str reference
    let config_str = unsafe { CStr::from_ptr(config_ptr) }.to_string_lossy();
    
    // Execute logic and serialize results to string
    let result_json = run_icmp_scan(&config_str);
    
    // Allocate return buffer on Rust heap and export pointer
    let c_result = CString::new(result_json).unwrap();
    c_result.into_raw()
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // Reconstruct CString instance from raw pointer and drop it
        unsafe { CString::from_raw(ptr) };
    }
}
```

---

## 3. Tokio Threading & Cancellation Model

To run asynchronous operations inside the statically linked library, the Rust core initializes a single multi-threaded Tokio runtime managed by a `OnceLock` singleton.

```
       Go Goroutine Worker ──► [ CGO Link Call ] ──► [ OnceLock runtime ]
                                                              │
                                                              ▼
                                                    [ runtime.block_on ]
                                                              │
                                                              ▼
                                                     [ Tokio Worker Thread ]
                                                              │
                                            ┌─────────────────┴─────────────────┐
                                            ▼                                   ▼
                                     [ Async Task ]                       [ Task Semaphore ]
                                     Uses mpsc logs                      Concurrency limits
```

*   **OS Thread Pinning:** CGO calls block on `runtime.block_on`, pinning the calling OS thread until the async Tokio task completes.
*   **Bounded Semaphores:** Hard-coded limits prevent CPU bottlenecking (e.g. capping TCP scans to 1024 concurrent checks).
*   **Cooperative Task Cancellation:** Each running task is registered with a `CancellationToken` linked to a unique job ID. When a cancel request is received, the cancellation token is triggered. The active async tasks check the token periodically and exit gracefully if it is set.

---

## 4. Low-Level Evasion Algorithms

### 4.1 Stateless Scanning via Blackrock Shuffling
To scan large networks without saturating target subnets or consuming excessive memory, the ICMP sweep engine implements the **Blackrock index shuffling algorithm** (adapted from `masscan`):
* **Mathematical Permutation:** Shuffles the range of target IP indices using a key-based pseudo-random block cipher permutation.
* **Stateless Execution:** Maps each index `i` (from `0` to `N-1`) to a unique shuffled address `f(i)` deterministically. This allows millions of hosts to be scanned in a random order without maintaining a list of visited addresses in memory.
* **IDS Evasion:** Distributes target addresses pseudo-randomly over time, preventing local intrusion detection systems (IDS) from triggering on sequential IP range scans.

### 4.2 Padded WireGuard Probes
Standard WireGuard handshakes use a fixed 148-byte UDP packet, which is easily blocked by length-matching DPI systems. The WireGuard auditor (`core/src/wg/prober.rs`) implements configurable UDP padding:
* **Variable Payload Size:** Appends randomized padding bytes to the WireGuard Handshake Initiation packet, changing its length signature (e.g. up to 512+ bytes).
* **Evasion Auditing:** Probes target endpoints with padded vs. standard handshakes to determine if the local ISP blocks connections based on fixed packet lengths.

### 4.3 Encrypted Client Hello (ECH) Parser
The DNS subsystem implements HTTPS (Type 65) resource record checks to detect Encrypted Client Hello configurations:
* Query target domains for Type 65 HTTPS resource records.
* Parse the raw record payload to identify the presence of the `ech` parameter.
* If ECH blocks are present, the engine checks whether local UDP DNS queries drop these records to verify DNS-level censorship policies.

---

## 5. Panic Safety Boundaries

Rust crashes (panics) unwinding across C ABI boundaries cause immediate stack corruptions and crash the calling Go host application. To prevent this, LumiNet wraps all FFI-exported functions inside `std::panic::catch_unwind` wrappers:

```rust
#[no_mangle]
pub extern "C" fn scan_icmp_ffi_safe(config: *const c_char) -> *const c_char {
    let result = std::panic::catch_unwind(|| {
        scan_icmp_ffi(config)
    });
    
    match result {
        Ok(res_ptr) => res_ptr,
        Err(_) => {
            // Panic caught. Return serialized JSON error.
            let err_json = r#"{"status_code":9001,"message":"Panic caught inside Rust core FFI"}"#;
            let c_err = CString::new(err_json).unwrap();
            c_err.into_raw()
        }
    }
}
```

---

## 6. Raw Sockets Abstraction Layer

Raw socket configurations are abstracted behind the `Platform` trait to ensure cross-platform compatibility:

```rust
pub trait PlatformSocket {
    fn create_raw_icmp_socket() -> Result<RawSocketDescriptor, SocketError>;
    fn set_socket_timeouts(fd: RawSocketDescriptor, timeout: Duration) -> Result<(), SocketError>;
    fn receive_packet(fd: RawSocketDescriptor, buffer: &mut [u8]) -> Result<usize, SocketError>;
}
```

* **Windows:** Winsock2 implementation utilizing `SOCK_RAW` for ICMP sweeps.
* **Linux:** Uses standard raw socket interfaces with `CAP_NET_RAW` capability rules.
