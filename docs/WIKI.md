# 🌐 LumiNet — Complete Technical, Architectural, and Operations Wiki Handbook

Welcome to the canonical Technical Manual and Wiki Handbook for the **LumiNet** platform. This document serves as the absolute single source of truth for operators, developers, and security auditors. It covers product vision, low-level technical design, user-space active evasion protocols, desktop GUI architectures, deployment steps, and developer guidelines.

---

## 📖 TABLE OF CONTENTS
1. [Chapter 1: Product Overview & Core Mission](#chapter-1-product-overview--core-mission)
2. [Chapter 2: Platform Architecture & Multi-Language Runtime](#chapter-2-platform-architecture--multi-language-runtime)
3. [Chapter 3: Core Subsystems & Operational Pillars](#chapter-3-core-subsystems--operational-pillars)
4. [Chapter 4: Advanced Active Evasion & Circumvention Layers](#chapter-4-advanced-active-evasion--circumvention-layers)
5. [Chapter 5: Win32/Walk Desktop GUI & Telemetry Cockpit](#chapter-5-win32walk-desktop-gui--telemetry-cockpit)
6. [Chapter 6: Comprehensive CLI Command Reference](#chapter-6-comprehensive-cli-command-reference)
7. [Chapter 7: Developer Guide, Concurrency Hardening, and Security Controls](#chapter-7-developer-guide-concurrency-hardening-and-security-controls)
8. [Chapter 8: Compilation, Toolchain, and System Verification](#chapter-8-compilation-toolchain-and-system-verification)

---

## CHAPTER 1: Product Overview & Core Mission

LumiNet is a local network dashboard, active evasion tunnel, and system configuration console. The platform is designed to run locally on client machines to audit network adapters, test proxy routing performance, scan subnets, and bypass deep packet inspection (DPI) censorship gates.

```
  ┌───────────────────────────────────────────────────────────┐
  │                 LumiNet Core Philosophy                   │
  ├───────────────────────────────────────────────────────────┤
  │ 1. Zero-Budget Execution: No external cloud dependencies. │
  │ 2. User-Space Evasion: No kernel drivers required.        │
  │ 3. Transparent Diagnostics: Honest socket measurement.    │
  └───────────────────────────────────────────────────────────┘
```

### 1.1 Core Principles
1. **Zero-Budget Execution:** LumiNet operates entirely within the local host boundaries. It does not introduce dependencies on external cloud databases, SaaS subscriptions, or proprietary API backends. All data metrics, scan histories, and logs are cached locally inside SQLite instances.
2. **Zero-Driver Portability:** The evasion tunnels, socket splitter layers, and network scanners operate entirely within user-space socket boundaries. The system does not depend on privileged subprocesses or administrative driver installations (such as `WinDivert` drivers) for its core TCP splitting operations.
3. **Transparent Diagnostics:** Unlike diagnostic utilities that mock connections or return simulated status grades, LumiNet conducts actual socket handshakes and TCP sweeps. If a network pathway is blocked, hijacked, or degraded, the console reports the precise error code, handshake phase failure, and trust grade.

---

## CHAPTER 2: Platform Architecture & Multi-Language Runtime

LumiNet utilizes a statically linked, multi-language architecture combining a Go api/UI orchestrator with a performance-critical Rust scanning engine:

```
                  ┌───────────────────────────────┐
                  │    Windows Desktop Client     │
                  │       (Go + Walk GUI)         │
                  └───────────────┬───────────────┘
                                  │ (HTTP REST / WebSockets)
                                  ▼
                  ┌───────────────────────────────┐
                  │     Local Daemon Server       │
                  │          (Go + Gin)           │
                  └───────────────┬───────────────┘
                                  │ (CGO Boundary / liblumicore.a)
                                  ▼
                  ┌───────────────────────────────┐
                  │       Rust Core Engine        │
                  │         (Tokio Async)         │
                  └───────────────────────────────┘
```

### 2.1 Workspace Directory Structure
The repository is organized into three primary directories:

*   **`core/` (Rust Scanning Core):**
    *   `src/icmp/`: high-precision ICMP subnet scanning using raw sockets.
    *   `src/tcp/`: parallel TCP port scanning and banner parsing.
    *   `src/dns/`: multi-resolver UDP and DoH hostname auditing.
    *   `src/tls/`: TLS ClientHello parsing and SNI reachability testing.
    *   `src/ffi/`: exports C-compatible structures and handles JSON boundaries.
*   **`server/` (Go Orchestrator & GUI):**
    *   `cmd/`: Cobra subcommands, Windows GUI controls, and layout drawings.
    *   `internal/api/`: Gin REST endpoints, auth, and SOCKS5 tunnel control.
    *   `internal/bridge/`: CGO mappings linking Go structures to Rust FFI headers.
    *   `internal/proxy/`: raw proxy parse blocks, tests, and Telegram scrapers.
    *   `internal/system/`: OS configuration APIs (DNS, proxy, DDNS, and startup settings).
    *   `internal/store/`: SQLite schema configuration and data caching.
*   **`web/` (TypeScript Legacy Web Assets):**
    *   Contains the Vite configurations and React codebases used for the legacy console fallbacks.

### 2.2 FFI Communication Lifecycle
The interface between Go and Rust uses a statically linked C ABI library. To avoid memory leakages across runtimes, allocations follow a structured lifecycle:

1. **Serialization:** Go serializes parameters to a JSON string and translates it to a C-compatible char array (`C.CString`).
2. **Execution:** Go passes the C-string pointer across the boundary to Rust's FFI function.
3. **Rust Processing:** Rust deserializes the JSON parameters, runs the task asynchronously on a Tokio thread pool, and serializes the results into a returned `const char*` pointer.
4. **Cleanup:** Go copies the returned C-string to native Go memory (`C.GoString`) and dispatches a command to release the Rust-allocated memory pointer.

---

## CHAPTER 3: Core Subsystems & Operational Pillars

LumiNet divides its features into five core subsystems:

### 3.1 🔍 LumiScan — Network Scanning Engine
*   **ICMP Sweep:** Dispatches concurrent ICMP echo requests with rate limiting and RTT calculations.
*   **TCP Port Sweep:** Probes TCP port ranges and reads initial packets to parse application banner headers.
*   **DNS Record Harvesting:** Queries target hostnames across major record types (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`) simultaneously.
*   **TLS Certificate Audit:** Performs TLS handshakes to validate certificate chains, expiration dates, and list cipher suites.

### 3.2 🛡️ LumiGuard — Integrity Auditing & Warnings
*   **DNS Hijacking Audit:** Performs parallel DNS resolutions over unencrypted UDP and secure DoH side-by-side. If the IP configurations mismatch, the engine flags a DNS hijacking alert.
*   **SSL Interception Audit:** Inspects certificate validation roots. If a known firewall root (e.g. Fortinet, Sophos) is detected, it flags a Man-in-the-Middle (MITM) warning.
*   **Forced SafeSearch Redirection Auditor:** Audits resolutions for major search engines (Google, Bing, YouTube). Flags CNAME mappings to forced filtering endpoints (e.g., `forcesafesearch.google.com`).
*   **NCSI Registry Overrides:** Modifies Windows registry keys (`ActiveWebProbeHost`, etc.) to bypass fake network access indicators caused by ISP blockages of validation domains.
*   **SOCKS5 UDP Associate NAT Mapper:** Employs UDP associate bindings for gaming consoles and STUN servers. Maintains a 120-second active NAT translation state to avoid session disconnects over strict firewall gates.

### 3.3 🌐 LumiProxy — Subscription Engine
*   **Multi-Protocol Parser:** Bulk parses VMess, VLESS, Trojan, Shadowsocks, Hysteria2, TUIC, and WireGuard proxy configurations.
*   **Credential Redaction:** Redacts API keys, tokens, and credentials in the logs and preview windows before displaying config structures.
*   **V8 Isolates Edge Dialer:** Handles client-side WebSockets and TCP/TLS streams directly to serverless edge workers (such as Cloudflare Workers) via VLESS or Trojan protocols.

### 3.4 🩺 LumiDiag — Diagnostics Engine
*   **6-Phase Diagnostic Runbook:** Executes an automated diagnostic sequence: Connectivity -> DNS Integrity -> TLS Validity -> Portal Check -> Evasion Scanner -> Speed Grade.
*   **HTML/PDF Export:** Compiles diagnostic logs, packet trace metrics, and latency charts into styled HTML templates and PDFs for distribution.

### 3.5 ⚙️ LumiSystem — OS Configuration Integrators
*   **DNS Adapter Switcher:** Modifies adapter DNS servers. Caches default DNS parameters inside local SQLite tables to ensure automatic rollback on application exit or sudden crash.
*   **Dynamic DNS Automation:** Updates DDNS records against Cloudflare, DuckDNS, Dynu, or No-IP over secure HTTPS requests based on configurable cron schedules.

---

## CHAPTER 4: Advanced Active Evasion & Circumvention Layers

### 4.1 SOCKS5 Smart Evasion Tunnel
The local SOCKS5 evasion tunnel captures system outbound connections and applies packet-level manipulation:

```
  Outgoing App Packet
          │
          ▼
   [ SOCKS5 Listener ]
          │
          ├─► TCP Segment Splitting: Slices packet at byte offset
          ├─► Auto-Split TLS SNI: Splits packet at TLS ClientHello SNI boundary
          ├─► Packet Fragmentation: Slices payload into randomized sizes
          └─► HTTP Header Mutation: Alters HTTP header capitalization
```

1.  **TCP Segment Splitting:** Slices initial TCP streams at custom byte boundaries (e.g. offset 3) and delays subsequent segments by a configurable interval (in milliseconds) to interrupt signature extraction.
2.  **Auto-Split TLS SNI:** Strips the TLS ClientHello header, parses SNI extensions automatically, and splits the TCP segment exactly at the SNI payload string boundary, preventing signature-matching engines from parsing hostnames.
3.  **Userspace Raw Handshake Injection (paqet mode):** Bypasses the standard OS TCP 3-way handshake to prevent tracking. Injects custom `PSH-ACK` buffers via raw sockets. Uses `WinDivert` on Windows and `AF_PACKET` on Linux to drop host-generated kernel `RST` packets, keeping the stream active exclusively in user-space.
4.  **Plaintext HTTP Header Case Mutations:** For non-TLS TCP port 80 traffic, the parser searches for standard HTTP verbs (`GET`, `POST`, `CONNECT`). It rewrites HTTP header fields using mixed capitalization (e.g., `Host:` becomes `hOsT:`, `Connection:` becomes `cOnNeCtIoN:`) and adjusts spacing around colons to bypass filtering rules.

### 4.2 Netrix KCP/UDP Transport Obfuscation
The Netrix transport protocol runs KCP over UDP connections to scramble traffic fingerprints and bypass UDP filters:
*   **Performance Profiles:** Predefined optimization configurations mapping directly to the underlying KCP engine:
    *   `balanced`: nodelay=0, interval=20ms, resend=2, nc=0, sndwnd=512, rcvwnd=512, mtu=1350
    *   `aggressive`: nodelay=0, interval=10ms, resend=2, nc=1, sndwnd=2048, rcvwnd=2048, mtu=1400
    *   `latency`: nodelay=1, interval=5ms, resend=1, nc=1, sndwnd=256, rcvwnd=256, mtu=1200
    *   `cpu-efficient`: nodelay=0, interval=50ms, resend=3, nc=0, sndwnd=128, rcvwnd=128, mtu=1400
*   **Obfuscated Stream Wrapper (`NetrixConn`):** Outbound data payloads larger than 1024 bytes are compressed using Zstandard (`zstd`) or LZ4 framing. The wrapper adds random timing delays (jitter between 5ms and 20ms) to scramble packet timing signatures.

### 4.3 Zephyr Google Drive Mailbox Transport
Bridges outbound proxy connections over Google Drive file uploads:
* **GDrive Mailbox:** Clients write connection payloads to temporary files in a Google Drive directory. Upstream relays poll the directory, parse payloads, execute the connection, and upload responses.
* **Envelope Framing:** Encapsulates SOCKS5 stream frames in binary envelopes prepended with MagicBytes (`0x1F`), SessionID, and payload length descriptors.

---

## CHAPTER 5: Win32/Walk Desktop GUI & Telemetry Cockpit

LumiNet provides a Windows-native desktop interface designed using the Go `walk` framework, running directly on native Win32 windowing controls.

*   **Telemetry Cards:** Displays real-time CPU, RAM, and Disk space utilization. Repaints canvas views dynamically at 1-second intervals using custom pen drawing operations.
*   **Operations Tabs:** Organizes tools into six panels: Dashboard stats, DNS Auditing, Evasion Tunnel configurations, LAN Scanning, WireGuard handshakes, and Diagnostics.
*   **Thread Safety:** The Walk UI loop runs on the main OS thread. Background diagnostic and scanning tasks communicate progress to the UI using thread-safe synchronize events to prevent layout lockups:
    ```go
    mainWindow.Synchronize(func() {
        progressBar.SetValue(progressUpdate.Percent)
    })
    ```

---

## CHAPTER 6: Comprehensive CLI Command Reference

### 6.1 Subcommand Reference Mappings
*   **Start Local Daemon:** Starts the background orchestrator and Walk GUI interface:
    ```bash
    luminet serve --port 8470 --host 127.0.0.1 --gui
    ```
*   **Run ICMP Subnet Sweep:** Ping all hosts in a target CIDR range concurrently:
    ```bash
    luminet scan icmp 192.168.1.0/24 --concurrency 150 --timeout 1000
    ```
*   **TCP Port Scan with Banner Grabbing:**
    ```bash
    luminet scan ports 10.0.0.5 --ports 22,80,443 --banner --output json
    ```
*   **Start SOCKS5 Evasion Tunnel:** Start the local tunnel with TLS SNI splitting and custom DNS resolver:
    ```bash
    luminet system evasion-tunnel start --port 1080 --auto-sni --dns-resolver 9.9.9.9
    ```
*   **Modifying System DNS Address:** Set system-wide DNS to secure public servers (e.g., Quad9):
    ```bash
    luminet system dns apply 9.9.9.9,149.112.112.112
    ```
*   **Restoring Adapter DNS:** Restore network adapter configurations to their default dynamic values:
    ```bash
    luminet system dns restore
    ```

---

## CHAPTER 7: Developer Guide, Concurrency Hardening, and Security Controls

### 7.1 Go Concurrency & Mutex Safety
To prevent lock duplication and thread blockages, never copy struct values that embed sync primitives (such as `sync.RWMutex`). Implement explicit cloning methods that copy only the primitive data fields and leave the synchronization elements uncopied:

```go
func (j *Job) Clone() *Job {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return &Job{
		ID:        j.ID,
		Type:      j.Type,
		Status:    j.Status,
		Progress:  j.Progress,
		CreatedAt: j.CreatedAt,
		// sync.RWMutex is left initialized to its zero-value
	}
}
```

### 7.2 Log Sanitization & Redaction
All log statements must be sanitized before being written to standard output or cached in SQLite databases. The system uses regex pattern matching to identify and redact credentials, access tokens, and private query parameters from connection URIs:

```go
var credentialRegex = regexp.MustCompile(`(?i)(pass(word)?|token|auth|key|secret)=[^&\s]+`)

func SanitizeURL(rawURL string) string {
    return credentialRegex.ReplaceAllString(rawURL, "${1}=[REDACTED]")
}
```

---

## CHAPTER 8: Compilation, Toolchain, and System Verification

### 8.1 Build Steps (Windows / PowerShell)
Compile the static Rust library, generate the bindings header, and build the Windows GUI executable:
```powershell
# Run the automated build script (skipping React web assets)
.\scripts\build-all.ps1 -SkipWeb
```

### 8.2 Build Outputs
*   **C Binding Header:** `luminet_core.h` (autogenerated by `cbindgen` from Rust exports).
*   **Rust Static Library:** `core/target/release/liblumicore.a` (GNU target).
*   **GUI Binary:** `build/luminet.exe` (compiled with the `-H windowsgui` linker flag to prevent blank console popups on double-click).

### 8.3 Compilation Verification
Ensure all Rust and Go test suites compile and execute successfully before pushing updates to the main repository:

```bash
# Run Go unit and integration tests
cd server
go test -v ./...

# Run Rust core tests
cd ../core
cargo test
```
