# 🌐 LumiNet — Complete Product Specification & Scope Document

## 1. Executive Summary & Core Mission

LumiNet is a local, sovereignty-grade network diagnostics console, active circumvention engine, and system management workstation. The platform provides transparent, raw network instrumentation for power users, developers, and censorship researchers working in hostile, restricted, or actively monitored network spaces.

Unlike typical diagnostic suites that rely on cloud-dependent servers or commercial SaaS, LumiNet is built on the philosophy of **zero-budget local execution**, **honest diagnostic feedback**, and **user-space network manipulation**. It bridges a high-performance Rust core (`lumicore`) with an orchestration server (`go-server`) and a native desktop UI to enable comprehensive system control and secure routing.

---

## 2. Target User Personas

### 2.1 The Censorship Researcher
*   **Context:** Auditing network pathways in nations with state-level Deep Packet Inspection (DPI) firewalls.
*   **Needs:** Active SNI block probing, certificate hijacking identification, forced redirection auditing, and raw TCP segment splitting.
*   **Pain Points:** Generic network tools trigger firewall alarms or return simplified "connection refused" errors without detailing the block type.

### 2.2 The Remote Developer & System Administrator
*   **Context:** Operating remote hosts across restricted infrastructure, managing DNS, Dynamic DNS, and egress tunnels.
*   **Needs:** Bulletproof system DNS switcher with automatic crash rollback, concurrent port scanner with service fingerprinting, and automated proxy routing rulesets.
*   **Pain Points:** Hostname poisoning, local DNS manipulation, and manual configuration of bypass routing rules.

### 2.3 The Privacy-Conscious Power User
*   **Context:** Securing personal telemetry, bypassing local captive portals, and routing system traffic securely over multi-hop chains.
*   **Needs:** SOCKS5 evasion tunnels, SOCKS5 UDP STUN associate bindings for console gaming, and QUIC/WireGuard obfuscation presets (e.g., Cloudflare WARP integrations).
*   **Pain Points:** ISP packet inspection, local network device tracking, and VPN leakage.

---

## 3. Product Pillars & Architectural Features

LumiNet is divided into five core pillars, each mapping to a dedicated subsystem inside the codebase:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                LumiNet                                  │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────┤
│   LumiScan   │  LumiGuard   │  Active      │   LumiDiag   │ LumiSystem  │
│  (Scanning)  │ (Integrity)  │  Evasion     │ (Diagnostic) │ (OS Config) │
└──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘
```

### 3.1 🔍 Pillar 1: LumiScan (Stateless & Parallel Scanning)
1.  **Stateful & Stateless Sweeps:**
    *   **ICMP Sweep:** Concurrent subnet sweep utilizing high-precision async sockets. Implements rate limiting, adaptive timeouts, and raw round-trip-time (RTT) calculations.
    *   **TCP Port Sweep:** Discovers open ports, issues raw socket connect checks, and performs service banner grabbing (parsing SSH headers, HTTP Server banners, SSL fingerprints).
2.  **DNS Record Harvesting:**
    *   Retrieves records (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`) from multiple recursive resolvers simultaneously.
3.  **TLS Certificate Inspector:**
    *   Initiates standard TLS handshakes, parses the remote certificate chain, checks expiration, evaluates certificate trust paths, and lists supported SSL/TLS cipher suites.
4.  **SNI Reachability Probe:**
    *   Crafts a raw ClientHello with a target Server Name Indication (SNI) header to verify if local firewalls block the SNI, returning step-by-step handshake trace logs.

### 3.2 🛡️ Pillar 2: LumiGuard (Integrity Verification & Hazard Warnings)
1.  **DNS Poisoning Detector:**
    *   Queries a set of reference hostnames via standard unencrypted UDP (port 53) and encrypted DNS-over-HTTPS (DoH) side-by-side. If the IP sets mismatch, the console triggers a **DNS Poisoning Alarm** displaying the hijacked IP addresses.
2.  **Man-in-the-Middle (MITM) & SSL Decryption Warners:**
    *   Audits SSL certificate issuers during HTTPS handshakes against local trust roots. Flags instances where known enterprise SSL decryption firewalls (e.g., Sophos, Fortinet, Zscaler) have intercepted connection packets.
3.  **Forced SafeSearch / Restricted Mode Redirection Auditor:**
    *   Inspects DNS resolutions for major search engines (Google, Bing, YouTube). Identifies instances where local network gateways force CNAME redirection (e.g., CNAME to `forcesafesearch.google.com` or `restrict.youtube.com`), alerting the user of content filtering policies.
4.  **Windows NCSI Overrides:**
    *   Allows users to override active Windows Network Connectivity Status Indicator (NCSI) registry keys (`ActiveWebProbeHost`, `ActiveWebProbePath`, `ActiveWebProbeContents`). This bypasses fake "No Internet Access" indicators caused by local ISP blockages of Microsoft's validation domains, ensuring standard OS updates compile and download successfully.
5.  **CAPTCHA Bypass Integration:**
    *   Provides built-in 2Captcha APIs to extract sitekeys (`SITEKEY`) from Cloudflare Turnstile, hCaptcha, and Google reCAPTCHA challenges encountered during proxy subscription downloads. Solves the challenge programmatically and appends the validation tokens to successfully download configuration files.
6.  **SOCKS5 UDP Associate NAT Mapper:**
    *   Handles UDP mapping diagnostics for gaming consoles and STUN servers. Bridges incoming SOCKS5 UDP packets, maintaining a 120-second active NAT translation state to avoid session disconnects over strict firewall gates.

### 3.3 ⚡ Pillar 3: Active Evasion & Circumvention Layers
The active evasion suite manipulates TCP packets and streams in user-space to prevent censors from tracking network endpoints:

1.  **TCP Segment Splitting & Delay:**
    *   Slices initial connection streams at custom byte boundaries (e.g., offset 3) and delays subsequent segments by a configurable interval (in milliseconds) to interrupt signature extraction on deep packet inspection (DPI) firewalls.
2.  **Auto-Split TLS SNI (Smart Evasion):**
    *   Strips the TLS ClientHello header, parses SNI extensions automatically, and splits the TCP segment exactly at the SNI payload string boundary, preventing signature-matching engines from parsing hostnames.
3.  **Userspace Raw Handshake Injection (paqet mode):**
    *   Bypasses the standard OS TCP 3-way handshake to prevent tracking. Injects custom `PSH-ACK` buffers via raw sockets. Uses `WinDivert` on Windows and `AF_PACKET` on Linux to drop host-generated kernel `RST` packets, keeping the stream active exclusively in user-space.
4.  **Plaintext HTTP Header Mutation:**
    *   Mutates standard headers (e.g. `Host: google.com` -> `hOsT: google.com` or `Host  : google.com`) to cause deep packet parsing failures in legacy firewalls.
5.  **Range-Based Fragmentation:**
    *   Divides outgoing packets into random chunk sizes (between `minLength` and `maxLength`) with a customizable write delay (`delayMs`) to randomize traffic fingerprints.
6.  **Secure Hostname Outbounds:**
    *   Bypasses local system DNS entirely by resolving connection hostnames via custom DNS UDP or DoH servers directly from the tunnel engine before initiating TCP handshakes.

### 3.4 🩺 Pillar 4: LumiDiag (Diagnostics & Runbook Engine)
1.  **6-Phase Diagnostic Runbook:**
    *   Executes an automated diagnostic sequence: Connectivity -> DNS Integrity -> TLS Validity -> HTTP Portal Redirection -> Evasion Scanner -> Speed Grade.
2.  **Dynamic PDF/HTML Report Generator:**
    *   Compiles diagnostic logs, packet trace metrics, and latency charts into styled HTML templates and PDFs for distribution.

### 3.5 ⚙️ Pillar 5: LumiSystem (OS Configuration Integrators)
1.  **System DNS Switcher with Rollback Protection:**
    *   Modifies network adapter DNS configurations. Automatically registers system signals (`SIGINT`, `SIGTERM`) and logs original adapter values to SQLite database caches, ensuring full automatic rollback on application exit or sudden crash.
2.  **Global Proxy Registry Adaptor:**
    *   Sets current-user Windows/Linux system proxy configurations and maintains bypass Lists.
3.  **Dynamic DNS (DDNS) Updates:**
    *   Provides a built-in scheduler to update DDNS domains against Cloudflare, DuckDNS, Dynu, or No-IP over secure HTTPS requests.

---

## 4. Advanced Covert & Outbound Transports

LumiNet integrates specialized connection wrapper transports to ensure resilience against firewall changes:

1.  **Netrix KCP Performance Profiles:**
    *   Implements the high-speed KCP ARQ UDP protocol with predefined optimization modes:
        *   `balanced`: balanced latency and memory consumption.
        *   `aggressive`: maximum speed, lowest retransmission latency, high bandwidth consumption.
        *   `latency`: absolute lowest latency, small window clamps.
        *   `cpu-efficient`: long intervals, low context-switching overhead.
2.  **Netrix Obfuscated Stream (`NetrixConn`):**
    *   Wraps TCP/UDP sockets to compress frames using LZ4 or Zstandard block framing compression (skipping payloads below 1024 bytes). Introduces randomized timing delays (jitter between 5ms and 20ms) to scramble packet size and timing signatures.
3.  **Covert Telemetry IP Tracker:**
    *   Serves dynamic decoy landing pages for unauthenticated scanner hits. Stores visit records (headers, client IPs, parsed OS/browser device types, and GeoIP records) in SQLite tables (`covert_links` and `covert_visits`) and exposes CRUD routes (`/api/system/covert`) protected by secure API header tokens.
4.  **Active DNS Resolver Scanner:**
    *   Audits recursive DNS nodes by launching parallel queries with random subdomains (e.g., `<random>.tunnel.com`). Forces resolvers to query authoritative servers directly, bypassing DNS cache to measure true path latency and detect Slipstream/DNSTT tunneling availability.
5.  **Zephyr Google Drive Mailbox Transport:**
    *   Bridges connection outbounds over Google Drive. Encapsulates connection streams inside binary files, appending MagicBytes (`0x1F`), SessionID, and payload markers. Clients poll directory contents to send and retrieve packet payloads.
6.  **Android JNI & PLT Interface Protection:**
    *   *Socket Protection:* Outbound sockets are passed via local Unix Domain Sockets using `SCM_RIGHTS` control flags, enabling JVM execution of `vpnService.protect(fd)` to prevent routing loops.
    *   *VPN Interface Hider:* Uses Zygisk hooks to intercept libc `getifaddrs` inside user applications, hiding active `tun` or `wg` adapters from banking or media applications that restrict VPN execution.
7.  **Obfuscated QUIC MASQUE & WireGuard Decoys:**
    *   Implements RFC 9484 capsule framing to support dynamic address assignment tunnels. PACs UDP handshakes with decoy IKEv2 SA headers and initial packet fragmentation, keeping standard payloads intact for WARP/Psiphon compatibility.
8.  **V8 Isolates Edge Dialer:**
    *   Enables client-side routing to Cloudflare Workers or serverless edge hosts via VLESS or Trojan protocols over WebSocket.

---

## 5. Brand Identity & Aesthetic Principles

### 5.1 Creative North Star: "Sovereign Glass Command Cockpit"
The LumiNet visual style represents high technical precision and resilience. The design is optimized for power users operating under dark ambient conditions.

*   **Color Scheme:** Space Void Navy base (`#0a0e1a`), slate grey card overlays (`#0f1425`), and electric blue interactive elements (`#3b82f6`). High-status events are accented in Terminal Green (`#10b981`), while CPU and diagnostic telemetry are highlighted in Neon Cyan (`#06b6d4`) and Neon Purple (`#8b5cf6`).
*   **Typography:** The Outfit font family is used for layout titles and displays to ensure crisp readability. The JetBrains Mono font family is used for all console logs, hostnames, IP addresses, port maps, and command-line inputs.
*   **Contrast and Performance:** All visual indicators, logs, and text elements maintain a minimum contrast ratio of **4.5:1** against backgrounds. Interactive transitions utilize brief, non-shifting transforms (150ms-200ms ease) to keep the app highly responsive. Emojis are replaced by scalable vector SVGs.

---

## 6. Accessibility & Compliance

*   **Keyboard Navigation:** Visual focus outlines are mapped for all interactive elements to support keyboard-only traversal.
*   **Reduced Motion:** Respects the `prefers-reduced-motion` browser flag, turning off sliding status bars and glowing scans upon request.
*   **Local Data Privacy:** All logging telemetry (covert visits, scan histories, configurations) is stored locally inside encrypted SQLite databases, leaving zero cloud storage footprints.
