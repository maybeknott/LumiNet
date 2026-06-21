# 🌐 Go Server Architecture & Operations Manual

This document provides a comprehensive technical overview of the orchestration layer located under `server/`. It details package design, API schemas, background job workers, anti-censorship proxy layers, and system integration interfaces.

---

## 1. Directory & Package Mapping

The Go orchestrator codebase is organized into several directories to isolate API boundaries, database persistence, and native GUI rendering modules:

```
server/
├── cmd/
│   └── luminet/
│       ├── main.go               # Cobra CLI and boot orchestrator
│       ├── cli.go                # Subcommand flags and validation
│       └── gui.go                # Walk framework UI layout and main loop
├── internal/
│   ├── api/
│   │   ├── router.go             # Gin routing, WebSocket setups, and CORS
│   │   ├── middleware.go         # API key auth and origin validation
│   │   ├── handlers_scans.go     # ICMP and TCP scan endpoints
│   │   ├── handlers_proxy_tests.go # Proxy benchmarking endpoints
│   │   ├── handlers_covert_tracker.go # Decoy tracker and visit metrics
│   │   └── handlers_system.go    # DNS, system proxy, and DDNS endpoints
│   ├── bridge/
│   │   ├── core.go               # Static library static CGO FFI links
│   │   ├── core_mock.go          # Mock bindings for non-CGO testing
│   │   └── types.go              # Shared JSON request/response structures
│   ├── jobs/
│   │   ├── manager.go            # Concurrency-safe job scheduler and queue
│   │   └── runners.go            # CGO task wrappers and status updates
│   ├── proxy/
│   │   ├── parser.go             # Raw configuration parse and preview logic
│   │   ├── parser_kcp.go         # Netrix KCP parameter validator
│   │   ├── netrix_conn.go        # Compressed and timing-jitter socket wrapper
│   │   ├── kcp_transport.go      # KCP dialer and profile binder
│   │   ├── evasion_tunnel.go     # SOCKS5 active split tunnel listener
│   │   └── telegram_mtproto.go   # Telegram channel MTProto proxy scraper
│   ├── system/
│   │   ├── dns.go                # Adapter DNS switcher and backup manager
│   │   ├── dns_balancer.go       # DNS active resolver checking
│   │   ├── proxy.go              # Global HTTP/SOCKS registry manager
│   │   ├── ddns.go               # DDNS dynamic updates scheduler
│   │   └── startup.go            # OS registry auto-start manager
│   └── store/
│       ├── database.go           # SQLite database connection pool
│       └── migrations.go         # Database schemas and updates
└── web/dist/                     # Static React dashboard bundle
```

---

## 2. API Server & Middleware Chain

The daemon runs an HTTP REST and WebSocket server using the Gin framework. It is configured to run on localhost by default to ensure local isolation.

### 2.1 Complete Middleware Chain
Every HTTP request goes through this middleware pipeline:

```
  HTTP Client Request 
          │
          ▼
   [ Gin Recovery ]  <── Captures runtime panics and returns 500
          │
          ▼
   [ Gin Logger ]    <── Standard output request audit logger
          │
          ▼
   [ CORS Handler ]  <── Configured for localhost interface checks
          │
          ▼
   [ Auth Token ]    <── Verifies X-API-Key headers
          │
          ▼
   [ WebSockets ]    <── Upgrades connections (e.g. for /ws)
          │
          ▼
   Target API Controller
```

*   **WebSocket Origin Validation:** The WebSocket upgrade path enforces strict origin checks to prevent Cross-Site WebSocket Hijacking (CSWSH) attacks:
    ```go
    var upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool {
            origin := r.Header.Get("Origin")
            return origin == "" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1")
        },
    }
    ```

---

## 3. Endpoints & Schema Specification

The tables below define the schemas and formats used by the REST API:

### 3.1 Subnet ICMP Sweep (`POST /api/scans`)
*   **Request Schema:**
    ```json
    {
      "target_cidr": "192.168.1.0/24",
      "concurrency": 128,
      "timeout_ms": 1000
    }
    ```
*   **Response Schema (202 Accepted):**
    ```json
    {
      "job_id": "job_d98124b8-f076-4d1a-8263-448f",
      "status": "queued",
      "created_at": "2026-06-22T01:00:00Z"
    }
    ```

### 3.2 SOCKS5 Evasion Tunnel (`POST /api/system/evasion-tunnel`)
*   **Request Schema:**
    ```json
    {
      "action": "start",
      "socks_port": 1080,
      "split_offset": 3,
      "split_delay_ms": 10,
      "auto_sni": true,
      "fragment_min": 100,
      "fragment_max": 500,
      "fragment_delay": 15,
      "filter_scope": "tlshello",
      "dns_resolver": "9.9.9.9"
    }
    ```
*   **Response Schema (200 OK):**
    ```json
    {
      "status": "active",
      "port": 1080,
      "pid": 1392
    }
    ```

### 3.3 Covert Tracker Redirects (`POST /api/system/covert/links`)
*   **Headers:** `X-API-Key: SecToken123`
*   **Request Schema:**
    ```json
    {
      "name": "decoy-update",
      "redirect_url": "https://google.com"
    }
    ```
*   **Response Schema (201 Created):**
    ```json
    {
      "id": 1,
      "name": "decoy-update",
      "redirect_url": "https://google.com",
      "tracker_url": "http://127.0.0.1:8470/c/decoy-update"
    }
    ```

---

## 4. Background Job Scheduling Subsystem

The Job Scheduler (`internal/jobs/`) manages and executes concurrent diagnostic and scanning tasks.

```
       [ Client POST Request ]
                  │
                  ▼
         [ Model Validation ]
                  │
                  ▼
         [ Persist to SQLite ] 
                  │
                  ▼
      [ Add to Schedule Queue ]
                  │
                  ▼
      [ Spawn Go Async Runner ] ──► [ CGO / Rust Tokio Thread ]
                  │
                  ├─► Read FFI results
                  ├─► Save results to DB
                  └─► Dispatch WS status frame
```

*   **Concurrency Rules:** The Job Scheduler limits concurrent scanning runs using a bounded worker pool. The Go orchestrator dynamically spins up runners based on the global concurrency configuration, while Rust's static library uses semaphores to prevent system socket exhaustion.
*   **Memory Safety (Cloning structs):** The job struct contains synchronization mutexes. Direct struct copying duplicates the mutex memory state, which can lead to deadlocks or panic states. The system enforces explicit data cloning:
    ```go
    func (j *Job) SafeClone() *Job {
        j.mu.RLock()
        defer j.mu.RUnlock()
        return &Job{
            ID:        j.ID,
            Type:      j.Type,
            Status:    j.Status,
            Progress:  j.Progress,
            CreatedAt: j.CreatedAt,
            UpdatedAt: j.UpdatedAt,
            Config:    j.Config,
            Result:    j.Result,
            Error:     j.Error,
        }
    }
    ```

---

## 5. SOCKS5 Evasion Tunnel State Machine

The SOCKS5 Evasion Tunnel (`internal/proxy/evasion_tunnel.go`) captures outbound traffic and applies packet-level manipulation:

```
  [ SOCKS5 Server ] ──► [ Receive Connect CMD ] ──► [ Read IP & Port ]
                                                             │
                                                             ▼
                                                   [ Dial Remote Server ]
                                                             │
                                     ┌───────────────────────┴───────────────────────┐
                                     ▼                                               ▼
                              [ Plaintext HTTP ]                                [ TLS Stream ]
                                     │                                               │
                                     ▼                                               ▼
                             [ Case Mutations ]                              [ Parse ClientHello ]
                        Mutate header casing patterns                                │
                                                                                     ▼
                                                                             [ TLS SNI Finder ]
                                                                             Extract extension
                                                                                     │
                                                                                     ▼
                                                                             [ TCP split writes ]
                                                                             Slices SNI string
```

1. **Connection Capture:** The SOCKS5 listener negotiates handshakes, validates requested commands (`0x01` for Connect), and checks target destinations.
2. **Dynamic Evasion Routing:**
   * **TCP Segment Splitting:** Slices the outgoing payload array at a specified split offset. It writes the first segment to the socket, yields for a configurable delay, and then writes the remaining payload.
   * **Smart SNI split:** Checks the initial payload for a TLS ClientHello identifier (`0x16 0x03`). If found, it parses the payload structure to extract the Server Name Indication (SNI) extension. The engine then splits the payload array at the SNI boundary and writes the fragments with a timing delay.
   * **Plaintext Case Mutations:** If HTTP GET/POST headers are detected, the engine modifies the header capitalization (e.g. `Host: -> hOsT:`) to cause deep packet parsing failures in legacy firewalls.

---

## 6. System Registry & Commands Interface

System configuration operations interface directly with operating system APIs and commands:

### 6.1 Windows Platform
*   **System DNS Management:** Updates adapter configurations using `netsh` commands:
    ```bash
    netsh interface ipv4 set dns name="Ethernet" source=static address=9.9.9.9
    ```
*   **System HTTP/SOCKS Proxy Registry Keys:** Modifies keys under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`:
    *   `ProxyEnable` (DWORD): `1` to enable, `0` to disable.
    *   `ProxyServer` (SZ): `http://127.0.0.1:1080` (proxy endpoint).
    *   `ProxyOverride` (SZ): bypass configurations.
*   **Auto-Start Registry Settings:** Modifies key mappings under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

### 6.2 Linux Platform
*   **System DNS Integration:** Interfaces with Systemd Name Service resolvers:
    ```bash
    resolvectl dns eth0 1.1.1.1 8.8.8.8
    ```

### 6.3 macOS Platform
*   **DNS & Proxy Settings:** Interfaces with system network configuration commands:
    ```bash
    networksetup -setdnsservers "Wi-Fi" 9.9.9.9 149.112.112.112
    ```

---

## 7. External Plugin System Design

The server supports external binary discovery and communication via standard streams:

```
  Go Server Engine ──► [ JSON-RPC 2.0 Payload ] ──► [ Write to Plugin stdin ]
                                                             │
                                                             ▼
                                                      [ Plugin Process ]
                                                             │
                                                             ▼
  Go Server Engine ◄── [ JSON-RPC 2.0 Response ] ◄── [ Read from stdout ]
```

*   **Plugin Discovery:** The server scans the `plugins/` directory for `plugin.json` manifests.
*   **JSON-RPC 2.0 Interface:** The server executes the plugin binary, writes JSON-RPC payloads to `stdin`, and reads responses from `stdout`.
*   **Events Pipeline:** Standard events (such as `scan_result`, `proxy_result`, and `diag_complete`) are piped to the plugins to execute custom hooks.
