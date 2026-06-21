# 🌐 LumiNet Architecture Blueprint & Design Specification

This document provides a technical blueprint of the **LumiNet** platform. It details system layers, CGO translation mechanics, multi-threaded execution, data flows, and security guidelines.

---

## 1. Overall System Architecture

LumiNet combines a Windows-native Go-based desktop console with a statically linked Rust scanning library (`liblumicore.a`) and an embedded SQLite database.

```
       ┌────────────────────────────────────────────────────────┐
       │                 Presentation Layer                     │
       │  - Win32 Native Desktop UI (Go + Walk)                 │
       │  - Browser Compatibility Interface (React Console)      │
       └───────────────────────────┬────────────────────────────┘
                                   │ (HTTP REST / WebSockets)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                 Go Orchestration Layer                 │
       │  - Gin API Router, WS Telemetry Hub, SQLite DB Cache   │
       │  - SOCKS5 Evasion Listener, Scheduled DDNS Workers     │
       └───────────────────────────┬────────────────────────────┘
                                   │ (CGO Boundary Link)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                  FFI Translation Bridge                │
       │  - C ABI Interface Mappings, JSON Serializations       │
       └───────────────────────────┬────────────────────────────┘
                                   │ (C ABI Calls)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                   Rust Core Engine                     │
       │  - Concurrent ICMP Scanner, TCP Port Sweep, DNS Probes │
       │  - Async Tokio Worker Pools, Platform trait wrappers   │
       └────────────────────────────────────────────────────────┘
```

---

## 2. Layer-by-Layer Components

### 2.1 Presentation & GUI Cockpit (`server/cmd/`)
*   **Walk GUI Subsystem:** Interacts directly with Windows user controls using native Win32 message dispatch loops. Renders sparkline canvas drawings using cosmetic pen draw callbacks on active card surfaces.
*   **Job Status Sync Loops:** Schedules non-blocking background WebSocket client workers to update progress bars and dashboard tables upon synchronization commands.

### 2.2 Go Server Daemon Orchestrator (`server/internal/`)
*   **Gin REST Router:** Mounts request groups for scans, proxy validation runs, system adapter updates, and covert link redirection.
*   **WebSocket Telemetry Hub:** Upgrades HTTP endpoints and maintains a pool of active subscriber handles to stream scanner logs and diagnostic progress in real-time.
*   **Job Concurrency Scheduler:** Runs a bounded worker pool that executes CGO tasks, writes results to the SQLite cache, and triggers WebSocket update frames.
*   **SOCKS5 Evasion Tunnel:** Captures system traffic in user-space and applies packet division (segment splitting, auto-SNI split) to bypass DPI firewalls.

### 2.3 Rust Core Engine (`core/src/`)
*   **Stateless Scanning Core:** Coordinates sweeps using the Blackrock Cipher Index Shuffler to randomize target address paths.
*   **Raw Sockets Abstraction Trait:** Abstracts Winsock2 (`SOCK_RAW`) and Linux socket interfaces behind the `Platform` trait boundaries.
*   **Async Tokio Runtime:** Allocates async tasks across thread pools using semaphores to limit concurrent socket checks.

---

## 3. Detailed Data Flow Scenarios

### 3.1 SOCKS5 Smart Evasion Connection Setup
The flowchart below illustrates the packet-level flow when an application dials out through the evasion tunnel:

```
  Client Application          SOCKS5 Evasion Tunnel          Remote Web Host
          │                             │                           │
          ├───► 1. SOCKS5 Handshake ───►│                           │
          │     (Negotiate Auth & Port) │                           │
          │                             │                           │
          ├───► 2. Connect Command ────►│                           │
          │     (Request target IP)     ├───► 3. Establish TCP ────►│
          │                             │     (Standard handshake)  │
          │                             │                           │
          ├───► 4. Outbound Payload ───►│                           │
          │     (TLS ClientHello)       │                           │
          │                             │   5. TCP Segment Split    │
          │                             ├───► Write 1st chunk ─────►│
          │                             │     (Before SNI string)   │
          │                             │                           │
          │                             │     [ 10ms Split Delay ]  │
          │                             │                           │
          │                             ├───► Write 2nd chunk ─────►│
          │                             │     (Remaining bytes)     │
          │                             │                           │
```

---

### 3.2 Telemetry Decoy Tracker Logging Pipeline
This sequence shows how scanner visits are captured and logged:

```
  Scanner Client              LumiNet Server Daemon            SQLite Database
        │                               │                             │
        ├───► 1. HTTP Request ─────────►│                             │
        │     (Unauthenticated GET)     │                             │
        │                               ├───► 2. Parse User-Agent ───►│
        │                               │     (Extract OS & Device)   │
        │                               │                             │
        │                               ├───► 3. Resolve Client IP ──►│
        │                               │     (Fetch GeoIP Metadata)  │
        │                               │                             │
        │                               ├───► 4. Log Visit Record ───►│
        │                               │     (Insert SQL entry)      │
        │                               │                             │
        │◄─── 5. Redirect Response ─────┤                             │
        │     (302 Decoy Location)      │                             │
```

---

### 3.3 Zephyr Google Drive Mailbox Protocol
The GDrive mailbox transport enables covert communication over file uploads:

```
  LumiNet Client              Google Drive API             Upstream Relay Host
        │                            │                            │
        ├───► 1. Write Envelope ────►│                            │
        │     (Upload: client.bin)   │                            │
        │                            │                            │
        │                            │◄─── 2. Poll Folder ────────┤
        │                            │     (Check for updates)    │
        │                            │                            │
        │                            │────► 3. Read Envelope ────►│
        │                            │     (Download: client.bin) │
        │                            │                            │
        │                            │◄─── 4. Write Response ─────┤
        │                            │     (Upload: relay.bin)    │
        │                            │                            │
        ├───► 5. Poll Folder ───────►│                            │
        │     (Check for updates)    │                            │
        │                            │                            │
        │◄─── 6. Read Response ──────┤                            │
        │     (Download: relay.bin)  │                            │
```

---

## 4. Multi-Language Memory & Concurrency Boundaries

To ensure safe execution across Go and Rust, the following design boundaries are enforced:

### 4.1 CGO Memory Boundary
*   All complex structures are serialized as JSON strings before crossing the FFI boundary to simplify data mapping.
*   **Manual Pointer Disposal:** Rust manages its own memory allocations. Pointers returned to Go must be returned to Rust via `C.free_string(ptr)` to be dropped and deallocated safely.

### 4.2 Go Scheduler Mutex Safety
To prevent lock duplication and scheduler panics, structures containing synchronization primitives (`sync.Mutex` or `sync.RWMutex`) must not be copied. Developers must implement explicit cloning methods to copy only primitive fields:

```go
func (orig *SystemProfile) Clone() *SystemProfile {
    orig.mutex.Lock()
    defer orig.mutex.Unlock()
    return &SystemProfile{
        Name:     orig.Name,
        Adapter:  orig.Adapter,
        DnsList:  orig.DnsList,
        ProxyURL: orig.ProxyURL,
    }
}
```

### 4.3 Rust Panic Isolation
If a panic occurs inside Rust, it must not unwind across the C ABI, as this causes immediate memory corruption. All FFI-exported functions must be wrapped inside `std::panic::catch_unwind` blocks to catch panics and return them as structured JSON error codes.

---

## 5. External Plugin IPC Architecture

The daemon supports external binary discovery and communication via standard streams using a JSON-RPC 2.0 interface:

*   **Discovery:** The daemon scans the `plugins/` directory for `plugin.json` manifests.
*   **IPC Communication:** Processes exchange JSON-RPC payloads over standard streams (`stdin`/`stdout`).
*   **Hooks Pipeline:** Core events (such as `scan_result`, `proxy_result`, and `diag_complete`) are piped to the plugins to execute custom hooks.

```json
{
  "jsonrpc": "2.0",
  "method": "on_scan_result",
  "params": {
    "job_id": "job_uuid",
    "targets": ["192.168.1.1"]
  },
  "id": 4
}
```
