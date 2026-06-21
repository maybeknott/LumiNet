# 🌐 LumiNet Daemon REST & WebSocket API Manual

This reference manual documents the local HTTP REST and WebSocket APIs exposed by the LumiNet daemon.

*   **Base URL:** `http://localhost:8470`
*   **Authentication:** When `--api-key` is configured on daemon boot, all `/api/*` endpoints require the header:
    ```http
    X-API-Key: your_configured_api_token
    ```

---

## 1. Subsystem: Daemon Health & Status

### 1.1 `GET /health`
Verifies daemon responsiveness.

*   **Request Headers:** None (unauthenticated)
*   **Success Response (200 OK):**
    ```json
    {
      "status": "ok",
      "timestamp": "2026-06-22T01:00:00Z",
      "version": "0.1.0",
      "go_version": "go1.22.4",
      "platform": "windows/amd64"
    }
    ```

### 1.2 `GET /api/capabilities`
Returns the operational capabilities compiled into the running daemon.

*   **Success Response (200 OK):**
    ```json
    {
      "cgo_enabled": true,
      "native_gui": true,
      "socks5_evasion": true,
      "covert_tracking": true,
      "dns_tunnel_scanner": true,
      "zephyr_transport": true
    }
    ```

---

## 2. Subsystem: Stateless Network Scanning (`/api/scans`)

This subsystem interfaces with the Rust core to run subnet sweeps and port scans.

### 2.1 `POST /api/scans` (ICMP Subnet Sweep)
Creates a background ICMP sweep job.

*   **Request Schema:**
    ```json
    {
      "targets": ["192.168.1.0/24"],
      "timeout": 1000,
      "concurrency": 100
    }
    ```
*   **Success Response (202 Accepted):**
    ```json
    {
      "id": "job_d98124b8-f076-4d1a-8263-448f",
      "status": "queued",
      "progress": 0,
      "created_at": "2026-06-22T01:00:00Z"
    }
    ```

### 2.2 `GET /api/scans/:id`
Retrieves progress parameters of an active scan.

*   **Success Response (200 OK):**
    ```json
    {
      "id": "job_d98124b8-f076-4d1a-8263-448f",
      "status": "running",
      "progress": 45,
      "error": ""
    }
    ```

### 2.3 `GET /api/scans/:id/results`
Returns probe results for completed scans.

*   **Success Response (200 OK):**
    ```json
    {
      "job_id": "job_d98124b8-f076-4d1a-8263-448f",
      "hosts": [
        { "ip": "192.168.1.1", "status": "alive", "rtt_ms": 1.2 },
        { "ip": "192.168.1.15", "status": "alive", "rtt_ms": 2.4 }
      ]
    }
    ```

### 2.4 `POST /api/scans/:id/cancel`
Terminates an active scan job.

*   **Success Response (200 OK):**
    ```json
    {
      "id": "job_d98124b8-f076-4d1a-8263-448f",
      "status": "cancelled"
    }
    ```

---

## 3. Subsystem: Active Circumvention & Evasion Tunnels

### 3.1 `GET /api/system/evasion-tunnel`
Retrieves the active SOCKS5 Evasion Tunnel configurations.

*   **Success Response (200 OK):**
    ```json
    {
      "running": true,
      "port": 1080,
      "split_bytes": 3,
      "delay_ms": 10,
      "mutate_host": true,
      "auto_sni": true,
      "packets": "tlshello",
      "min_length": 100,
      "max_length": 500,
      "tls_record_split": true,
      "dns_resolver": "9.9.9.9"
    }
    ```

### 3.2 `POST /api/system/evasion-tunnel`
Toggles SOCKS5 Evasion Tunnel state.

*   **Request Schema:**
    ```json
    {
      "enabled": true,
      "port": 1080,
      "split_bytes": 3,
      "delay_ms": 10,
      "mutate_host": true,
      "auto_sni": true,
      "packets": "tlshello",
      "min_length": 100,
      "max_length": 500,
      "tls_record_split": true,
      "dns_resolver": "9.9.9.9"
    }
    ```
*   **Success Response (200 OK):**
    ```json
    {
      "status": "active",
      "port": 1080
    }
    ```

### 3.3 `GET /api/system/evasion-tunnel/logs`
Returns connection logs buffered in memory from the SOCKS5 Evasion Tunnel.

*   **Success Response (200 OK):**
    ```json
    {
      "logs": [
        "[12:04:12] Capturing TCP stream from 127.0.0.1:5321",
        "[12:04:12] Detected TLS ClientHello. Running Auto-Split SNI desynchronization.",
        "[12:04:13] Tunnel connect succeeded to: encrypted-site.net:443"
      ]
    }
    ```

---

## 4. Subsystem: Covert Telemetry IP Tracker

Protected endpoints used to manage tracking decoy links and read captured visit logs.

### 4.1 `POST /api/system/covert/links`
Registers a new decoy mapping link.

*   **Request Schema:**
    ```json
    {
      "name": "decoy-patch",
      "redirect_url": "https://google.com"
    }
    ```
*   **Success Response (201 Created):**
    ```json
    {
      "id": 2,
      "name": "decoy-patch",
      "redirect_url": "https://google.com",
      "tracker_url": "http://localhost:8470/c/decoy-patch",
      "created_at": "2026-06-22T01:01:00Z"
    }
    ```

### 4.2 `GET /api/system/covert/links`
Lists all decoy mapping links registered in the SQLite store.

*   **Success Response (200 OK):**
    ```json
    [
      {
        "id": 1,
        "name": "decoy-update",
        "redirect_url": "https://microsoft.com",
        "created_at": "2026-06-22T01:00:00Z"
      }
    ]
    ```

### 4.3 `GET /api/system/covert/visits`
Lists telemetry parameters collected from decoy link visitors.

*   **Success Response (200 OK):**
    ```json
    [
      {
        "id": 12,
        "link_name": "decoy-update",
        "client_ip": "185.112.45.12",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
        "os_family": "Windows",
        "device_brand": "Desktop PC",
        "country_code": "IR",
        "visited_at": "2026-06-22T01:02:15Z"
      }
    ]
    ```

### 4.4 `DELETE /api/system/covert/links/:name`
Deletes a registered decoy tracking link.

*   **Success Response (200 OK):**
    ```json
    {
      "name": "decoy-patch",
      "status": "deleted"
    }
    ```

---

## 5. Subsystem: Telegram MTProto Scraper

### 5.1 `GET /api/telegram/mtproto`
Initiates a Telegram MTProto proxy scrap and runs a parallel latency benchmark.

*   **Success Response (200 OK):**
    ```json
    {
      "checked_proxies": 24,
      "working_proxies": [
        { "link": "tg://proxy?server=198.51.100.5&port=443&secret=dd...", "latency_ms": 42 },
        { "link": "tg://proxy?server=203.0.113.12&port=8888&secret=ee...", "latency_ms": 115 }
      ]
    }
    ```

---

## 6. Subsystem: WebSocket Server (Real-Time Subscriptions)

Upgrades standard HTTP calls to real-time WebSocket communication channels at:
```http
ws://localhost:8470/ws
```

### 6.1 Client Actions

#### Subscribe to Job Logs
```json
{
  "action": "subscribe",
  "job_id": "job_d98124b8-f076-4d1a-8263-448f"
}
```

#### Unsubscribe from Job Logs
```json
{
  "action": "unsubscribe",
  "job_id": "job_d98124b8-f076-4d1a-8263-448f"
}
```

### 6.2 Event Envelope
The server returns event messages wrapped in a standard JSON envelope:

```json
{
  "type": "progress",
  "job_id": "job_d98124b8-f076-4d1a-8263-448f",
  "data": {
    "percent": 45,
    "message": "Stateless index shuffle: 115 active targets processed"
  },
  "timestamp": "2026-06-22T01:00:15Z"
}
```
*   **Envelope Types:** `status_change` (notifies start/completion updates), `progress` (yields log metrics), `result` (returns final datasets), `error` (provides crash parameters).
