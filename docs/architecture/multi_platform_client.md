# 📱 Multi-Platform Client & System Integration Handbook

This handbook documents the client-side system architecture and deployment patterns for running **LumiNet** configurations across Android, macOS, Linux, Cloudflare Workers, and Telegram Bot managers.

---

## 1. Android VPN Client Core & Interface Protection

The Android implementation uses a Go-compiled core wrapper (linked via Java Native Interface - JNI) that manages the low-level `sing-box` or `xray` routing loop.

```
  [ Android UI / VPNService ] ──► [ SCM_RIGHTS UNIX Socket ] ──► [ Go Core Engine ]
               │                                                       │
               │◄── Protect Socket Descriptor (vpnService.protect) ────┤
               │                                                       │
               ▼                                                       ▼
  [ Virtual TUN Device (fd) ] ◄─────────────────────────────── [ Tunnel Traffic ]
```

### 1.1 SCM_RIGHTS Socket Protection Protocol
When the client engine initiates outbound sockets, the packets must not loop back into the VPN virtual interface (which would cause a packet loop crash).
1. **Descriptor Forwarding:** The Go core creates outbound TCP/UDP connection descriptors. It sends these descriptors over a local Unix domain socket using `SCM_RIGHTS` ancillary control data flags.
2. **JVM Protection:** The JVM side receives the file descriptor and calls `VpnService.protect(fd)`.
3. **Execution:** This binds the socket to the system's physical network interface (e.g., cell or Wi-Fi). Once protected, the JVM sends a confirmation byte back to Go, which can then safely write payload packets.

### 1.2 Zygisk VPN Interface Hider (`client/zygisk-vpnhide/`)
Many applications (like banking and streaming apps) check for active VPN adapters (`tun0`, `wg0`) to restrict access. LumiNet uses Zygisk hooks to intercept dynamic library calls and hide these interfaces from specific app processes:
* **Hook Mechanism:** Intercepts libc `getifaddrs` calls in application contexts (where `uid >= 10000`).
* **Filtering:** Iterates through the list of returned network interfaces and drops entries matching patterns like `tun*`, `wg*`, `tap*`, or `ppp*`.
* **Execution:** Allows target apps to run while the system continues to route their traffic through the encrypted VPN tunnel.

---

## 2. macOS (MAX) & Linux Client Implementations

### 2.1 macOS Network Extension Framework
The macOS application wraps the core engine in a native Swift application that integrates with Apple's Network Extension APIs:
* **Packet Tunnel Provider:** Uses `NEPacketTunnelProvider` to capture system-wide IP packets.
* **Network Routing:** Configures the client DNS using `NEDNSSettings` to route queries over local SOCKS5 resolvers. This prevents system-level DNS leaks and bypasses network filtering.

### 2.2 Linux `tun2socks` Routing Pipeline
For Linux, LumiNet provides shell setup scripts to route system traffic through the local evasion proxy:
1. **Virtual Interface Creation:** Creates a virtual `tun` device using `ip tuntap`:
   ```bash
   ip tuntap add dev tun0 mode tun
   ip link set dev tun0 up
   ip addr add 10.0.0.1/24 dev tun0
   ```
2. **Traffic Forwarding:** Launches the `tun2socks` engine to forward raw IP packets from `tun0` to the local SOCKS5 evasion listener:
   ```bash
   tun2socks -device tun0 -proxy socks5://127.0.0.1:1080
   ```
3. **Routing Table Configuration:** Updates system routing rules to direct all non-proxy traffic through `tun0`:
   ```bash
   ip route add $PROXY_SERVER_IP via $DEFAULT_GATEWAY
   ip route replace default dev tun0
   ```

---

## 3. Serverless Edge Workers (Cloudflare VLESS)

To run proxies without dedicated servers, LumiNet integrates client outbounds with serverless JavaScript isolates running on Cloudflare's network:

```
  Go Client Evasion ──► [ WebSocket Handshake ] ──► [ Cloudflare Edge Worker ]
                                                           │
                                                           ▼ (CF connect() API)
                                                    [ Remote Host ]
```

*   **VLESS Protocol Mappings:** Clients use VLESS-over-WebSockets to route data to the worker.
*   **Zero-Trust Relay:** The worker validates client request credentials (UUID) and extracts connection parameters (address, port). It then uses Cloudflare's native `connect()` API to open a direct TCP connection to the remote host.
*   **Security:** This configuration hides the remote host's IP address and secures traffic using Cloudflare's edge certificate infrastructure.

---

## 4. Telegram VPS & Cloudflare Management Bot

The administration bot script (`enterprise/templates/telegram-bot/bot.py`) provides system control over a secure chat interface:

*   **Node Resource Telemetry:** Collects system telemetry (CPU, RAM, Disk) using Python's `psutil` library.
*   **Service Supervision:** Restarts local proxy core services (Xray, sing-box) by running shell commands via `systemctl` wrappers.
*   **Cloudflare DNS Integration:** Interacts with Cloudflare's DNS APIs to update proxy domain configurations and manage Strict SSL settings.
*   **Credential Generation:** Generates secure UUIDs for new users and adds them to the server's configuration files.
