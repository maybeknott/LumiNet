# 🚀 LumiNet Quick Start & Administration Guide

Welcome to the **LumiNet** setup and operations manual. This guide will walk you through the system prerequisites, binary deployment, compilation from source, command-line operations, evasion tunnel setup, and recovery runbooks.

---

## 1. Installation & Deployment

LumiNet can be run by downloading pre-compiled binaries or by compiling the codebase from source.

### 1.1 Downloading Pre-compiled Releases
Pre-compiled packages for Windows (x64), Linux (x86_64), and macOS (Apple Silicon/Intel) are available on the [LumiNet Releases page](https://github.com/maybeknott/luminet/releases).
1. Download the archive matching your operating system.
2. Extract the archive into a permanent directory of your choice.
3. Add the extraction path to your system's `PATH` variable to enable global terminal access.

---

## 2. Compiling from Source

LumiNet compiles into a static binary. Because it interfaces Go's networking API with a low-level Rust scanning engine, a valid C compiler toolchain (CGO) is required.

### 2.1 Toolchain Prerequisites

| Language/Tool | Version | Purpose | Installation |
|:---|:---|:---|:---|
| **Rust** | 1.78+ | Compiles the `lumicore` scanning engine | [rustup.rs](https://rustup.rs) |
| **Go** | 1.22+ | Compiles the daemon API and Walk GUI | [go.dev/dl](https://go.dev/dl/) |
| **C Compiler** | GCC 12+ | Links Rust's static library via CGO | See Platform Guides below |
| **Node.js** | 20+ | Builds the optional React web dashboard | [nodejs.org](https://nodejs.org) |
| **pnpm** | 9+ | Package manager for frontend assets | `npm install -g pnpm` |
| **cbindgen** | 0.27+ | Generates C headers from Rust sources | `cargo install cbindgen` |

### 2.2 Installing the C Compiler Toolchain

#### Windows (MSYS2 MinGW-w64)
1. Download and run the installer from [msys2.org](https://www.msys2.org/).
2. Open the **MSYS2 UCRT64 Terminal** and execute:
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-gcc git make
   ```
3. Add the MinGW binary path (`C:\msys64\ucrt64\bin`) to your Windows environment `Path`.
4. Open a new PowerShell terminal and verify: `gcc --version`.

#### Linux (Ubuntu/Debian)
Install developer build tools and library headers via `apt`:
```bash
sudo apt update
sudo apt install build-essential gcc git make -y
```

#### macOS (Xcode Command Line Tools)
Install Apple developer tools:
```bash
xcode-select --install
```

### 2.3 Compilation Workflow

#### Windows Deployment (PowerShell)
```powershell
# Clone the repository
git clone https://github.com/maybeknott/luminet.git
cd LumiNet

# Execute the Windows build script
.\scripts\build-all.ps1 -SkipWeb

# Run the compiled binary from the build directory
.\build\luminet.exe serve
```

#### Linux & macOS Deployment (Terminal)
```bash
# Clone the repository
git clone https://github.com/maybeknott/luminet.git
cd LumiNet

# Grant execution rights to the Unix build script
chmod +x scripts/build-all.sh
./scripts/build-all.sh --skip-web

# Run the compiled binary
./build/luminet serve
```

---

## 3. Starting the Daemon (`serve` command)

LumiNet functions as a background orchestrator daemon that coordinates scanning runs and proxy tunnels.

```bash
# Start the daemon on the default port (8470)
luminet serve

# Start the daemon on a custom port and restrict to localhost
luminet serve --port 9090 --host 127.0.0.1

# Enable compatibility mode to serve retired React web assets (Vite console)
luminet serve --web
```

### 3.1 Initial Operations Checklist
When `luminet serve` is executed, the daemon runs these initialization tasks:
1. **Database Schema Setup:** Creates the configuration SQLite database (`luminet.db`) in the user directory if it is missing.
2. **DNS Adapter Backup:** Audits all active network adapters, reads their current DNS addresses, and writes them to a persistent rollback cache to ensure restore capability.
3. **Evasion Listener:** Starts the local SOCKS5 Evasion Tunnel if configured for autostart.

---

## 4. CLI Subcommand Reference & Examples

### 4.1 Subnet & Service Port Scanning (`scan`)

#### Stateless ICMP Sweep
Ping all hosts in a target CIDR range concurrently:
```bash
# Run a sweep with 200 concurrent threads and a 1500ms timeout
luminet scan icmp 192.168.1.0/24 --concurrency 200 --timeout 1500
```

#### TCP Port Scan & Banner Grabbing
Audit TCP ports and attempt to fetch application banner fingerprints:
```bash
# Scan common ports on a host and output results in JSON format
luminet scan ports 10.0.0.15 --ports 21,22,80,443,3306,8080 --banner --output json
```

#### TLS Certificate Inspection
Inspect the TLS configuration of a target endpoint:
```bash
luminet scan tls example.com:443
```

#### SNI Block Checker
Probe whether a local firewall filters a specific Server Name Indication (SNI) header:
```bash
luminet scan sni blockeddomain.com --dns-resolver 1.1.1.1
```

---

### 4.2 Comprehensive Network Diagnostics (`diagnose`)

The diagnostics tool runs a 6-phase test: Connectivity -> DNS Integrity -> TLS Validity -> Portal Check -> Evasion Scanner -> Speed Grade.

```bash
# Run a full diagnostic check
luminet diagnose

# Run specific phases (e.g., DNS Integrity and Portal Checks) and export the report
luminet diagnose --phases 2,4 --export D:\diagnostics-report.html
```

---

### 4.3 Proxy Operations & Subscriptions (`proxy`)

#### Benchmarking Proxy Latency
Bulk test a list of proxies from a text file:
```bash
# Test proxies using 32 parallel threads and measure download latency
luminet proxy test -f my_proxies.txt --concurrency 32 --speed-test
```

#### Managing Subscription Links
Add a subscription URL to the auto-fetch parser list:
```bash
luminet proxy subscribe add https://example-provider.com/sub/raw?token=123
```

#### Exporting Verified Working Proxies
Filter working proxies and export them to a Clash-compatible format:
```bash
luminet proxy export --format clash --output C:\Users\ACER\.config\clash\config.yaml
```

---

### 4.4 System Configuration & Evasion Setup (`system`)

#### Modifying System DNS Servers
Set system-wide DNS to secure public servers (e.g., Quad9):
```bash
luminet system dns set 9.9.9.9,149.112.112.112
```

#### Restoring Adapter DNS Configuration
Restore adapter DNS to their original values fetched during startup:
```bash
luminet system dns restore
```

#### SOCKS5 Active Evasion Tunnel
Start a local SOCKS5 tunnel with TCP segment splitting and auto-SNI desynchronization:
```bash
# Enable SOCKS5 evasion on port 1080 with SNI splitting enabled
luminet system evasion-tunnel start --port 1080 --split-offset 3 --split-delay 10 --auto-sni
```

#### Firewall Leak Protection
Enable firewall restrictions to block all outgoing traffic not routed through the SOCKS5 proxy:
```bash
# Apply leak protection rules for SOCKS5 proxy port 1080
luminet system leak-protection enable 1080

# Disable leak protection rules
luminet system leak-protection disable
```

---

## 5. Recovery Runbook

### 5.1 Restoring DNS Settings After an Unexpected Crash
If the LumiNet daemon terminates unexpectedly while custom system DNS servers are active, the original settings may not revert automatically. Run the following command to restore DHCP or original DNS cache records manually:

```powershell
# Restore DNS settings from the cache database
luminet system dns restore --force
```

If the CLI fails to execute due to file lockouts, reset the network adapter settings using native OS shell tools:

#### Windows (Administrator PowerShell)
```powershell
# Reset all Ethernet and Wi-Fi adapters to receive DNS dynamically via DHCP
Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected' } | Set-DnsClientServerAddress -ResetServerAddresses
```

#### Linux (Terminal)
```bash
# Restore default resolv.conf via Systemd resolver
sudo systemctl restart systemd-resolved
```
