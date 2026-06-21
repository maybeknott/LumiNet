# 💻 Command-Line Interface (CLI) Reference Manual

This document provides a comprehensive reference for the `luminet` command-line tool. It lists all subcommands, arguments, parameters, default configurations, and output formats.

---

## 1. Global CLI Options
These flags are processed before subcommand execution and apply globally:

```bash
luminet [global-flags] [subcommand] [subcommand-flags]
```

| Flag | Shortcut | Default | Type | Description |
|:---|:---|:---|:---|:---|
| `--config` | `-c` | `~/.luminet/config.json` | String | Absolute path to the JSON configuration file |
| `--log-level` | `-l` | `info` | String | Log verbosity limit: `debug`, `info`, `warn`, `error` |
| `--data-dir` | `-d` | `~/.luminet/` | String | Data folder containing the SQLite file and logs |
| `--help` | `-h` | — | Boolean | Displays help text and option syntax |
| `--version` | `-v` | — | Boolean | Displays compiler build version and commit hash |

---

## 2. Command: `luminet serve`
Launches the background orchestrator API server and initializes the Windows Walk GUI.

```bash
luminet serve [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--port` | `8470` | Integer | HTTP REST and WebSocket listener port |
| `--host` | `127.0.0.1` | String | Bind address. Set to `0.0.0.0` to allow external network access |
| `--api-key` | *(empty)* | String | Secret key required in client request headers (e.g. `X-API-Key`) |
| `--no-browser` | `false` | Boolean | Prevents the default browser from opening when running in compatibility mode |
| `--gui` | `false` | Boolean | Forces the native Walk GUI window to load |
| `--web` | `false` | Boolean | Starts the retired React web console compatibility mode |

**Examples:**
```bash
# Start the local daemon and load the Walk interface
luminet serve --gui

# Run as a headless server bound to all adapters with authentication
luminet serve --host 0.0.0.0 --port 9000 --api-key "SecToken123"
```

---

## 3. Command Group: `luminet scan`
Subcommands for network auditing and scanning.

### 3.1 Common Scan Flags
These flags are inherited by all `scan` subcommands:

| Flag | Shortcut | Default | Type | Description |
|:---|:---|:---|:---|:---|
| `--timeout` | `-t` | `3000` | Integer | Per-probe network timeout in milliseconds |
| `--concurrency` | `-p` | `64` | Integer | Max concurrent asynchronous workers |
| `--output` | `-o` | `table` | String | Renders results in: `table`, `json`, `csv` |

### 3.2 Subcommand: `scan icmp`
Sweeps target ranges using parallel ICMP echo requests.

```bash
luminet scan icmp [CIDR-or-IP-Range] [flags]
```

**Examples:**
```bash
# Sweep local subnet and return results in CSV format
luminet scan icmp 192.168.1.0/24 --concurrency 100 --output csv

# Ping a specified range of IP addresses with a custom timeout
luminet scan icmp 10.0.0.5-10.0.0.50 --timeout 500
```

### 3.3 Subcommand: `scan ports`
Scans TCP ports and attempts to retrieve application headers or banners.

```bash
luminet scan ports [Target-Host] [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--ports` | `1-1024` | String | Target ports as a range (e.g. `1-1000`) or list (e.g. `22,80,443`) |
| `--banner` | `false` | Boolean | Read initial socket bytes to harvest application signatures |

**Examples:**
```bash
# Scan common ports on a host and display banner descriptions
luminet scan ports web.domain.com --ports 22,80,443,8080 --banner

# Scan a wide port range on a local IP and export to JSON
luminet scan ports 192.168.1.1 --ports 1-10000 --concurrency 250 -o json
```

### 3.4 Subcommand: `scan dns`
Resolves target hostnames against a specified recursive resolver.

```bash
luminet scan dns [Domain-Names] [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--server` | `8.8.8.8` | String | DNS server IP address (e.g. `9.9.9.9` or `1.1.1.1`) |
| `--record-type` | `A` | String | DNS record type to query (`A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`) |

**Examples:**
```bash
# Query the MX records of a domain using Quad9
luminet scan dns target.org --server 9.9.9.9 --record-type MX
```

### 3.5 Subcommand: `scan tls`
Performs TLS handshakes to extract certificate chains and cipher configurations.

```bash
luminet scan tls [Target-Hosts] [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--port` | `443` | Integer | Destination TLS port |

**Examples:**
```bash
# Audit the certificate chain of an HTTPS server
luminet scan tls secure-site.net --port 8443
```

### 3.6 Subcommand: `scan sni`
Sends a client handshake to check if a local firewall blocks a Server Name Indication.

```bash
luminet scan sni [Target-Domains] [flags]
```

**Examples:**
```bash
# Audit if local network gates intercept handshakes to specific domains
luminet scan sni censored-site.com twitter.com --timeout 5000
```

### 3.7 Subcommand: `scan resolver-dns`
Queries recursive DNS resolvers using dynamic subdomains to measure end-to-end lookup latency and check path availability for DNS covert tunneling.

```bash
luminet scan resolver-dns [Resolver-IP] --subdomain [Base-Domain] [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--subdomain` | *(required)* | String | Base domain name for random queries (e.g., `tunnel.net`) |

**Examples:**
```bash
# Audit recursive DNS resolver 192.168.1.1 using random subdomain lookups
luminet scan resolver-dns 192.168.1.1 --subdomain tunnel.org --concurrency 10
```

---

## 4. Command: `luminet diagnose`
Executes the 6-phase network diagnostic routine.

```bash
luminet diagnose [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--phases` | `1,2,3,4,5,6` | String | Comma-separated list of diagnostic phases to execute |
| `--json` | `false` | Boolean | Outputs report data in raw JSON format |
| `--output` | *(stdout)* | String | Output filepath for the diagnostics report |

**Examples:**
```bash
# Run all phases and export the styled HTML report to a file
luminet diagnose --output C:\Users\ACER\Documents\report.html

# Run Connectivity, DNS, and TLS phases and export the results to JSON
luminet diagnose --phases 1,2,3 --json -o C:\Users\ACER\Documents\report.json
```

---

## 5. Command Group: `luminet proxy`
Subcommands for parsing, validating, benchmarking, and exporting proxy servers.

### 5.1 Subcommand: `proxy test`
Tests a list of proxy server configurations.

```bash
luminet proxy test [Proxy-URIs] [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--file` | — | String | File containing proxy configurations (one URI per line) |
| `--concurrency` | `8` | Integer | Parallel testing workers |
| `--timeout` | `10` | Integer | Timeout limit in seconds for each proxy |
| `--speed-test` | `false` | Boolean | Measures download throughput on connection paths |
| `--geoip` | `true` | Boolean | Dispatches exit IP lookup checks |

**Examples:**
```bash
# Test a list of proxies from a file and measure download throughput
luminet proxy test -f list.txt --concurrency 16 --speed-test
```

### 5.2 Subcommand: `proxy subscribe`
Gathers proxies from a subscription endpoint.

```bash
# Add a subscription URL
luminet proxy subscribe add [URL]

# Force fetch and parse from a subscription URL
luminet proxy subscribe fetch [URL] --output [Path]
```

---

## 6. Command Group: `luminet system`
Subcommands for system network integrations.

### 6.1 Subcommand: `system dns`
Configures system network adapter DNS addresses.

```bash
# View active adapter DNS addresses
luminet system dns status

# Apply DNS addresses to the default network adapter
luminet system dns apply 9.9.9.9,149.112.112.112

# Apply DNS addresses to a specific network interface
luminet system dns apply 1.1.1.1,1.0.0.1 --interface "Wi-Fi"

# Restore original DNS configurations from the cache database
luminet system dns restore
```

### 6.2 Subcommand: `system evasion-tunnel`
Controls SOCKS5 Active Evasion background tunnels.

```bash
luminet system evasion-tunnel start [flags]
```

| Flag | Default | Type | Description |
|:---|:---|:---|:---|
| `--port` | `1080` | Integer | Local SOCKS5 listener port |
| `--split-offset` | `3` | Integer | TCP write split boundary offset in bytes |
| `--split-delay` | `10` | Integer | Delay in milliseconds between split segments |
| `--auto-sni` | `true` | Boolean | Enables automatic TLS ClientHello parsing and SNI splitting |
| `--fragment-min` | `100` | Integer | Minimum size in bytes for range-based fragmentation |
| `--fragment-max` | `500` | Integer | Maximum size in bytes for range-based fragmentation |
| `--fragment-delay` | `15` | Integer | Jitter write delay in milliseconds between fragments |
| `--filter` | `tlshello` | String | Traffic filter scope: `tlshello` or `all` |
| `--dns-resolver` | *(empty)* | String | Remote UDP DNS address for resolving SOCKS hostnames |
| `--dns-doh` | *(empty)* | String | Remote DoH HTTPS resolver address for hostname resolution |

**Examples:**
```bash
# Start the evasion tunnel on port 1080 with SNI splitting and custom DNS resolver
luminet system evasion-tunnel start --port 1080 --auto-sni --dns-resolver 9.9.9.9
```

### 6.3 Subcommand: `system covert-tracker`
Manages the decoy covert tracker link mappings.

```bash
# Add a tracker link mapping
luminet system covert-tracker add --name "decoy-update" --redirect "https://google.com"

# List existing tracker link metrics
luminet system covert-tracker list

# List visits recorded for a tracker link mapping
luminet system covert-tracker visits --name "decoy-update"
```
