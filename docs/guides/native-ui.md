# 🖥️ Windows-Native Desktop App & GUI Cockpit

LumiNet provides a Windows-native desktop interface designed using the Go `walk` framework. It communicates with the local background Go daemon through secure localhost REST and WebSocket interfaces. This interface avoids web-view resource overhead, running directly on the native Win32 windowing controls.

---

## 1. GUI Component Layout & Operation

The desktop application organizes network controls, monitoring stats, and diagnostics into a single cockpit interface containing six tabs.

```
┌────────────────────────────────────────────────────────────────────────┐
│  LumiNet Native Operations Console (Port 8470)                        │
├────────────────────────────────────────────────────────────────────────┤
│ [Dashboard]  [DNS Audit]  [Evasion & Tunnel]  [Scanning]  [Diagnostics] │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────────────┐          ┌─────────────────────────────┐  │
│  │   System Telemetry      │          │     System Posture          │  │
│  │   CPU: [■■■■■■....] 35% │          │     IPv4: 185.112.44.12     │  │
│  │   RAM: [■■■■......] 24% │          │     DNS:  9.9.9.9 (Quad9)   │  │
│  └─────────────────────────┘          └─────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  Live Telemetry Logs                                             │  │
│  │  [12:04:12] INF Starting ICMP Subnet Sweep on 192.168.1.0/24     │  │
│  │  [12:04:13] DBG Discovered active host: 192.168.1.1 (1.2ms)       │  │
│  │  [12:04:15] INF ICMP sweep complete. 8 active hosts found.       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Dashboard (Operations Cockpit)
The primary workspace view display contains real-time status modules:
*   **System Telemetry Cards:** Renders active system CPU, RAM, and Disk space utilization. Sparkline visualizations are painted dynamically onto Win32 canvas elements at 1-second intervals.
*   **System Posture Panel:** Displays the public IPv4 and IPv6 addresses, active adapter DNS server configurations, and system-wide HTTP/SOCKS proxy states.
*   **Capability Lanes:** Lists registered network libraries, imported tools, active background DDNS update routines, and scheduled diagnostic sweeps.

### 1.2 Operations Workbench Tabs
1.  **DNS Audit:** Executes side-by-side DNSSEC, plain UDP, and encrypted DoH queries. Includes a drop-down menu with 11 secure resolver presets (e.g. Quad9, Cloudflare, cleanbrowsing) and alerts the user of DNS CNAME redirections (such as forced SafeSearch filtering).
2.  **DPI Evasion & Tunneling:** Configures SOCKS5 Evasion Tunnel settings, including segment split offsets, write delays, SNI splitting, range-based fragmentation, and custom resolver mappings.
3.  **Telegram MTProto Workbench:** Gathers proxies from public channel feeds, launches parallel TCP benchmark runs, lists working proxies by round-trip latency, and copies connection strings directly to the clipboard.
4.  **LAN Subnet Scanner:** Discovers active hosts via parallel ICMP or TCP port sweeps. Allows the user to select specific network adapters or dynamically detect target subnets using the **Auto-Detect** adapter sweep.
5.  **WireGuard Auditor:** Tests handshake reachability to specific endpoints or benchmarks public WARP, ProtonVPN, and Mullvad servers.
6.  **Diagnostics Console:** Manages manual execution of the 6-phase diagnostic sequence, outputs diagnostic logs in real-time, and exports results to styled HTML or PDF reports.

---

## 2. Multi-Threaded GUI Architecture

The Walk UI library relies on single-threaded Win32 UI dispatch loops. To ensure that long-running operations (such as port scanning or speed benchmarking) do not block or freeze the user interface, LumiNet isolates UI rendering from core execution.

```
    [ Win32 Main UI Thread ]              [ Go Daemon Workers ]
               │                                    │
               ├─► Rest/WS Job Dispatch ───────────►│ (Runs Scan/Tunnel)
               │                                    │
    (Listens on Msg Loop)                           │ (Yields status update)
               │◄─ [ Walk Synchronize Callback ] ───┤
               │                                    │
     (Updates Sparklines / Status)                  ▼
```

### 2.1 Non-Blocking Job Dispatching
When the user triggers a network sweep, the UI thread delegates the task to background workers:
1. The UI creates a background context, serializes configuration parameters, and sends a non-blocking execution request to the local Go daemon.
2. The Go daemon routes the request across the CGO boundary to Rust's async Tokio worker pools.
3. As progress is reported back, the Go daemon sends progress notifications over WebSockets.
4. The GUI receives WebSocket notifications on a background client thread and schedules main-thread interface updates using Walk's synchronizer:
   ```go
   // Go Walk Thread-Safe UI Update
   mainWindow.Synchronize(func() {
       progressBar.SetValue(progressUpdate.Percent)
       logView.AppendText(progressUpdate.Message + "\r\n")
   })
   ```

### 2.2 Sparkline Telemetry Drawing (Win32 Canvas)
Sparkline telemetry charts are painted directly onto Win32 canvases inside the dashboard cards:
* A rolling array of recent telemetry samples (e.g., the last 60 CPU utilization updates) is kept in memory.
* When a canvas repaint trigger is received, a Walk paint event callback is executed:
  ```go
  telemetryCard.Paint().Attach(func(canvas *walk.Canvas, updateBounds walk.Rectangle) {
      brush, _ := walk.NewSolidColorBrush(walk.RGB(6, 182, 212)) // Neon Cyan
      defer brush.Dispose()
      
      pen, _ := walk.NewCosmeticPen(walk.PenStyleSolid, walk.RGB(59, 130, 246))
      defer pen.Dispose()
      
      // Calculate drawing paths based on rolling memory stats
      var points []walk.Point
      for i, val := range cpuUsageHistory {
          x := int32(i * (updateBounds.Width / len(cpuUsageHistory)))
          y := int32(updateBounds.Height - (val * updateBounds.Height / 100))
          points = append(points, walk.Point{X: x, Y: y})
      }
      
      canvas.DrawPolyline(pen, points)
  })
  ```

---

## 3. Windows Application Manifest & Compilation

To build a standalone executable that correctly links native Windows styles (ComCtl32) and runs with the appropriate system permissions, a custom XML application manifest must be compiled into the binary.

### 3.1 Application Manifest Structure (`luminet.exe.manifest`)
Create this manifest file inside the main build folder:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <assemblyIdentity
        version="1.0.0.0"
        processorArchitecture="*"
        name="LumiNet.Console"
        type="win32"
    />
    <description>LumiNet Native Operations Console</description>
    <dependency>
        <dependentAssembly>
            <assemblyIdentity
                type="win32"
                name="Microsoft.Windows.Common-Controls"
                version="6.0.0.0"
                processorArchitecture="*"
                publicKeyToken="6595b64144ccf1df"
                language="*"
            />
        </dependentAssembly>
    </dependency>
    <!-- Configure execution level: Requires administrator credentials to toggle network interfaces -->
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel
                    level="asInvoker"
                    uiAccess="false"
                />
            </requestedPrivileges>
        </security>
    </trustInfo>
</assembly>
```

### 3.2 Compiling Manifest Resources
Use the `rsrc` tool to compile the XML manifest file into a format Go can embed:

1. **Install rsrc:**
   ```bash
   go install github.com/akavel/rsrc@latest
   ```
2. **Generate COFF Object File:**
   Compile the manifest (and optionally the application icon) into `rsrc.syso`:
   ```bash
   rsrc -manifest luminet.exe.manifest -o rsrc.syso
   ```
3. **Compile the Executable:**
   When you run `go build`, Go detects `rsrc.syso` in the directory and links the manifest resource into the final binary.
   ```bash
   go build -ldflags="-H windowsgui" -o ../build/luminet.exe
   ```
   *(Note: The `-H windowsgui` flag suppresses the default OS cmd command-line popup when double-clicking the compiled executable).*
