package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

type CFClient struct {
	token  string
	client *http.Client
}

func NewCFClient(token string) *CFClient {
	return &CFClient{
		token:  token,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *CFClient) doReq(ctx context.Context, method, url string, body []byte, contentType string) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBytes, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

func (c *CFClient) VerifyToken(ctx context.Context) error {
	url := "https://api.cloudflare.com/client/v4/user/tokens/verify"
	_, err := c.doReq(ctx, "GET", url, nil, "")
	if err != nil {
		return fmt.Errorf("token verification failed: %w", err)
	}
	return nil
}

func (c *CFClient) GetZoneID(ctx context.Context, domain string) (string, error) {
	// Extract apex domain if domain is sub-domain
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		domain = strings.Join(parts[len(parts)-2:], ".")
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain)
	respBytes, err := c.doReq(ctx, "GET", url, nil, "")
	if err != nil {
		return "", err
	}

	var res struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &res); err != nil {
		return "", err
	}

	if !res.Success || len(res.Result) == 0 {
		return "", fmt.Errorf("no active zone found for domain %s", domain)
	}

	return res.Result[0].ID, nil
}

func (c *CFClient) UpsertDNSRecord(ctx context.Context, zoneID, name, ip string, proxied bool) error {
	// 1. Search existing record
	searchURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", zoneID, name)
	respBytes, err := c.doReq(ctx, "GET", searchURL, nil, "")
	if err != nil {
		return err
	}

	var searchRes struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &searchRes); err != nil {
		return err
	}

	payload := map[string]interface{}{
		"type":    "A",
		"name":    name,
		"content": ip,
		"ttl":     1, // 1 = automatic (required for proxied records)
		"proxied": proxied,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if len(searchRes.Result) > 0 {
		// Update existing
		recordID := searchRes.Result[0].ID
		updateURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
		_, err = c.doReq(ctx, "PUT", updateURL, body, "application/json")
		return err
	}

	// Create new
	createURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	_, err = c.doReq(ctx, "POST", createURL, body, "application/json")
	return err
}

// SetSSLModeStrict sets the Cloudflare zone SSL setting to "strict" mode.
// This adopts the SSL hardening logic from WhiteDNS-Wizard.
func (c *CFClient) SetSSLModeStrict(ctx context.Context, zoneID string) error {
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/settings/ssl", zoneID)
	payload := map[string]interface{}{
		"value": "strict",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = c.doReq(ctx, "PATCH", url, body, "application/json")
	return err
}

// CreateOriginCertificate requests an Origin CA Certificate from Cloudflare.
// Hostnames is a list of hosts/wildcards, and csrPEM is the PEM-encoded CSR.
func (c *CFClient) CreateOriginCertificate(ctx context.Context, hostnames []string, csrPEM string, validityDays int) ([]byte, error) {
	url := "https://api.cloudflare.com/client/v4/certificates"
	
	validity := 5475 // Default 15 years
	if validityDays > 0 {
		validity = validityDays
	}
	
	payload := map[string]interface{}{
		"hostnames":          hostnames,
		"requested_validity": validity,
		"request_type":       "origin-ecc",
		"csr":                csrPEM,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	
	respBytes, err := c.doReq(ctx, "POST", url, body, "application/json")
	if err != nil {
		return nil, err
	}
	
	var res struct {
		Success bool `json:"success"`
		Result  struct {
			Certificate string `json:"certificate"`
		} `json:"result"`
	}
	
	if err := json.Unmarshal(respBytes, &res); err != nil {
		return nil, err
	}
	
	return []byte(res.Result.Certificate), nil
}


func DeployWorker(ctx context.Context, cfg EdgeConfig, logger *ProvisionLogger) error {
	client := NewCFClient(cfg.CFToken)
	logger.Log("Verifying Cloudflare API Token...")
	if err := client.VerifyToken(ctx); err != nil {
		return err
	}

	scriptName := cfg.ScriptName
	if scriptName == "" {
		scriptName = "luminet-edge-relay"
	}

	camouflageHost := cfg.CamouflageHost
	if camouflageHost == "" {
		camouflageHost = "https://ubuntu.com"
	}
	if !strings.HasPrefix(camouflageHost, "http://") && !strings.HasPrefix(camouflageHost, "https://") {
		camouflageHost = "https://" + camouflageHost
	}

	var workerScript string
	if cfg.Type == "vless" {
		logger.Logf("Compiling serverless VLESS proxy worker script (UUID: %s, Camouflage: %s)...", cfg.UUID, camouflageHost)
		workerScript = fmt.Sprintf(`// Cloudflare Workers Serverless VLESS Proxy for LumiNet
// Target Platform: Cloudflare Workers edge runtime

const userID = "%s";
const camouflageHost = "%s";
const dbBindingName = "%s";

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  try {
    const url = new URL(request.url);
    if (url.pathname === '/sync/dash') {
      return new Response(getDashboardHTML(dbBindingName !== ""), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
    if (url.pathname === '/' || url.pathname === '/sync') {
      return fetch(camouflageHost);
    }

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader === 'websocket') {
      return await handleVLESS(request);
    }
    
    return new Response('LumiNet Serverless VLESS Proxy Online', { status: 200 });
  } catch (err) {
    return new Response(err.toString(), { status: 500 });
  }
}

async function handleVLESS(request) {
  const [client, server] = new WebSocketPair();
  server.accept();

  let isFirstPacket = true;
  let socket = null;
  let writer = null;
  const clientUUID = userID.replace(/-/g, '');

  server.addEventListener('message', async (event) => {
    try {
      const buffer = event.data;
      if (isFirstPacket) {
        isFirstPacket = false;
        
        if (buffer.byteLength < 18) {
          throw new Error('VLESS header too short');
        }

        const view = new DataView(buffer);
        const version = view.getUint8(0);
        if (version !== 0) {
          throw new Error('Unsupported VLESS version: ' + version);
        }

        const uuidHex = [...new Uint8Array(buffer.slice(1, 17))]
          .map(function(b) { return b.toString(16).padStart(2, '0'); })
          .join('');
        if (uuidHex !== clientUUID) {
          throw new Error('Unauthorized UUID');
        }

        const addonLen = view.getUint8(17);
        const commandOffset = 18 + addonLen;
        if (buffer.byteLength < commandOffset + 4) {
          throw new Error('Header truncated');
        }

        const command = view.getUint8(commandOffset);
        if (command !== 1) {
          throw new Error('Unsupported VLESS command: ' + command);
        }

        const port = view.getUint16(commandOffset + 1);
        const addrType = view.getUint8(commandOffset + 3);
        let addrOffset = commandOffset + 4;
        let hostname = '';

        if (addrType === 1) {
          if (buffer.byteLength < addrOffset + 4) throw new Error('IPv4 truncated');
          hostname = [...new Uint8Array(buffer.slice(addrOffset, addrOffset + 4))].join('.');
          addrOffset += 4;
        } else if (addrType === 2) {
          if (buffer.byteLength < addrOffset + 1) throw new Error('Domain length truncated');
          const domainLen = view.getUint8(addrOffset);
          addrOffset += 1;
          if (buffer.byteLength < addrOffset + domainLen) throw new Error('Domain truncated');
          hostname = new TextDecoder().decode(buffer.slice(addrOffset, addrOffset + domainLen));
          addrOffset += domainLen;
        } else if (addrType === 3) {
          if (buffer.byteLength < addrOffset + 16) throw new Error('IPv6 truncated');
          const ipv6Bytes = new Uint8Array(buffer.slice(addrOffset, addrOffset + 16));
          const groups = [];
          for (let i = 0; i < 16; i += 2) {
            groups.push(((ipv6Bytes[i] << 8) | ipv6Bytes[i + 1]).toString(16));
          }
          hostname = groups.join(':');
          addrOffset += 16;
        } else {
          throw new Error('Unsupported address type: ' + addrType);
        }

        const earlyData = buffer.slice(addrOffset);
        socket = connect({ hostname: hostname, port: port });
        writer = socket.writable.getWriter();

        if (earlyData.byteLength > 0) {
          await writer.write(earlyData);
        }

        server.send(new Uint8Array([0, 0]));

        const reader = socket.readable.getReader();
        (async () => {
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              server.send(value);
            }
          } catch (err) {
            console.error('Socket read error:', err);
          } finally {
            server.close();
          }
        })();
      } else {
        if (writer) {
          await writer.write(buffer);
        }
      }
    } catch (err) {
      console.error('VLESS error:', err);
      server.close(1011, err.message);
      if (socket) {
        try { socket.close(); } catch (e) {}
      }
    }
  });

  server.addEventListener('close', () => {
    if (socket) {
      try { socket.close(); } catch (e) {}
    }
  });

  server.addEventListener('error', () => {
    if (socket) {
      try { socket.close(); } catch (e) {}
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}
`, cfg.UUID, camouflageHost, cfg.D1DatabaseBinding) + "\n" + getDashboardHTMLJS()
	} else {
		logger.Logf("Compiling serverless worker script for relaying to %s:%d (Camouflage: %s)...", cfg.TargetHost, cfg.TargetPort, camouflageHost)

		workerScript = fmt.Sprintf(`// Cloudflare Workers VLESS/WebSocket Reverse Proxy Relay for LumiNet
// Target Platform: Cloudflare Workers edge runtime

const camouflageHost = "%s";
const dbBindingName = "%s";

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url);
  if (url.pathname === '/sync/dash') {
    return new Response(getDashboardHTML(dbBindingName !== ""), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
  if (url.pathname === '/' || url.pathname === '/sync') {
    return fetch(camouflageHost);
  }

  const upgradeHeader = request.headers.get('Upgrade');
  if (!upgradeHeader || upgradeHeader !== 'websocket') {
    return new Response('LumiNet Serverless Relay Online', { status: 200 });
  }

  const [client, server] = new WebSocketPair();
  server.accept();

  server.addEventListener('message', async (event) => {
    // Connect to target SOCKS5/Reality proxy server
    const targetHost = "%s";
    const targetPort = %d;
    
    try {
      const socket = connect({ hostname: targetHost, port: targetPort });
      const writer = socket.writable.getWriter();
      writer.write(event.data);
      
      const reader = socket.readable.getReader();
      (async () => {
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            server.send(value);
          }
        } catch (e) {
          console.error('Socket error:', e);
        } finally {
          server.close();
        }
      })();
    } catch (err) {
      server.close(1011, 'Failed to connect: ' + err.message);
    }
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}
`, camouflageHost, cfg.D1DatabaseBinding, cfg.TargetHost, cfg.TargetPort) + "\n" + getDashboardHTMLJS()
	}

	// Evasion tactic: append junk code to alter the SHA256 of the script on the fly
	workerScript += "\n" + generateJunkCode()

	var body []byte
	var contentType string
	var err error
	if cfg.D1DatabaseBinding != "" && cfg.D1DatabaseID != "" {
		logger.Logf("Constructing multipart upload with D1 Database Binding (%s -> %s)...", cfg.D1DatabaseBinding, cfg.D1DatabaseID)
		body, contentType, err = buildMultipartBody(workerScript, cfg.D1DatabaseBinding, cfg.D1DatabaseID)
		if err != nil {
			return fmt.Errorf("failed to build multipart body: %w", err)
		}
	} else {
		body = []byte(workerScript)
		contentType = "application/javascript"
	}

	logger.Logf("Uploading script %s to Cloudflare Workers...", scriptName)
	uploadURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s", cfg.CFAccountID, scriptName)
	_, err = client.doReq(ctx, "PUT", uploadURL, body, contentType)
	if err != nil {
		return fmt.Errorf("failed to upload worker script: %w", err)
	}

	logger.Log("Activating workers.dev subdomain route...")
	routeURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s/subdomain", cfg.CFAccountID, scriptName)
	subdomainPayload := map[string]interface{}{"enabled": true}
	subdomainBody, _ := json.Marshal(subdomainPayload)
	_, err = client.doReq(ctx, "POST", routeURL, subdomainBody, "application/json")
	if err != nil {
		// Log warning but don't fail, maybe subdomain is already active
		logger.Logf("Warning: subdomain activation returned: %v", err)
	}

	logger.Logf("Cloudflare Edge Worker %s deployed and active on workers.dev!", scriptName)
	return nil
}

func buildMultipartBody(scriptContent string, bindingName, databaseID string) ([]byte, string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// 1. Add metadata part
	metadataPartHeaders := make(textproto.MIMEHeader)
	metadataPartHeaders.Set("Content-Disposition", `form-data; name="metadata"`)
	metadataPartHeaders.Set("Content-Type", "application/json")
	metadataPart, err := writer.CreatePart(metadataPartHeaders)
	if err != nil {
		return nil, "", err
	}

	metadata := map[string]interface{}{
		"body_part": "script",
		"bindings": []map[string]interface{}{
			{
				"type":        "d1",
				"name":        bindingName,
				"database_id": databaseID,
			},
		},
	}

	metaBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, "", err
	}
	if _, err := metadataPart.Write(metaBytes); err != nil {
		return nil, "", err
	}

	// 2. Add script part
	scriptPartHeaders := make(textproto.MIMEHeader)
	scriptPartHeaders.Set("Content-Disposition", `form-data; name="script"; filename="index.js"`)
	scriptPartHeaders.Set("Content-Type", "application/javascript")
	scriptPart, err := writer.CreatePart(scriptPartHeaders)
	if err != nil {
		return nil, "", err
	}
	if _, err := scriptPart.Write([]byte(scriptContent)); err != nil {
		return nil, "", err
	}

	if err := writer.Close(); err != nil {
		return nil, "", err
	}

	return body.Bytes(), writer.FormDataContentType(), nil
}

func getDashboardHTMLJS() string {
	return `function getDashboardHTML(dbExists) {
  return [
    '<!DOCTYPE html>',
    '<html lang="fa" dir="rtl">',
    '<head>',
    '  <meta charset="UTF-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
    '  <title>LumiNet Edge Dashboard</title>',
    '  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Vazirmatn:wght@300;400;700&display=swap" rel="stylesheet">',
    '  <style>',
    '    :root {',
    '      --bg-color: #0b0b0f;',
    '      --card-bg: rgba(20, 20, 30, 0.7);',
    '      --primary: #6366f1;',
    '      --primary-hover: #4f46e5;',
    '      --text: #e2e8f0;',
    '      --text-muted: #94a3b8;',
    '      --border: rgba(255, 255, 255, 0.08);',
    '      --accent: #10b981;',
    '    }',
    '    * { box-sizing: border-box; margin: 0; padding: 0; }',
    '    body {',
    '      background-color: var(--bg-color);',
    '      color: var(--text);',
    '      font-family: \'Outfit\', \'Vazirmatn\', sans-serif;',
    '      min-height: 100vh;',
    '      display: flex;',
    '      flex-direction: column;',
    '      align-items: center;',
    '      padding: 40px 20px;',
    '    }',
    '    .container {',
    '      width: 100%;',
    '      max-width: 900px;',
    '    }',
    '    header {',
    '      display: flex;',
    '      justify-content: space-between;',
    '      align-items: center;',
    '      margin-bottom: 40px;',
    '      border-bottom: 1px solid var(--border);',
    '      padding-bottom: 20px;',
    '    }',
    '    h1 {',
    '      font-size: 28px;',
    '      font-weight: 800;',
    '      background: linear-gradient(135deg, #a5b4fc, var(--primary));',
    '      -webkit-background-clip: text;',
    '      -webkit-text-fill-color: transparent;',
    '    }',
    '    .lang-btn {',
    '      background: var(--card-bg);',
    '      border: 1px solid var(--border);',
    '      color: var(--text);',
    '      padding: 8px 16px;',
    '      border-radius: 8px;',
    '      cursor: pointer;',
    '      font-weight: 600;',
    '      transition: all 0.3s ease;',
    '    }',
    '    .lang-btn:hover {',
    '      background: var(--primary);',
    '      border-color: var(--primary);',
    '    }',
    '    .card {',
    '      background: var(--card-bg);',
    '      backdrop-filter: blur(16px);',
    '      border: 1px solid var(--border);',
    '      border-radius: 16px;',
    '      padding: 30px;',
    '      margin-bottom: 24px;',
    '      box-shadow: 0 8px 32px rgba(0,0,0,0.4);',
    '    }',
    '    .card-title {',
    '      font-size: 20px;',
    '      font-weight: 700;',
    '      margin-bottom: 20px;',
    '      display: flex;',
    '      align-items: center;',
    '      gap: 10px;',
    '    }',
    '    .status-badge {',
    '      display: inline-flex;',
    '      align-items: center;',
    '      gap: 6px;',
    '      background: rgba(16, 185, 129, 0.1);',
    '      color: var(--accent);',
    '      padding: 6px 12px;',
    '      border-radius: 9999px;',
    '      font-size: 14px;',
    '      font-weight: 600;',
    '    }',
    '    .status-dot {',
    '      width: 8px;',
    '      height: 8px;',
    '      background-color: var(--accent);',
    '      border-radius: 50%;',
    '      box-shadow: 0 0 12px var(--accent);',
    '    }',
    '    p {',
    '      color: var(--text-muted);',
    '      line-height: 1.6;',
    '      margin-bottom: 16px;',
    '    }',
    '    .grid {',
    '      display: grid;',
    '      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));',
    '      gap: 20px;',
    '      margin-top: 20px;',
    '    }',
    '    .stat-item {',
    '      background: rgba(255, 255, 255, 0.03);',
    '      border: 1px solid var(--border);',
    '      border-radius: 12px;',
    '      padding: 20px;',
    '      text-align: center;',
    '    }',
    '    .stat-value {',
    '      font-size: 24px;',
    '      font-weight: 800;',
    '      color: var(--primary);',
    '      margin-top: 8px;',
    '    }',
    '  </style>',
    '</head>',
    '<body>',
    '  <div class="container">',
    '    <header>',
    '      <h1 id="title-main">LumiNet Edge Node</h1>',
    '      <button class="lang-btn" id="lang-toggle" onclick="toggleLang()">EN</button>',
    '    </header>',
    '    ',
    '    <div class="card">',
    '      <div class="card-title">',
    '        <span id="title-status">Node Status</span>',
    '        <span class="status-badge"><span class="status-dot"></span><span id="badge-active">Active</span></span>',
    '      </div>',
    '      <p id="desc-node">This edge node is running successfully on Cloudflare Global Network. It intercepts proxy connections and redirects normal web requests.</p>',
    '      ',
    '      <div class="grid">',
    '        <div class="stat-item">',
    '          <div id="stat-storage-title">Storage Binding</div>',
    '          <div class="stat-value">' + (dbExists ? 'D1 (Active)' : 'Memory (Ephemeral)') + '</div>',
    '        </div>',
    '        <div class="stat-item">',
    '          <div id="stat-region-title">Active Edge Region</div>',
    '          <div class="stat-value">Global Anycast</div>',
    '        </div>',
    '      </div>',
    '    </div>',
    '  </div>',
    '  <script>',
    '    let currentLang = \'fa\';',
    '    const dict = {',
    '      en: {',
    '        titleMain: "LumiNet Edge Node",',
    '        titleStatus: "Node Status",',
    '        badgeActive: "Active",',
    '        descNode: "This edge node is running successfully on Cloudflare Global Network. It intercepts proxy connections and redirects normal web requests.",',
    '        statStorage: "Storage Binding",',
    '        statRegion: "Active Edge Region",',
    '      },',
    '      fa: {',
    '        titleMain: "گره لبه LumiNet",',
    '        titleStatus: "وضعیت گره",',
    '        badgeActive: "فعال",',
    '        descNode: "این گره لبه با موفقیت در شبکه جهانی کلودفلر در حال اجرا است. این گره اتصالات پروکسی را رهگیری کرده و درخواست‌های وب عادی را هدایت می‌کند.",',
    '        statStorage: "اتصال ذخیره‌سازی",',
    '        statRegion: "منطقه لبه فعال",',
    '      }',
    '    };',
    '    function toggleLang() {',
    '      currentLang = currentLang === \'fa\' ? \'en\' : \'fa\';',
    '      document.getElementById(\'lang-toggle\').innerText = currentLang === \'fa\' ? \'EN\' : \'FA\';',
    '      document.dir = currentLang === \'fa\' ? \'rtl\' : \'ltr\';',
    '      applyLang();',
    '    }',
    '    function applyLang() {',
    '      const data = dict[currentLang];',
    '      document.getElementById(\'title-main\').innerText = data.titleMain;',
    '      document.getElementById(\'title-status\').innerText = data.titleStatus;',
    '      document.getElementById(\'badge-active\').innerText = data.badgeActive;',
    '      document.getElementById(\'desc-node\').innerText = data.descNode;',
    '      document.getElementById(\'stat-storage-title\').innerText = data.statStorage;',
    '      document.getElementById(\'stat-region-title\').innerText = data.statRegion;',
    '    }',
    '    applyLang();',
    '  </script>',
    '</body>',
    '</html>\'',
  ].join(\'\n\');
}`
}

const charsetAlphaNumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func generateJunkCode() string {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	minVars, maxVars := 50, 500
	minFuncs, maxFuncs := 50, 500

	varCount := rng.Intn(maxVars-minVars+1) + minVars
	funcCount := rng.Intn(maxFuncs-minFuncs+1) + minFuncs

	var sb strings.Builder

	for i := 0; i < varCount; i++ {
		varName := fmt.Sprintf("__var_%s_%d", generateRandomString(charsetAlphaNumeric, 8), i)
		value := rng.Intn(100000)
		sb.WriteString(fmt.Sprintf("let %s = %d; ", varName, value))
	}

	for i := 0; i < funcCount; i++ {
		funcName := fmt.Sprintf("__Func_%s_%d", generateRandomString(charsetAlphaNumeric, 8), i)
		ret := rng.Intn(1000)
		sb.WriteString(fmt.Sprintf("function %s() { return %d; } ", funcName, ret))
	}

	return sb.String()
}

func generateRandomString(charSet string, length int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomBytes := make([]byte, length)

	for i := range randomBytes {
		randomBytes[i] = charSet[r.Intn(len(charSet))]
	}

	return string(randomBytes)
}


