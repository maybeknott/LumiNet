#!/bin/bash
# -----------------------------------------------------------------------------
# LumiNet Render VLESS/WebSocket Proxy Deployment Automation
# -----------------------------------------------------------------------------
# This script automates packaging and preparing a standard VLESS over WebSocket
# service wrapper designed to run on free-tier Render or Railway web services.
# -----------------------------------------------------------------------------

set -e

APP_PORT=${PORT:-8080}
OUTPUT_DIR="./dist_render"

echo "=== LumiNet Deployment Packager ==="
echo "Target Port: $APP_PORT"
echo "Creating staging directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Write package.json for Node.js runtime environment
cat <<EOF > "$OUTPUT_DIR/package.json"
{
  "name": "luminet-vless-render-relay",
  "version": "1.0.0",
  "description": "Standard VLESS/WebSocket relay for LumiNet edge routing",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "ws": "^8.16.0"
  }
}
EOF

# Write standard WebSocket proxy relay index.js
cat <<EOF > "$OUTPUT_DIR/index.js"
const http = require('http');
const { WebSocketServer } = require('ws');
const net = require('net');

const PORT = process.env.PORT || 8080;
const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('LumiNet Edge Node Active\n');
});

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
    console.log('New connection from:', req.socket.remoteAddress);
    let targetSocket = null;

    ws.on('message', (message) => {
        // First message handles structural destination mapping
        if (!targetSocket) {
            try {
                const meta = JSON.parse(message.toString());
                const targetHost = meta.host;
                const targetPort = parseInt(meta.port, 10);

                console.log(\`Relaying connection to \${targetHost}:\${targetPort}\`);
                targetSocket = net.connect({ host: targetHost, port: targetPort }, () => {
                    ws.send(JSON.stringify({ status: 'connected' }));
                });

                targetSocket.on('data', (data) => {
                    if (ws.readyState === ws.OPEN) {
                        ws.send(data);
                    }
                });

                targetSocket.on('close', () => {
                    ws.close();
                });

                targetSocket.on('error', (err) => {
                    console.error('Target socket error:', err.message);
                    ws.close();
                });

            } catch (err) {
                console.error('Failed to parse metadata message:', err.message);
                ws.close();
            }
        } else {
            // Forward raw data bytes to the reassembled target socket
            targetSocket.write(message);
        }
    });

    ws.on('close', () => {
        if (targetSocket) {
            targetSocket.end();
        }
        console.log('Connection closed');
    });
});

server.listen(PORT, () => {
    console.log(\`Server is listening on port \${PORT}\`);
});
EOF

echo "✓ Packaged successfully in $OUTPUT_DIR"
echo "Instructions to deploy:"
echo "1. Initialize a git repository inside $OUTPUT_DIR"
echo "2. Push it to a new private repository on GitHub."
echo "3. Connect the repository to Render (Web Service) or Railway."
echo "4. Set the build command to 'npm install' and start command to 'npm start'."
echo "5. Configure your LumiNet client with the service URL."
echo "====================================="
