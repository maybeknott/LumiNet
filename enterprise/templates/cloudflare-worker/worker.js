/**
 * LumiNet Cloudflare Worker Proxy Template
 *
 * Implements VLESS over WebSockets utilizing the native cloudflare connect() TCP API.
 * Encapsulates network payloads in secure edge isolates with zero-trust routing.
 *
 * Deployment:
 * 1. Generate a secure UUID.
 * 2. Set the `UUID` variable or define it as a Worker Environment Variable.
 * 3. Deploy via Wrangler or the Cloudflare Dashboard.
 */

import { connect } from 'cloudflare:sockets';

const DEFAULT_UUID = 'your-secure-uuid-here';

export default {
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        // Return decoy landing page for standard web requests
        return new Response('LumiNet Edge Node Status: Operational', {
          status: 200,
          headers: { 'Content-Type': 'text/plain' },
        });
      }

      const webSocketPair = new WebSocketPair();
      const [client, server] = Object.values(webSocketPair);

      await handleWebSocketConnection(server, request, env);

      return new Response(null, {
        status: 101,
        webSocketStatus: 'switching-protocols',
        headers: { Upgrade: 'websocket' },
        webSocket: client,
      });
    } catch (err) {
      return new Response(`Edge Socket Error: ${err.message}`, { status: 500 });
    }
  },
};

async function handleWebSocketConnection(webSocket, request, env) {
  webSocket.accept();

  const userUUID = env.UUID || DEFAULT_UUID;
  let remoteSocket = null;
  let parsedHeader = false;

  webSocket.addEventListener('message', async (event) => {
    try {
      const messageData = event.data;
      if (typeof messageData === 'string') {
        webSocket.close(1003, 'Unsupported string payload format');
        return;
      }

      const buffer = new Uint8Array(messageData);

      if (!parsedHeader) {
        // Parse VLESS Header
        // Byte 0: Protocol Version
        // Bytes 1-16: UUID
        // Byte 17: Addr Type (1: IPv4, 2: Domain, 3: IPv6)
        // Subsequent bytes: Port and Address payload
        if (buffer.length < 18) {
          webSocket.close(1002, 'VLESS Header length mismatch');
          return;
        }

        const version = buffer[0];
        const uuidBytes = buffer.slice(1, 17);
        const uuidStr = bytesToUUID(uuidBytes);

        if (uuidStr !== userUUID) {
          webSocket.close(1008, 'Unauthorized UUID validation failed');
          return;
        }

        const addressType = buffer[17];
        let offset = 18;
        let address = '';

        if (addressType === 1) {
          // IPv4 (4 bytes)
          address = buffer.slice(offset, offset + 4).join('.');
          offset += 4;
        } else if (addressType === 2) {
          // Domain Name (Length prefixed)
          const domainLen = buffer[offset];
          offset += 1;
          address = new TextDecoder().decode(buffer.slice(offset, offset + domainLen));
          offset += domainLen;
        } else if (addressType === 3) {
          // IPv6 (16 bytes)
          const ipv6Bytes = buffer.slice(offset, offset + 16);
          address = bytesToIPv6(ipv6Bytes);
          offset += 16;
        } else {
          webSocket.close(1002, 'Unsupported address family type');
          return;
        }

        const port = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        // Dial remote server via Cloudflare connect()
        remoteSocket = connect({ hostname: address, port: port });
        const writer = remoteSocket.writable.getWriter();

        // Write VLESS Handshake response (Version + Metadata length 0)
        webSocket.send(new Uint8Array([version, 0]));

        // Write remaining WebSocket buffer to remote TCP connection
        if (buffer.length > offset) {
          const remainingData = buffer.slice(offset);
          await writer.write(remainingData);
        }
        writer.releaseLock();

        // Start bidirectional piping
        parsedHeader = true;
        pipeRemoteToWebSocket(remoteSocket, webSocket);
      } else {
        // Pipe ongoing client WebSocket data to target TCP write stream
        if (remoteSocket) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(buffer);
          writer.releaseLock();
        }
      }
    } catch (err) {
      webSocket.close(1011, `Relay Error: ${err.message}`);
    }
  });

  webSocket.addEventListener('close', () => {
    if (remoteSocket) remoteSocket.close();
  });

  webSocket.addEventListener('error', () => {
    if (remoteSocket) remoteSocket.close();
  });
}

async function pipeRemoteToWebSocket(remoteSocket, webSocket) {
  try {
    const reader = remoteSocket.readable.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      webSocket.send(value);
    }
  } catch (err) {
    webSocket.close(1011, `Upstream stream pipe error: ${err.message}`);
  } finally {
    if (remoteSocket) remoteSocket.close();
  }
}

function bytesToUUID(bytes) {
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

function bytesToIPv6(bytes) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return parts.join(':');
}
