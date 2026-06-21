// docs/ports/serverless_worker.js
// Cloudflare Workers VLESS/WebSocket Reverse Proxy Relay for LumiNet
// Target Platform: Cloudflare Workers edge runtime

export default {
  async fetch(request, env) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('LumiNet Serverless Relay Online', { status: 200 });
    }

    const [client, server] = new WebSocketPair();
    server.accept();

    server.addEventListener('message', async (event) => {
      // Connect to target TCP server specified in headers
      const targetHost = request.headers.get('X-Target-Host');
      const targetPort = request.headers.get('X-Target-Port');
      
      if (!targetHost || !targetPort) {
        server.close(1008, 'Missing Target Host or Port headers');
        return;
      }

      try {
        // Use Cloudflare Workers connect() socket API
        const socket = connect({ hostname: targetHost, port: parseInt(targetPort) });
        const writer = socket.writable.getWriter();
        
        // Pipe incoming websocket data directly to target socket
        writer.write(event.data);
        
        // Pipe response from target socket back to websocket
        const reader = socket.readable.getReader();
        (async () => {
          try {
            while (true) {
              const { value, done } = await reader.read();
              if (done) break;
              server.send(value);
            }
          } catch (e) {
            console.error('Error reading from socket:', e);
          } finally {
            server.close();
          }
        })();
      } catch (err) {
        server.close(1011, `Failed to connect to target: ${err.message}`);
      }
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }
};
