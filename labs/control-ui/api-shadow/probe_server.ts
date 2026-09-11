export interface ProbeResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export class EmbeddedProbeServer {
  private authHeader: string | null = null;
  private payloads: Map<string, Uint8Array> = new Map();
  public host: string;
  public port: number;
  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
  }

  setAuth(user: string, pass: string): void {
    this.authHeader = `Basic ${user}:${pass}`;
  }

  registerPayload(path: string, data: Uint8Array): void {
    this.payloads.set(path, data);
  }

  handleRequest(path: string, auth?: string, range?: string): ProbeResponse {
    const headers: Record<string, string> = { Server: 'LumiProbe-TS/1.0' };

    if (this.authHeader && auth !== this.authHeader) {
      headers['WWW-Authenticate'] = 'Basic realm="LumiProbe"';
      return {
        statusCode: 401,
        headers,
        body: new TextEncoder().encode('Unauthorized'),
      };
    }

    if (path === '/health' || path === '/ping') {
      headers['Content-Type'] = 'text/plain';
      return {
        statusCode: 200,
        headers,
        body: new TextEncoder().encode('OK'),
      };
    }

    const payload = this.payloads.get(path);
    if (payload) {
      headers['Content-Type'] = 'application/octet-stream';
      if (range && range.startsWith('bytes=')) {
        const parts = range.replace('bytes=', '').split('-');
        if (parts.length === 2) {
          const start = parseInt(parts[0]!, 10) || 0;
          const end = Math.min(parseInt(parts[1]!, 10) || payload.length - 1, payload.length - 1);
          if (start <= end && start < payload.length) {
            const slice = payload.slice(start, end + 1);
            headers['Content-Range'] = `bytes ${start}-${end}/${payload.length}`;
            headers['Content-Length'] = slice.length.toString();
            return { statusCode: 206, headers, body: slice };
          }
        }
      }

      headers['Content-Length'] = payload.length.toString();
      return { statusCode: 200, headers, body: payload };
    }

    return {
      statusCode: 404,
      headers,
      body: new TextEncoder().encode('Not Found'),
    };
  }
}
