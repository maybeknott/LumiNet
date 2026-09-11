// Control UI TypeScript: Mesh SOCKS5 Exit Bridge API

export type Socks5RouteDisposition = 'direct' | 'mesh_exit' | 'blocked';

export interface MeshExitNode {
  nodeId: string;
  virtualIp: string;
  active: boolean;
}

export class MeshSocks5Bridge {
  public listenPort: number;
  public exitNode: MeshExitNode | null = null;
  public credentials: Map<string, string> = new Map();

  constructor(listenPort: number) {
    this.listenPort = listenPort;
  }

  public setExitNode(node: MeshExitNode): void {
    this.exitNode = node;
  }

  public addUser(user: string, pass: string): void {
    this.credentials.set(user, pass);
  }

  public authenticate(user: string, pass: string): boolean {
    if (this.credentials.size === 0) return true;
    return this.credentials.get(user) === pass;
  }

  public evaluateRoute(
    host: string,
    port: number,
  ): { disposition: Socks5RouteDisposition; targetIp: string | null } {
    if (port <= 0 || port > 65535) return { disposition: 'blocked', targetIp: null };
    if (host === 'localhost' || host === '127.0.0.1')
      return { disposition: 'direct', targetIp: null };

    if (this.exitNode && this.exitNode.active) {
      return { disposition: 'mesh_exit', targetIp: this.exitNode.virtualIp };
    }
    return { disposition: 'direct', targetIp: null };
  }

  public parseGreeting(data: Uint8Array): number {
    if (data.length < 2 || data[0] !== 0x05) return 0xff;
    const nmethods = data[1]!;
    if (data.length < 2 + nmethods) return 0xff;

    const methods = Array.from(data.slice(2, 2 + nmethods));
    if (this.credentials.size === 0) {
      return methods.includes(0x00) ? 0x00 : 0xff;
    }
    return methods.includes(0x02) ? 0x02 : 0xff;
  }

  public craftReply(repCode: number, bindIp: string, bindPort: number): Uint8Array {
    const reply = [0x05, repCode, 0x00, 0x01];
    const octets = bindIp.split('.').map((o) => parseInt(o, 10));
    reply.push(...octets);
    reply.push((bindPort >> 8) & 0xff, bindPort & 0xff);
    return new Uint8Array(reply);
  }
}
