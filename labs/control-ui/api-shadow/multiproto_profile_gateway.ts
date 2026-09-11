import { UiClientProtocol } from './protocol_profile_orchestrator.js';
import { OvpnConfigTranspiler } from './ovpn_config_transpiler.js';
import { PublicRelayAggregator } from './public_relay_aggregator.js';
import type { UiRelayNode } from './public_relay_aggregator.js';

export interface UiGatewayEndpoint {
  endpointId: string;
  protocol: UiClientProtocol;
  host: string;
  port: number;
  pingMs: number;
  isHealthy: boolean;
}

export class MultiprotoProfileGateway {
  private endpoints: Map<string, UiGatewayEndpoint> = new Map();
  private failoverChain: string[] = [];
  private transpiler = new OvpnConfigTranspiler();
  private relayAggregator = new PublicRelayAggregator();

  registerEndpoint(ep: UiGatewayEndpoint): void {
    this.endpoints.set(ep.endpointId, ep);
  }

  setFailoverChain(chain: string[]): void {
    this.failoverChain = chain;
  }

  resolveActiveRoute(): UiGatewayEndpoint | null {
    for (const id of this.failoverChain) {
      const ep = this.endpoints.get(id);
      if (ep && ep.isHealthy) {
        return ep;
      }
    }
    for (const ep of this.endpoints.values()) {
      if (ep.isHealthy) return ep;
    }
    return null;
  }

  importRelays(relays: UiRelayNode[]): void {
    for (const r of relays) {
      this.relayAggregator.ingestNode(r);
      let proto: UiClientProtocol = UiClientProtocol.Masque;
      const lower = r.protocol.toLowerCase();
      if (lower === 'shadowsocks') {
        proto = UiClientProtocol.Shadowsocks2022;
      } else if (lower === 'vless') {
        proto = UiClientProtocol.Vless;
      } else if (lower === 'wireguard') {
        proto = UiClientProtocol.AmneziaWg;
      }

      this.registerEndpoint({
        endpointId: r.nodeId,
        protocol: proto,
        host: r.host,
        port: r.port,
        pingMs: r.pingMs,
        isHealthy: r.isAlive ?? true,
      });
    }
  }

  transpileAndRegisterOvpn(endpointId: string, rawOvpn: string): UiGatewayEndpoint | null {
    const parsed = this.transpiler.transpile(rawOvpn);
    if (!parsed) return null;

    const ep: UiGatewayEndpoint = {
      endpointId,
      protocol: UiClientProtocol.AmneziaWg,
      host: parsed.remoteHost,
      port: parsed.remotePort,
      pingMs: 50,
      isHealthy: true,
    };
    this.registerEndpoint(ep);
    return ep;
  }
}
