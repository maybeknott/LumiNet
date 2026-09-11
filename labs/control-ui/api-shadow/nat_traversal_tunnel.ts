// Control UI TypeScript: NAT Traversal & Hole Punching API

export type NatType = 'open_internet' | 'full_cone' | 'restricted_cone' | 'port_restricted_cone' | 'symmetric';
export type PunchState = 'initial' | 'probing' | 'established' | 'fallback_relay';

export interface PeerCandidate {
  peerId: string;
  localEndpoint: string;
  reflexiveEndpoint: string;
  natType: NatType;
}

export class NatTraversalTunnel {
  public localPeerId: string;
  public localNat: NatType;
  public peers: Map<string, PunchState> = new Map();
  public readonly magic: number = 0x564E5431; // "VNT1"

  constructor(localPeerId: string, localNat: NatType) {
    this.localPeerId = localPeerId;
    this.localNat = localNat;
  }

  public canDirectPunch(a: NatType, b: NatType): boolean {
    if (a === 'symmetric' && b === 'symmetric') return false;
    if ((a === 'port_restricted_cone' && b === 'symmetric') ||
        (a === 'symmetric' && b === 'port_restricted_cone')) return false;
    return true;
  }

  public craftPunchPacket(seq: number): Uint8Array {
    const idBytes = new TextEncoder().encode(this.localPeerId);
    const packet = new Uint8Array(10 + idBytes.length);
    const view = new DataView(packet.buffer);

    view.setUint32(0, this.magic);
    view.setUint32(4, seq);
    view.setUint16(8, idBytes.length);
    packet.set(idBytes, 10);
    return packet;
  }

  public parsePunchPacket(data: Uint8Array): { sequence: number; peerId: string } | null {
    if (data.length < 10) return null;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    if (view.getUint32(0) !== this.magic) return null;

    const sequence = view.getUint32(4);
    const idLen = view.getUint16(8);
    if (data.length < 10 + idLen) return null;

    const peerId = new TextDecoder().decode(data.slice(10, 10 + idLen));
    return { sequence, peerId };
  }

  public initiatePeerPunch(candidate: PeerCandidate): PunchState {
    const state: PunchState = this.canDirectPunch(this.localNat, candidate.natType)
      ? 'probing'
      : 'fallback_relay';

    this.peers.set(candidate.peerId, state);
    return state;
  }

  public markEstablished(peerId: string): boolean {
    if (this.peers.has(peerId)) {
      this.peers.set(peerId, 'established');
      return true;
    }
    return false;
  }
}
