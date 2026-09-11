import { MasqueDatagramTunnel } from './masque_datagram_tunnel.js';
import type { AmneziaObfsConfig } from './amnezia_obfs_parameters.js';

export class MasqueAmneziaHybridTunnel {
  private masque: MasqueDatagramTunnel;
  public contextId: number;
  public amneziaConfig: AmneziaObfsConfig;
  constructor(contextId: number, amneziaConfig: AmneziaObfsConfig) {
    this.contextId = contextId;
    this.amneziaConfig = amneziaConfig;
    this.masque = new MasqueDatagramTunnel(contextId);
  }

  generateHandshakePreamble(initPayload: Uint8Array): Uint8Array[] {
    const packets: Uint8Array[] = [];

    // 1. Generate Jc junk packets
    for (let i = 0; i < this.amneziaConfig.jc; i++) {
      const span = this.amneziaConfig.jmax - this.amneziaConfig.jmin;
      const junkLen = this.amneziaConfig.jmin + (span > 0 ? Math.floor(Math.random() * span) : 0);
      const junk = new Uint8Array(junkLen);
      for (let j = 0; j < junkLen; j++) {
        junk[j] = Math.floor(Math.random() * 256);
      }
      packets.push(junk);
    }

    // 2. Wrap initiation with H1 header and S1 padding
    const totalLen = 4 + initPayload.length + this.amneziaConfig.s1;
    const frame = new Uint8Array(totalLen);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    view.setUint32(0, this.amneziaConfig.h1 >>> 0);
    frame.set(initPayload, 4);

    if (this.amneziaConfig.s1 > 0) {
      for (let i = 0; i < this.amneziaConfig.s1; i++) {
        frame[4 + initPayload.length + i] = Math.floor(Math.random() * 256);
      }
    }

    const capsule = this.masque.encodeDatagram(frame);
    packets.push(capsule);
    return packets;
  }

  encapsulateData(ipPacket: Uint8Array): Uint8Array {
    const frame = new Uint8Array(4 + ipPacket.length);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    view.setUint32(0, this.amneziaConfig.h4 >>> 0);
    frame.set(ipPacket, 4);
    return this.masque.encodeDatagram(frame);
  }

  decapsulateData(capsule: Uint8Array): Uint8Array | null {
    const res = this.masque.decodeDatagram(capsule);
    if (!res) return null;
    const { contextId, payload } = res;
    if (contextId !== this.contextId || payload.length < 4) return null;

    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    const h = view.getUint32(0);
    if (h !== this.amneziaConfig.h4 >>> 0) return null;

    return payload.slice(4);
  }
}
