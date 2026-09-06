// Control UI TypeScript: On-Device DPI Evasion API

export class OnDeviceDpiEvader {
  public defaultSplitOffset: number;
  public evadedCount: number = 0;

  constructor(defaultSplitOffset: number = 2) {
    this.defaultSplitOffset = defaultSplitOffset;
  }

  public applySniSplit(clientHello: Uint8Array, splitOffset: number): Uint8Array[] {
    this.evadedCount++;
    if (clientHello.length < 5 || clientHello[0] !== 0x16) {
      return [clientHello];
    }
    const pos = Math.max(1, Math.min(splitOffset, clientHello.length - 1));
    return [clientHello.slice(0, pos), clientHello.slice(pos)];
  }

  public applyHttpDesync(request: Uint8Array): Uint8Array {
    this.evadedCount++;
    const str = new TextDecoder().decode(request);
    const lines = str.split('\r\n');
    const desynced = lines.map((line) => {
      if (line.toLowerCase().startsWith('host:')) {
        const parts = line.split(':');
        if (parts.length >= 2) {
          return `hOst: ${parts.slice(1).join(':').trim()}`;
        }
      }
      return line;
    });
    return new TextEncoder().encode(desynced.join('\r\n'));
  }

  public generateOutOfOrderChunks(data: Uint8Array, chunkSize: number): Uint8Array[] {
    this.evadedCount++;
    const size = Math.max(1, chunkSize);
    const chunks: Uint8Array[] = [];
    let offset = 0;

    while (offset < data.length) {
      const end = Math.min(offset + size, data.length);
      chunks.push(data.slice(offset, end));
      offset = end;
    }

    if (chunks.length > 1) {
      const temp = chunks[0];
      chunks[0] = chunks[1]!;
      chunks[1] = temp!;
    }
    return chunks;
  }

  public craftTtlDecoyPair(
    realPayload: Uint8Array,
    decoyTtl: number,
  ): {
    decoy: { ttl: number; payload: Uint8Array };
    real: { ttl: number; payload: Uint8Array };
  } {
    this.evadedCount++;
    const decoy = new Uint8Array(realPayload.length);
    for (let i = 0; i < realPayload.length; i++) {
      decoy[i] = realPayload[i]! ^ 0x55;
    }
    return {
      decoy: { ttl: decoyTtl, payload: decoy },
      real: { ttl: 64, payload: realPayload },
    };
  }
}
