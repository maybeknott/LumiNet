export class TcpChunkSplitter {
  public static splitBytes(data: Uint8Array, chunkSize: number): Uint8Array[] {
    if (chunkSize <= 0 || data.length === 0) return [data];
    const chunks: Uint8Array[] = [];
    for (let offset = 0; offset < data.length; offset += chunkSize) {
      const end = Math.min(data.length, offset + chunkSize);
      chunks.push(data.slice(offset, end));
    }
    return chunks;
  }

  public static mutateHeaderCase(headerLine: string): string {
    const idx = headerLine.indexOf(':');
    if (idx === -1) return headerLine;
    const key = headerLine.slice(0, idx);
    const rest = headerLine.slice(idx);
    let mutated = '';
    for (let i = 0; i < key.length; i++) {
      const c = key[i] ?? '';
      mutated += (i % 2 === 0) ? c.toLowerCase() : c.toUpperCase();
    }
    return mutated + rest;
  }
}
