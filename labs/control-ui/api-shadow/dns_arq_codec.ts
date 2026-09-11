export interface DnsArqMessageUI {
  seq: number;
  isLast: boolean;
  data: string;
}

export class DnsArqCodecUI {
  public readonly rootDomain: string;
  constructor(rootDomain: string) {
    this.rootDomain = rootDomain;
  }

  formatLabel(seq: number, isLast: boolean, payloadHex: string): string {
    const flag = isLast ? '1' : '0';
    return `arq-${seq}-${flag}-${payloadHex}.${this.rootDomain}`;
  }

  parseLabel(query: string): DnsArqMessageUI | null {
    if (!query.endsWith(`.${this.rootDomain}`)) return null;
    const label = query.slice(0, -(this.rootDomain.length + 1));
    const parts = label.split('-');
    if (parts.length !== 4 || parts[0] !== 'arq') return null;

    const seq = parseInt(parts[1]!, 10);
    const isLast = parts[2] === '1';
    return { seq, isLast, data: parts[3]! };
  }
}
