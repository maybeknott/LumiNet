export type ControlProbeCategory = 'HOST_HEADER' | 'PATH_KEYWORD' | 'SNI_PATTERN' | 'DNS_QUERY_NAME';

export interface ControlTriggerProbeSpec {
  category: ControlProbeCategory;
  payloadString: string;
  expectedBlockMechanism: string;
}

export class CensorshipTriggerGenerator {
  private triggers: ControlTriggerProbeSpec[] = [];

  constructor() {
    this.populateDefaultTriggers();
  }

  private populateDefaultTriggers(): void {
    this.triggers.push(
      {
        category: 'SNI_PATTERN',
        payloadString: 'zh.wikipedia.org',
        expectedBlockMechanism: 'SNI_RST',
      },
      {
        category: 'HOST_HEADER',
        payloadString: 'Host: epochtimes.com\r\n',
        expectedBlockMechanism: 'HTTP_RESET',
      },
      {
        category: 'DNS_QUERY_NAME',
        payloadString: 'www.youtube.com',
        expectedBlockMechanism: 'DNS_POISON',
      },
      {
        category: 'PATH_KEYWORD',
        payloadString: '/search?q=falun',
        expectedBlockMechanism: 'HTTP_KEYWORD_RST',
      }
    );
  }

  addCustomTrigger(category: ControlProbeCategory, payload: string, mechanism: string): void {
    this.triggers.push({
      category,
      payloadString: payload,
      expectedBlockMechanism: mechanism,
    });
  }

  generateHttpProbe(targetHost: string, path: string): Uint8Array {
    const req = `GET ${path} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: LumiProbe/1.0\r\nConnection: close\r\n\r\n`;
    return new TextEncoder().encode(req);
  }

  getProbesByCategory(category: ControlProbeCategory): ControlTriggerProbeSpec[] {
    return this.triggers.filter((t) => t.category === category);
  }

  totalProbes(): number {
    return this.triggers.length;
  }
}
