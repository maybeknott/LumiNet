export interface CrawlSource {
  url: string;
  intervalSecs: number;
  lastCrawl: number;
  totalHarvested: number;
  enabled: boolean;
}

interface NodeBufferShim {
  Buffer?: {
    from(input: string, encoding: string): { toString(encoding: string): string };
  };
}

function nodeGlobalBuffer() {
  return (globalThis as NodeBufferShim).Buffer;
}

function decodeBase64Safe(input: string): string {
  try {
    if (typeof atob === 'function') {
      return atob(input);
    }
    const buf = nodeGlobalBuffer();
    if (buf) {
      return buf.from(input, 'base64').toString('utf-8');
    }
  } catch {
    // Return original string if base64 decoding fails
  }
  return input;
}

export class SubscriptionCrawlerPipeline {
  private sources: Map<string, CrawlSource> = new Map();
  private harvestedProxies: Set<string> = new Set();

  addSource(url: string, intervalSecs: number = 3600): void {
    this.sources.set(url, {
      url,
      intervalSecs: Math.max(60, intervalSecs),
      lastCrawl: 0,
      totalHarvested: 0,
      enabled: true,
    });
  }

  dispatchPendingSources(currentTime: number): string[] {
    const toCrawl: string[] = [];
    for (const source of this.sources.values()) {
      if (
        source.enabled &&
        (source.lastCrawl === 0 || currentTime >= source.lastCrawl + source.intervalSecs)
      ) {
        source.lastCrawl = currentTime;
        toCrawl.push(source.url);
      }
    }
    return toCrawl;
  }

  ingestCrawlContent(sourceUrl: string, rawContent: string): number {
    let count = 0;
    const contentTrimmed = rawContent.trim();

    let decodedText = contentTrimmed;
    const possibleDecoded = decodeBase64Safe(contentTrimmed);
    if (possibleDecoded !== contentTrimmed && (
      possibleDecoded.includes('://') || possibleDecoded.includes('\n')
    )) {
      decodedText = possibleDecoded;
    }

    const lines = decodedText.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (
        trimmed.startsWith('ss://') ||
        trimmed.startsWith('vmess://') ||
        trimmed.startsWith('vless://') ||
        trimmed.startsWith('trojan://') ||
        trimmed.startsWith('hysteria2://') ||
        trimmed.startsWith('tuic://')
      ) {
        if (!this.harvestedProxies.has(trimmed)) {
          this.harvestedProxies.add(trimmed);
          count++;
        }
      }
    }

    const source = this.sources.get(sourceUrl);
    if (source) {
      source.totalHarvested += count;
    }

    return count;
  }

  getHarvestedProxies(): string[] {
    return Array.from(this.harvestedProxies).sort();
  }

  totalHarvestedCount(): number {
    return this.harvestedProxies.size;
  }
}
