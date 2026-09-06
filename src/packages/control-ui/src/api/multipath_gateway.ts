export interface EgressLinkUI {
  id: string;
  rttMs: number;
  active: boolean;
  sentBytes: number;
}

export class MultipathGatewayUI {
  private links = new Map<string, EgressLinkUI>();
  private order: string[] = [];
  private cursor = 0;

  register(link: EgressLinkUI): void {
    if (!this.links.has(link.id)) {
      this.order.push(link.id);
    }
    this.links.set(link.id, { ...link });
  }

  routePacket(bytes: number): string | null {
    const active = this.order.filter((id) => this.links.get(id)?.active);
    if (active.length === 0) return null;
    const picked = active[this.cursor % active.length];
    this.cursor++;
    const link = this.links.get(picked!)!;
    if (link) link.sentBytes += bytes;
    return picked!;
  }

  setActive(id: string, active: boolean): void {
    const link = this.links.get(id);
    if (link) link.active = active;
  }
}
