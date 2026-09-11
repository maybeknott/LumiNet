export interface ClashProxyNode {
  name: string;
  type: string;
  server: string;
  port: number;
  uuid: string;
}

export interface ClashProxyGroupDef {
  name: string;
  type: string;
  proxies: string[];
}

export class ClashSynthesizer {
  private nodes: ClashProxyNode[] = [];
  private groups: ClashProxyGroupDef[] = [];
  public mixedPort: number;
  constructor(mixedPort: number = 7890) {
    this.mixedPort = mixedPort;
  }

  addNode(node: ClashProxyNode): void {
    this.nodes.push(node);
  }

  addGroup(group: ClashProxyGroupDef): void {
    this.groups.push(group);
  }

  synthesizeYaml(): string {
    let yaml = `mixed-port: ${this.mixedPort}\nmode: rule\n\nproxies:\n`;
    for (const n of this.nodes) {
      yaml += `  - name: "${n.name}"\n    type: ${n.type}\n    server: ${n.server}\n    port: ${n.port}\n    uuid: ${n.uuid}\n`;
    }
    yaml += `\nproxy-groups:\n`;
    for (const g of this.groups) {
      yaml += `  - name: "${g.name}"\n    type: ${g.type}\n    proxies:\n`;
      for (const p of g.proxies) {
        yaml += `      - "${p}"\n`;
      }
    }
    return yaml;
  }
}
