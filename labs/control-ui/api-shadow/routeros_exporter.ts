export class RouterOsExporter {
  public entries: string[] = [];

  addEntry(entry: string): void {
    const clean = entry.trim();
    if (clean) this.entries.push(clean);
  }

  exportAddressList(listName: string): string {
    let script = '/ip firewall address-list\n';
    for (const e of this.entries) {
      script += `add list=${listName} address=${e} comment="LumiNet auto"\n`;
    }
    return script;
  }
}
