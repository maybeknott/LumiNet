export class PeerAclMatrix {
  private readonly acl = new Map<string, Map<string, boolean>>();
  private readonly defaultAllow: boolean;
  constructor(defaultAllow: boolean = true) {
    this.defaultAllow = defaultAllow;
  }

  public setRule(source: string, target: string, allowed: boolean): void {
    let row = this.acl.get(source);
    if (!row) {
      row = new Map();
      this.acl.set(source, row);
    }
    row.set(target, allowed);
  }

  public isAllowed(source: string, target: string): boolean {
    const row = this.acl.get(source);
    if (row && row.has(target)) {
      return row.get(target)!;
    }
    return this.defaultAllow;
  }
}
