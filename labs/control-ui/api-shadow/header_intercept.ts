export interface InterceptRule {
  headerName: string;
  headerValueExact: string;
  targetLocalAddress: string;
}

export class HeaderInterceptRouter {
  private readonly rules: InterceptRule[] = [];

  public addRule(name: string, val: string, target: string): void {
    this.rules.push({
      headerName: name.toLowerCase(),
      headerValueExact: val,
      targetLocalAddress: target
    });
  }

  public evaluateHeaders(headers: Record<string, string>): string | null {
    for (const rule of this.rules) {
      for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === rule.headerName && v === rule.headerValueExact) {
          return rule.targetLocalAddress;
        }
      }
    }
    return null;
  }
}
