export type RewriteAction =
  | { type: 'redirect_url'; newUrl: string }
  | { type: 'set_header'; name: string; value: string }
  | { type: 'remove_header'; name: string }
  | { type: 'replace_body'; pattern: string; replacement: string };

export interface RewriteRule {
  ruleId: string;
  domainPattern: string;
  pathPrefix: string;
  isActive: boolean;
  action: RewriteAction;
}

export class MitmTrafficRewriter {
  private rules: RewriteRule[] = [];
  public totalMutations = 0;

  addRule(rule: RewriteRule): void {
    this.rules.push(rule);
  }

  matchRule(domain: string, path: string): RewriteRule | undefined {
    const domLower = domain.toLowerCase();
    return this.rules.find((r) => {
      if (!r.isActive) return false;
      const match =
        r.domainPattern === '*'
          ? true
          : r.domainPattern.startsWith('*.')
          ? domLower.endsWith(r.domainPattern.slice(2))
          : domLower === r.domainPattern.toLowerCase();
      return match && path.startsWith(r.pathPrefix);
    });
  }

  rewriteRequest(domain: string, path: string, headers: Record<string, string>): { path: string; action?: RewriteAction } {
    const rule = this.matchRule(domain, path);
    if (!rule) return { path };

    this.totalMutations++;
    let newPath = path;

    if (rule.action.type === 'redirect_url') {
      newPath = rule.action.newUrl;
    } else if (rule.action.type === 'set_header') {
      headers[rule.action.name] = rule.action.value;
    } else if (rule.action.type === 'remove_header') {
      delete headers[rule.action.name];
    }
    return { path: newPath, action: rule.action };
  }

  rewriteResponseBody(domain: string, path: string, body: Uint8Array): Uint8Array {
    const rule = this.matchRule(domain, path);
    if (rule && rule.action.type === 'replace_body') {
      const text = new TextDecoder().decode(body);
      if (text.includes(rule.action.pattern)) {
        this.totalMutations++;
        return new TextEncoder().encode(text.replaceAll(rule.action.pattern, rule.action.replacement));
      }
    }
    return body;
  }
}
