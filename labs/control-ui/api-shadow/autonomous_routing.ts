import { PacScriptCompiler } from './pac_compiler.js';
import { AutoProxyMatcher } from './autoproxy_matcher.js';
import { SingboxCompiler } from './singbox_compiler.js';

export class AutonomousRoutingCoordinator {
  public pac: PacScriptCompiler;
  public autoProxy: AutoProxyMatcher;
  public singbox: SingboxCompiler;
  public defaultProxyNode: string;
  constructor(defaultProxyNode: string = 'US-Primary') {
    this.defaultProxyNode = defaultProxyNode;
    this.pac = new PacScriptCompiler(defaultProxyNode);
    this.autoProxy = new AutoProxyMatcher();
    this.singbox = new SingboxCompiler();
  }

  evaluate(target: string): string {
    const ap = this.autoProxy.match(target);
    if (ap) {
      return ap === 'DIRECT' ? 'DIRECT' : `PROXY ${this.defaultProxyNode}`;
    }

    const sb = this.singbox.matchDomain(target);
    if (sb) {
      return sb === 'direct' ? 'DIRECT' : `PROXY ${sb}`;
    }

    return this.pac.evaluateDomain(target);
  }
}
