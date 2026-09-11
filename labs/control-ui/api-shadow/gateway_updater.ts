export interface GatewayRoute {
  destinationCidr: string;
  gatewayIp: string;
  interfaceName: string;
  metric: number;
}

export class DynamicGatewayUpdater {
  public routes = new Map<string, GatewayRoute>();

  addRoute(route: GatewayRoute): void {
    this.routes.set(route.destinationCidr, route);
  }

  removeRoute(cidr: string): void {
    this.routes.delete(cidr);
  }

  compileCommands(): string[] {
    const cmds: string[] = [];
    for (const r of this.routes.values()) {
      cmds.push(`ip route add ${r.destinationCidr} via ${r.gatewayIp} dev ${r.interfaceName} metric ${r.metric}`);
    }
    return cmds;
  }
}
