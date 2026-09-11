export type PipelineVerdictType =
  | { type: 'PassThrough' }
  | { type: 'ShortCircuit'; statusCode: number; body: Uint8Array }
  | { type: 'ModifyHeaders'; headers: Array<[string, string]> };

export interface ProxyFilterHook {
  onRequest(method: string, path: string, headers: Array<[string, string]>): PipelineVerdictType;
}

export class HeaderInjectorHook implements ProxyFilterHook {
  private headerName: string;
  private headerValue: string;
  constructor(headerName: string, headerValue: string) {
    this.headerName = headerName;
    this.headerValue = headerValue;
  }

  onRequest(
    _method: string,
    _path: string,
    _headers: Array<[string, string]>,
  ): PipelineVerdictType {
    return {
      type: 'ModifyHeaders',
      headers: [[this.headerName, this.headerValue]],
    };
  }
}

export class BlockPathHook implements ProxyFilterHook {
  private blockedPrefix: string;
  constructor(blockedPrefix: string) {
    this.blockedPrefix = blockedPrefix;
  }

  onRequest(_method: string, path: string, _headers: Array<[string, string]>): PipelineVerdictType {
    if (path.startsWith(this.blockedPrefix)) {
      return {
        type: 'ShortCircuit',
        statusCode: 403,
        body: new TextEncoder().encode('Forbidden by LumiProxy Pipeline'),
      };
    }
    return { type: 'PassThrough' };
  }
}

export class ProgrammableProxyPipeline {
  private hooks: ProxyFilterHook[] = [];

  addHook(hook: ProxyFilterHook): void {
    this.hooks.push(hook);
  }

  processRequest(
    method: string,
    path: string,
    headers: Array<[string, string]>,
  ): { statusCode: number; body?: Uint8Array } {
    for (const hook of this.hooks) {
      const verdict = hook.onRequest(method, path, headers);
      if (verdict.type === 'ShortCircuit') {
        return { statusCode: verdict.statusCode, body: verdict.body };
      } else if (verdict.type === 'ModifyHeaders') {
        headers.push(...verdict.headers);
      }
    }
    return { statusCode: 200 };
  }
}
