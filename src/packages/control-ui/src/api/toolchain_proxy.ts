export const ToolchainTarget = {
  Git: 'git',
  Pip: 'pip',
  Npm: 'npm',
  Gradle: 'gradle',
  Curl: 'curl',
  Docker: 'docker',
  Env: 'env',
} as const;
export type ToolchainTarget = (typeof ToolchainTarget)[keyof typeof ToolchainTarget];

export class ToolchainProxyWrapper {
  public httpProxy: string;
  public socks5Proxy: string;
  constructor(httpProxy: string, socks5Proxy: string) {
    this.httpProxy = httpProxy;
    this.socks5Proxy = socks5Proxy;
  }

  generateEnvVars(): Record<string, string> {
    return {
      http_proxy: this.httpProxy,
      https_proxy: this.httpProxy,
      HTTP_PROXY: this.httpProxy,
      HTTPS_PROXY: this.httpProxy,
      all_proxy: this.socks5Proxy,
      ALL_PROXY: this.socks5Proxy,
      no_proxy: 'localhost,127.0.0.1,::1',
    };
  }

  generateSnippet(target: ToolchainTarget): string {
    switch (target) {
      case ToolchainTarget.Git:
        return `[http]\n\tproxy = ${this.httpProxy}\n[https]\n\tproxy = ${this.httpProxy}\n`;
      case ToolchainTarget.Pip:
        return `[global]\nproxy = ${this.httpProxy}\n`;
      case ToolchainTarget.Npm:
        return `proxy=${this.httpProxy}\nhttps-proxy=${this.httpProxy}\n`;
      case ToolchainTarget.Gradle: {
        const parts = this.httpProxy.replace(/^https?:\/\//, '').split(':');
        const host = parts[0] || '127.0.0.1';
        const port = parts[1] || '8080';
        return `systemProp.http.proxyHost=${host}\nsystemProp.http.proxyPort=${port}\nsystemProp.https.proxyHost=${host}\nsystemProp.https.proxyPort=${port}\n`;
      }
      case ToolchainTarget.Curl:
        return `proxy = "${this.socks5Proxy}"\n`;
      case ToolchainTarget.Docker:
        return `{\n  "proxies": {\n    "default": {\n      "httpProxy": "${this.httpProxy}",\n      "httpsProxy": "${this.httpProxy}"\n    }\n  }\n}\n`;
      case ToolchainTarget.Env:
        return `export HTTP_PROXY="${this.httpProxy}"\nexport HTTPS_PROXY="${this.httpProxy}"\nexport ALL_PROXY="${this.socks5Proxy}"\n`;
    }
  }
}
