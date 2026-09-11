export class PoisonedDnsResponseFilter {
  private bogusIps: Set<string> = new Set();
  public droppedCount = 0;
  public acceptedCount = 0;

  constructor() {
    const knownBogus = [
      '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113',
      '189.163.17.5', '209.85.229.138', '249.129.46.48', '77.4.7.92',
      '128.121.126.139', '159.106.121.75', '169.132.13.103', '192.67.198.6',
      '202.106.1.2', '202.181.7.85', '203.161.230.171', '203.98.7.65',
      '207.12.88.98', '208.56.31.43', '209.145.54.50', '209.220.30.174',
      '209.36.73.33', '211.94.66.147', '213.169.251.35', '216.221.188.182',
      '216.234.179.13', '243.185.187.39', '37.61.54.158', '4.36.66.178',
      '46.82.174.68', '59.24.3.173', '64.33.88.161', '64.33.99.47',
      '64.66.163.251', '65.104.202.252', '65.160.219.113', '66.45.252.237',
      '72.14.205.104', '72.14.205.99', '78.16.49.15', '8.7.198.45', '93.46.8.89',
      '253.157.14.165', '180.168.41.175', '49.2.123.56'
    ];
    for (const ip of knownBogus) {
      this.bogusIps.add(ip);
    }
  }

  isBogus(ip: string): boolean {
    return this.bogusIps.has(ip.trim());
  }

  filterIps(candidateIps: string[]): string[] {
    const clean: string[] = [];
    for (const ip of candidateIps) {
      if (this.isBogus(ip)) {
        this.droppedCount++;
      } else {
        this.acceptedCount++;
        clean.push(ip);
      }
    }
    return clean;
  }
}
