export interface AmneziaObfsConfig {
  jc: number;
  jmin: number;
  jmax: number;
  s1: number;
  s2: number;
  h1: number;
  h2: number;
  h3: number;
  h4: number;
}

export class AmneziaObfsParameters {
  public params: AmneziaObfsConfig = {
    jc: 4,
    jmin: 40,
    jmax: 70,
    s1: 56,
    s2: 56,
    h1: 0x01000000,
    h2: 0x02000000,
    h3: 0x03000000,
    h4: 0x04000000,
  };

  isValid(): boolean {
    if (this.params.jc < 0 || this.params.jc > 128) return false;
    if (this.params.jmin < 0 || this.params.jmax < this.params.jmin || this.params.jmax > 1500)
      return false;
    if (this.params.s1 < 0 || this.params.s1 > 1024 || this.params.s2 < 0 || this.params.s2 > 1024)
      return false;
    return true;
  }

  parseLine(line: string): boolean {
    const parts = line.split('=');
    if (parts.length !== 2) return false;

    const key = parts[0]!.trim().toUpperCase();
    const rawVal = parts[1]!.trim();

    let num: number;
    if (rawVal.toLowerCase().startsWith('0x')) {
      num = parseInt(rawVal.substring(2), 16);
    } else {
      num = parseInt(rawVal, 10);
    }
    if (isNaN(num)) return false;

    switch (key) {
      case 'JC':
        this.params.jc = num;
        break;
      case 'JMIN':
        this.params.jmin = num;
        break;
      case 'JMAX':
        this.params.jmax = num;
        break;
      case 'S1':
        this.params.s1 = num;
        break;
      case 'S2':
        this.params.s2 = num;
        break;
      case 'H1':
        this.params.h1 = num >>> 0;
        break;
      case 'H2':
        this.params.h2 = num >>> 0;
        break;
      case 'H3':
        this.params.h3 = num >>> 0;
        break;
      case 'H4':
        this.params.h4 = num >>> 0;
        break;
      default:
        return false;
    }
    return true;
  }
}
