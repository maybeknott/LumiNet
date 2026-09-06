export interface AttemptMetric {
  success: boolean;
  durationMs: number;
  errorCategory?: string;
}

export interface TcpProbeResult {
  success: boolean;
  attempts?: AttemptMetric[];
  medianRttMs?: number;
  consistency?: number;
  errorCategory?: string;
}

export interface TlsProbeResult {
  success: boolean;
  handshakeMs?: number;
  version?: string;
  cipherSuite?: string;
  alpn?: string;
  verified?: boolean;
  errorCategory?: string;
}

export interface HttpProbeItem {
  method: string;
  url: string;
  statusCode: number;
  durationMs: number;
  redirected?: boolean;
  errorCategory?: string;
}

export interface HttpProbeResult {
  success: boolean;
  probes?: HttpProbeItem[];
}

export interface WsProbeResult {
  success: boolean;
  statusCode?: number;
  durationMs?: number;
  errorCategory?: string;
}

export interface UdpProbeResult {
  reachable: boolean;
  attempts?: AttemptMetric[];
  errorCategory?: string;
}

export interface QuicProbeResult {
  success: boolean;
  handshakeMs?: number;
  alpn?: string;
  errorCategory?: string;
}

export interface DnsProbeResult {
  udpResponsive: boolean;
  tcpResponsive: boolean;
  answers?: string[];
  attempts?: AttemptMetric[];
  errorCategory?: string;
}

export interface ProbeMetrics {
  rttMs: number;
  jitterMs: number;
  packetLossEstimate: number;
  stabilityPercent: number;
  timeoutFrequency: number;
}

export interface ScoreResult {
  numeric: number;
  grade: string;
  classification: 'Blocked' | 'Unstable' | 'Partially Usable' | 'Tunnel Ready' | 'False Positive';
  confidence: number;
  falsePositive: boolean;
  reasons: string[];
}

export function computeProbeMetrics(
  tcp: TcpProbeResult,
  udp: UdpProbeResult,
  dns: DnsProbeResult,
): ProbeMetrics {
  const attempts: AttemptMetric[] = [
    ...(tcp.attempts || []),
    ...(udp.attempts || []),
    ...(dns.attempts || []),
  ];

  const successfulDurations: number[] = [];
  let timeouts = 0;

  for (const a of attempts) {
    if (a.success) {
      successfulDurations.push(a.durationMs);
    }
    if (a.errorCategory && a.errorCategory.toLowerCase() === 'timeout') {
      timeouts++;
    }
  }

  let jitter = 0;
  if (successfulDurations.length > 1) {
    const sum = successfulDurations.reduce((acc, v) => acc + v, 0);
    const mean = sum / successfulDurations.length;
    const variance =
      successfulDurations.reduce((acc, v) => acc + (v - mean) * (v - mean), 0) /
      successfulDurations.length;
    jitter = Math.round(Math.sqrt(variance));
  }

  const rtt =
    tcp.medianRttMs && tcp.medianRttMs > 0 ? tcp.medianRttMs : medianLatency(successfulDurations);

  const totalAttempts = attempts.length;
  const successRatio =
    totalAttempts > 0 ? attempts.filter((a) => a.success).length / totalAttempts : 0;

  const loss = 1 - successRatio;
  const timeoutFreq = totalAttempts > 0 ? timeouts / totalAttempts : 0;

  let stability = 100 * (1 - loss);
  if (jitter > 250) {
    stability -= 15;
  }
  if (timeoutFreq > 0.25) {
    stability -= 20;
  }
  if (stability < 0) {
    stability = 0;
  }

  return {
    rttMs: rtt,
    jitterMs: jitter,
    packetLossEstimate: roundTwoDec(loss * 100),
    stabilityPercent: roundTwoDec(stability),
    timeoutFrequency: roundTwoDec(timeoutFreq * 100),
  };
}

export function scoreProbeResult(
  tcp: TcpProbeResult,
  tls: TlsProbeResult,
  http: HttpProbeResult,
  ws: WsProbeResult,
  quic: QuicProbeResult,
  dns: DnsProbeResult,
  metrics: ProbeMetrics,
): ScoreResult {
  let points = 0;
  const reasons: string[] = [];

  if (tcp.success) {
    points += 25;
    reasons.push('tcp_connectivity');
  }
  const consistency = tcp.consistency ?? 0;
  if (consistency >= 0.67) {
    points += 15;
    reasons.push('retry_consistency');
  }
  if (tls.success) {
    points += 20;
    reasons.push('tls_handshake');
  }
  if (http.success) {
    points += 8;
    reasons.push('http_behavior');
  }
  if (ws.success) {
    points += 10;
    reasons.push('websocket_upgrade');
  }
  if (quic.success) {
    points += 8;
    reasons.push('quic_handshake');
  }
  if (dns.udpResponsive || dns.tcpResponsive) {
    points += 6;
    reasons.push('dns_responsive');
  }

  if (metrics.rttMs > 0 && metrics.rttMs < 150) {
    points += 5;
  }
  if (metrics.jitterMs < 80) {
    points += 5;
  }
  if (metrics.stabilityPercent >= 90) {
    points += 8;
  }
  if (points > 100) {
    points = 100;
  }

  let falsePositive = tcp.success && consistency < 0.67;
  if (
    tcp.success &&
    !tls.success &&
    !http.success &&
    !ws.success &&
    !quic.success &&
    !dns.udpResponsive &&
    !dns.tcpResponsive
  ) {
    falsePositive = true;
  }

  let classification: ScoreResult['classification'] = 'Blocked';
  if (falsePositive) {
    classification = 'False Positive';
  } else if (points >= 82 && consistency >= 0.67 && (tls.success || ws.success || quic.success)) {
    classification = 'Tunnel Ready';
  } else if (points >= 58) {
    classification = 'Partially Usable';
  } else if (points >= 38) {
    classification = 'Unstable';
  }

  const grade = calculateGrade(points);
  const conf = calculateConfidence(tcp, tls, http, ws, quic, metrics, falsePositive);

  return {
    numeric: points,
    grade,
    classification,
    confidence: roundTwoDec(conf),
    falsePositive,
    reasons,
  };
}

export function parseCloudflareTrace(raw: string): {
  ip: string | null;
  countryCode: string | null;
} {
  let ip: string | null = null;
  let countryCode: string | null = null;
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    const idx = trimmed.indexOf('=');
    if (idx !== -1) {
      const key = trimmed.slice(0, idx).trim();
      const val = trimmed.slice(idx + 1).trim();
      if (key === 'ip' && val.length > 0) {
        ip = val;
      } else if (key === 'loc' && val.length > 0) {
        countryCode = val.toUpperCase();
      }
    }
  }
  return { ip, countryCode };
}

function calculateGrade(points: number): string {
  if (points >= 94) return 'A+';
  if (points >= 85) return 'A';
  if (points >= 72) return 'B';
  if (points >= 58) return 'C';
  if (points >= 38) return 'D';
  return 'F';
}

function calculateConfidence(
  tcp: TcpProbeResult,
  tls: TlsProbeResult,
  http: HttpProbeResult,
  ws: WsProbeResult,
  quic: QuicProbeResult,
  metrics: ProbeMetrics,
  falsePositive: boolean,
): number {
  let c = (tcp.consistency ?? 0) * 45;
  if (tls.success) c += 20;
  if (http.success || ws.success || quic.success) c += 20;
  if (metrics.stabilityPercent >= 85) c += 15;
  if (falsePositive) c -= 25;
  if (c < 0) return 0;
  if (c > 100) return 100;
  return c;
}

function medianLatency(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)]!;
}

function roundTwoDec(v: number): number {
  return Math.round(v * 100) / 100;
}
