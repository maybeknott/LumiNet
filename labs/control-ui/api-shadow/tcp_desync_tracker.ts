/**
 * TCP connection 4-tuple identifier.
 */
export interface ConnId {
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
}

/**
 * Handshake progression states for TCP 3-way handshake tracking.
 */
export type HandshakePhase =
  | 'INITIAL'
  | 'SYN_SENT'
  | 'SYN_ACK_RECEIVED'
  | 'HANDSHAKE_COMPLETE'
  | 'DECOY_INJECTED'
  | 'DECOY_ACKNOWLEDGED'
  | 'TERMINATED';

/**
 * Outbound action instructions after evaluating packet.
 */
export interface OutboundAction {
  scheduleDecoy: boolean;
  decoySeq: number;
  newIdent: number;
}

/**
 * Inbound action outcomes after evaluating packet.
 */
export interface InboundAction {
  decoyAcknowledged: boolean;
}

/**
 * TCP desync tracker state interface for UI dashboard monitoring.
 */
export interface TcpDesyncTrackerState {
  id: ConnId;
  synSeq: number;
  synAckSeq: number;
  phase: HandshakePhase;
  fakeSent: boolean;
  schFakeSent: boolean;
}

/**
 * State machine tracking TCP 3-way handshakes and timing out-of-window decoy injection.
 */
export class TcpDesyncTracker {
  public readonly id: ConnId;
  public synSeq: number = -1;
  public synAckSeq: number = -1;
  public phase: HandshakePhase = 'INITIAL';
  public fakeSent: boolean = false;
  public schFakeSent: boolean = false;

  constructor(id: ConnId) {
    this.id = id;
  }

  public getState(): TcpDesyncTrackerState {
    return {
      id: { ...this.id },
      synSeq: this.synSeq,
      synAckSeq: this.synAckSeq,
      phase: this.phase,
      fakeSent: this.fakeSent,
      schFakeSent: this.schFakeSent,
    };
  }

  public processOutbound(
    seq: number,
    ack: number,
    isSyn: boolean,
    isAck: boolean,
    isRst: boolean,
    isFin: boolean,
    payloadLen: number,
    currIdent: number,
    fakeLen: number
  ): OutboundAction {
    if (this.phase === 'DECOY_INJECTED' || this.phase === 'DECOY_ACKNOWLEDGED') {
      return { scheduleDecoy: false, decoySeq: 0, newIdent: 0 };
    }

    // 1. Outbound SYN: SYN=1, ACK=0, payload=0
    if (isSyn && !isAck && !isRst && !isFin && payloadLen === 0) {
      if (ack !== 0) {
        this.phase = 'TERMINATED';
        throw new Error(`outbound SYN ack number is not zero: ${ack}`);
      }
      if (this.synSeq !== -1 && this.synSeq !== seq) {
        this.phase = 'TERMINATED';
        throw new Error(`outbound SYN seq mismatch: ${this.synSeq} !== ${seq}`);
      }
      this.synSeq = seq;
      this.phase = 'SYN_SENT';
      return { scheduleDecoy: false, decoySeq: 0, newIdent: 0 };
    }

    // 2. Outbound ACK completing handshake: SYN=0, ACK=1, payload=0
    if (isAck && !isSyn && !isRst && !isFin && payloadLen === 0) {
      const expectedSeq = (this.synSeq + 1) >>> 0;
      if (this.synSeq === -1 || seq !== expectedSeq) {
        this.phase = 'TERMINATED';
        throw new Error(`outbound ACK seq mismatch: ${seq} !== ${expectedSeq}`);
      }
      const expectedAck = (this.synAckSeq + 1) >>> 0;
      if (this.synAckSeq === -1 || ack !== expectedAck) {
        this.phase = 'TERMINATED';
        throw new Error(`outbound ACK ack mismatch: ${ack} !== ${expectedAck}`);
      }

      this.schFakeSent = true;
      this.phase = 'HANDSHAKE_COMPLETE';

      // Out-of-window sequence formula: (SynSeq + 1 - fakeLen) >>> 0
      const decoySeq = (this.synSeq + 1 - fakeLen) >>> 0;
      const newIdent = (currIdent + 1) & 0xffff;
      return { scheduleDecoy: true, decoySeq, newIdent };
    }

    // Normal outbound data payload
    return { scheduleDecoy: false, decoySeq: 0, newIdent: 0 };
  }

  public processInbound(
    seq: number,
    ack: number,
    isSyn: boolean,
    isAck: boolean,
    isRst: boolean,
    isFin: boolean,
    payloadLen: number
  ): InboundAction {
    if (this.synSeq === -1) {
      this.phase = 'TERMINATED';
      throw new Error('unexpected inbound packet before outbound SYN');
    }

    // 1. Inbound SYN-ACK: SYN=1, ACK=1, payload=0
    if (isSyn && isAck && !isRst && !isFin && payloadLen === 0) {
      const expectedAck = (this.synSeq + 1) >>> 0;
      if (ack !== expectedAck) {
        this.phase = 'TERMINATED';
        throw new Error(`inbound SYN-ACK ack mismatch: ${ack} !== ${expectedAck}`);
      }
      if (this.synAckSeq !== -1 && this.synAckSeq !== seq) {
        this.phase = 'TERMINATED';
        throw new Error(`inbound SYN-ACK seq change: ${this.synAckSeq} !== ${seq}`);
      }
      this.synAckSeq = seq;
      this.phase = 'SYN_ACK_RECEIVED';
      return { decoyAcknowledged: false };
    }

    // 2. Inbound ACK for decoy or post-handshake: ACK=1, SYN=0, payload=0
    if (isAck && !isSyn && !isRst && !isFin && payloadLen === 0 && (this.fakeSent || this.phase === 'DECOY_INJECTED')) {
      const expectedSeq = (this.synAckSeq + 1) >>> 0;
      if (this.synAckSeq === -1 || seq !== expectedSeq) {
        this.phase = 'TERMINATED';
        throw new Error(`inbound ACK seq mismatch: ${seq} !== ${expectedSeq}`);
      }
      const expectedAck = (this.synSeq + 1) >>> 0;
      if (ack !== expectedAck) {
        this.phase = 'TERMINATED';
        throw new Error(`inbound ACK ack mismatch: ${ack} !== ${expectedAck}`);
      }

      this.phase = 'DECOY_ACKNOWLEDGED';
      return { decoyAcknowledged: true };
    }

    this.phase = 'TERMINATED';
    throw new Error('unexpected inbound packet');
  }
}
