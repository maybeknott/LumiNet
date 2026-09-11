export const UiIkeState = {
  Init: 'INIT',
  SaInitSent: 'SA_INIT_SENT',
  SaInitRecv: 'SA_INIT_RECV',
  AuthSent: 'AUTH_SENT',
  Established: 'ESTABLISHED',
  Closed: 'CLOSED',
} as const;
export type UiIkeState = (typeof UiIkeState)[keyof typeof UiIkeState];

export class IpsecIkev2StateMachine {
  public state: UiIkeState = UiIkeState.Init;
  public initiatorSpi: Uint8Array = new Uint8Array(8);
  public responderSpi: Uint8Array = new Uint8Array(8);
  private messageId: number = 0;
  public sharedSecret: Uint8Array;
  constructor(sharedSecret: Uint8Array) {
    this.sharedSecret = sharedSecret;
    if (sharedSecret.length < 16) {
      throw new Error('Shared secret must be at least 16 bytes');
    }
    for (let i = 0; i < 8; i++) {
      this.initiatorSpi[i] = Math.floor(Math.random() * 256);
    }
  }

  buildSaInitRequest(nonce: Uint8Array): Uint8Array {
    if (this.state !== UiIkeState.Init) {
      throw new Error('Cannot build SA_INIT request from non-INIT state');
    }

    const totalLen = 28 + nonce.length;
    const frame = new Uint8Array(totalLen);
    frame.set(this.initiatorSpi, 0);
    // responder SPI = 0 at offset 8
    frame[16] = 33; // Next payload: SA
    frame[17] = 0x20; // Version 2.0
    frame[18] = 34; // IKE_SA_INIT
    frame[19] = 0x08; // Initiator flag

    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    view.setUint32(20, this.messageId++);
    view.setUint32(24, totalLen);
    frame.set(nonce, 28);

    this.state = UiIkeState.SaInitSent;
    return frame;
  }

  processSaInitResponse(resp: Uint8Array): boolean {
    if (this.state !== UiIkeState.SaInitSent || resp.length < 28) return false;

    // Check initiator SPI matches
    for (let i = 0; i < 8; i++) {
      if (resp[i] !== this.initiatorSpi[i]) return false;
    }

    // Capture responder SPI
    this.responderSpi.set(resp.slice(8, 16));
    this.state = UiIkeState.SaInitRecv;
    return true;
  }

  transitionToAuth(): boolean {
    if (this.state !== UiIkeState.SaInitRecv) return false;
    this.state = UiIkeState.AuthSent;
    return true;
  }

  finalizeEstablished(): boolean {
    if (this.state !== UiIkeState.AuthSent) return false;
    this.state = UiIkeState.Established;
    return true;
  }

  close(): void {
    this.state = UiIkeState.Closed;
  }
}
