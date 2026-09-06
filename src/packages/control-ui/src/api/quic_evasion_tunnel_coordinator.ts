import {
  SegmentationStrategy,
  SniSegmentationMasquerader,
} from './sni_segmentation_masquerader.js';
import { QuicConnectionController, QuicConnectionState } from './quic_connection_controller.js';
import { QuicHeaderType, QuicPacketCodec } from './quic_packet_codec.js';
import type { QuicPacketHeader } from './quic_packet_codec.js';
import { QuicStreamMultiplexer, QuicStreamType } from './quic_stream_multiplexer.js';
import type { QuicStreamFrame } from './quic_stream_multiplexer.js';
import { ReplayResistantTunnelSession } from './replay_resistant_tunnel.js';
import type { ReplayResistantConfig } from './replay_resistant_tunnel.js';

export interface QuicTunnelMetrics {
  connectionState: QuicConnectionState;
  totalDatagramsSent: number;
  totalDatagramsReceived: number;
  activeStreams: number;
  evasionActive: boolean;
}

export class QuicEvasionTunnelCoordinator {
  private multiplexer: QuicStreamMultiplexer;
  private connection: QuicConnectionController;
  private masquerader: SniSegmentationMasquerader;
  private replaySession: ReplayResistantTunnelSession;
  public destCid: Uint8Array;
  public srcCid: Uint8Array;
  private nextPacketNum: number = 1;
  private totalSent: number = 0;
  private totalRecv: number = 0;
  public evasionMode: boolean;

  constructor(
    destCid: Uint8Array,
    srcCid: Uint8Array,
    clientRandom: Uint8Array,
    serverRandom: Uint8Array,
    evasionMode: boolean = false,
  ) {
    const replayConfig: ReplayResistantConfig = {
      psk: new Uint8Array(32).fill(0x3a),
      maxSkewSecs: 30,
      maxTrackedNonces: 10000,
    };
    this.replaySession = new ReplayResistantTunnelSession(replayConfig, clientRandom, serverRandom);

    this.connection = new QuicConnectionController(65536);
    this.connection.setState(QuicConnectionState.Established);

    this.multiplexer = new QuicStreamMultiplexer(65536);
    this.masquerader = new SniSegmentationMasquerader(SegmentationStrategy.MidSniSplit, 8, 32);

    this.destCid = destCid;
    this.srcCid = srcCid;
    this.evasionMode = evasionMode;
  }

  openTunnelStream(): number {
    return this.multiplexer.openStream(QuicStreamType.ClientBidirectional);
  }

  prepareOutboundDatagram(
    streamId: number,
    appData: Uint8Array,
    timestampSecs: number,
  ): Uint8Array[] {
    // 1. Multiplex stream frame
    const streamFrame = this.multiplexer.writeStreamData(streamId, appData, false);
    // Serialize frame as JSON string in Uint8Array
    const frameObj = {
      streamId: streamFrame.streamId,
      offset: streamFrame.offset,
      fin: streamFrame.fin,
      data: Array.from(streamFrame.data),
    };
    const frameBytes = new TextEncoder().encode(JSON.stringify(frameObj));

    // 2. Wrap in QUIC 1-RTT Short packet
    const header: QuicPacketHeader = {
      headerType: QuicHeaderType.OneRttShort,
      version: 0,
      destCid: this.destCid,
      srcCid: this.srcCid,
      packetNumber: this.nextPacketNum,
    };
    const quicPacket = QuicPacketCodec.encodePacket(header, frameBytes);

    // 3. Seal with replay resistance
    const sealed = this.replaySession.sealPacket(this.nextPacketNum, timestampSecs, quicPacket);

    this.connection.onPacketSent(this.nextPacketNum, sealed.length, timestampSecs * 1000);
    this.nextPacketNum += 1;
    this.totalSent += 1;

    // 4. If evasion mode is enabled, segment datagram to evade DPI
    if (this.evasionMode) {
      return this.masquerader.segmentStream(sealed, this.nextPacketNum);
    } else {
      return [sealed];
    }
  }

  processInboundDatagram(
    sealedDatagram: Uint8Array,
    currentTimeSecs: number,
  ): { streamId: number; payload: Uint8Array } {
    // 1. Verify replay resistance and open envelope
    const { sequence, payload: quicPacket } = this.replaySession.openPacket(
      sealedDatagram,
      currentTimeSecs,
    );

    this.connection.onAckReceived(sequence, currentTimeSecs * 1000);
    this.totalRecv += 1;

    // 2. Decode QUIC packet
    const { payload } = QuicPacketCodec.decodePacket(quicPacket, this.destCid.length);

    // 3. Deserialize stream frame
    const jsonStr = new TextDecoder().decode(payload);
    const parsed = JSON.parse(jsonStr);
    const frame: QuicStreamFrame = {
      streamId: parsed.streamId,
      offset: parsed.offset,
      fin: parsed.fin,
      data: new Uint8Array(parsed.data),
    };

    // 4. Reassemble stream data
    const assembled = this.multiplexer.receiveStreamFrame(frame);
    return { streamId: frame.streamId, payload: assembled };
  }

  getTunnelMetrics(): QuicTunnelMetrics {
    return {
      connectionState: this.connection.getMetrics().state,
      totalDatagramsSent: this.totalSent,
      totalDatagramsReceived: this.totalRecv,
      activeStreams: 1,
      evasionActive: this.evasionMode,
    };
  }
}
