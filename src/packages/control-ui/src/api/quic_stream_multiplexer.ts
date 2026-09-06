export const QuicStreamType = {
  ClientBidirectional: 'ClientBidirectional',
  ServerBidirectional: 'ServerBidirectional',
  ClientUnidirectional: 'ClientUnidirectional',
  ServerUnidirectional: 'ServerUnidirectional',
} as const;
export type QuicStreamType = (typeof QuicStreamType)[keyof typeof QuicStreamType];

export interface QuicStreamFrame {
  streamId: number;
  offset: number;
  fin: boolean;
  data: Uint8Array;
}

interface StreamState {
  streamType: QuicStreamType;
  sendOffset: number;
  recvOffset: number;
  maxSendCredit: number;
  receivedChunks: Map<number, Uint8Array>;
  finReceived: boolean;
  finOffset?: number;
}

export class QuicStreamMultiplexer {
  private streams: Map<number, StreamState> = new Map();
  private nextClientBidi: number = 0;
  private nextClientUni: number = 2;
  public defaultStreamWindow: number;

  constructor(defaultStreamWindow: number = 65536) {
    this.defaultStreamWindow = Math.max(1024, defaultStreamWindow);
  }

  openStream(streamType: QuicStreamType): number {
    let streamId: number;
    switch (streamType) {
      case QuicStreamType.ClientBidirectional:
        streamId = this.nextClientBidi;
        this.nextClientBidi += 4;
        break;
      case QuicStreamType.ClientUnidirectional:
        streamId = this.nextClientUni;
        this.nextClientUni += 4;
        break;
      case QuicStreamType.ServerBidirectional:
        streamId = 1;
        break;
      case QuicStreamType.ServerUnidirectional:
        streamId = 3;
        break;
    }

    this.streams.set(streamId, {
      streamType,
      sendOffset: 0,
      recvOffset: 0,
      maxSendCredit: this.defaultStreamWindow,
      receivedChunks: new Map(),
      finReceived: false,
    });

    return streamId;
  }

  writeStreamData(streamId: number, data: Uint8Array, fin: boolean = false): QuicStreamFrame {
    const stream = this.streams.get(streamId);
    if (!stream) throw new Error('Stream not found');

    const len = data.length;
    if (stream.sendOffset + len > stream.maxSendCredit) {
      throw new Error('Flow control window exceeded');
    }

    const frame: QuicStreamFrame = {
      streamId,
      offset: stream.sendOffset,
      fin,
      data: new Uint8Array(data),
    };

    stream.sendOffset += len;
    return frame;
  }

  receiveStreamFrame(frame: QuicStreamFrame): Uint8Array {
    let stream = this.streams.get(frame.streamId);
    if (!stream) {
      stream = {
        streamType: QuicStreamType.ClientBidirectional,
        sendOffset: 0,
        recvOffset: 0,
        maxSendCredit: this.defaultStreamWindow,
        receivedChunks: new Map(),
        finReceived: false,
      };
      this.streams.set(frame.streamId, stream);
    }

    if (frame.fin) {
      stream.finReceived = true;
      stream.finOffset = frame.offset + frame.data.length;
    }

    stream.receivedChunks.set(frame.offset, frame.data);

    // Reassemble contiguous bytes starting from recvOffset
    const assembledChunks: Uint8Array[] = [];
    let totalLen = 0;

    while (true) {
      // Find chunk matching stream.recvOffset
      const chunk = stream.receivedChunks.get(stream.recvOffset);
      if (chunk) {
        stream.receivedChunks.delete(stream.recvOffset);
        stream.recvOffset += chunk.length;
        assembledChunks.push(chunk);
        totalLen += chunk.length;
      } else {
        // Discard any chunks that are entirely before recvOffset
        for (const [offset, ch] of stream.receivedChunks.entries()) {
          if (offset + ch.length <= stream.recvOffset) {
            stream.receivedChunks.delete(offset);
          }
        }
        break;
      }
    }

    const result = new Uint8Array(totalLen);
    let pos = 0;
    for (const chunk of assembledChunks) {
      result.set(chunk, pos);
      pos += chunk.length;
    }

    return result;
  }

  grantFlowControlCredit(streamId: number, additionalBytes: number): void {
    const stream = this.streams.get(streamId);
    if (stream) {
      stream.maxSendCredit += additionalBytes;
    }
  }

  isStreamClosed(streamId: number): boolean {
    const stream = this.streams.get(streamId);
    if (stream && stream.finReceived && stream.finOffset !== undefined) {
      return stream.recvOffset >= stream.finOffset;
    }
    return false;
  }
}
