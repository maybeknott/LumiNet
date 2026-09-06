import { BondingMode, MultipathTunnelManager, PathState } from './multipath_tunnel.js';
import { PacketScrambler } from './packet_scrambler.js';
import { CensorshipProfileSynthesizer, CensorshipRegion } from './profile_synthesizer.js';
import type { RegionalEvasionProfile } from './profile_synthesizer.js';

export class MultipathEvasionPipeline {
  public tunnel: MultipathTunnelManager;
  public scrambler: PacketScrambler;
  public profile: RegionalEvasionProfile;
  public totalProcessed = 0;

  constructor(
    tunnelId: string,
    mode: BondingMode,
    queueNum: number,
    mark: number,
    region: CensorshipRegion,
  ) {
    const synth = new CensorshipProfileSynthesizer();
    this.profile = synth.getProfile(region);
    this.scrambler = new PacketScrambler(queueNum, mark);
    this.tunnel = new MultipathTunnelManager(tunnelId, mode);

    if (this.profile.tcpMssClamp < 1200) {
      this.scrambler.ttlHopLimit = 48;
    } else {
      this.scrambler.ttlHopLimit = 64;
    }
  }

  registerPath(pathId: number, local: string, remote: string, weight: number): void {
    this.tunnel.addPath({
      pathId,
      localAddr: local,
      remoteAddr: remote,
      rttMs: 0,
      lossPercentage: 0,
      txBytes: 0,
      rxBytes: 0,
      state: PathState.Active,
      weight,
    });
  }

  prepareOutboundPacket(
    dest: string,
    payload: Uint8Array,
  ): { pathId: number; frame: Uint8Array } | null {
    this.totalProcessed++;
    this.scrambler.processIPPacket(dest, payload);

    const pathId = this.tunnel.selectPathForEgress();
    if (pathId === null) return null;

    const frame = this.tunnel.encapsulate(pathId, payload);
    if (!frame) return null;

    return { pathId, frame };
  }
}
