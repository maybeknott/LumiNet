import { DualBackendController, type BackendEngine } from './dual_backend.js';
import { WindowClamper } from './window_clamper.js';
import { SniFragmenterV2 } from './sni_fragmenter_v2.js';
import type { AnomalyType } from './censorship_prober.js';

export interface TransportPosture {
  recommendedProtocol: string;
  activeBackend: BackendEngine;
  windowClampSize: number;
  mitigationStrategy: string;
}

export class AdaptiveProtocolCoordinator {
  public backendController = new DualBackendController();
  public windowClamper = new WindowClamper(2);
  public decoyInjector = new SniFragmenterV2('www.bing.com');

  adapt(anomaly: AnomalyType): TransportPosture {
    switch (anomaly) {
      case 'sni_reset':
        this.windowClamper.clampedSize = 2;
        return {
          recommendedProtocol: 'Trojan-SNI-Fragment',
          activeBackend: this.backendController.selectEngine(),
          windowClampSize: 2,
          mitigationStrategy: 'SNI fragmentation & window clamping to 2 bytes',
        };
      case 'udp_blackhole':
        this.backendController.recordMetrics('kcp_raw_socket', 999, 1.0, false);
        this.backendController.recordMetrics('kcp_raw_socket', 999, 1.0, false);
        this.backendController.recordMetrics('kcp_raw_socket', 999, 1.0, false);
        return {
          recommendedProtocol: 'VLESS-Reality',
          activeBackend: this.backendController.selectEngine(),
          windowClampSize: this.windowClamper.clampedSize,
          mitigationStrategy: 'Demoted UDP/KCP backend, transitioned to VLESS-Reality TCP',
        };
      case 'tcp_rst_injection':
        return {
          recommendedProtocol: 'Trojan-SNI-Fragment',
          activeBackend: 'violated_tcp_quic',
          windowClampSize: 4,
          mitigationStrategy: 'Activated Violated TCP/QUIC injection with RST poison filtering',
        };
      default:
        return {
          recommendedProtocol: 'Hysteria2',
          activeBackend: this.backendController.selectEngine(),
          windowClampSize: 65535,
          mitigationStrategy: 'Standard baseline transport maintained',
        };
    }
  }
}
