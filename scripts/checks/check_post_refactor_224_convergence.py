#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
GOV=ROOT/'governance'/'convergence'
SUCCESSOR_BASELINE=GOV/'post-refactor-225-baseline-files.csv'
errors=[]

def fail(msg): errors.append(msg)
def text(path):
    p=ROOT/path
    if not p.is_file(): fail(f'missing source: {path}'); return ''
    return p.read_text(errors='replace')
def require(path,*needles):
    s=text(path)
    for n in needles:
        if n not in s: fail(f'{path}: missing {n!r}')
    return s

def require_regex(path, *patterns):
    s = text(path)
    for pattern in patterns:
        if not re.search(pattern, s, re.MULTILINE):
            fail(f'{path}: missing semantic pattern {pattern!r}')
    return s

def read_csv(name):
    p=GOV/name
    if not p.is_file(): fail(f'missing evidence: {name}'); return []
    return list(csv.DictReader(p.open(encoding='utf-8')))


def sha_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):
            h.update(chunk)
    return h.hexdigest()

def current_inventory(exclude=None):
    exclude=set(exclude or ())
    # Historical post-224 evidence freezes once post-225 exists. Reconstruct
    # the post-224 current tree from the successor's exact pre-225 inventory
    # instead of interpreting intentional post-225 source/evidence changes as
    # regressions in the immutable post-224 delta.
    if SUCCESSOR_BASELINE.is_file():
        out={}
        for row in csv.DictReader(SUCCESSOR_BASELINE.open(encoding='utf-8', newline='')):
            rel=row.get('path','').strip()
            if not rel or rel in exclude:
                continue
            typ=row.get('type', row.get('file_type','file')).strip()
            out[rel]={'file_type':typ,'sha256':row.get('sha256','').strip()}
        return out
    out={}
    for p in sorted(ROOT.rglob('*')):
        rel=p.relative_to(ROOT).as_posix()
        if rel in exclude: continue
        if p.is_symlink():
            target=os.readlink(p)
            out[rel]={'file_type':'symlink','sha256':hashlib.sha256(target.encode()).hexdigest()}
        elif p.is_file():
            out[rel]={'file_type':'file','sha256':sha_file(p)}
    return out

def check_delta_evidence():
    baseline_rows=read_csv('post-refactor-224-baseline-files.csv')
    delta_rows=read_csv('post-refactor-224-target-delta.csv')
    if len(baseline_rows)!=2946: fail(f'223 successor baseline denominator {len(baseline_rows)} != 2946')
    baseline={}
    for r in baseline_rows:
        path=r.get('path','')
        if not path or path in baseline: fail(f'duplicate/empty baseline path {path!r}'); continue
        if r.get('file_type') not in {'file','symlink'}: fail(f'invalid baseline type {path}:{r.get("file_type")}')
        if not re.fullmatch(r'[0-9a-f]{64}',r.get('sha256','')): fail(f'invalid baseline hash {path}')
        baseline[path]={'file_type':r['file_type'],'sha256':r['sha256']}
    delta_rel='governance/convergence/post-refactor-224-target-delta.csv'
    current=current_inventory({delta_rel})
    expected={}
    for path in sorted(set(baseline)|set(current)):
        before=baseline.get(path); after=current.get(path)
        if before and after and before==after: continue
        change='added' if before is None else 'deleted' if after is None else 'modified'
        expected[path]=(change,before,after)
    ledger_ids={r['record_id'] for r in read_csv('post-refactor-224-adoption-ledger.csv')}
    seen={}
    for r in delta_rows:
        path=r.get('path','')
        if not path or path in seen: fail(f'duplicate/empty delta path {path!r}'); continue
        seen[path]=r
        exp=expected.get(path)
        if not exp:
            fail(f'delta extra/unchanged path {path}'); continue
        change,before,after=exp
        if r.get('change_type')!=change: fail(f'delta change type mismatch {path}: {r.get("change_type")} != {change}')
        bt=before['file_type'] if before else 'n/a'; ct=after['file_type'] if after else 'n/a'
        bh=before['sha256'] if before else 'n/a'; ch=after['sha256'] if after else 'n/a'
        if r.get('baseline_type')!=bt or r.get('current_type')!=ct: fail(f'delta type mismatch {path}')
        if r.get('baseline_sha256')!=bh or r.get('current_sha256')!=ch: fail(f'delta hash mismatch {path}')
        ids=r.get('semantic_record_ids','n/a')
        if ids!='n/a':
            bad=[x for x in ids.split(';') if x not in ledger_ids]
            if bad: fail(f'delta unknown semantic records {path}:{bad}')
        if not r.get('reason'): fail(f'delta missing reason {path}')
        verify=r.get('verification_path','')
        if not verify or not (ROOT/verify).exists(): fail(f'delta verification path missing {path}:{verify}')
    missing=sorted(set(expected)-set(seen))
    if missing: fail(f'delta missing {len(missing)} changed paths: {missing[:10]}')
    return len(delta_rows)

def check_surface_evidence():
    archives=read_csv('post-refactor-224-archive-accountability.csv')
    surfaces=read_csv('post-refactor-224-surface-accountability.csv')
    dirs=read_csv('post-refactor-224-directories.csv')
    symbols=read_csv('post-refactor-224-symbols.csv')
    ledger=read_csv('post-refactor-224-adoption-ledger.csv')
    if len(archives)!=15: fail(f'archive count {len(archives)} != 15')
    if len(surfaces)!=913: fail(f'surface count {len(surfaces)} != 913')
    if sum(r.get('type')=='file' for r in surfaces)!=911: fail('regular file denominator != 911')
    if sum(r.get('type')=='symlink' for r in surfaces)!=2: fail('symlink denominator != 2')
    if len(dirs)!=153: fail(f'directory denominator {len(dirs)} != 153')
    if len(ledger)<70: fail(f'semantic records unexpectedly low: {len(ledger)}')
    ids={r['record_id'] for r in ledger}
    if len(ids)!=len(ledger): fail('duplicate semantic record ids')
    linked=set()
    high_base=[]
    for r in surfaces:
        links=[x for x in r['semantic_record_ids'].split(';') if x]
        if not links: fail(f"unlinked surface {r['donor']}:{r['path']}")
        bad=[x for x in links if x not in ids]
        if bad: fail(f"bad surface links {r['donor']}:{r['path']} {bad}")
        linked.update(links)
        if r['classification'] in {'implementation','test','script','deployment','ui-or-product'} and all(x.startswith('BASE') for x in links):
            high_base.append(f"{r['donor']}:{r['path']}")
    if high_base: fail(f'high-signal base-only surfaces: {high_base[:10]}')
    orphan=sorted(ids-linked)
    if orphan: fail(f'orphan semantic records: {orphan}')
    surf_index={(r['donor'],r['path']):r for r in surfaces}
    test_nodes={}
    for r in ledger:
        s=surf_index.get((r['donor'],r['donor_path']))
        if not s: fail(f"ledger representative missing {r['record_id']}")
        elif s['sha256']!=r['donor_sha256']: fail(f"ledger hash mismatch {r['record_id']}")
        if r['validation_status'] not in {'verified','statically-validated','reviewed','inferred','unverified','pending'}:
            fail(f"invalid validation status {r['record_id']}:{r['validation_status']}")
        test_node=r.get('test_node','n/a')
        if r.get('disposition')!='reference-only' and test_node=='n/a':
            fail(f"non-reference semantic record lacks acceptance evidence {r['record_id']}")
        if test_node!='n/a':
            if test_node in test_nodes:
                fail(f"duplicate test node {test_node}: {test_nodes[test_node]} and {r['record_id']}")
            test_nodes[test_node]=r['record_id']
            test_path=test_node.split('#',1)[0]
            if test_path and not (ROOT/test_path).exists():
                fail(f"missing test path {r['record_id']}:{test_path}")
        target_nodes=r.get('target_nodes','n/a')
        if target_nodes!='n/a':
            for node in target_nodes.split(';'):
                target_path=node.split('#',1)[0]
                if target_path and not (ROOT/target_path).exists():
                    fail(f"missing target path {r['record_id']}:{target_path}")
    for r in symbols:
        s=surf_index.get((r['donor'],r['path']))
        if not s: fail(f"symbol surface missing {r['donor']}:{r['path']}")
        elif r['surface_sha256']!=s['sha256']: fail(f"symbol hash mismatch {r['donor']}:{r['path']}:{r['symbol']}")
        for link in filter(None,r['semantic_record_ids'].split(';')):
            if link not in ids: fail(f'bad symbol semantic link {link}')
    for r in archives:
        for field in ('zip_crc','path_safety','symlink_confinement','archive_tree_byte_equality'):
            if r.get(field)!='pass': fail(f"archive verification not pass {r['donor']}:{field}")
    return len(archives),len(surfaces),len(dirs),len(symbols),len(ledger)

def check_mutation_retry():
    s=require_regex('src/apps/daemon/internal/foundation/config/config.go',r'DefaultMutationAttempts\s*=\s*3',r'MaxMutationAttempts\s*=\s*8',r'AutomaticRetries',r'ExhaustedRetries',r'MutationStats\(\)')
    if 'ExpectedRevision' not in s: fail('explicit revision authority missing')
    api=require('src/apps/daemon/internal/adapters/api/types.go','ConfigMutationRetry','RemoteMutationRetry','WebSocketBackpressure')
    require('src/apps/daemon/internal/adapters/api/handlers_system_status.go','MutationStats()','.Stats()')
    return api

def check_websocket_guardrails():
    require('src/apps/daemon/internal/adapters/api/websocket.go','BroadcastDrops','SlowClientDisconnects','broadcastDrops.Add(1)','slowClientDisconnects.Add(1)')
    require('src/apps/daemon/internal/adapters/api/websocket_metrics_test.go','TestHubBackpressureStatsCountBroadcastDropsAndSlowClients','BroadcastDrops','SlowClientDisconnects')

def check_kcp_guardrails():
    require_regex('src/apps/daemon/internal/networking/kcppolicy/policy.go',r'MaxFECShards\s*=\s*64',r'func Resolve\(',r'ACKNoDelay',r'WriteDelay',r'ReadBufferBytes',r'WriteBufferBytes',r'PacketDuplication',r'RateLimitBPS')
    require('src/apps/daemon/internal/runtime/proxy/kcp_transport.go','kcppolicy.Resolve','applyKCPPolicy','kcpSessionKey')
    if (ROOT/'src/packages/lumicore/src/transport/kcp.rs').exists(): fail('obsolete Rust KCP placeholder still exists')

def check_single_kcp_owner(): check_kcp_guardrails()
def check_single_proxy_owner():
    require('src/apps/daemon/internal/runtime/proxy/kcp_transport.go','func (m *KcpTransportManager) Dial(','kcp.DialWithOptions','func ListenKcp(')

def check_endpoint_guardrails():
    require('src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go','endpointDiversityBand','CircuitOpen','least-loaded','weighted-quality','sticky')
    require('src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan.go','HealthState','StaleAfterSeconds')

def check_dns_guardrails():
    s=require('src/apps/daemon/internal/networking/dns/doh_pool_plan.go','ReadOnly','https','ResolverPoolPresets','quad9-secured','quad9-unsecured','quad9-secured-ecs')
    if 'http.Get' in s or 'net.Dial' in s: fail('DoH evidence planner performs network I/O')

def check_l7_guardrails():
    require_regex('src/apps/daemon/internal/analysis/diagnostics/l7_signature_plan.go',r'maxL7Signatures\s*=\s*256',r'OfflineOnly',r'InstallsClassifier')

def check_traffic_guardrails():
    require('src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan.go','DeclarativeOnly','ExecutesPlugins','TrafficBehaviorPresets')

def check_routing_guardrails():
    require('src/apps/daemon/internal/analysis/diagnostics/routing_corpus_plan.go','ImportsMutableDatasets','RoutingPolicyPresets')

def check_relay_guardrails():
    require('src/apps/daemon/internal/integrations/relayclient/adaptive_poll.go','relayIdlePollBaseDelay','relayIdlePollMaxDelay','runAdaptiveRelayPolling')
    require('src/apps/daemon/internal/integrations/relayclient/relay_conn_state.go','RecordIdlePoll')

def check_secret_guardrails():
    s=require('src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go','TestPostRefactor224CredentialFreeProxyFormatCorpus')
    if 'ir_configs.txt' in s: fail('live donor account corpus referenced by target tests')

def check_tls_guardrails():
    # New donor CERT_NONE mechanism must not be introduced by this wave.
    for p in [ROOT/'src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go',ROOT/'src/apps/daemon/internal/analysis/diagnostics/l7_signature_plan.go']:
        if p.exists() and 'InsecureSkipVerify: true' in p.read_text(errors='replace'): fail(f'insecure TLS in {p}')

def check_privileged_guardrails():
    allowed={
        # The historical transport/ shims stay exported for ABI continuity;
        # the canonical implementations live with their owning modules.
        'packages/lumicore/src/transport/ebpf_interceptor.rs',
        'packages/lumicore/src/transport/ebpf_redirector.rs',
        'packages/lumicore/src/dns/ebpf_dns_drop_filter.rs',
        'packages/lumicore/src/system/ebpf_redirector.rs',
    }
    found={str(p.relative_to(ROOT/'src')) for p in (ROOT/'src').rglob('*') if 'ebpf' in p.name.lower()}
    unexpected=sorted(found-allowed)
    missing=sorted(allowed-found)
    if unexpected: fail(f'unexpected eBPF donor path introduced under src: {unexpected}')
    if missing: fail(f'historical LumiCore eBPF baseline path unexpectedly missing: {missing}')

def check_lacuna_guardrail():
    if (ROOT/'src/packages/lumicore/src/evasion/stack_spoofing.rs').exists(): fail('StackSpoofing source still active')
    ev=text('src/packages/lumicore/src/evasion/mod.rs')
    if 'stack_spoofing' in ev.lower(): fail('StackSpoofing export still active')

def check_routing_and_parser():
    require('src/apps/daemon/internal/networking/proxyconfig/types.go','rejectAmbiguousProxyAuthority')
    require('src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go','TestPostRefactor224RejectsAmbiguousMultiAuthorityAndPreservesIPv6','TestPostRefactor224CredentialFreeProxyFormatCorpus','TestPostRefactor224KCPExplicitZeroFalseRoundTrip')

def check_operator_surface():
    require('src/apps/daemon/internal/adapters/api/routes_system.go','doh-resolver-pool-plan','l7-signature-plan','traffic-profile-plan','routing-corpus-plan','convergence-presets')
    require('src/packages/control-ui/src/pages/Operations.tsx','Convergence policy lab','endpointStrategy')
    require('src/packages/control-ui/src/api/contracts.ts','config_mutation_retry','websocket_backpressure')

def check_server_held_long_poll_rejection():
    relay = ROOT/'src/apps/daemon/internal/integrations/relayclient'
    for p in relay.glob('*.go'):
        if 'wait_ms' in p.read_text(errors='replace'):
            fail(f'unsupported donor server-held long poll surfaced in {p.relative_to(ROOT)}')

def check_balancer_service_supersession():
    require('src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go','BuildEndpointPoolPlan')
    daemon_mod = text('src/apps/daemon/go.mod').lower()
    if 'kafka' in daemon_mod: fail('donor balancing/logging dependency introduced')

def check_job_persistence_single_owner():
    require('src/apps/daemon/internal/workflows/jobs/manager.go','type JobManager struct')
    ws = text('src/apps/daemon/internal/adapters/api/websocket.go')
    if 'sqlite' in ws.lower() or 'bolt' in ws.lower(): fail('WebSocket hub gained competing durable event store')

def check_dns_mutation_rejection():
    s=require('src/apps/daemon/internal/networking/dns/doh_pool_plan.go','ReadOnly')
    for token in ('uci ', 'rpcd', 'exec.Command', 'http.Get', 'net.Dial'):
        if token in s: fail(f'DoH evidence planner gained mutation/network authority via {token!r}')

def check_shellcode_release_exclusion():
    evasion=ROOT/'src/packages/lumicore/src/evasion'
    for p in evasion.rglob('*'):
        if p.is_file():
            low=p.read_text(errors='replace').lower()
            if 'shellcode' in low or 'stack_spoof' in low or 'veh' in low:
                fail(f'LACUNA execution/evasion surface survived in {p.relative_to(ROOT)}')

def check_libxray_helper_supersession():
    require('src/apps/daemon/internal/runtime/proxy/core_manager.go','type CoreManager struct')
    if any('libxray' in str(p).lower() for p in (ROOT/'src').rglob('*')):
        fail('libXray donor runtime/helper path introduced under src')

def check_relay_runtime_single_owner():
    require('src/apps/daemon/internal/integrations/relayclient/adaptive_poll.go','runAdaptiveRelayPolling')
    if any('jjtcp' in str(p).lower() for p in (ROOT/'src').rglob('*')):
        fail('JJ donor runtime path introduced under src')

def check_kcp_upstream_implementation_ownership():
    require('src/apps/daemon/go.mod','github.com/xtaci/kcp-go/v5 v5.6.72')
    if any('kcp-go' in str(p).lower() for p in (ROOT/'src').rglob('*') if 'go.mod' not in p.name):
        fail('vendored/copy KCP implementation introduced under src')

def check_kcp_upstream_instrumentation_ownership():
    require('src/apps/daemon/internal/networking/kcppolicy/policy.go','func Resolve(')
    s=text('src/apps/daemon/internal/networking/kcppolicy/policy.go')
    for token in ('SNMP', 'entropy', 'autotune'):
        if token in s: fail(f'upstream KCP internal instrumentation copied into policy owner: {token}')

def check_kcp_aead_opt_in():
    s=require('src/apps/daemon/internal/runtime/proxy/kcp_transport.go','kcp.NewAESGCMCrypt','case "aes-gcm", "aes-gcm-256"')
    if 'case "aes-256":' not in s: fail('legacy AES compatibility path disappeared')
    require('src/apps/daemon/internal/networking/proxyconfig/post_refactor_224_test.go','TestPostRefactor224KCPAESGCMMethodRoundTrip')

def check_mesh_control_plane_supersession():
    require('src/apps/daemon/internal/analysis/diagnostics/mesh_route_plan.go','BuildMeshRoutePlan')
    if any('l7-snake' in str(p).lower() for p in (ROOT/'src').rglob('*')):
        fail('l7-snake donor control-plane path introduced under src')

def check_libxray_platform_supersession():
    require('src/apps/daemon/internal/platform/system/host_network.go','newHostNetworkManager')
    require('src/apps/daemon/internal/runtime/proxy/core_manager.go','type CoreManager struct')

def check_logdemux_daemon_supersession():
    require('src/apps/daemon/internal/adapters/api/websocket.go','type Hub struct')
    if any('log-demultiplexer' in str(p).lower() for p in (ROOT/'src').rglob('*')):
        fail('donor log-demultiplexer daemon introduced under src')

def check_marionette_transport_supersession():
    require('src/apps/daemon/internal/analysis/diagnostics/traffic_profile_plan.go','DeclarativeOnly','ExecutesPlugins')
    if any('marionette' in str(p).lower() for p in (ROOT/'src').rglob('*')):
        fail('Marionette runtime/transport path introduced under src')

def main():
    delta_count=check_delta_evidence()
    counts=check_surface_evidence()
    check_mutation_retry(); check_websocket_guardrails(); check_kcp_guardrails(); check_single_proxy_owner(); check_endpoint_guardrails()
    check_dns_guardrails(); check_l7_guardrails(); check_traffic_guardrails(); check_routing_guardrails(); check_relay_guardrails()
    check_secret_guardrails(); check_tls_guardrails(); check_privileged_guardrails(); check_lacuna_guardrail(); check_routing_and_parser(); check_operator_surface()
    check_server_held_long_poll_rejection(); check_balancer_service_supersession(); check_job_persistence_single_owner(); check_dns_mutation_rejection()
    check_shellcode_release_exclusion(); check_libxray_helper_supersession(); check_relay_runtime_single_owner(); check_kcp_upstream_implementation_ownership()
    check_kcp_upstream_instrumentation_ownership(); check_kcp_aead_opt_in(); check_mesh_control_plane_supersession(); check_libxray_platform_supersession()
    check_logdemux_daemon_supersession(); check_marionette_transport_supersession()
    if errors:
        print(f'post-refactor-224 convergence: FAIL errors={len(errors)}')
        for e in errors: print('ERROR:',e)
        return 1
    a,s,d,sy,l=counts
    print(f'post-refactor-224 convergence: PASS baseline=2946 delta={delta_count} archives={a} surfaces={s} directories={d} symbols={sy} semantic_records={l} default_attempts=3 max_attempts=8')
    return 0

if __name__=='__main__': raise SystemExit(main())
