#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, re, stat, sys, zipfile
from collections import Counter, defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; E=ROOT/'governance/convergence'
DONORS=Path(os.environ.get('LUMINET_236_DONORS','/mnt/data/luminet236_work/donors'))
if not DONORS.is_dir():
 print(f'SKIP: post-refactor-236 donor archives not mounted at {DONORS}; the donor cross-check is machine-local and cannot run here.')
 sys.exit(0)
META=Path(os.environ.get('LUMINET_236_META','/mnt/data/luminet236_work/meta'))
ORIG=Path(os.environ.get('LUMINET_236_ARCHIVES','/mnt/data'))
errors=[]; assertions=0
def check(cond,msg):
    global assertions; assertions+=1
    if not cond: errors.append(msg)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def rcsv(p):
    with Path(p).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))

summary=json.loads((E/'post-refactor-236-evidence-summary.json').read_text())
surfs=rcsv(E/'post-refactor-236-surface-accountability.csv'); mods=rcsv(E/'post-refactor-236-module-audit.csv'); ledger=rcsv(E/'post-refactor-236-semantic-ledger.csv'); defs=rcsv(E/'post-refactor-236-symbols.csv'); dirs=rcsv(E/'post-refactor-236-directories.csv'); archives=rcsv(E/'post-refactor-236-archive-accountability.csv'); syms=rcsv(E/'post-refactor-236-symlinks.csv'); delta=rcsv(E/'post-refactor-236-target-delta.csv')
check(summary['outer_donors']==20,'outer donor count');check(summary['regular_files']==938,'surface count summary');check(len(surfs)==938,'surface rows');check(len(mods)==142,'module rows');check(len(defs)==5653,'definition rows');check(len(dirs)==245,'directory rows');check(len(ledger)==79,'semantic ledger rows');check(summary['focused_semantic_records']==59,'focused records');check(summary['unresolved_modules']==0,'unresolved modules summary');check(summary['unresolved_high_signal_surfaces']==0,'unresolved high signal summary');check(sum(int(r['high_signal']) for r in surfs)==721,'high signal exact');check(sum(int(r['ui_product']) for r in surfs)==223,'ui product exact')

# Archive bytes and admission snapshots.
archive_by_d={r['donor']:r for r in archives};check(len(archive_by_d)==20,'archive donor identities unique')
for r in archives:
    p=ORIG/r['archive'];check(p.is_file(),f"archive missing {r['archive']}")
    if p.is_file():
        check(sha(p)==r['sha256'],f"archive hash drift {r['archive']}")
        try:
            with zipfile.ZipFile(p) as z:
                check(z.testzip() is None,f"archive CRC {r['archive']}")
        except Exception as e: errors.append(f"archive open {r['archive']}: {e}")
check(sum(int(r['members']) for r in archives)==1197,'archive member total');check(sum(int(r['symlinks']) for r in archives)==6,'archive symlink total')

# Every extracted file is present, hash-equal, linked to one known module and at least donor envelope.
modids={r['module_record_id']:r for r in mods}; semids={r['record_id']:r for r in ledger}; seen=set(); module_surface_counts=Counter()
for r in surfs:
    key=(r['donor'],r['path']);check(key not in seen,f'duplicate surface {key}');seen.add(key)
    p=DONORS/r['donor']/r['path'];check(p.is_file(),f'missing donor surface {key}')
    if p.is_file():
        check(sha(p)==r['sha256'],f'hash drift {key}');check(str(p.stat().st_size)==r['size_bytes'],f'size drift {key}')
    check(r['module_record_id'] in modids,f'missing module backlink {key}')
    module_surface_counts[r['module_record_id']]+=1
    ids=[x for x in r['semantic_record_ids'].split(';') if x];check(bool(ids),f'no semantic backlink {key}')
    for sid in ids:check(sid in semids,f'unknown semantic backlink {key}:{sid}')
    check(r['disposition']=='resolved' and r['unresolved']=='0',f'unresolved surface {key}')
for mid,r in modids.items():
    check(r['unresolved']=='0',f'unresolved module {mid}');check(module_surface_counts[mid]==int(r['surfaces']),f'module surface count {mid}');check(bool(r['semantic_record_ids']),f'module no semantic backlinks {mid}')

# Semantic records are exact-evidence anchored and every donor has envelope + focused evidence.
levels=Counter(); disp=Counter(); donors=defaultdict(lambda:Counter())
for r in ledger:
    levels[r['level']]+=1;disp[r['disposition']]+=1;donors[r['donor']][r['level']]+=1
    p=DONORS/r['donor']/r['source_path'];check(p.is_file(),f"semantic source missing {r['record_id']}")
    if p.is_file():check(sha(p)==r['source_sha256'],f"semantic hash drift {r['record_id']}")
    check(bool(r['invariant']),f"semantic invariant missing {r['record_id']}");check(bool(r['negative_invariant']),f"negative invariant missing {r['record_id']}");check(r['validation_status'] in {'verified','statically-validated','reviewed','inferred','unverified','pending'},f"bad validation status {r['record_id']}")
for d in archive_by_d:
    check(donors[d]['repository']==1,f'{d} repository envelope');check(sum(v for k,v in donors[d].items() if k!='repository')>=1,f'{d} no focused semantic record')
check(disp['rejected-with-reason']>=5,'negative guardrails retained');check(disp['adopted']>=15,'positive adopted primitives present')

# Definitions and directory/Merkle records remain exact path-backed evidence.
for r in defs:
    p=DONORS/r['donor']/r['path'];check(p.is_file(),f"definition file missing {r['donor']}:{r['path']}")
    if p.is_file():check(sha(p)==r['sha256'],f"definition hash drift {r['donor']}:{r['path']}:{r['line']}")
    check(int(r['line'])>=1,f"definition line invalid {r['name']}")
for r in dirs:
    check(r['donor'] in archive_by_d,f"unknown directory donor {r['donor']}");check(len(r['merkle_sha256'])==64,f"bad directory merkle {r['donor']}:{r['path']}")

# Symlink evidence: never materialized into donor tree, exact target retained.
check(len(syms)==6,'symlink records exact')
for r in syms:
    check(not (DONORS/r['donor']/r['path']).exists(),f"archived symlink materialized {r['path']}");check(bool(r['target']),f"empty symlink target {r['path']}")

# Target implementation and API/UI integration.
plans=(ROOT/'src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans.go').read_text(); tests=(ROOT/'src/apps/daemon/internal/analysis/diagnostics/post_refactor_236_plans_test.go').read_text(); jq=(ROOT/'src/apps/daemon/internal/analysis/diagnostics/jq_evaluator.go').read_text(); routes=(ROOT/'src/apps/daemon/internal/adapters/api/routes_system.go').read_text(); handlers=(ROOT/'src/apps/daemon/internal/adapters/api/handlers_post_refactor_236_planners.go').read_text(); handlers235=(ROOT/'src/apps/daemon/internal/adapters/api/handlers_post_refactor_235_planners.go').read_text(); ui=(ROOT/'src/packages/control-ui/src/pages/Operations.tsx').read_text(); uiscript=(ROOT/'src/packages/control-ui/scripts/test-post-refactor-236.mjs').read_text()
rows=[('clienthello-evidence-plan','PlanClientHelloEvidence','BuildClientHelloEvidencePlan','clientHelloEvidence'),('encrypted-dns-policy-plan','PlanEncryptedDNSPolicy','BuildEncryptedDNSPolicyPlan','encryptedDNSPolicy'),('tor-lab-relay-plan','PlanTorLabRelay','BuildTorLabRelayPlan','torLabRelay'),('proxy-chain-safety-plan','PlanProxyChainSafety','BuildProxyChainSafetyPlan','proxyChainSafety'),('transport-replay-plan','PlanTransportReplay','BuildTransportReplayPlan','transportReplay'),('secret-refresh-policy-plan','PlanSecretRefreshPolicy','BuildSecretRefreshPolicyPlan','secretRefreshPolicy'),('reality-admission-plan','PlanRealityAdmission','BuildRealityAdmissionPlan','realityAdmission'),('service-recovery-policy-plan','PlanServiceRecoveryPolicy','BuildServiceRecoveryPolicyPlan','serviceRecoveryPolicy'),('network-trust-bundle-plan','PlanNetworkTrustBundle','BuildNetworkTrustBundlePlan','networkTrustBundle')]
for ep,h,fn,opt in rows:
    check(f'"/{ep}"' in routes,f'route {ep}');check(f'func (s *Server) {h}' in handlers,f'handler {h}');check(f'func {fn}' in plans,f'planner {fn}');check(f'value="{opt}"' in ui,f'UI option {opt}');check(f'/api/system/{ep}' in ui,f'UI endpoint {ep}')
for bad in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','syscall.','systemctl','iptables','pfctl']:
    check(bad not in handlers,f'236 handler side effect {bad}')
check('RunWithContext(ctx, input)' in jq,'jq context execution');check('const maxJQResults = 4096' in jq,'jq result cap');check('SetModuleLoader' not in jq and 'SetEnvironLoader' not in jq and 'SetInputIter' not in jq,'jq loader boundary');check('func (s *Server) PlanNetworkEvidenceBundle(c *gin.Context)' in handlers235,'235 bundle Gin signature');check('echo.Context' not in handlers235,'stale Echo signature removed');check('post-refactor-236 product/security convergence characterization' in uiscript,'UI characterization script')
for token in ['InsecureSkipVerify/TLS1.1/RC4 compatibility is not ported','shared embedded key never becomes a LumiNet trust root','list order alone never makes an endpoint best','no LD_PRELOAD or API-hook runtime is imported']:
    check(any(token in r['negative_invariant'] for r in ledger),f'negative donor lesson {token}')
for fn in ['TestPostRefactor236ClientHelloNormalizesGREASEAndDetectsQUICGaps','TestPostRefactor236EncryptedDNSPreservesExistingECSAndBoundsTTL','TestPostRefactor236TorLabCountsFailuresAndConsensus','TestPostRefactor236ProxyChainModesAreExplicit','TestPostRefactor236ReplayScopesSaltByKeyAndAge','TestPostRefactor236SecretRefreshKeepsUnknownLookupClosed','TestPostRefactor236RealityAdmissionRejectsMalformedShortIDs','TestPostRefactor236ServiceRecoveryRequiresValidatedRollbackPath','TestPostRefactor236NetworkTrustBundleDegradesConservatively']:
    check(f'func {fn}' in tests,f'missing focused Go test {fn}')

# Delta/evidence graph consistency.
dcounts=Counter(r['change_type'] for r in delta);check(summary['delta']==dict(dcounts),'delta summary exact');check(dcounts['deleted']==0,'236 introduces no source deletion');check(summary['all_history']['unique_donors']==123,'all-history identity count');check(summary['all_history']['surfaces']==85563,'all-history surface count')

if errors:
    for e in errors[:100]: print('ERROR',e,file=sys.stderr)
    if len(errors)>100:print(f'ERROR ... {len(errors)-100} more',file=sys.stderr)
    print(f'post-refactor-236 convergence assertions={assertions} errors={len(errors)}')
    sys.exit(1)
print(f'post-refactor-236 convergence assertions={assertions} errors=0')
