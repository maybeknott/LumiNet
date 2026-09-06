#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json, os, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]; E=ROOT/'governance/convergence'; A=0; ERR=[]
def check(c,m):
 global A; A+=1
 if not c: ERR.append(m)
def rcsv(n):
 with (E/n).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def txt(p):return (ROOT/p).read_text(encoding='utf-8',errors='replace')
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
req=['semantic-ledger.csv','module-semantic-audit.csv','supersession-map.csv','baseline-files.csv','target-delta.csv','evidence-summary.json','all-history-summary.json','architecture.md','security-model.md','state-machines.md','peer-synthesis.md','omission-audit.md','operator-runbook.md','validation.md','all-history-second-order-audit.md']
for s in req:check((E/f'post-refactor-235-{s}').is_file(),f'missing {s}')
if ERR:print('\n'.join(ERR));sys.exit(1)
sm=json.loads((E/'post-refactor-235-evidence-summary.json').read_text());check(sm['baseline_release']=='post-refactor-234','baseline');check(sm['source_surfaces_reexamined']==3769,'3769 surfaces');check(sm['module_groups_reexamined']==921,'921 modules');check(sm['semantic_records_total']>=88,'semantic depth');check(sm['focused_semantic_records']>=75,'focused depth');check(sm['unresolved_modules']==0,'module unresolved');check(sm['unresolved_high_signal_surfaces']==0,'high signal unresolved');check(sm['new_read_only_planners']==9,'planner count')
# Exact baseline release bytes and inventory.
bz=Path('/mnt/data/luminet234/release/LumiNet-post-refactor-234-converged-working-tree.zip')
if bz.is_file():
    check(sha(bz)=='cb63130f0c3e4f7a748751a179630a8f73bee8cd3aeec4bf15450b993a075396','234 zip identity')
else:
    print('SKIP: post-refactor-234 release zip not mounted; zip byte-identity cross-check is machine-local.')
base=rcsv('post-refactor-235-baseline-files.csv');check(len(base)==3316,'3316 baseline files')
# Semantic records are exact donor paths/hashes from the frozen 234 evidence.
surf=rcsv('post-refactor-234-surface-accountability.csv');smap={(r['donor'],r['path']):r for r in surf};check(len(smap)==3769,'surface unique')
ledger=rcsv('post-refactor-235-semantic-ledger.csv');check(len({r['record_id'] for r in ledger})==len(ledger),'semantic ids unique')
for r in ledger:
 s=smap.get((r['donor'],r['source_path']));check(s is not None,f'source {r["record_id"]}')
 if s:check(s['sha256']==r['source_sha256'],f'hash {r["record_id"]}')
 check(r['validation_status'] in {'verified','reviewed','statically-validated','inferred','unverified','pending'},f'status {r["record_id"]}')
 for n in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:
  check((ROOT/n.split('#',1)[0]).exists(),f'target node {r["record_id"]}:{n}')
mods=rcsv('post-refactor-235-module-semantic-audit.csv');check(len(mods)==921,'module count');check(sum(int(r['surfaces']) for r in mods)==3769,'module partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==2061,'high-signal partition');check(sum(int(r['ui_product_surfaces']) for r in mods)==299,'ui partition')
for r in mods:check(r['unresolved']=='0','module resolved');check(bool(r['semantic_record_ids']),'module backlink')
# Changed target semantics and authority boundaries.
plans=txt('src/apps/daemon/internal/analysis/diagnostics/post_refactor_235_plans.go');prior=txt('src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go');routes=txt('src/apps/daemon/internal/adapters/api/routes_system.go');handlers=txt('src/apps/daemon/internal/adapters/api/handlers_post_refactor_235_planners.go');ops=txt('src/packages/control-ui/src/pages/Operations.tsx');dns=txt('src/apps/daemon/internal/analysis/diagnostics/dns_transport_integrity.go');dnst=txt('src/apps/daemon/internal/analysis/diagnostics/dns_transport_integrity_test.go')
items=[('scan-load-policy-plan','BuildScanLoadPolicyPlan','PlanScanLoadPolicy','scanLoadPolicy'),('mobile-connection-readiness-plan','BuildMobileConnectionReadinessPlan','PlanMobileConnectionReadiness','mobileConnectionReadiness'),('config-fallback-plan','BuildConfigFallbackPlan','PlanConfigFallback','configFallback'),('dns-intercept-safety-plan','BuildDNSInterceptSafetyPlan','PlanDNSInterceptSafety','dnsInterceptSafety'),('tor-consensus-evidence-plan','BuildTorConsensusEvidencePlan','PlanTorConsensusEvidence','torConsensusEvidence'),('dnscrypt-topology-plan','BuildDNSCryptTopologyPlan','PlanDNSCryptTopology','dnscryptTopology'),('evidence-receipt-topology-plan','BuildEvidenceReceiptTopologyPlan','PlanEvidenceReceiptTopology','evidenceReceiptTopology'),('dns-filter-preset-plan','BuildDNSFilterPresetPlan','PlanDNSFilterPreset','dnsFilterPreset'),('network-evidence-bundle-plan','BuildNetworkEvidenceBundlePlan','PlanNetworkEvidenceBundle','networkEvidenceBundle')]
for ep,fn,h,opt in items:check(fn in plans,fn);check(f'"/{ep}"' in routes,ep);check(f'func (s *Server) {h}' in handlers,h);check(f'value="{opt}"' in ops,opt);check(f'/api/system/{ep}' in ops,'ui '+ep)
for bad in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.MkdirAll(','os.Chmod(']:check(bad not in handlers,'handler side effect '+bad)
check('wild-scan timeout rate is informational and never independently proves congestion' in plans,'timeout guard');check('invalid or failed candidates stop fallback rather than being silently bypassed' in plans,'fallback guard');check('DNS-only flows must not create an otherwise-unused base transport session' in plans,'lazy dns');check('unknown signature or timestamp status never counts as complete' in plans,'unknown evidence');check('no scanner, DNS service, Tor controller, tunnel, proxy, packet mutator, or evidence signer is started' in plans,'bundle boundary')
check('SensitiveFieldsOmitted' in prior and 'authorization' in plans and 'x-api-key' in plans,'API redaction');check('ProcessProxyRuleFinding' in prior and 'shadowed' in prior and 'conflict' in prior,'rule findings')
check('insufficient-evidence' in dns and 'absence of evidence is not classified as clean' in dns,'dns unknown not clean');check('TestDNSTransportIntegrityEmptyReachableEvidenceIsNotClean' in dnst,'dns regression test')
check(not (ROOT/'src/apps/daemon/internal/analysis/scanner/adaptive_throttle.go').exists(),'orphan throttle retired');check(not (ROOT/'src/apps/daemon/internal/analysis/scanner/adaptive_throttle_alignment_test.go').exists(),'orphan-only test retired')
# Mutation retry stays single-authority and must not be shadowed here.
check('foundation/config.Manager.Mutate' in (E/'post-refactor-233-final-report.md').read_text(errors='ignore') if (E/'post-refactor-233-final-report.md').exists() else True,'historical retry owner')
for bad in ['MutateWithRetry','RetryMutation','AutomaticMutationRetry']:
 check(bad not in plans,'no duplicate retry '+bad)
# Negative lessons are explicit.
sec=(E/'post-refactor-235-security-model.md').read_text();check('Unknown evidence never becomes pass/clean' in sec,'unknown guard doc');check('no kernel extension/driver install' in ';'.join(r['negative_invariant'] for r in ledger),'kernel guard');check(any(r['donor']=='skivpn' and 'cookies/localStorage' in r['value_unit'] and r['disposition']=='rejected-with-reason' for r in ledger),'credential store rejected')
print(f'post-refactor-235 convergence assertions={A} errors={len(ERR)}')
if ERR:
 print('\n'.join(ERR[:100]));sys.exit(1)
