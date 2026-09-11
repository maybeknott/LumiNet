#!/usr/bin/env python3
"""Independent verification for the post-refactor-232 four-donor convergence wave."""
from __future__ import annotations
import csv, hashlib, json, os, stat, sys, zipfile
from collections import defaultdict
from pathlib import Path, PurePosixPath

ROOT=Path(os.environ.get('LUMINET_232_TARGET_ROOT',Path(__file__).resolve().parents[2]))
WORK=Path(os.environ.get('LUMINET_232_WORK_ROOT','/mnt/data/luminet232_work'))
E=ROOT/'governance/convergence'; BASE=E/'post-refactor-232-baseline-files.csv'; DONOR_BASE=WORK/'donors'
if not WORK.is_dir() or not Path('/mnt/data/LumiNet-post-refactor-232-source-inventory.csv').is_file():
 print(f'SKIP: post-refactor-232 donor archives not mounted at {WORK}; the donor cross-check is machine-local and cannot run here.')
 sys.exit(0)
ROOTS={'splitpt':'splitpt-main','dns-tunnel-deploy':'dns-tunnel-deploy-main','outline-client':'outline-client-master','pydns-scanner':'PYDNS-Scanner-main'}
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'}
assertions=0; errors=[]
def check(c,msg):
 global assertions; assertions+=1
 if not c: errors.append(msg)
def sha_file(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def readcsv(name):
 with (E/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def text(p):return (ROOT/p).read_text(encoding='utf-8',errors='replace')
def norm(name):
 p=PurePosixPath(name.replace('\\','/'))
 if p.is_absolute() or any(x in {'','.', '..'} for x in p.parts) or (p.parts and ':' in p.parts[0]):raise ValueError(name)
 return p

SUCCESSOR_233=E/'post-refactor-233-baseline-files.csv'
if SUCCESSOR_233.is_file():
 released=Path('/mnt/data/LumiNet-post-refactor-232-source-inventory.csv')
 check(released.is_file(),'released 232 source inventory available')
 if released.is_file():
  with released.open(newline='',encoding='utf-8') as f: released_rows=list(csv.DictReader(f))
  with SUCCESSOR_233.open(newline='',encoding='utf-8') as f: successor_rows=list(csv.DictReader(f))
  check(successor_rows==released_rows,'233 embeds exact released 232 source inventory rows')
  check(len(successor_rows)==3255,'232 frozen inventory has 3255 files')
  frozen=[r for r in successor_rows if r['path'].startswith('governance/convergence/post-refactor-232-')]
  check(len(frozen)==23,'23 frozen post-refactor-232 governance artifacts')
  for r in frozen:
   q=ROOT/r['path'];check(q.is_file(),f'232 frozen artifact exists {r["path"]}')
   if q.is_file():
    check(sha_file(q)==r['sha256'],f'232 frozen artifact hash {r["path"]}')
    check(str(q.stat().st_size)==r['size_bytes'],f'232 frozen artifact size {r["path"]}')
    check(oct(stat.S_IMODE(q.stat().st_mode))==r['mode'],f'232 frozen artifact mode {r["path"]}')
  frozen_summary=json.loads((E/'post-refactor-232-evidence-summary.json').read_text())
  for k,v in {'outer_donors':4,'surfaces':750,'definitions':611,'module_records':218,'semantic_value_records':47,'unresolved_high_signal_surfaces':0}.items():check(frozen_summary.get(k)==v,f'232 frozen summary {k}')
 print(f'post-refactor-232 successor evidence: assertions={assertions} errors={len(errors)}')
 if errors:
  for e in errors:print('ERROR',e)
  sys.exit(1)
 sys.exit(0)

required=['post-refactor-232-archive-accountability.csv','post-refactor-232-surface-accountability.csv','post-refactor-232-directories.csv','post-refactor-232-symbols.csv','post-refactor-232-symlinks.csv','post-refactor-232-module-audit.csv','post-refactor-232-adoption-ledger.csv','post-refactor-232-supersession-map.csv','post-refactor-232-evidence-summary.json','post-refactor-232-baseline-files.csv','post-refactor-232-target-delta.csv','post-refactor-232-all-history-surface-audit.csv','post-refactor-232-all-history-symbol-index.csv','post-refactor-232-all-history-module-audit.csv','post-refactor-232-all-history-summary.json','post-refactor-232-architecture.md','post-refactor-232-security-model.md','post-refactor-232-state-machines.md','post-refactor-232-peer-synthesis.md','post-refactor-232-omission-audit.md','post-refactor-232-operator-runbook.md','post-refactor-232-validation.md','post-refactor-232-all-history-second-order-audit.md']
for n in required:check((E/n).is_file(),f'missing evidence {n}')
if errors:
 print('\n'.join(errors));sys.exit(1)
summary=json.loads((E/'post-refactor-232-evidence-summary.json').read_text())
expected={'outer_donors':4,'archive_members':1036,'surfaces':750,'directories':286,'definitions':611,'symlinks':0,'module_records':218,'high_signal_surfaces':433,'ui_product_surfaces':57,'semantic_value_records':47,'repository_records':4,'file_records':750,'ledger_records':1019,'baseline_files':3219,'vendored_surfaces':77,'unresolved_high_signal_surfaces':0}
for k,v in expected.items():check(summary.get(k)==v,f'summary {k}: {summary.get(k)!r} != {v!r}')
check(sha_file(BASE)=='1eaf71719e55474a146ce6d2be2baafda3ae44cacadff9fc0df8878f3da463e7','exact released 231 inventory embedded')

surfs=readcsv('post-refactor-232-surface-accountability.csv');check(len(surfs)==750,'750 surfaces');by={(r['donor'],r['path']):r for r in surfs};check(len(by)==750,'surface keys unique')
links=readcsv('post-refactor-232-symlinks.csv');check(len(links)==0,'zero symlinks')
arch=readcsv('post-refactor-232-archive-accountability.csv');check(len(arch)==4,'4 archives');arch_by={r['archive']:r for r in arch};check(len(arch_by)==4,'archive keys unique')
expected_arch={
 'splitpt-main(1).zip':'3de5227b2ac083afcda89b2201faea25b1cdf735424e8f1bc86b6d7a72c7f3a4',
 'dns-tunnel-deploy-main(1).zip':'d07306fb557595cfde33175f0202ed3d8f3244c8314d1f172c1b7c46e8058c96',
 'outline-client-master(1).zip':'3cfdb6fa1a811f928eb6a6d9c439ee855232c51ac6a97f8a18d3a15b11ebe358',
 'PYDNS-Scanner-main(1).zip':'da2aae8579164cbbb2198000f53fe2e5a6eabe883b7d7fe7f2b80316c4a4b75c'}
for name,digest in expected_arch.items():
 p=Path('/mnt/data')/name; row=arch_by.get(name);check(row is not None,f'archive evidence {name}');check(p.is_file(),f'archive exists {name}')
 if row is None or not p.is_file():continue
 check(sha_file(p)==digest==row['archive_sha256'],f'archive hash {name}')
 donor=row['donor']; prefix=ROOTS[donor]+'/'
 with zipfile.ZipFile(p) as z:
  check(z.testzip() is None,f'CRC {name}');infos=z.infolist();check(len(infos)==int(row['members']),f'member count {name}')
  seen=set();fold=set();files=dirs=symlinks=0;total=0
  for info in infos:
   try: rel=norm(info.filename)
   except ValueError:check(False,f'unsafe member {name}:{info.filename}');continue
   key=rel.as_posix().rstrip('/');check(key not in seen,f'duplicate {name}:{key}');check(key.casefold() not in fold,f'case collision {name}:{key}');seen.add(key);fold.add(key.casefold());check(not(info.flag_bits&1),f'encrypted {name}:{key}')
   mode=info.external_attr>>16;kind=stat.S_IFMT(mode);islink=stat.S_ISLNK(mode);check(kind in {0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK},f'special {name}:{key}')
   inner=key[len(prefix):] if key.startswith(prefix) else key
   if islink:symlinks+=1
   elif info.is_dir():dirs+=1
   else:
    files+=1;total+=info.file_size; sr=by.get((donor,inner));check(sr is not None,f'file evidence {donor}:{inner}')
    if sr is not None:
     data=z.read(info);check(str(len(data))==sr['size_bytes'],f'archive size {donor}:{inner}');check(hashlib.sha256(data).hexdigest()==sr['sha256'],f'archive bytes {donor}:{inner}')
   if info.compress_size:check(info.file_size/info.compress_size<=1000.0,f'compression ratio {name}:{key}')
  check(files==int(row['files']),f'file count {name}');check(dirs==int(row['dirs']),f'dir count {name}');check(symlinks==int(row['symlinks']),f'symlink count {name}');check(total==int(row['uncompressed_bytes']),f'uncompressed bytes {name}')

# Extracted donor bytes/modes and surface backlinks.
for r in surfs:
 p=DONOR_BASE/r['donor']/ROOTS[r['donor']]/r['path'];check(p.is_file() and not p.is_symlink(),f'donor file exists {r["donor"]}:{r["path"]}')
 if p.is_file():
  check(str(p.stat().st_size)==r['size_bytes'],f'size {r["donor"]}:{r["path"]}');check(oct(stat.S_IMODE(p.stat().st_mode))==r['mode'],f'mode {r["donor"]}:{r["path"]}');check(sha_file(p)==r['sha256'],f'hash {r["donor"]}:{r["path"]}')
 check(r['semantic_record_ids']!='',f'surface backlinks {r["donor"]}:{r["path"]}');check(r['post_refactor_232_disposition'] not in {'','pending','unresolved'},f'disposition {r["donor"]}:{r["path"]}')
 if r['classification'] in HIGH:check('PR232-F' in r['semantic_record_ids'] and 'PR232-M' in r['semantic_record_ids'],f'high-signal ownership {r["donor"]}:{r["path"]}')

# Rebuild Merkle evidence in the same normalized path order, independently from CSV values.
rows_by=defaultdict(list)
for r in surfs:rows_by[r['donor']].append(r)
recomputed={}
for donor in sorted(rows_by):
 desc=defaultdict(list); direct=defaultdict(int); child=defaultdict(set); dirs_seen={'.'}
 for r in sorted(rows_by[donor],key=lambda x:x['path']):
  parts=r['path'].split('/');anc=['.']+['/'.join(parts[:i]) for i in range(1,len(parts))]
  for d in anc:desc[d].append(r);dirs_seen.add(d)
  parent='.' if len(parts)==1 else '/'.join(parts[:-1]);direct[parent]+=1
  for i in range(1,len(parts)):
   d='/'.join(parts[:i]);parent='.' if i==1 else '/'.join(parts[:i-1]);child[parent].add(d)
 for d in dirs_seen:
  h=hashlib.sha256()
  for r in desc[d]:h.update(f"F\0{r['path']}\0{r['sha256']}\0{r['size_bytes']}\0{r['mode']}\n".encode())
  recomputed[(donor,d)]=(h.hexdigest(),str(direct[d]),str(len(child[d])),str(len(desc[d])),'0')
dirs=readcsv('post-refactor-232-directories.csv');check(len(dirs)==286,'286 directory records');check(len({(r['donor'],r['directory']) for r in dirs})==286,'directory keys unique')
for r in dirs:
 got=recomputed.get((r['donor'],r['directory']));check(got is not None,f'merkle key {r["donor"]}:{r["directory"]}')
 if got is not None:
  check(got[0]==r['tree_sha256'],f'merkle {r["donor"]}:{r["directory"]}');check(got[1]==r['direct_files'],f'direct files {r["donor"]}:{r["directory"]}');check(got[2]==r['direct_dirs'],f'direct dirs {r["donor"]}:{r["directory"]}');check(got[3]==r['descendant_files'],f'desc files {r["donor"]}:{r["directory"]}');check(got[4]==r['descendant_symlinks'],f'desc links {r["donor"]}:{r["directory"]}')

# Definition evidence resolves to exact file/source line.
defs=readcsv('post-refactor-232-symbols.csv');check(len(defs)==611,'611 definitions');line_cache={}
for r in defs:
 s=by.get((r['donor'],r['path']));check(s is not None,f'def file backlink {r["donor"]}:{r["path"]}')
 if s:check(s['sha256']==r['sha256'],f'def file hash {r["donor"]}:{r["path"]}');check(s['classification']!='vendored',f'vendored definition excluded {r["donor"]}:{r["path"]}')
 k=(r['donor'],r['path'])
 if k not in line_cache:line_cache[k]=(DONOR_BASE/r['donor']/ROOTS[r['donor']]/r['path']).read_text(encoding='utf-8',errors='replace').splitlines()
 try:actual=line_cache[k][int(r['line'])-1].strip()[:320]
 except Exception:actual='__MISSING__'
 check(actual==r['snippet'],f'def source line {r["donor"]}:{r["path"]}:{r["line"]}')

# Decision graph.
ledger=readcsv('post-refactor-232-adoption-ledger.csv');check(len(ledger)==1019,'1019 ledger rows');ids={r['record_id'] for r in ledger};check(len(ids)==1019,'ledger IDs unique');parents={r['record_id']:r['parent_record_id'] for r in ledger}
check(sum(r['record_id'].startswith('PR232-R') for r in ledger)==4,'4 repository records');check(sum(r['record_id'].startswith('PR232-M') for r in ledger)==218,'218 module records');check(sum(r['record_id'].startswith('PR232-F') for r in ledger)==750,'750 file records');focus=[r for r in ledger if r['record_id'].startswith('PR232-S')];check(len(focus)==47,'47 focused records')
for r in ledger:
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in ids,f'parent exists {r["record_id"]}')
 check(r['validation_status'] in {'verified','statically-validated','reviewed','inferred','unverified','pending'},f'valid status {r["record_id"]}')
for r in focus:
 s=by.get((r['donor'],r['donor_path']));check(s is not None,f'focus source {r["record_id"]}')
 if s:check(r['record_id'] in s['semantic_record_ids'].split(';'),f'focus backlink {r["record_id"]}')
 for n in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:
  check((ROOT/n.split('#',1)[0]).exists(),f'focus target {r["record_id"]}:{n}')
 if r['test_node']!='n/a':check((ROOT/r['test_node'].split('#',1)[0]).exists(),f'focus test {r["record_id"]}')
for rid in ids:
 seen=set();cur=rid
 while cur!='n/a':check(cur not in seen,f'parent cycle {rid}');seen.add(cur);cur=parents.get(cur,'n/a')
mods=readcsv('post-refactor-232-module-audit.csv');check(len(mods)==218,'218 module rows');check(sum(int(r['surfaces']) for r in mods)==750,'module surface partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==433,'module high partition');check(sum(int(r['ui_product_surfaces']) for r in mods)==57,'module UI partition')

# Exact predecessor append.
prev_s=readcsv('post-refactor-231-all-history-surface-audit.csv');hist_s=readcsv('post-refactor-232-all-history-surface-audit.csv');check(len(prev_s)==51673 and len(hist_s)==52423,'history surface counts');check(hist_s[:len(prev_s)]==prev_s,'history surface predecessor prefix exact')
prev_d=readcsv('post-refactor-231-all-history-symbol-index.csv');hist_d=readcsv('post-refactor-232-all-history-symbol-index.csv');check(len(prev_d)==79330 and len(hist_d)==79941,'history definition counts');check(hist_d[:len(prev_d)]==prev_d,'history definition predecessor prefix exact')
prev_m=readcsv('post-refactor-231-all-history-module-audit.csv');hist_m=readcsv('post-refactor-232-all-history-module-audit.csv');check(len(prev_m)==1586 and len(hist_m)==1804,'history module counts');check(hist_m[:len(prev_m)]==prev_m,'history module predecessor prefix exact')
ah=json.loads((E/'post-refactor-232-all-history-summary.json').read_text()); expah={'unique_donors':80,'surfaces':52423,'definitions':79941,'module_records':1804,'high_signal_surfaces':13459,'ui_product_surfaces':2668}
for k,v in expah.items():check(ah.get(k)==v,f'all-history {k}')

# Exact predecessor -> 232 delta.
with BASE.open(newline='',encoding='utf-8') as f:base={r['path']:r for r in csv.DictReader(f)}
delta=readcsv('post-refactor-232-target-delta.csv');dby={(r['change_type'],r['path']):r for r in delta};check(len(dby)==len(delta),'delta keys unique');cur={}
for p in ROOT.rglob('*'):
 if not p.is_file() or p.is_symlink():continue
 rel=p.relative_to(ROOT).as_posix()
 if rel=='governance/convergence/post-refactor-232-target-delta.csv' or rel.startswith('.git/') or '/node_modules/' in '/'+rel or '__pycache__' in rel:continue
 cur[rel]={'sha256':sha_file(p),'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode))}
expected_delta={}
for path in set(base)|set(cur):
 b,c=base.get(path),cur.get(path)
 if b is None:typ='added'
 elif c is None:typ='deleted'
 elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
 else:continue
 expected_delta[(typ,path)]=(b,c)
check(set(dby)==set(expected_delta),'delta path/type exact')
for key,(b,c) in expected_delta.items():
 r=dby.get(key)
 if r:check(r['baseline_sha256']==(b['sha256'] if b else 'n/a'),f'delta baseline {key}');check(r['current_sha256']==(c['sha256'] if c else 'n/a'),f'delta current {key}')

# Target contracts.
contracts={
 'src/apps/daemon/internal/analysis/diagnostics/multipath_transport_plan.go':['multipathSessionIDBytes      = 8','multipathLengthPrefixBytes   = 2','multipathMaxPacketBytes      = 65535','multipathDefaultQueuePackets = 32','backpressure','reject-new','sort.Strings(plan.EligiblePaths)','DropsSilently: false','StartsTransports: false','PerformsNetworkIO: false','WritesPackets: false'],
 'src/apps/daemon/internal/analysis/diagnostics/dns_resolver_campaign_plan.go':['maxDNSCampaignCandidates  = 10_000_000','maxDNSCampaignConcurrency = 2048','maxDNSCampaignDrain       = 5000','batch := concurrency / 4','batch = 4','batch = 16','scan-%x','DownloadsClients: false','MutatesMTU: false','PerformsNetworkIO: false','StartsWorkerThread: false'],
 'src/apps/daemon/internal/analysis/diagnostics/outline_access_plan.go':['maxOutlineAccessCandidateBytes = 8192','FingerprintSHA256','ssconf://','u.Scheme = "https"','public global-unicast','EvaluateExternalCoreCompatibility','PerformsNetworkIO: false','PersistsSecret: false'],
 'src/apps/daemon/internal/networking/dnstunnel/deployment_plan.go':['mtu = 1232','mtu < 512 || mtu > 1400','listen = 5300','RedirectUDPPort: 53','RequiresRoot: true','DownloadsBinary: false','MutatesFirewall: false','WritesSystemd: false','GeneratesKeys: false','PerformsNetworkIO: false'],
 'src/apps/daemon/internal/integrations/sub/outline_import.go':['maxOutlineInviteBytes = 8192','url.PathUnescape','ParseProxyURI','ProtocolShadowsocks']}
for p,toks in contracts.items():
 body=text(p)
 for tok in toks:check(tok in body,f'contract {p}:{tok}')
ingest=text('src/apps/daemon/internal/integrations/sub/ingest.go');check('unwrapOutlineStaticInvite(content)' in ingest,'Outline import wired');check(ingest.index('unwrapOutlineStaticInvite(content)')<ingest.index('parseLumiNetBundle'),'Outline import before generic format detection')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
for route in ['/multipath-transport-plan','/dns-resolver-campaign-plan','/outline-access-plan','/dns-tunnel-deployment-plan']:check(route in routes,f'232 route {route}')
handlers=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_232_planners.go');check(all(x not in handlers for x in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.Chmod(']),'232 handlers side-effect free')
ops=text('src/packages/control-ui/src/pages/Operations.tsx')
for tok in ['multipathTransport','dnsResolverCampaign','outlineAccess','dnsTunnelDeployment','Convergence policy lab']:check(tok in ops,f'Operations 232 surface {tok}')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:232')=='node scripts/test-post-refactor-232.mjs','test:232 script');check('npm run test:232' in pkg['scripts']['test'] and (pkg['scripts'].get('test:233') is None or pkg['scripts']['test'].endswith('&& npm run test:233')),'aggregate UI includes 232 and successor tail')
product=text('src/packages/control-ui/scripts/test-post-refactor-232.mjs');check('checks !== 117' in product,'232 UI denominator 117')
for p,toks in {
 'src/apps/daemon/internal/analysis/diagnostics/post_refactor_232_plans_test.go':['TestPostRefactor232MultipathRoundRobinAndAuthority','TestPostRefactor232DNSCampaignLifecycleAndBatching','TestPostRefactor232OutlineStaticDynamicAndInvite'],
 'src/apps/daemon/internal/networking/dnstunnel/deployment_plan_test.go':['TestPostRefactor232DeploymentDefaultsAndAuthority','TestPostRefactor232DeploymentRejectsUnsafeInputs'],
 'src/apps/daemon/internal/integrations/sub/outline_import_test.go':['TestPostRefactor232OutlineInviteUnwrapsLocally','TestPostRefactor232OutlineDynamicURLIsNotFetchedByContentParser']}.items():
 body=text(p)
 for tok in toks:check(tok in body,f'232 Go test {p}:{tok}')
mk=text('Makefile');check('post-refactor-232-evidence' in mk and 'check_post_refactor_232_convergence.py' in mk,'Makefile owns 232')
reports={'post-refactor-232-architecture.md':['Four donors','750 files','local-only Outline static invite'],'post-refactor-232-security-model.md':['no transports','ssconf','private key material'],'post-refactor-232-state-machines.md':['idle, running, paused','backpressure','rollback'],'post-refactor-232-peer-synthesis.md':['SplitPT','DNS-Tunnel-Deploy','Outline','PYDNS'],'post-refactor-232-omission-audit.md':['750/750','611/611','unresolved high-signal surfaces: 0'],'post-refactor-232-operator-runbook.md':['Convergence policy lab','guarded-egress'],'post-refactor-232-all-history-second-order-audit.md':['80 unique donor','52,423','79,941']}
for name,toks in reports.items():
 body=(E/name).read_text(encoding='utf-8',errors='replace')
 for tok in toks:check(tok in body,f'{name} token {tok}')
print(f'post-refactor-232 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:500]:print('ERROR',e)
 if len(errors)>500:print(f'... {len(errors)-500} more')
 sys.exit(1)
