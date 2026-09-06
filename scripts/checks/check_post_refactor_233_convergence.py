#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json,os,stat,sys,zipfile
from collections import defaultdict
from pathlib import Path,PurePosixPath
ROOT=Path(os.environ.get('LUMINET_233_TARGET_ROOT',Path(__file__).resolve().parents[2]));WORK=Path(os.environ.get('LUMINET_233_WORK_ROOT','/mnt/data/luminet233_work'))
if not WORK.is_dir():
 print(f'SKIP: post-refactor-233 donor archives not mounted at {WORK}; the donor cross-check is machine-local and cannot run here.')
 sys.exit(0);E=ROOT/'governance/convergence';BASE=E/'post-refactor-233-baseline-files.csv';DON=WORK/'donors'
ROOTS={'location':'location-main','gfw_resist_https_proxy':'gfw_resist_HTTPS_proxy-main','kscanner':'kscanner-main','dnsrefiner':'DnsRefiner-main','exitmap':'exitmap-main','candyconnect':'CandyConnect-main','psiphon_over_mitm':'PsiphonOverMITM-main','personal_security_checklist':'personal-security-checklist-master','orbot_apple':'orbot-apple-main','karing':'karing-main','fptn':'fptn-master','https_everywhere':'https-everywhere-master'}
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'}; assertions=0;errors=[]
def check(c,m):
 global assertions;assertions+=1
 if not c:errors.append(m)
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def rcsv(n):
 with (E/n).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def text(p):return (ROOT/p).read_text(encoding='utf-8',errors='replace')
def norm(n):
 p=PurePosixPath(n.replace('\\','/'))
 if p.is_absolute() or any(x in {'','.', '..'} for x in p.parts) or (p.parts and ':' in p.parts[0]):raise ValueError(n)
 return p
def inner(d,key):
 pref=ROOTS[d]+'/';return key[len(pref):] if key.startswith(pref) else key
def donor_file(d,p):
 a=DON/d/ROOTS[d]/p
 return a if a.exists() else DON/d/p
required=['archive-accountability.csv','surface-accountability.csv','directories.csv','symbols.csv','symlinks.csv','module-audit.csv','adoption-ledger.csv','supersession-map.csv','evidence-summary.json','baseline-files.csv','target-delta.csv','all-history-surface-audit.csv','all-history-symbol-index.csv','all-history-module-audit.csv','all-history-summary.json','architecture.md','security-model.md','state-machines.md','peer-synthesis.md','omission-audit.md','operator-runbook.md','validation.md','all-history-second-order-audit.md']
for s in required:check((E/f'post-refactor-233-{s}').is_file(),f'missing {s}')
if errors:print('\n'.join(errors));sys.exit(1)
sm=json.loads((E/'post-refactor-233-evidence-summary.json').read_text());exp={'outer_donors':12,'archive_members':29304,'surfaces':28433,'directories':586,'definitions':3557,'symlinks':282,'module_records':241,'high_signal_surfaces':27277,'ui_product_surfaces':228,'semantic_value_records':69,'repository_records':12,'file_records':28433,'ledger_records':28755,'baseline_files':3255,'vendored_surfaces':5,'unresolved_high_signal_surfaces':0}
for k,v in exp.items():check(sm.get(k)==v,f'summary {k} {sm.get(k)} != {v}')
released_base=Path('/mnt/data/LumiNet-post-refactor-232-source-inventory.csv')
check(released_base.is_file(),'released 232 inventory available')
if released_base.is_file():
 check(rcsv(BASE)==list(csv.DictReader(released_base.open(newline='',encoding='utf-8'))),'exact released 232 inventory rows embedded')
surfs=rcsv('post-refactor-233-surface-accountability.csv');check(len(surfs)==28433,'surface count');by={(r['donor'],r['path']):r for r in surfs};check(len(by)==28433,'surface keys unique');links=rcsv('post-refactor-233-symlinks.csv');check(len(links)==282,'symlink count');lby={(r['donor'],r['path']):r for r in links};check(len(lby)==282,'symlink keys unique')
arch=rcsv('post-refactor-233-archive-accountability.csv');check(len(arch)==12,'12 archives')
for row in arch:
 p=Path('/mnt/data')/row['archive'];check(p.is_file(),f'archive exists {row["archive"]}')
 if not p.is_file():continue
 check(sha(p)==row['archive_sha256'],f'archive sha {row["archive"]}')
 with zipfile.ZipFile(p) as z:
  check(z.testzip() is None,f'CRC {row["archive"]}');infos=z.infolist();check(len(infos)==int(row['members']),f'members {row["archive"]}');seen=set();fold=set();files=dirs=syms=0;total=0
  for info in infos:
   try:rel=norm(info.filename)
   except ValueError:check(False,f'unsafe {info.filename}');continue
   key=rel.as_posix().rstrip('/');check(key not in seen,f'duplicate {key}');check(key.casefold() not in fold,f'case collision {key}');seen.add(key);fold.add(key.casefold());mode=info.external_attr>>16;kind=stat.S_IFMT(mode);islink=stat.S_ISLNK(mode);check(kind in {0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK},f'special {key}');check(not(info.flag_bits&1),f'encrypted {key}');ip=inner(row['donor'],key)
   if islink:
    syms+=1;lr=lby.get((row['donor'],ip));check(lr is not None,f'link evidence {row["donor"]}:{ip}');
    if lr:check(z.read(info).decode('utf-8','replace')==lr['target'],f'link target {ip}')
   elif info.is_dir():dirs+=1
   else:
    files+=1;total+=info.file_size;sr=by.get((row['donor'],ip));check(sr is not None,f'file evidence {row["donor"]}:{ip}')
    if sr:
     b=z.read(info);check(str(len(b))==sr['size_bytes'],f'archive size {ip}');check(hashlib.sha256(b).hexdigest()==sr['sha256'],f'archive hash {ip}')
   if info.compress_size:check(info.file_size/info.compress_size<=1000,f'compression ratio {key}')
  check(files==int(row['files']),f'file total {row["archive"]}');check(dirs==int(row['dirs']),f'dir total {row["archive"]}');check(syms==int(row['symlinks']),f'link total {row["archive"]}');check(total<=int(row['uncompressed_bytes']),f'payload bytes bounded {row["archive"]}')
# extracted files and backlinks
for r in surfs:
 p=donor_file(r['donor'],r['path']);check(p.is_file() and not p.is_symlink(),f'extracted {r["donor"]}:{r["path"]}')
 if p.is_file():check(str(p.stat().st_size)==r['size_bytes'],f'size {r["path"]}');check(sha(p)==r['sha256'],f'hash {r["path"]}')
 check(r['semantic_record_ids']!='',f'backlink {r["path"]}');check(r['post_refactor_233_disposition'] in {'focused','accounted-reference'},f'disposition {r["path"]}')
 if r['classification'] in HIGH:check('PR233-F' in r['semantic_record_ids'] and 'PR233-M' in r['semantic_record_ids'],f'high ownership {r["path"]}')
# merkle recompute exactly from normalized file/link evidence
rows_by=defaultdict(list);links_by=defaultdict(list)
for r in surfs:rows_by[r['donor']].append(r)
for r in links:links_by[r['donor']].append(r)
re={}
for d,rows in rows_by.items():
 dirs={'.'}
 for r in rows:
  for par in Path(r['path']).parents:dirs.add('.' if par.as_posix()=='.' else par.as_posix())
 for r in links_by[d]:
  for par in Path(r['path']).parents:dirs.add('.' if par.as_posix()=='.' else par.as_posix())
 for di in dirs:
  pref='' if di=='.' else di.rstrip('/')+'/';ds=[r for r in rows if r['path'].startswith(pref)];ls=[r for r in links_by[d] if r['path'].startswith(pref)];direct=sum('/' not in r['path'][len(pref):] for r in ds);children=set()
  for r in ds+ls:
   rest=r['path'][len(pref):]
   if '/' in rest:children.add(rest.split('/')[0])
  mat=[f"F\t{r['path']}\t{r['sha256']}\t{r['size_bytes']}\t{r['mode']}" for r in ds]+[f"L\t{r['path']}\t{r['target']}\t{r['mode']}" for r in ls];h=hashlib.sha256(('\n'.join(sorted(mat))+'\n').encode()).hexdigest();re[(d,di)]=(h,str(direct),str(len(children)),str(len(ds)),str(len(ls)))
dirs=rcsv('post-refactor-233-directories.csv');check(len(dirs)==586,'586 directories');check(len({(r['donor'],r['directory']) for r in dirs})==586,'dir unique')
for r in dirs:
 got=re.get((r['donor'],r['directory']));check(got is not None,f'merkle key {r["donor"]}:{r["directory"]}')
 if got:check(got[0]==r['tree_sha256'],f'merkle hash {r["donor"]}:{r["directory"]}');check(got[1]==r['direct_files'],f'direct files');check(got[2]==r['direct_dirs'],f'direct dirs');check(got[3]==r['descendant_files'],f'desc files');check(got[4]==r['descendant_symlinks'],f'desc links')
# definitions
defs=rcsv('post-refactor-233-symbols.csv');check(len(defs)==3557,'3557 definitions');cache={}
for r in defs:
 s=by.get((r['donor'],r['path']));check(s is not None,f'def surface {r["path"]}')
 if s:check(s['sha256']==r['sha256'],f'def hash {r["path"]}')
 k=(r['donor'],r['path'])
 if k not in cache:cache[k]=donor_file(*k).read_text(encoding='utf-8',errors='replace').splitlines()
 try:actual=cache[k][int(r['line'])-1].strip()[:240]
 except:actual='__MISSING__'
 check(actual==r['snippet'],f'def line {r["donor"]}:{r["path"]}:{r["line"]}')
# ledger
ledger=rcsv('post-refactor-233-adoption-ledger.csv');check(len(ledger)==28755,'28755 ledger');ids={r['record_id'] for r in ledger};check(len(ids)==28755,'ledger unique');check(sum(x.startswith('PR233-R') for x in ids)==12,'repo records');check(sum(x.startswith('PR233-M') for x in ids)==241,'module records');check(sum(x.startswith('PR233-F') for x in ids)==28433,'file records');focus=[r for r in ledger if r['record_id'].startswith('PR233-S')];check(len(focus)==69,'focus records');parents={r['record_id']:r['parent_record_id'] for r in ledger}
for r in ledger:
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in ids,f'parent {r["record_id"]}')
 check(r['validation_status'] in {'verified','statically-validated','reviewed','inferred','unverified','pending'},f'status {r["record_id"]}')
for r in focus:
 s=by.get((r['donor'],r['donor_path']));check(s is not None,f'focus source {r["record_id"]}')
 if s:check(r['record_id'] in s['semantic_record_ids'].split(';'),f'focus backlink {r["record_id"]}')
 for n in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:check((ROOT/n.split('#',1)[0]).exists(),f'target {r["record_id"]}:{n}')
 if r['test_node']!='n/a':check((ROOT/r['test_node'].split('#',1)[0]).exists(),f'test {r["record_id"]}')
for rid in ids:
 seen=set();cur=rid
 while cur!='n/a':check(cur not in seen,f'cycle {rid}');seen.add(cur);cur=parents.get(cur,'n/a')
mods=rcsv('post-refactor-233-module-audit.csv');check(len(mods)==241,'module rows');check(sum(int(r['surfaces']) for r in mods)==28433,'module partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==27277,'high partition');check(sum(int(r['ui_product_surfaces']) for r in mods)==228,'ui partition')
# history prefix
ps=rcsv('post-refactor-232-all-history-surface-audit.csv');hs=rcsv('post-refactor-233-all-history-surface-audit.csv');check(len(ps)==52423 and len(hs)==80856,'history surfaces');check(hs[:len(ps)]==ps,'surface prefix')
pd=rcsv('post-refactor-232-all-history-symbol-index.csv');hd=rcsv('post-refactor-233-all-history-symbol-index.csv');check(len(pd)==79941 and len(hd)==83498,'history definitions');check(hd[:len(pd)]==pd,'definition prefix')
pm=rcsv('post-refactor-232-all-history-module-audit.csv');hm=rcsv('post-refactor-233-all-history-module-audit.csv');check(len(pm)==1804 and len(hm)==2045,'history modules');check(hm[:len(pm)]==pm,'module prefix')
ah=json.loads((E/'post-refactor-233-all-history-summary.json').read_text());ea={'unique_donors':92,'surfaces':80856,'definitions':83498,'module_records':2045,'high_signal_surfaces':40736,'ui_product_surfaces':2896}
for k,v in ea.items():check(ah.get(k)==v,f'all history {k}')
# delta exact
with BASE.open(newline='',encoding='utf-8') as f:base={r['path']:r for r in csv.DictReader(f)}
delta=rcsv('post-refactor-233-target-delta.csv');dby={(r['change_type'],r['path']):r for r in delta};cur={}
# Successor-aware: validate the immutable 233 delta against its frozen release inventory.
frozen233=Path('/mnt/data/luminet233/LumiNet-post-refactor-233-source-inventory.csv')
check(frozen233.is_file(),'frozen 233 source inventory exists')
if frozen233.is_file():
 with frozen233.open(newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f):
   rel=r['path']
   if rel=='governance/convergence/post-refactor-233-target-delta.csv':continue
   cur[rel]={'sha256':r['sha256'],'size_bytes':r['size_bytes'],'mode':r['mode']}
ex={}
for path in set(base)|set(cur):
 b,c=base.get(path),cur.get(path)
 if b is None:typ='added'
 elif c is None:typ='deleted'
 elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
 else:continue
 ex[(typ,path)]=(b,c)
check(set(dby)==set(ex),'delta exact');check(len(dby)==len(delta),'delta unique')
for key,(b,c) in ex.items():
 r=dby.get(key)
 if r:check(r['baseline_sha256']==(b['sha256'] if b else 'n/a'),f'delta base {key}');check(r['current_sha256']==(c['sha256'] if c else 'n/a'),f'delta current {key}')
# target contracts
body=text('src/apps/daemon/internal/analysis/diagnostics/post_refactor_233_plans.go')
for tok in ['BuildDNSRefinerPlan','BuildHTTPSUpgradeRulesetPlan','BuildTorExitScanPlan','BuildMobileTorLifecyclePlan','BuildSecurityPosturePlan','BuildTrafficShaperPlan','BuildEndpointLocationEvidencePlan','credential values are never accepted or emitted','audit never installs browser rules or redirects traffic','planner does not control Tor or build circuits','unknown is never treated as pass','leaky-bucket sizing is planning evidence only','geolocation is evidence, never endpoint-selection authority']:check(tok in body,f'planner contract {tok}')
handlers=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_233_planners.go');check(all(x not in handlers for x in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.Chmod(']),'handlers side-effect free')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
for r in ['/dns-refiner-plan','/https-upgrade-ruleset-plan','/tor-exit-scan-plan','/mobile-tor-lifecycle-plan','/security-posture-plan','/traffic-shaper-plan','/endpoint-location-evidence-plan']:check(r in routes,f'route {r}')
ops=text('src/packages/control-ui/src/pages/Operations.tsx')
for x in ['dnsRefiner','httpsUpgradeAudit','torExitScan','mobileTorLifecycle','securityPosture','trafficShaper','endpointLocation']:check(x in ops,f'ui {x}')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:233')=='node scripts/test-post-refactor-233.mjs','test233 script');check('&& npm run test:233' in pkg['scripts']['test'],'aggregate includes test:233')
pt=text('src/packages/control-ui/scripts/test-post-refactor-233.mjs');check('product/security convergence characterization passed' in pt,'233 UI gate')
# donor overlap ownership guards
pres=text('src/apps/daemon/internal/integrations/presets/presets.go');check('NumFragment' in pres and 'FragmentSleep' in pres,'fragment presets remain canonical')
check((ROOT/'src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go').is_file(),'TLS interception evidence owner')
check((ROOT/'src/apps/daemon/internal/platform/system/tor_controller.go').is_file(),'Tor controller owner')
check((ROOT/'src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go').is_file(),'split tunnel owner')
check((ROOT/'src/apps/daemon/internal/analysis/diagnostics/routing_policy_group_plan.go').is_file(),'routing group owner')
mk=text('Makefile');check('post-refactor-233-evidence' in mk and 'check_post_refactor_233_convergence.py' in mk,'Makefile owns 233')
for n,toks in {'architecture.md':['Twelve donors','28,433 files'],'security-model.md':['active scan','host mutation'],'peer-synthesis.md':['DNS subscription normalization','Tor-exit scheduling'],'omission-audit.md':['28,433/28,433','3,557/3,557','unresolved high-signal surfaces: 0'],'operator-runbook.md':['Convergence policy lab','planning-only'],'all-history-second-order-audit.md':['92 donor identities','80,856','83,498']}.items():
 b=(E/f'post-refactor-233-{n}').read_text(encoding='utf-8',errors='replace')
 for t in toks:check(t in b,f'report {n}:{t}')
print(f'post-refactor-233 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:500]:print('ERROR',e)
 sys.exit(1)
