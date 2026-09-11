#!/usr/bin/env python3
from __future__ import annotations
import csv,hashlib,json,os,stat,sys,zipfile
from collections import defaultdict,Counter
from pathlib import Path,PurePosixPath
ROOT=Path(os.environ.get('LUMINET_234_TARGET_ROOT',Path(__file__).resolve().parents[2]));WORK=Path(os.environ.get('LUMINET_234_WORK_ROOT','/mnt/data/luminet234'))
if not WORK.is_dir():
 print(f'SKIP: post-refactor-234 donor archives not mounted at {WORK}; the donor cross-check is machine-local and cannot run here.')
 sys.exit(0);E=ROOT/'governance/convergence';DON=WORK/'donors'
ROOTMAP={'whitedns_android':('whitedns_android_234','WhiteDNS-Android-main'),'proofmode_android':('proofmode_android','proofmode-android-main'),'dns_blocklists':('dns_blocklists','dns-blocklists-main'),'tor_metrics_library':('library','library-master'),'mitmproxy2swagger':('mitmproxy2swagger','mitmproxy2swagger-master'),'outline_tun2socks_demo':('outline_tun2socks_demo','outline-go-tun2socks-demo-main'),'outline_apps':('outline_apps','outline-apps-master'),'kingo_vpn':('kingo_vpn','Kingo-vpn-main'),'simplednscrypt':('simplednscrypt','SimpleDnsCrypt-master'),'proxybridge':('proxybridge','ProxyBridge-master'),'skivpn':('skivpn','skivpn-main'),'tor_atlas':('atlas','atlas-master'),'whitedns_cleanip':('whitedns_cleanip_234','WhiteDNS-cleanip-finder-main')}
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'};assertions=0;errors=[]
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
def donor_file(d,p):
 folder,root=ROOTMAP[d];base=DON/folder;candidate=base/root/p
 return candidate if candidate.exists() else base/p
def norm(n):
 p=PurePosixPath(n.replace('\\','/'))
 if p.is_absolute() or any(x in {'','.', '..'} for x in p.parts) or (p.parts and ':' in p.parts[0]):raise ValueError(n)
 return p
required=['archive-accountability.csv','surface-accountability.csv','directories.csv','symbols.csv','symlinks.csv','module-audit.csv','adoption-ledger.csv','supersession-map.csv','whitedns-revision-delta.csv','evidence-summary.json','baseline-files.csv','target-delta.csv','all-history-surface-audit.csv','all-history-symbol-index.csv','all-history-module-audit.csv','all-history-summary.json','architecture.md','security-model.md','state-machines.md','peer-synthesis.md','omission-audit.md','operator-runbook.md','validation.md','all-history-second-order-audit.md']
for s in required:check((E/f'post-refactor-234-{s}').is_file(),f'missing {s}')
if errors:
 print('\n'.join(errors));sys.exit(1)
sm=json.loads((E/'post-refactor-234-evidence-summary.json').read_text());exp={'submitted_archives':15,'active_donor_revisions':13,'exact_historical_reuploads':2,'archive_members':29293,'surfaces':3769,'directories':1016,'definitions':5564,'symlinks':4,'module_records':921,'high_signal_surfaces':2061,'ui_product_surfaces':299,'semantic_value_records':29,'ledger_records':4732,'baseline_files':3285,'vendored_surfaces':156,'unresolved_high_signal_surfaces':0}
for k,v in exp.items():check(sm.get(k)==v,f'summary {k} {sm.get(k)} != {v}')
# baseline identity is exact frozen 233 release
bz=Path('/mnt/data/luminet233/LumiNet-post-refactor-233-converged-working-tree.zip');check(bz.is_file(),'233 baseline zip exists')
if bz.is_file():check(sha(bz)=='61d0c88cadb777f9c202ecbdaa9712baa595825c3e655d1263f44596e7b9ec6a','233 baseline zip hash')
base=rcsv('post-refactor-234-baseline-files.csv');check(len(base)==3285,'baseline row count')
# archives: exact bytes, CRC, safe names, counts
arch=rcsv('post-refactor-234-archive-accountability.csv');check(len(arch)==15,'archive rows')
expected_dups={'https-everywhere-master(1).zip':'fe88904e77ed0beed6bcac680e0e1f7716c0d23660c4da9dc1d6a60327aa1a0a','exitmap-main(1).zip':'8a65ebd7251fc37a5ca7b5121521598e75172c492e684c99090c8aabb59f39ba'}
for row in arch:
 ap=Path('/mnt/data')/row['archive'];check(ap.is_file(),f'archive {row["archive"]}')
 if not ap.exists():continue
 check(sha(ap)==row['archive_sha256'],f'archive sha {row["archive"]}')
 if row['archive'] in expected_dups:check(row['archive_sha256']==expected_dups[row['archive']] and row['duplicate_of']=='historical-identical',f'duplicate identity {row["archive"]}')
 with zipfile.ZipFile(ap) as z:
  check(z.testzip() is None,f'crc {row["archive"]}');infos=z.infolist();check(len(infos)==int(row['members']),f'members {row["archive"]}');seen=set();fold=set();files=dirs=links=0;total=0
  for info in infos:
   try:p=norm(info.filename)
   except ValueError:check(False,f'unsafe {info.filename}');continue
   key=p.as_posix().rstrip('/');check(key not in seen,f'duplicate {key}');check(key.casefold() not in fold,f'case collision {key}');seen.add(key);fold.add(key.casefold());mode=info.external_attr>>16;kind=stat.S_IFMT(mode);islink=stat.S_ISLNK(mode);check(kind in {0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK},f'special {key}');check(not(info.flag_bits&1),f'encrypted {key}')
   if islink:links+=1
   elif info.is_dir():dirs+=1
   else:files+=1;total+=info.file_size
  check(files==int(row['files']),f'files {row["archive"]}');check(dirs==int(row['dirs']),f'dirs {row["archive"]}');check(links==int(row['symlinks']),f'links {row["archive"]}');check(total==int(row['uncompressed_bytes']),f'payload {row["archive"]}')
# active surfaces exact extracted bytes
surfs=rcsv('post-refactor-234-surface-accountability.csv');check(len(surfs)==3769,'surface count');by={(r['donor'],r['path']):r for r in surfs};check(len(by)==3769,'surface keys unique')
for r in surfs:
 p=donor_file(r['donor'],r['path']);check(p.is_file() and not p.is_symlink(),f'extracted {r["donor"]}:{r["path"]}')
 if p.is_file():check(str(p.stat().st_size)==r['size_bytes'],f'size {r["path"]}');check(sha(p)==r['sha256'],f'hash {r["path"]}')
 check(r['semantic_record_ids']!='',f'backlink {r["path"]}')
 if r['classification'] in HIGH:check('PR234-F' in r['semantic_record_ids'] and 'PR234-M' in r['semantic_record_ids'],f'high ownership {r["path"]}')
# symlinks exact from outline apps archive
links=rcsv('post-refactor-234-symlinks.csv');check(len(links)==4,'4 active symlinks');check(len({(r['donor'],r['path']) for r in links})==4,'link unique')
# directory Merkle exact
dirrows=rcsv('post-refactor-234-directories.csv');check(len(dirrows)==1016,'directory rows');rows_by=defaultdict(list);links_by=defaultdict(list)
for r in surfs:rows_by[r['donor']].append(r)
for r in links:links_by[r['donor']].append(r)
recomp={}
for d,rows in rows_by.items():
 dirs={'.'}
 for r in rows+links_by[d]:
  for par in Path(r['path']).parents:dirs.add('.' if par.as_posix()=='.' else par.as_posix())
 for di in dirs:
  pref='' if di=='.' else di.rstrip('/')+'/';ds=[r for r in rows if r['path'].startswith(pref)];ls=[r for r in links_by[d] if r['path'].startswith(pref)];direct=sum('/' not in r['path'][len(pref):] for r in ds);children=set()
  for r in ds+ls:
   rest=r['path'][len(pref):]
   if '/' in rest:children.add(rest.split('/')[0])
  mat=[f"F\t{r['path']}\t{r['sha256']}\t{r['size_bytes']}\t{r['mode']}" for r in ds]+[f"L\t{r['path']}\t{r['target']}\t{r['mode']}" for r in ls];h=hashlib.sha256(('\n'.join(sorted(mat))+'\n').encode()).hexdigest();recomp[(d,di)]=(h,str(direct),str(len(children)),str(len(ds)),str(len(ls)))
for r in dirrows:
 got=recomp.get((r['donor'],r['directory']));check(got is not None,f'merkle key {r["donor"]}:{r["directory"]}')
 if got:check(got==(r['tree_sha256'],r['direct_files'],r['direct_dirs'],r['descendant_files'],r['descendant_symlinks']),f'merkle {r["donor"]}:{r["directory"]}')
# definitions line-level provenance
defs=rcsv('post-refactor-234-symbols.csv');check(len(defs)==5564,'definition count');cache={}
for r in defs:
 s=by.get((r['donor'],r['path']));check(s is not None and s['sha256']==r['sha256'],f'def source {r["donor"]}:{r["path"]}')
 k=(r['donor'],r['path'])
 if k not in cache:cache[k]=donor_file(*k).read_text(encoding='utf-8',errors='replace').splitlines()
 try:actual=cache[k][int(r['line'])-1].strip()[:240]
 except:actual='__MISSING__'
 check(actual==r['snippet'],f'def line {r["donor"]}:{r["path"]}:{r["line"]}')
# ledger integrity and focused records
ledger=rcsv('post-refactor-234-adoption-ledger.csv');check(len(ledger)==4732,'ledger count');ids={r['record_id'] for r in ledger};check(len(ids)==4732,'ledger unique');check(sum(i.startswith('PR234-R') for i in ids)==13,'repo records');check(sum(i.startswith('PR234-M') for i in ids)==921,'module records');check(sum(i.startswith('PR234-F') for i in ids)==3769,'file records');focus=[r for r in ledger if r['record_id'].startswith('PR234-S')];check(len(focus)==29,'focus count');parents={r['record_id']:r['parent_record_id'] for r in ledger}
for r in ledger:
 if r['parent_record_id']!='n/a':check(r['parent_record_id'] in ids,f'parent {r["record_id"]}')
 check(r['validation_status'] in {'verified','statically-validated','reviewed','inferred','unverified','pending'},f'status {r["record_id"]}')
for r in focus:
 s=by.get((r['donor'],r['donor_path']));check(s is not None,f'focus source {r["record_id"]}')
 if s:check(r['record_id'] in s['semantic_record_ids'].split(';'),f'focus backlink {r["record_id"]}')
 for n in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:check((ROOT/n.split('#',1)[0]).exists(),f'target {r["record_id"]}:{n}')
# modules partition
mods=rcsv('post-refactor-234-module-audit.csv');check(len(mods)==921,'module rows');check(sum(int(r['surfaces']) for r in mods)==3769,'module partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==2061,'high partition');check(sum(int(r['ui_product_surfaces']) for r in mods)==299,'ui partition')
# WhiteDNS revisions are exact newer revisions, not fake new identities
rev=rcsv('post-refactor-234-whitedns-revision-delta.csv');c=Counter((r['donor'],r['change_type']) for r in rev);check(c[('whitedns_android','same')]==98 and c[('whitedns_android','modified')]==32 and c[('whitedns_android','removed')]==9,'WhiteDNS Android revision delta');check(c[('whitedns_cleanip','same')]==229 and c[('whitedns_cleanip','modified')]==26 and c[('whitedns_cleanip','removed')]==15,'WhiteDNS CleanIP revision delta')
# all-history prefix preservation
ps=rcsv('post-refactor-233-all-history-surface-audit.csv');hs=rcsv('post-refactor-234-all-history-surface-audit.csv');check(hs[:len(ps)]==ps and len(hs)==84625,'surface history prefix')
pd=rcsv('post-refactor-233-all-history-symbol-index.csv');hd=rcsv('post-refactor-234-all-history-symbol-index.csv');check(hd[:len(pd)]==pd and len(hd)==89062,'definition history prefix')
pm=rcsv('post-refactor-233-all-history-module-audit.csv');hm=rcsv('post-refactor-234-all-history-module-audit.csv');check(hm[:len(pm)]==pm and len(hm)==2966,'module history prefix')
ah=json.loads((E/'post-refactor-234-all-history-summary.json').read_text());ea={'unique_donors':103,'surfaces':84625,'definitions':89062,'module_records':2966,'high_signal_surfaces':42797,'ui_product_surfaces':3195}
for k,v in ea.items():check(ah.get(k)==v,f'all history {k}')
# exact target delta against frozen 233 inventory
b={r['path']:r for r in base};cur={}
# Successor-aware: validate the immutable 234 delta against the frozen 234 release
# inventory rather than the mutable current successor tree.
frozen234=Path('/mnt/data/luminet234/release/LumiNet-post-refactor-234-source-inventory.csv')
check(frozen234.is_file(),'frozen 234 source inventory exists')
if frozen234.is_file():
 with frozen234.open(newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f):
   rel=r['path']
   if rel=='governance/convergence/post-refactor-234-target-delta.csv':continue
   cur[rel]={'sha256':r['sha256'],'size_bytes':r['size_bytes'],'mode':r['mode']}
ex={}
for path in set(b)|set(cur):
 br,cr=b.get(path),cur.get(path)
 if br is None:typ='added'
 elif cr is None:typ='deleted'
 elif (br['sha256'],br['size_bytes'],br['mode'])!=(cr['sha256'],cr['size_bytes'],cr['mode']):typ='modified'
 else:continue
 ex[(typ,path)]=(br,cr)
delta=rcsv('post-refactor-234-target-delta.csv');dby={(r['change_type'],r['path']):r for r in delta};check(set(dby)==set(ex) and len(dby)==34,'delta exact');check(Counter(r['change_type'] for r in delta)==Counter({'added':30,'modified':4}),'delta counts')
# target contracts and product surface
plans=text('src/apps/daemon/internal/analysis/diagnostics/post_refactor_234_plans.go')
for tok in ['BuildDNSBlocklistCorpusPlan','BuildAPITraceSchemaPlan','BuildTorDescriptorEvidencePlan','BuildProcessProxyRulePlan','BuildEvidenceChainPlan','BuildDNSCryptResolverPolicyPlan','only caller-supplied list metadata is audited','schema inference consumes already-captured metadata only','relay flags are descriptive evidence, not trust or routing authority','proxy process matches are reported as loop risks','unknown signature or timestamp state never counts as pass','resolver ranking uses caller-supplied observations only']:check(tok in plans,f'planner {tok}')
handlers=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_234_planners.go');check(all(x not in handlers for x in ['http.Get(','http.Post(','net.Dial(','exec.Command(','os.WriteFile(','os.Remove(','os.Chmod(']),'handlers side-effect free')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go');ops=text('src/packages/control-ui/src/pages/Operations.tsx')
for ep,opt in [('/dns-blocklist-corpus-plan','dnsBlocklistAudit'),('/api-trace-schema-plan','apiTraceSchema'),('/tor-descriptor-evidence-plan','torDescriptorEvidence'),('/process-proxy-rule-plan','processProxyRules'),('/evidence-chain-plan','evidenceChain'),('/dnscrypt-resolver-policy-plan','dnscryptResolver')]:check(ep in routes,f'route {ep}');check(opt in ops and '/api/system'+ep in ops,f'ui {opt}')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:234')=='node scripts/test-post-refactor-234.mjs','ui test script');check('&& npm run test:234' in pkg['scripts']['test'],'aggregate includes test:234')
mk=text('Makefile');check('post-refactor-234-evidence' in mk and 'check_post_refactor_234_convergence.py' in mk,'Makefile 234')
# reports state actual denominator and authority boundary
for n,toks in {'architecture.md':['13 active donor revisions','2 exact historical reuploads','Six new read-only planners'],'security-model.md':['MITM','controls Tor','changes system DNS'],'peer-synthesis.md':['DNS corpus auditing','passive API-trace schema inference','WhiteDNS'],'omission-audit.md':['3,769','unresolved high-signal surfaces: 0'],'operator-runbook.md':['Convergence policy lab','caller-supplied JSON'],'all-history-second-order-audit.md':['103 donor identities','84,625','89,062']}.items():
 body=(E/f'post-refactor-234-{n}').read_text(encoding='utf-8',errors='replace')
 for t in toks:check(t in body,f'report {n}:{t}')
print(f'post-refactor-234 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:300]:print('ERROR',e)
 sys.exit(1)
