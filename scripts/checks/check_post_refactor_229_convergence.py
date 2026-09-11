#!/usr/bin/env python3
"""Verify post-refactor-229 five-donor + nested-archive convergence and exact successor state."""
from __future__ import annotations
import csv, hashlib, json, os, stat, sys, zipfile
from pathlib import Path, PurePosixPath

ROOT=Path(os.environ.get('LUMINET_229_TARGET_ROOT',Path(__file__).resolve().parents[2]))
E=ROOT/'governance/convergence'
WORK=Path(os.environ.get('LUMINET_229_WORK_ROOT','/mnt/data/luminet229_work'))
if not WORK.is_dir():
 print(f'SKIP: post-refactor-229 donor archives not mounted at {WORK}; the donor cross-check is machine-local and cannot run here.')
 sys.exit(0)
DONORS={
 'hiddify-app-main':WORK/'donors/hiddify-app-main',
 'ProxyCloud-master':WORK/'donors/ProxyCloud-master',
 'mullvadvpn-app-main':WORK/'donors/mullvadvpn-app-main',
 'my-relay-assets-main':WORK/'donors/my-relay-assets-main',
 'MasterHttpRelayVPN-RUST-main':WORK/'donors/MasterHttpRelayVPN-RUST-main',
}
ARCHIVES={
 'hiddify-app-main':Path('/mnt/data/hiddify-app-main(1).zip'),
 'ProxyCloud-master':Path('/mnt/data/ProxyCloud-master(1).zip'),
 'mullvadvpn-app-main':Path('/mnt/data/mullvadvpn-app-main.zip'),
 'my-relay-assets-main':Path('/mnt/data/my-relay-assets-main.zip'),
 'MasterHttpRelayVPN-RUST-main':Path('/mnt/data/MasterHttpRelayVPN-RUST-main(1).zip'),
}
EXPECTED_ARCHIVE_SHA={
 'hiddify-app-main':'2c66d521932e23cf13c035fdf8f7e470a086122041fb8c5bba62d204ee43cbfd',
 'ProxyCloud-master':'c2d1f4876be647181331988ca74143303b7cc7bc27ca6f0f80d2d05b3ed05d1a',
 'mullvadvpn-app-main':'0133f629f609275bec8ded89e9d29e0306575c2414448ed870ead62a4e5665e6',
 'my-relay-assets-main':'17a50fea567459227ef3f73536364e1e30884ea4cd8136c4cbc1a799b284ba65',
 'MasterHttpRelayVPN-RUST-main':'5d3f2ec9f8a5e4b9d788abd379aa1aa613289f0a45dcde36c10971a826709bac',
}
NESTED=WORK/'nested/my-relay-assets-main/mitmengine-master'
NESTED_ARCHIVE=DONORS['my-relay-assets-main']/'mitmengine-master.zip'
NESTED_SHA='d1a9ea21875e190cd181897bde798331188a9aefe20f7afaf302cc68e6d64dc5'
HIGH={'implementation','ui-or-product','configuration','deployment','script','test'}
errors=[]; assertions=0

def check(cond,msg):
 global assertions
 assertions+=1
 if not cond: errors.append(msg)

def sha_file(p:Path)->str:
 h=hashlib.sha256()
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1<<20),b''):h.update(c)
 return h.hexdigest()
def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def readcsv(name):
 p=E/name if isinstance(name,str) else name
 with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def text(rel):return (ROOT/rel).read_text(encoding='utf-8',errors='replace')
def safe_member(name):
 if '\x00' in name:return False
 p=PurePosixPath(name.replace('\\','/'))
 return bool(p.parts) and not p.is_absolute() and all(x not in ('','.','..') for x in p.parts) and ':' not in p.parts[0]
def outer_rel(donor,p:PurePosixPath)->str:
 # Four archives use one project root. my-relay-assets deliberately contains a
 # normal project root plus a sibling nested-source archive at archive root.
 if donor=='my-relay-assets-main':
  if p.parts and p.parts[0]=='my-relay-assets-main':
   return PurePosixPath(*p.parts[1:]).as_posix()
  return p.as_posix()
 return PurePosixPath(*p.parts[1:]).as_posix()

def build_merkle_index(rows):
 # The inventory generator sorts pathlib.Path objects component-wise. Sort once
 # in the same order and stream each leaf into its ancestor directory buckets.
 # This is exactly equivalent to per-directory rglob sorting without O(D*F).
 buckets={'.':[]}
 for row in sorted(rows,key=lambda row: PurePosixPath(row['path']).parts):
  parts=PurePosixPath(row['path']).parts
  leaf=f"{row['path']}\0{row['size_bytes']}\0{row['sha256']}\n".encode()
  buckets['.'].append(leaf)
  for depth in range(1,len(parts)):
   directory=PurePosixPath(*parts[:depth]).as_posix()
   buckets.setdefault(directory,[]).append(leaf)
 return {directory:(len(leaves),sha_bytes(b''.join(leaves))) for directory,leaves in buckets.items()}

required=[
 'post-refactor-229-archive-accountability.csv','post-refactor-229-symlinks.csv','post-refactor-229-surface-accountability.csv','post-refactor-229-directories.csv','post-refactor-229-symbols.csv','post-refactor-229-adoption-ledger.csv','post-refactor-229-module-audit.csv','post-refactor-229-supersession-map.csv','post-refactor-229-evidence-summary.json','post-refactor-229-baseline-files.csv','post-refactor-229-target-delta.csv','post-refactor-229-all-history-surface-audit.csv','post-refactor-229-all-history-symbol-index.csv','post-refactor-229-all-history-module-audit.csv','post-refactor-229-all-history-summary.json','post-refactor-229-architecture.md','post-refactor-229-security-model.md','post-refactor-229-state-machines.md','post-refactor-229-peer-synthesis.md','post-refactor-229-omission-audit.md','post-refactor-229-operator-runbook.md','post-refactor-229-validation.md','post-refactor-229-all-history-second-order-audit.md',
 'post-refactor-229-nested-archive-admission.json','post-refactor-229-nested-archive-members.csv','post-refactor-229-nested-mitm-surfaces.csv','post-refactor-229-nested-mitm-directories.csv','post-refactor-229-nested-mitm-symbols.csv',
]
for name in required:check((E/name).is_file(),f'missing {name}')
if errors:
 print('\n'.join(errors));sys.exit(1)

# Immutable predecessor identity and exact denominators.
BASE=E/'post-refactor-229-baseline-files.csv'
check(sha_file(BASE)=='4cf881c8764d47cfbd7cbfa816f424fee889878b75f11a6109d29ed807ff1dbd','229 baseline must be exact released 228 source inventory')
summary=json.loads((E/'post-refactor-229-evidence-summary.json').read_text())
expected={'donors':5,'archive_members':10933,'files':7531,'surfaces':7531,'symlinks':3,'directories_excluding_roots':2256,'directory_merkle_records':2261,'definitions':30602,'high_signal_surfaces':6420,'ui_product_surfaces':1892,'file_accountability_records':7531,'semantic_value_records':118,'adoption_ledger_records':7654,'module_records':173,'high_signal_unaccounted':0,'unresolved_high_signal_surfaces':0,'symlink_external_absolute_quarantined':1,'nested_archives':1,'nested_archive_members':2781,'nested_files':1477,'nested_directory_merkle_records':1268,'nested_definitions':242,'nested_symlinks':0,'baseline_228_inventory_sha256':'4cf881c8764d47cfbd7cbfa816f424fee889878b75f11a6109d29ed807ff1dbd','predecessor_source_tree_sha256':'e1777de597b37200f21a745810e6084996768f48be4c7be590b7a06ed5e3df35'}
for k,v in expected.items():check(summary.get(k)==v,f'evidence summary {k}: {summary.get(k)!r} != {v!r}')

# Archive admission and exact donor bytes.
arch_rows=readcsv('post-refactor-229-archive-accountability.csv');check(len(arch_rows)==5,'5 archive rows')
arch_by={r['donor']:r for r in arch_rows};check(set(arch_by)==set(DONORS),'archive donor set exact')
surfs=readcsv('post-refactor-229-surface-accountability.csv');check(len(surfs)==7531,'7531 outer surface rows')
by={(r['donor'],r['path']):r for r in surfs};check(len(by)==7531,'outer surface keys unique')
syms=readcsv('post-refactor-229-symlinks.csv');check(len(syms)==3,'3 symlink rows');sym_by={(r['donor'],r['member']):r for r in syms}
for donor,archive in ARCHIVES.items():
 root=DONORS[donor];row=arch_by[donor]
 check(archive.is_file(),f'archive exists {donor}');check(root.is_dir(),f'extracted donor exists {donor}')
 if not archive.is_file():continue
 check(sha_file(archive)==EXPECTED_ARCHIVE_SHA[donor]==row['archive_sha256'],f'archive hash {donor}')
 with zipfile.ZipFile(archive) as z:
  check(z.testzip() is None,f'CRC {donor}');infos=z.infolist();check(len(infos)==int(row['members']),f'member count {donor}')
  seen=set();fold=set();files=dirs=links=total=0;root_names=set()
  for info in infos:
   check(safe_member(info.filename),f'safe path {donor}:{info.filename}')
   if not safe_member(info.filename):continue
   p=PurePosixPath(info.filename.replace('\\','/'));name=p.as_posix().rstrip('/');root_names.add(p.parts[0])
   check(name not in seen,f'no duplicate {donor}:{name}');check(name.casefold() not in fold,f'no case collision {donor}:{name}');seen.add(name);fold.add(name.casefold())
   check(not(info.flag_bits&1),f'not encrypted {donor}:{name}');mode=info.external_attr>>16;kind=stat.S_IFMT(mode);check(kind in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK),f'no special member {donor}:{name}');total+=info.file_size
   if info.is_dir():dirs+=1;continue
   if kind==stat.S_IFLNK:
    links+=1;target=z.read(info).decode('utf-8',errors='strict');sr=sym_by.get((donor,name));check(sr is not None,f'symlink evidence {donor}:{name}')
    if sr:check(sr['target']==target,f'symlink target {donor}:{name}');check(sr['materialized']=='false',f'symlink not materialized {donor}:{name}')
    continue
   files+=1;rel=outer_rel(donor,p);sr=by.get((donor,rel));check(sr is not None,f'archive file surface {donor}:{rel}')
   if sr:
    data=z.read(info);check(sha_bytes(data)==sr['sha256'],f'archive file hash {donor}:{rel}');ep=root/rel;check(ep.is_file(),f'extracted file {donor}:{rel}')
    if ep.is_file():check(sha_file(ep)==sr['sha256'],f'extracted hash {donor}:{rel}')
  expected_roots=2 if donor=='my-relay-assets-main' else 1
  check(len(root_names)==expected_roots,f'archive root count {donor}: {root_names}');check(files==int(row['files']),f'file count {donor}');check(dirs==int(row['directories']),f'dir count {donor}');check(links==int(row['symlinks']),f'symlink count {donor}');check(total==int(row['uncompressed_bytes']),f'expanded bytes {donor}');check(total<512*1024*1024,f'bounded expanded bytes {donor}')
check(sum(r['status']=='contained-relative-recorded' for r in syms)==2,'two contained-relative symlinks')
check(sum(r['status']=='external-absolute-quarantined' for r in syms)==1,'one external absolute symlink quarantined')
check(any(r['target']=='/opt/Mullvad VPN/resources/mullvad-problem-report' and r['post_refactor_229_disposition']=='quarantined-external' for r in syms),'absolute Mullvad support symlink exact quarantine')

# Outer surface/hash/definition/directory accountability.
ledger=readcsv('post-refactor-229-adoption-ledger.csv');ids={r['record_id'] for r in ledger};check(len(ledger)==len(ids)==7654,'7654 unique ledger records')
check(sum(r['record_id'].startswith('PR229-R') for r in ledger)==5,'5 repository records');check(sum(r['record_id'].startswith('PR229-F') for r in ledger)==7531,'7531 file records');check(sum(r['record_id'].startswith('PR229-S') for r in ledger)==118,'118 focused semantic records')
high=ui=0; donor_surface_rows={d:[] for d in DONORS}
donor_surface_by_path={d:{} for d in DONORS}
for r in surfs:
 p=DONORS[r['donor']]/r['path'];check(p.is_file(),f'surface exists {r["donor"]}:{r["path"]}')
 if p.is_file():check(sha_file(p)==r['sha256'],f'surface hash {r["donor"]}:{r["path"]}');check(str(p.stat().st_size)==r['size_bytes'],f'surface size {r["donor"]}:{r["path"]}')
 refs=[x for x in r['semantic_record_ids'].split(';') if x];check(refs,f'surface backlink {r["donor"]}:{r["path"]}');check(all(x in ids for x in refs),f'surface backlink IDs {r["donor"]}:{r["path"]}');check(any(x.startswith('PR229-F') for x in refs),f'per-file record {r["donor"]}:{r["path"]}')
 if r['classification'] in HIGH:high+=1
 if r['classification']=='ui-or-product':ui+=1
 check(r['post_refactor_229_review']=='fresh-byte-reverified-and-context-reviewed',f'surface review status {r["donor"]}:{r["path"]}')
 donor_surface_rows[r['donor']].append(r);donor_surface_by_path[r['donor']][r['path']]=r
check(high==6420,'6420 high-signal surfaces recomputed');check(ui==1892,'1892 UI/product surfaces recomputed')
dirs=readcsv('post-refactor-229-directories.csv');check(len(dirs)==2261,'2261 outer directory Merkle rows');check(len({(r['donor'],r['path']) for r in dirs})==2261,'outer directory keys unique')
outer_merkle={donor:build_merkle_index(rows) for donor,rows in donor_surface_rows.items()}
for r in dirs:
 root=DONORS[r['donor']];d=root if r['path']=='.' else root/r['path'];check(d.is_dir(),f'directory exists {r["donor"]}:{r["path"]}')
 count,digest=outer_merkle[r['donor']].get(r['path'],(0,sha_bytes(b'')));check(count==int(r['descendant_files']),f'directory descendant count {r["donor"]}:{r["path"]}');check(digest==r['tree_sha256'],f'directory Merkle {r["donor"]}:{r["path"]}')
defs=readcsv('post-refactor-229-symbols.csv');check(len(defs)==30602,'30602 outer definition records')
for r in defs:
 sr=by.get((r['donor'],r['path']));check(sr is not None,f'definition surface {r["donor"]}:{r["path"]}:{r["line"]}')
 if sr:check(r['sha256']==sr['sha256'],f'definition hash {r["donor"]}:{r["path"]}:{r["line"]}');check(r['semantic_record_ids']==sr['semantic_record_ids'],f'definition backlinks {r["donor"]}:{r["path"]}:{r["line"]}')
 try:ln=int(r['line'])
 except ValueError:ln=0
 check(ln>=1,f'definition positive line {r["donor"]}:{r["path"]}:{r["line"]}')

# Nested MITM archive: independently admitted, fully accounted, not donor-inflated.
nadm=json.loads((E/'post-refactor-229-nested-archive-admission.json').read_text());check(len(nadm)==1,'one nested archive admission row');nr=nadm[0]
for k,v in {'members':2781,'regular_files':1477,'directories':1304,'symlinks':0,'sha256':NESTED_SHA,'single_root':'mitmengine-master'}.items():check(nr.get(k)==v,f'nested admission {k}')
check(NESTED_ARCHIVE.is_file() and sha_file(NESTED_ARCHIVE)==NESTED_SHA,'nested archive hash exact')
nsurfs=readcsv('post-refactor-229-nested-mitm-surfaces.csv');check(len(nsurfs)==1477,'1477 nested surfaces');nby={r['path']:r for r in nsurfs};check(len(nby)==1477,'nested surface keys unique')
with zipfile.ZipFile(NESTED_ARCHIVE) as z:
 check(z.testzip() is None,'nested ZIP CRC');check(len(z.infolist())==2781,'nested ZIP member count')
 seen=set();fold=set();nf=nd=nl=0
 for info in z.infolist():
  check(safe_member(info.filename),f'nested safe path {info.filename}')
  if not safe_member(info.filename):continue
  pp=PurePosixPath(info.filename.replace('\\','/'));nm=pp.as_posix().rstrip('/');check(nm not in seen,f'nested no duplicate {nm}');check(nm.casefold() not in fold,f'nested no case collision {nm}');seen.add(nm);fold.add(nm.casefold())
  mode=info.external_attr>>16;kind=stat.S_IFMT(mode);check(kind in (0,stat.S_IFREG,stat.S_IFDIR),f'nested no special/link {nm}')
  if info.is_dir():nd+=1;continue
  nf+=1;rel=PurePosixPath(*pp.parts[1:]).as_posix();sr=nby.get(rel);check(sr is not None,f'nested surface {rel}')
  if sr:
   data=z.read(info);check(sha_bytes(data)==sr['sha256'],f'nested archive file hash {rel}');ep=NESTED/rel;check(ep.is_file(),f'nested extracted file {rel}')
   if ep.is_file():check(sha_file(ep)==sr['sha256'],f'nested extracted hash {rel}')
 check(nf==1477 and nd==1304 and nl==0,'nested exact files/dirs/symlinks')
ndirs=readcsv('post-refactor-229-nested-mitm-directories.csv');check(len(ndirs)==1268,'1268 nested Merkle rows')
nested_merkle=build_merkle_index(nsurfs)
for r in ndirs:
 count,digest=nested_merkle.get(r['directory'],(0,sha_bytes(b'')));check(count==int(r['recursive_files']),f'nested directory descendants {r["directory"]}');check(digest==r['merkle_sha256'],f'nested directory Merkle {r["directory"]}')
ndefs=readcsv('post-refactor-229-nested-mitm-symbols.csv');check(len(ndefs)==242,'242 nested definition records')
for r in ndefs:
 sr=nby.get(r['path']);check(sr is not None,f'nested definition source {r["path"]}:{r["line"]}')
 if sr:check(r['file_sha256']==sr['sha256'],f'nested definition hash {r["path"]}:{r["line"]}')
# Direct semantic anchors inside nested source; historical fingerprint corpus is evidence, not authority.
match=(NESTED/'fputil/match.go').read_text(errors='replace');grade=(NESTED/'fputil/grade.go').read_text(errors='replace');cipher=(NESTED/'fputil/ciphercheck.go').read_text(errors='replace');report=(NESTED/'report.go').read_text(errors='replace')
for tok in ['MatchEmpty','MatchPossible','MatchUnlikely','MatchImpossible']:check(tok in match,f'nested match lattice {tok}')
check('WeakCiphers' in report or 'WeakCiphers' in cipher,'nested weak-cipher evidence');check('LosesPfs' in report or 'IsPfs' in (NESTED/'fputil/request.go').read_text(errors='replace') or 'IsFirstPfs' in cipher,'nested PFS evidence');check((NESTED/'reference_fingerprints/fingerprint_metadata.jsonl').is_file(),'nested historical fingerprint corpus retained')

# Ledger graph, exact donor evidence, target ownership and focused backlinks.
parent={r['record_id']:r['parent_record_id'] for r in ledger};focus=[]
for r in ledger:
 rid=r['record_id'];par=r['parent_record_id'];check(par=='n/a' or par in ids,f'{rid} parent exists')
 for dep in [x for x in r['dependency_record_ids'].split(';') if x and x!='n/a']:check(dep in ids,f'{rid} dependency {dep}')
 p=DONORS[r['donor']]/r['donor_path'];check(p.is_file(),f'{rid} donor evidence exists')
 if p.is_file():check(sha_file(p)==r['donor_sha256'],f'{rid} donor evidence hash')
 if rid.startswith('PR229-S'):
  focus.append(r);check(r['decision_rationale']!='n/a' and r['invariant']!='n/a' and r['negative_invariant']!='n/a',f'{rid} semantic rationale/invariants')
  if r['disposition']!='reference-only':check(r['test_node']!='n/a',f'{rid} acceptance anchor');check(r['target_nodes']!='n/a',f'{rid} target ownership')
 for node in [x for x in r['target_nodes'].split(';') if x and x!='n/a']:
  path=node.split('#',1)[0];check('#' in node,f'{rid} target node has symbol');check((ROOT/path).exists(),f'{rid} target path exists {path}')
for rid in ids:
 seen=set();cur=rid
 while cur!='n/a':check(cur not in seen,f'parent cycle {rid}');seen.add(cur);cur=parent.get(cur,'n/a')
for r in focus:
 sr=by[(r['donor'],r['donor_path'])];check(r['record_id'] in sr['semantic_record_ids'].split(';'),f'focused backlink {r["record_id"]}')
check(any(r['donor']=='my-relay-assets-main' and r['domain']=='artifact-admission' for r in focus),'artifact mismatch semantic record')
check(any(r['donor']=='my-relay-assets-main' and r['domain']=='tls-interception' and r['disposition']=='adapted' for r in focus),'nested TLS semantic adoption')
check(any(r['donor']=='MasterHttpRelayVPN-RUST-main' and r['domain']=='relay-sequencing' and r['disposition']=='adapted' for r in focus),'relay sequencing semantic adoption')
check(any(r['donor']=='MasterHttpRelayVPN-RUST-main' and r['domain']=='tls-ca' and r['disposition']=='rejected-with-reason' for r in focus),'active CA rejection record')

mods=readcsv('post-refactor-229-module-audit.csv');check(len(mods)==173,'173 module records');check(sum(int(r['surfaces']) for r in mods)==7531,'module surface partition');check(sum(int(r['high_signal_surfaces']) for r in mods)==6420,'module high-signal total');check(sum(int(r['ui_product_surfaces']) for r in mods)==1892,'module UI total')
all_summary=json.loads((E/'post-refactor-229-all-history-summary.json').read_text())
all_expected={'donors':58,'unique_donor_names':58,'surfaces':11341,'symbols':56423,'modules':470,'high_signal_surfaces':8780,'ui_product_surfaces':2054,'wave_229_surfaces':7531,'wave_229_symbols':30602,'wave_229_modules':173,'semantic_value_records_229':118,'file_accountability_records_229':7531,'symlinks_229':3,'history_inflation_from_229':0}
for k,v in all_expected.items():check(all_summary.get(k)==v,f'all-history {k}: {all_summary.get(k)} != {v}')
check(len(readcsv('post-refactor-229-all-history-surface-audit.csv'))==11341,'all-history surface rows');check(len(readcsv('post-refactor-229-all-history-symbol-index.csv'))==56423,'all-history symbol rows');check(len(readcsv('post-refactor-229-all-history-module-audit.csv'))==470,'all-history module rows')

# Exact 228->229 source delta on a 229 tree. On a 230+ successor, preserve the
# predecessor proof by requiring the successor's frozen 229 inventory byte-for-byte.
successor230=E/'post-refactor-230-baseline-files.csv'
if successor230.is_file():
 check(sha_file(successor230)=='29cf2a4a936b8c3940a0e8576b3bbdd41617d905ca92d37f3a9cb8cc30ae33fa','230 successor embeds exact released 229 inventory')
 check(len(readcsv(successor230.name))==3151,'230 successor baseline has 3151 released 229 files')
else:
 base={r['path']:r for r in readcsv(BASE)};delta=readcsv('post-refactor-229-target-delta.csv');delta_by={(r['change_type'],r['path']):r for r in delta};check(len(delta_by)==len(delta),'delta keys unique')
 cur={}
 for p in ROOT.rglob('*'):
  if not p.is_file() or p.is_symlink():continue
  rel=p.relative_to(ROOT).as_posix()
  if rel=='governance/convergence/post-refactor-229-target-delta.csv' or rel.startswith('.git/') or '/node_modules/' in '/'+rel or '__pycache__' in rel:continue
  cur[rel]={'sha256':sha_file(p),'size_bytes':str(p.stat().st_size),'mode':oct(stat.S_IMODE(p.stat().st_mode))}
 expected_delta={}
 for path in set(base)|set(cur):
  b=base.get(path);c=cur.get(path)
  if b is None:typ='added'
  elif c is None:typ='deleted'
  elif (b['sha256'],b['size_bytes'],b['mode'])!=(c['sha256'],c['size_bytes'],c['mode']):typ='modified'
  else:continue
  expected_delta[(typ,path)]=(b,c)
 check(set(delta_by)==set(expected_delta),'delta path/type set exact')
 for key,(b,c) in expected_delta.items():
  r=delta_by.get(key)
  if r:check(r['baseline_sha256']==(b['sha256'] if b else 'n/a'),f'delta baseline hash {key}');check(r['current_sha256']==(c['sha256'] if c else 'n/a'),f'delta current hash {key}')

# Target behavioral/authority contracts, predecessor plus new donor-derived slices.
tunnel=text('src/apps/daemon/internal/analysis/diagnostics/tunnel_safety_plan.go');check('persisted target state is corrupt; fail-closed recovery treats the desired state as secured' in tunnel,'corrupt tunnel intent fail closed');check('degraded-unsafe' in tunnel,'block failure unsafe state');check('MutatesHostNetwork' in tunnel and 'false' in tunnel,'tunnel planner read-only')
for tok in ['RequiredGuards','MissingOrFailedGuards','QUICGuardApplied','STUNGuardApplied','DoHGuardApplied','IPv6GuardApplied']:check(tok in tunnel,f'tunnel leak guard {tok}')
split=text('src/apps/daemon/internal/analysis/diagnostics/split_tunnel_plan.go');check('RuntimeSupported:     false' in split and 'RuntimeEnforced:      false' in split,'split enforcement truth');check('ManifestSHA256' in split and '512' in split,'split manifest/bound')
relay=text('src/apps/daemon/internal/analysis/diagnostics/relay_constraint_plan.go');check('RequiresEndpointScoring: true' in relay,'relay delegates scoring');check('PerformsNetworkIO: false' in relay and 'InstallsTunnel: false' in relay,'relay planner non-authoritative')
artifact=text('src/apps/daemon/internal/analysis/diagnostics/artifact_admission_plan.go');check('detectArtifactFormat' in artifact and 'artifact format mismatch' in artifact,'artifact magic/type admission');check('maxArtifactAdmissionSampleBytes = 1 << 20' in artifact,'artifact sample bound')
tls=text('src/apps/daemon/internal/analysis/diagnostics/tls_interception_evidence_plan.go');check('UsesFingerprintDatabase:       false' in tls or 'UsesFingerprintDatabase' in tls,'TLS no fingerprint DB truth');check('IdentifiesInterceptionProduct' in tls and 'PerformsNetworkIO' in tls,'TLS authority boundaries');check('maxTLSInterceptionEvidenceComponents = 32' in tls,'TLS component bound')
endpoint=text('src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go');check('QuotaSafetyBuffer' in endpoint and 'QuotaHeadroom' in endpoint and 'quota-guarded' in endpoint,'quota reserve/headroom')
wire=text('src/apps/daemon/internal/integrations/relayclient/relay_wire.go');gsa=text('src/apps/daemon/internal/integrations/relayclient/gsa_relay.go');bounds=text('src/apps/daemon/internal/integrations/relayclient/http_bounds.go')
check('validateRelayResponseSequence' in wire and 'sequence mismatch' in wire,'shared relay sequence validator');check('validateRelayResponseSequence' in gsa and 'writeSeq' in gsa and 'querySeq' in gsa,'GSA sequence integration');check('relayControlDecodeError' in bounds and 'cause is ambiguous' in bounds,'ambiguous relay decode diagnostics')
roll=text('src/apps/daemon/internal/analysis/diagnostics/update_rollout_plan.go');check('RequiresPersistedHighWaterMark: true' in roll and 'PersistsHighWaterMark: false' in roll,'rollout replay boundary')
wg=text('src/apps/daemon/internal/analysis/diagnostics/wireguard_device_policy_plan.go');check('EphemeralPeerTimeoutSeconds' in wg and 'timeout == 48' in wg,'WireGuard 48s timeout cap')
upd=text('src/apps/daemon/internal/foundation/updateadmission/updateadmission.go');check('ManifestSchemaVersion       = 2' in upd and 'below persisted high-water mark' in upd,'signed update replay')
store=text('src/apps/daemon/internal/foundation/store/update_metadata.go');check('ON CONFLICT(product) DO UPDATE' in store and 'excluded.highest_sequence > update_metadata_state.highest_sequence' in store,'atomic update high-water')
helper=text('src/apps/daemon/internal/adapters/api/update_metadata_admission.go');stage=text('src/apps/daemon/internal/adapters/api/handlers_update_stage.go');check('verifySignedUpdateAgainstHighWater' in helper and 'acceptSignedUpdateSequence' in helper,'API replay helpers');check(stage.index('acceptSignedUpdateSequence')<stage.index('updateadmission.Stage'),'metadata accepted before artifact stage')
routes=text('src/apps/daemon/internal/adapters/api/routes_system.go')
for route in ['/tunnel-safety-plan','/split-tunnel-plan','/relay-constraint-plan','/update-rollout-plan','/tls-interception-evidence-plan']:check(route in routes,f'229 authenticated system route {route}')
handlers=text('src/apps/daemon/internal/adapters/api/handlers_post_refactor_229_planners.go');check(all(x not in handlers for x in ['http.Get(','http.Post(','exec.Command(','os.WriteFile(']),'229 planner handlers no hidden side effects')
ui_parser=text('src/packages/control-ui/src/api/planners.ts')
for tok in ['parseTunnelSafetyPlan','parseSplitTunnelPlan','parseRelayConstraintPlan','parseUpdateRolloutPlan','parseTLSInterceptionEvidencePlan']:check(tok in ui_parser,f'UI typed parser {tok}')
for page,toks in [('src/packages/control-ui/src/pages/Rules.tsx',['Split-tunnel admission & backup identity']),('src/packages/control-ui/src/pages/Health.tsx',['Tunnel safety lifecycle','TLS interception evidence']),('src/packages/control-ui/src/pages/Profiles.tsx',['Relay, multihop & obfuscation constraints']),('src/packages/control-ui/src/pages/Settings.tsx',['Update rollout & metadata replay posture']),('src/packages/control-ui/src/pages/Operations.tsx',['quota headroom','claimed_format'])]:
 body=text(page)
 for tok in toks:check(tok in body,f'229 product surface {page}:{tok}')
for owner in ['src/apps/daemon/internal/platform/system/host_network.go','src/apps/daemon/internal/analysis/diagnostics/endpoint_pool_plan.go','src/apps/daemon/internal/integrations/sub/profile_service.go']:check((ROOT/owner).is_file(),f'authority owner retained {owner}')

mk=text('Makefile');check('post-refactor-229-evidence' in mk and 'check_post_refactor_229_convergence.py' in mk,'Makefile owns 229 evidence/checker')
pkg=json.loads(text('src/packages/control-ui/package.json'));check(pkg['scripts'].get('test:229')=='node scripts/test-post-refactor-229.mjs','UI test:229 script');check('npm run test:229' in pkg['scripts']['test'],'aggregate UI test includes 229')
product=text('src/packages/control-ui/scripts/test-post-refactor-229.mjs');check('checks !== 168' in product,'229 product denominator 168');check('artifact format mismatch' in product and 'shared relay response sequence validator' in product,'229 new product characterization')

REPORTS={
 'post-refactor-229-architecture.md':['five outer donor','1,477','MasterHttpRelayVPN-RUST'],
 'post-refactor-229-security-model.md':['ezytel_ConfigWireguard.zip','read-only compatibility/anomaly','safety reserve'],
 'post-refactor-229-state-machines.md':['Relay sequencing','quota-guarded','degraded-unsafe'],
 'post-refactor-229-peer-synthesis.md':['five outer donors','118','historical fingerprint'],
 'post-refactor-229-omission-audit.md':['7,531/7,531','1,477/1,477','unresolved outer high-signal surfaces: 0'],
 'post-refactor-229-operator-runbook.md':['TLS interception evidence','quota safety buffer','supplied sequence must correlate'],
 'post-refactor-229-validation.md':['Go 1.26.5','frozen-source/archive integrity'],
 'post-refactor-229-all-history-second-order-audit.md':['five unique outer donor','58','7,531 per-file'],
}
for name,tokens in REPORTS.items():
 body=(E/name).read_text(encoding='utf-8',errors='replace')
 for tok in tokens:check(tok in body,f'{name} token {tok!r}')

print(f'post-refactor-229 convergence: assertions={assertions} errors={len(errors)}')
if errors:
 for e in errors[:300]:print('ERROR',e)
 if len(errors)>300:print(f'... {len(errors)-300} more errors')
 sys.exit(1)
