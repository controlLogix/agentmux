import pathlib,json,hashlib
b=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-mac-ci-f520');H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
artifacts=[];verification=[]
for d in sorted(b.glob('artifact-*')):
 if not d.is_dir():continue
 r=json.loads((d/'result.json').read_text());checks=[]
 for c in r['checks']:
  for name,key in [('raw','rawSha256'),('stderr','stderrSha256')]:
   if c.get(name):verification.append({'path':str((d/c[name]).relative_to(b)),'matches':H(d/c[name])==c[key]})
  if c['status']=='passed':continue
  events=[json.loads(x) for x in (d/c['raw']).read_text().splitlines()]
  failed=[x['Test'] for x in events if x.get('Action')=='fail' and x.get('Test')]
  compiler=sorted(set(x['Output'].strip() for x in events if x.get('Action')=='build-output' and 'error:' in x.get('Output','')))
  checks.append({'name':c['name'],'exitCode':c['exitCode'],'namedPassed':c['passedTestEvents'],'namedFailures':failed,'compilerErrors':compiler})
 artifacts.append({'id':d.name,'host':r['host'],'resultSHA256':H(d/'result.json'),'checks':checks})
rows=json.loads((b/'repair-source-pins.json').read_text())
record={'scope':'P02 source and exact native CI failure diagnosis; no phase acceptance','runId':38635588141,'commit':'f5202b265c8ef1128534401a8f0ec0e6dc26bf84','artifacts':artifacts,'rawVerification':verification,'allRecordedRawHashesMatch':all(x['matches'] for x in verification),'sourcePins':rows,'controls':json.loads((b/'acl-controls.json').read_text()),'limits':['Actual Mac runtime compiler error is proven; spelling correction is not native execution proof.','Valid empty-ACL fixtures are refused on both native Mac architectures. Explicit absence is the source-supported likely mechanism; original native records do not expose each native C predicate.','C controls extract exact candidate functions with test-only modeled Apple APIs; they do not execute an Apple SDK, filesystem, ACL or mount.','Runtime before control normalizes only old mount spelling so the separate absent-ACL refusal can execute.','Initial runtime model incorrectly checked ACL-only function against mount-denial expectations and failed; corrected producer calls the actual composite ACL-plus-mount predicate. Initial tool chunks d9aaba/174f3f preserve this harness correction, not a product failure.','Linux ARM now passes but its original poll failure cause remains unknown.','No CI rerun, source promotion, Docker job or native qualification by this worker.'],'primarySources':['https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/posix1e/acl_file.c','https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/gen/filesec.c','https://raw.githubusercontent.com/apple-oss-distributions/Libc/main/sys/statx_np.c','https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/fcntl.h','https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/mount.h']}
manifest={str(p.relative_to(b)):H(p) for p in b.rglob('*') if p.is_file() and p.suffix not in ['.zip'] and p.name not in ['review.json','manifest.json'] and not p.name.endswith('-control')}
(b/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');record['manifestSHA256']=H(b/'manifest.json');(b/'review.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'reviewSHA256':H(b/'review.json'),'manifestSHA256':H(b/'manifest.json'),'rawHashesMatch':record['allRecordedRawHashesMatch'],'sourcePins':rows}))