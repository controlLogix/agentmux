import pathlib,json,hashlib,ast,subprocess,re
repo=pathlib.Path(r'C:\Users\RyanHelms\GitHub\agentmux');root=repo/'docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/calibration-interop'
sha=lambda b:hashlib.sha256(b).hexdigest()
manifest=json.loads((root/'archive.json').read_bytes());entries=manifest['entries'];assert len(entries)==119
producer=root/manifest['archiveProducer']['path'];assert sha(producer.read_bytes())==manifest['archiveProducer']['sha256']=='a69f7079ed2df3c58ed90ede9e6a989c49525c6ce6ace6b6f7acdc9faff2a841'
tree=ast.parse(producer.read_text(encoding='utf-8'));groups=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='GROUPS' for t in n.targets))
expected={str(pathlib.PurePosixPath(group)/name) for group,(_,names) in groups.items() for name in names};assert len(expected)==119 and expected=={e['path'] for e in entries}
for e in entries:
 p=root/pathlib.Path(e['path']);source=pathlib.Path(e['source']);data=p.read_bytes();assert len(data)==e['bytes'] and sha(data)==e['sha256'];assert source.read_bytes()==data
 assert not p.is_symlink() and p.resolve().is_relative_to(root.resolve())
 assert not set(pathlib.PurePosixPath(e['path']).parts).intersection({'.git','sqlite','logs','synthetic-profile','sessions'})
 assert p.name not in {'auth.json','config.toml','token','token.json','credentials.json'}
allfiles={str(p.relative_to(root)).replace('\\','/') for p in root.rglob('*') if p.is_file()}
assert allfiles==expected|{'.gitattributes','archive-producer.py','archive.json','README.md'},sorted(allfiles-expected)
verified=[]
commit=manifest['sourceCommit'];assert commit=='36cc149a774d823716c81d7b5443b852cb0c63d1'
for row in manifest['sourceVerification']:
 p=root/row['group']/row['report'];obj=json.loads(p.read_bytes());assert sha(p.read_bytes())==row['reportSha256']
 if row['group']=='mcp-override-probe':
  assert obj['passed'];records={r['case']:r for r in obj['records']};assert records['quoted']['exitCode']==1 and 'invalid transport' in records['quoted']['stderr'];assert records['bare']['exitCode']==0 and records['bare']['namesAndEnabled']==[{'name':'agent-browser','enabled':False}]
  for source,h in obj['sourceHashes'].items():assert sha(pathlib.Path(source).read_bytes())==h
  verified.append({'group':row['group'],'installedSourceFiles':3,'quotedExit':1,'bareExit':0})
 else:
  assert obj['commit']==commit and len(obj['sourceHashes'])==67
  for rel,h in obj['sourceHashes'].items():assert sha(subprocess.check_output(['git','-C',str(repo),'show',commit+':'+rel]))==h
  verified.append({'group':row['group'],'exactGitBlobReferences':67})
first=json.loads((root/'original-calibration-first-failure/20261011-181922-calib.json').read_bytes());assert first['checks']=={'E1_all_top_done':False,'E2_no_dead_delivery':True,'E3_no_failed_bell':True,'E4_no_blocked_or_died':False,'E5_all_acked':False,'E6_verified':False};assert first['error_free'] is False
assert all(work['claimed_by'] is None and work['attempts']==0 for work in first['work'])
retry=json.loads((root/'original-calibration-term-retry/attempt-result.json').read_bytes());assert not retry['originalReports']
startup=(root/'original-calibration-term-retry/startup-pane.log').read_text();assert 'invalid transport' in startup and 'agent-browser' in startup
readme=(root/'README.md').read_text(encoding='utf-8');assert readme.isascii();assert 'E1=false, E2=true, E3=true, E4=false, E5=false, E6=false' in readme;assert 'TERM retry is unscored' in readme;assert 'do not accept the phase' in readme;assert 'Four required real-provider scenarios remain open' in readme
for group,agent in [('original-calibration-first-failure','calc-worker-codex_1819'),('original-calibration-term-retry','calc-worker-codex_1828')]:
 launch=json.loads((root/group/'windows-supervisors'/agent/'launch-result.json').read_bytes());assert launch['jobAccounting']['ActiveProcesses']==0 and launch['windowsConfigBytesUnchanged'] is True
report={'passed':True,'scope':'Independent archive bytes, explicit allowlist, source references and first two failed actual results only.','archiveRawFiles':119,'archiveAllFiles':123,'sourceProof':verified,'producerSha256':sha(producer.read_bytes()),'archiveManifestSha256':sha((root/'archive.json').read_bytes()),'firstCalibrationChecks':first['checks'],'firstCalibrationErrorFree':False,'secondCalibrationScored':False,'unexpectedFiles':[],'excludedArtifactsAbsentByPathInventory':True,'configOrAuthContentsRead':False,'upcomingLiveThirdAttemptReviewed':False,'findings':[],'limits':['Exclusions are verified through the exact allowlist and file inventory, not a universal secret scanner.','Cleanup and synthetic prerequisites are not phase acceptance.']}
out=pathlib.Path(r'C:\Users\RyanHelms\.cache\agentmux\p01-calibration-interop-independent-review.json');out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2));print('Report SHA256 '+sha(out.read_bytes()))