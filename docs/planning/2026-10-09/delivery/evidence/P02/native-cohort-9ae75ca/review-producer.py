import pathlib,json,hashlib,collections
p=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-native-peer-38652680172-68a00928');repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();commit='9ae75ca1b96da069b3dd91c2cb149723c72215a9';run=json.loads((p/'run-state-final.json').read_text());qualification=json.loads((p/'qualification-state-final.json').read_text());assert run['headSha']==qualification['headSha']==commit
rows=[];allsource={};errors=[]
for d in sorted((p/'artifacts').iterdir()):
 r=json.loads((d/'result.json').read_text());assert r['sourceCommit']==commit
 hashes=r['sourceHashes'];executed=r['executedSourceHashes'];allsource.update(hashes);checks=[]
 for c in r['checks']:
  raw=d/c['raw'];stderr=d/c['stderr'];assert sha(raw)==c['rawSha256'] and sha(stderr)==c['stderrSha256'],'artifact_raw_digest_mismatch'
  events=[json.loads(s)for s in raw.read_text().splitlines()if s];began=collections.Counter();ended=collections.Counter();passes=[];fails=[];skips=[]
  for e in events:
   if 'Test'in e:
    key=(e.get('Package'),e['Test'])
    if e.get('Action')=='run':began[key]+=1
    if e.get('Action')in ['pass','fail','skip']:
     ended[key]+=1
     {'pass':passes,'fail':fails,'skip':skips}[e['Action']].append(e['Test'])
  assert began==ended,'unjoined_named_test_events'
  assert len(passes)==c['passedTestEvents'] and sum(e.get('Action')=='fail' for e in events)==c['failureEvents'] and len(skips)==c['skipEvents'],'reported_counts_mismatch'
  checks.append({'name':c['name'],'command':c['command'],'exitCode':c['exitCode'],'passedNamedEvents':len(passes),'failedNames':fails,'skippedNames':skips,'rawSHA256':sha(raw),'stderrSHA256':sha(stderr),'receiptSurvivalPass':[x for x in passes if x=='TestBootstrapReceiptSurvivesActualFrontendExit'],'rawNamedLifecycleComplete':True})
 rows.append({'artifact':d.name,'resultSHA256':sha(d/'result.json'),'host':r.get('host'),'status':r['status'],'checks':checks,'sourceCommit':r['sourceCommit'],'sourceHashCount':len(hashes),'executedSourceHashCount':len(executed),'executedManifestMatchesSource':all(hashes.get(k)==v for k,v in executed.items()),'recordedSourceStable':r.get('sourceUnchangedDuringRun'),'recordedExecutedStable':r.get('executedSourceUnchangedDuringRun'),'phaseAccepted':r.get('phaseAccepted'),'runtimeQualification':r.get('runtimeQualification'),'nativeProtectedBootQualified':r.get('nativeProtectedBootQualified'),'composeQualified':r.get('composeQualified')})
currentMismatch=[]
for n,v in allsource.items():
 f=repo/n
 if not f.is_file()or sha(f)!=v:currentMismatch.append(n)
q=[]
for d in sorted((p/'qualification-artifacts').iterdir()):
 r=json.loads((d/'ci-result.json').read_text());assert r['sourceCommit']==commit
 q.append({'artifact':d.name,'ciResultSHA256':sha(d/'ci-result.json'),'sourceCommit':r['sourceCommit'],'directExit':r['exitCode'],'recordedSourceStable':r['sourceUnchangedDuringRun'],'checkCount':len(r['checks']),'checks':r['checks']})
review={'scope':'Independent downloaded existing native/P01 CI evidence, no new execution','sourceCommit':commit,'nativeRun':{'id':38652680172,'status':run['status'],'conclusion':run['conclusion'],'url':run['url']},'nativeArtifacts':rows,'currentSourceComparison':{'uniqueRecordedSourceCount':len(allsource),'mismatches':currentMismatch},'retainedQualificationRun':{'id':38652680238,'status':qualification['status'],'conclusion':qualification['conclusion'],'url':qualification['url'],'artifacts':q},'downloadAuth':'Existing Windows ryanhelms account token used only in perprocess GH_TOKEN; no token stored or printed, global account not switched.','researchObservedFailure':'Both TestDarwinUnlinkedDescriptorResearch fail with permission denied executing /dev/fd/3; actualChildExecuted=false. Separate fail-closed control passes.','limits':['Nativefoundation fullmatrix is not installedCLI realCompose/fullphase acceptance.','NativeLinux receipt-survival namedcase passed onamd64 andarm64; Macfoundation runtime selection differs, do not infer same receiptcase.','Mac installedhost/protectedimage fixtures pass separately; no four-role NATS/EOF/Compose qualification asserted.','Research failures preserved as failures; entire native workflow conclusionfailure remains.','Retained P01 qualification artifacts collected/status checked; no phase advancement decision.','No CIrerun/cancel/dispatch, compiler/test/engine call, source edit or credential persistence.'],'artifactManifest':{str(f.relative_to(p)):{'sha256':sha(f),'bytes':f.stat().st_size}for f in sorted(p.rglob('*'))if f.is_file()}}
(p/'independent-review.json').write_text(json.dumps(review,indent=2)+'\n');print('reviewSHA256',sha(p/'independent-review.json'));print('currentSourceMismatches',currentMismatch);print('nativeRows',len(rows));print('nativeStatus',run['status'],run['conclusion']);print('qualificationStatus',qualification['status'],qualification['conclusion']);print('cohortCounts',[(r['artifact'].split('-9ae')[0],sum(c['passedNamedEvents']for c in r['checks']))for r in rows])