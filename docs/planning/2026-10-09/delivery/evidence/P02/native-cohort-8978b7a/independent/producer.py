import pathlib,json,hashlib,tempfile,collections
root=pathlib.Path('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-ci-8978-7ae31b3f'); original=root/'review.json'; record=json.loads(original.read_text()); expected='8978b7ae5ce8aad69d017b774861f19231c26b63'
assert hashlib.sha256(original.read_bytes()).hexdigest()=='fa28594ab7a5f8c5688b82bc47160af22f24e643a823fcc51e03e2d3716a7ff2'
for key,pin in record['artifactSHA256'].items():
 assert not key.startswith(('/','\\')) and '..' not in pathlib.PurePosixPath(key).parts and ':' not in key
 p=(root/key).resolve();assert p.is_relative_to(root.resolve());assert hashlib.sha256(p.read_bytes()).hexdigest()==pin
assert len(record['artifactSHA256'])==153
out=pathlib.Path(tempfile.mkdtemp(prefix='p02-ci-8978-independent-admission-',dir='/home/ryan/.cache/agentmux-governance'))
cohorts=[]; sourceMaps=[]
for cohort in record['reports']:
 d=root/cohort['directory']; rp=next(p for p in d.iterdir() if p.name in ['result.json','ci-result.json']); data=json.loads(rp.read_text())
 assert data['sourceCommit']==expected,(cohort['directory'],data['sourceCommit'])
 assert data['sourceUnchangedDuringRun'] is True
 sourceMaps.append(data['sourceHashes'])
 if 'executedSourceHashes' in data:
  assert data['executedSourceUnchangedDuringRun'] is True
  common=set(data['sourceHashes'])&set(data['executedSourceHashes']);assert all(data['sourceHashes'][k]==data['executedSourceHashes'][k] for k in common)
 checks=[];total=collections.Counter()
 for check in data['checks']:
  item={'name':check['name'],'directExit':check['exitCode'],'timedOut':check.get('timedOut',False)}
  if check.get('raw'):
   raw=d/check['raw'];events=[json.loads(line) for line in raw.read_text().splitlines() if line.strip()]; counts=collections.Counter(); named=[]; runs=[]
   for event in events:
    if event.get('Test'):
     if event['Action']=='run': runs.append((event['Package'],event['Test']))
     if event['Action'] in ['pass','fail','skip']:
      counts['named_'+event['Action']]+=1
      counts['top_'+event['Action']]+=int('/' not in event['Test'])
      named.append({'package':event['Package'],'test':event['Test'],'action':event['Action']})
    elif event['Action'] in ['pass','fail','skip']: counts['package_'+event['Action']]+=1
   completed=[(e['package'],e['test']) for e in named];assert collections.Counter(runs)==collections.Counter(completed)
   assert counts['named_pass']==check.get('passedTestEvents',counts['named_pass'])
   assert counts['named_skip']==check.get('skipEvents',counts['named_skip'])
   assert counts['named_fail']+counts['package_fail']==check.get('failureEvents',counts['named_fail']+counts['package_fail'])
   item.update({'rawSHA256':hashlib.sha256(raw.read_bytes()).hexdigest(),'counts':dict(counts),'allStartedNamedTestsCompleted':True,'namedOutcomes':named});total.update(counts)
  else:item['scope']='Retained P01 report check, not counted as a Go named event.'
  checks.append(item)
 cohorts.append({'artifact':cohort['directory'],'sourceCommit':data['sourceCommit'],'sourceHashesSHA256':hashlib.sha256(json.dumps(data['sourceHashes'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'sourceHashCount':len(data['sourceHashes']),'executedHashCount':len(data.get('executedSourceHashes',{})),'sourceUnchanged':True,'executedSourceUnchanged':data.get('executedSourceUnchangedDuringRun'),'checks':checks,'rawCounts':dict(total),'reportCheckCount':len(checks)})
common=set.intersection(*(set(m) for m in sourceMaps));assert all(len({m[k] for m in sourceMaps})==1 for k in common)
review={'scope':'Independent admission of already downloaded exact-candidate CI evidence only; no rerun/download/build/engine/shared change.','commit':expected,'originalReviewSHA256':hashlib.sha256(original.read_bytes()).hexdigest(),'relativeArtifactCount':153,'allArtifactHashesVerified':True,'allPathsConfined':True,'commonSourceReferencesAgree':True,'commonSourceReferenceCount':len(common),'cohorts':cohorts,'limits':['Retained P01 report checks are not Go event counts.','Descriptor research failures remain actual failed evidence; product fail-closed controls remain separate.','Foundation/install coverage does not imply real Compose, Windows observer or P02 phase acceptance.']}
(out/'independent-admission.json').write_text(json.dumps(review,indent=2)+'\n');summary=[{'artifact':x['artifact'],'reportChecks':x['reportCheckCount'],'rawGoCounts':x['rawCounts']} for x in cohorts];(out/'count-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2));print('record',out/'independent-admission.json');print('SHA256',hashlib.sha256((out/'independent-admission.json').read_bytes()).hexdigest());print('commonSources',len(common))