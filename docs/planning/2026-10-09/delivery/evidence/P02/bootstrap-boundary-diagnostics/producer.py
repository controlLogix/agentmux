import pathlib,hashlib,json,shutil,tempfile,subprocess,os,time
reviewRoot=pathlib.Path('/home/ryan/.cache/agentmux-governance/p02-cold-stage-implementation-9q417qj7');review=json.loads((reviewRoot/'review-before-tests.json').read_text());candidate=reviewRoot/'candidate';repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');base=reviewRoot/'before';H=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
out=pathlib.Path(tempfile.mkdtemp(prefix='p02-cold-boundary-focused-',dir='/home/ryan/.cache/agentmux-governance'));out.chmod(0o700)
paths={str(p.relative_to(base)) for folder in ['platform','contracts'] for p in (base/folder).rglob('*') if p.is_file()};assert len(paths)==272
before={k:H(repo/k) for k in sorted(paths)};basePins={k:H(base/k) for k in sorted(paths)};assert before==basePins,'shared_base_source_drift'
for folder in ['platform','contracts']:shutil.copytree(base/folder,out/'src'/folder)
copy={k:H(out/'src'/k) for k in sorted(paths)};assert before==copy
for k,pin in review['sourcePins'].items():
 assert H(candidate/k)==pin
 dest=out/'src'/k;dest.write_bytes((candidate/k).read_bytes());assert H(dest)==pin
executedPaths=paths|set(review['sourcePins']);executed={k:H(out/'src'/k) for k in sorted(executedPaths)}
for name,value in [('shared-before.json',before),('shared-copy.json',copy),('executed-before.json',executed)]: (out/name).write_text(json.dumps(value,indent=2)+'\n')
assert H(repo/'platform/launcher/docker_test.go')==H(out/'src/platform/launcher/docker_test.go')
# Actual TestMain uses controlled child mode only on explicit fixture env. All
# imported package init fixture controls must be absent in this real test parent.
for key in ['AMX_DOCKER_FIXTURE','AMX_OWNER_BRIDGE_DOCKER_FIXTURE','AMX_BOOTSTRAP_BOUNDARY_DOCKER_FIXTURE','AMX_BROKER_INSPECT_FIXTURE','AMX_DOCKER_FIXTURE_FILE','DOCKER_HOST','DOCKER_CONTEXT']:
 assert not os.environ.get(key),'unexpected_parent_fixture_override'
env=os.environ.copy();settings=dict(GOTOOLCHAIN='local',GOENV='off',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0',AMX_BOOTSTRAP_DOCKER_AUTHORIZED='0',AGENTMUX_TEST_NATS='/home/ryan/.cache/agentmux-governance/tools/nats-server');env.update(settings)
selector='^(TestBootstrapBoundaryStageTrustedAndClosed|TestBootstrapHistoryBoundaryStageRoundTrip|TestBootstrapBoundaryActualColdMutationGuard|TestBootstrapCleanupFailureRetainsActualSessionAndCauses)$'
args=['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','test','-race','-count=1','-json','./launcher','-run',selector]
invocation={'argv':args,'cwd':str(out/'src/platform'),'environment':settings,'sourceReviewSHA256':H(reviewRoot/'review-before-tests.json'),'diffSHA256':H(reviewRoot/'candidate.diff'),'overlayPins':review['sourcePins'],'parentFixtureOverridesAbsent':True,'TestMainSHA256':H(out/'src/platform/launcher/docker_test.go'),'sourceCounts':{'shared':len(paths),'executed':len(executedPaths)}};(out/'invocation.json').write_text(json.dumps(invocation,indent=2)+'\n')
started=time.monotonic();p=subprocess.Popen(args,cwd=out/'src/platform',env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);stdout,stderr=p.communicate();elapsed=time.monotonic()-started
(out/'events.jsonl').write_bytes(stdout);(out/'stderr.private').write_bytes(stderr);(out/'direct-exit.json').write_text(json.dumps({'exit':p.returncode,'seconds':elapsed,'exactOwnedGoHandleJoined':True},indent=2)+'\n')
events=[json.loads(x) for x in stdout.splitlines()];passes=[e['Test'] for e in events if e.get('Action')=='pass' and 'Test'in e];fails=[e.get('Test') for e in events if e.get('Action')=='fail'];skips=[e.get('Test') for e in events if e.get('Action')=='skip'];output=[e.get('Output','') for e in events if e.get('Action')=='output' and ('FAIL' in e.get('Output','') or '.go:' in e.get('Output',''))]
after={k:H(repo/k) for k in sorted(paths)};executedAfter={k:H(out/'src'/k) for k in sorted(executedPaths)};currentOverlayPins={k:H(candidate/k) for k in review['sourcePins']};stable=before==after and executed==executedAfter and currentOverlayPins==review['sourcePins']
for name,v in [('shared-after.json',after),('executed-after.json',executedAfter)]: (out/name).write_text(json.dumps(v,indent=2)+'\n')
record={'scope':'One exact four-group affected source selection, no real Docker/status/oldfixture','sourceReviewSHA256':invocation['sourceReviewSHA256'],'argv':args,'directExit':p.returncode,'seconds':elapsed,'passes':passes,'fails':fails,'skips':skips,'namedCounts':{'pass':len(passes),'fail':len([x for x in fails if x]),'skip':len(skips)},'sourceStable':stable,'ownedSourcePins':review['sourcePins'],'rawSHA256':{'events':H(out/'events.jsonl'),'stderr':H(out/'stderr.private')},'stderrBytes':len(stderr),'limits':['Cold boundary uses actual signed/static admission and Bootstrap with fixed synthetic Docker subprocesses. No real engine/broker.','Initialtimeout no-mutation and cold guarded compose-up require actual ledger assertion, not merely wrapped marker.','History component enter/complete seams are not actual installed-operation provenance.','Session.Close refusal uses actual OS lease/mutex+canceled child, no Group/physical native close failure.','No timing allowance change or native/phase acceptance.']};(out/'review.json').write_text(json.dumps(record,indent=2)+'\n')
for file in out.iterdir():
 if file.is_file():file.chmod(0o600)
print(json.dumps({'path':str(out),'reviewSHA256':H(out/'review.json'),'exit':p.returncode,'counts':record['namedCounts'],'failures':fails,'sourceStable':stable,'stderrBytes':len(stderr),'closedFailureOutput':output}),flush=True)
