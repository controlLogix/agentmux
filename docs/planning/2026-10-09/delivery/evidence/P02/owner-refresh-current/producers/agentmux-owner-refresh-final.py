import pathlib,json,hashlib,os,subprocess,time,sys
root=pathlib.Path('/home/ryan/.cache/agentmux-tests/p02-owner-bridge-tls-candidate-aeeryxie')
label,pattern=sys.argv[1:3]
freeze=json.loads((root/'freeze.json').read_text())['source']
def hashes(): return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'platform').rglob('*') if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum'))}
if freeze!=hashes(): raise SystemExit('frozen source drift')
env=os.environ.copy();env.update(GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0',AGENTMUX_TEST_NATS='/home/ryan/.cache/agentmux-governance/tools/nats-server')
outputs=root/'outputs';outputs.mkdir(exist_ok=True);env['AGENTMUX_OWNER_BRIDGE_OUTPUTS']=str(outputs)
cmd=['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','test','-race','-count=1','-json','./launcher','-run',pattern]
start=time.monotonic()
with (root/(label+'.jsonl')).open('w') as out,(root/(label+'.stderr')).open('w') as err: run=subprocess.run(cmd,cwd=root/'platform',env=env,stdout=out,stderr=err)
events=[json.loads(s) for s in (root/(label+'.jsonl')).read_text().splitlines()]
result={'command':cmd,'exit':run.returncode,'seconds':time.monotonic()-start,'sourceStable':freeze==hashes(),'namedPass':sum(e.get('Action')=='pass' and 'Test' in e for e in events),'namedFail':sum(e.get('Action')=='fail' and 'Test' in e for e in events),'skips':sum(e.get('Action')=='skip' for e in events)};(root/(label+'-result.json')).write_text(json.dumps(result,indent=2));print(json.dumps(result))
for e in events:
 if e.get('Action')=='fail' or e.get('OutputType')=='error' or e.get('Action')=='build-output': print(json.dumps(e))

