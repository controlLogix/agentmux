import pathlib,subprocess,os,json,time
root=pathlib.Path('/home/ryan/.cache/agentmux-tests/p02-owner-bridge-tls-candidate-aeeryxie');env=os.environ.copy();env.update(GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',GOFLAGS='-mod=readonly')
cmd=['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','vet','./launcher'];started=time.monotonic()
with (root/'vet-direct.stdout').open('w') as out,(root/'vet-direct.stderr').open('w') as err: p=subprocess.run(cmd,cwd=root/'platform',env=env,stdout=out,stderr=err)
result={'command':cmd,'exit':p.returncode,'seconds':time.monotonic()-started};(root/'vet-direct-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))

