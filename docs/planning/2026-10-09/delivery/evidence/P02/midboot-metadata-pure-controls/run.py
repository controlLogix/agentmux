from pathlib import Path
import hashlib,json,tempfile,subprocess,os,time,shutil
cache=Path('/home/ryan/.cache/agentmux-governance');draft=cache/'p02-installed-cli-midboot-draft-erisu2sf';out=Path(tempfile.mkdtemp(prefix='p02-midboot-metadata-pure-',dir=cache));os.chmod(out,0o700)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();expected={'installed_cli_midboot_metadata_predicate_test.go':'2ff0cd87051d8a25263ea2ba59ced3cb83f0148ecf6f73bd046f5a52aad83e16','installed_cli_midboot_metadata_controls_test.go':'531d4751a0824e9bd5538ba1b242d89304eb0a1023bcaad686fcb5e02011d80c'}
before={name:sha(draft/name) for name in expected};assert before==expected
for name in expected:shutil.copy2(draft/name,out/name)
assert {name:sha(out/name) for name in expected}==expected
shutil.copy2(__file__,out/'run.py');cwd=cache/'p02-midboot-local-controls-oqerocw2/src/platform';assert (cwd/'go.mod').exists()
env=os.environ.copy();env.update({'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GOENV':'off','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'});env.pop('AMX_BOOTSTRAP_SELECTION_FILE',None);env.pop('AMX_BOOTSTRAP_SELECTION_SHA256',None)
argv=[str(cache/'runtime-comparison/go/bin/go'),'test','-count=1','-json',str(out/'installed_cli_midboot_metadata_predicate_test.go'),str(out/'installed_cli_midboot_metadata_controls_test.go')]
inv={'argv':argv,'cwd':str(cwd),'environment':{k:env[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GOENV','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'sourceBefore':before,'startedUnix':time.time(),'fileListOnly':True,'launcherTestMainExcluded':True,'integrationFilesExcluded':True};(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');print(str(out),flush=True)
with (out/'events.jsonl').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:r=subprocess.run(argv,cwd=cwd,env=env,stdout=stdout,stderr=stderr)
(out/'exit.txt').write_text(str(r.returncode)+'\n');after={name:sha(draft/name) for name in expected};inv.update({'endedUnix':time.time(),'directExit':r.returncode,'sourceAfter':after,'sourceUnchanged':before==after==expected});(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');print('exit '+str(r.returncode),flush=True)