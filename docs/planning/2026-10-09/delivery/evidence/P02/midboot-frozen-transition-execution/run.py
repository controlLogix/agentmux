from pathlib import Path
import hashlib,json,shutil,tempfile,subprocess,os,time
cache=Path('/home/ryan/.cache/agentmux-governance'); root=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux'); out=Path(tempfile.mkdtemp(prefix='p02-midboot-local-controls-',dir=cache));os.chmod(out,0o700)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def manifest():return {str(p.relative_to(root)):sha(p) for area in ['platform','contracts'] if (root/area).exists() for p in sorted((root/area).rglob('*')) if p.is_file() and '.git' not in p.parts}
before=manifest();src=out/'src';src.mkdir();shutil.copytree(root/'platform',src/'platform');shutil.copytree(root/'contracts',src/'contracts');after=manifest();assert before==after
additions=[cache/'p02-installed-cli-midboot-draft-erisu2sf/installed_cli_midboot_compose_integration_linux_test.go',cache/'p02-installed-cli-midboot-draft-erisu2sf/installed_cli_midboot_discovery_controls_test.go',cache/'p02-midboot-retained-readonly-oj8o1iq4/midboot_private_docker_parser_test.go',cache/'p02-midboot-retained-readonly-oj8o1iq4/midboot_private_docker_parser_controls_test.go',cache/'p02-installed-cli-midboot-draft-erisu2sf/installed_cli_midboot_starting_controls_test.go',cache/'p02-installed-cli-midboot-draft-erisu2sf/installed_cli_midboot_frozen_transition_controls_test.go']
for p in additions:shutil.copy2(p,src/'platform/launcher'/p.name)
assert all(sha(src/p)==digest for p,digest in before.items())
(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n');(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n');(out/'added-source.json').write_text(json.dumps({p.name:sha(p) for p in additions},indent=2)+'\n');shutil.copy2(__file__,out/'run.py')
env=os.environ.copy();env.update({'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'});env.pop('AMX_BOOTSTRAP_SELECTION_FILE',None);env.pop('AMX_BOOTSTRAP_SELECTION_SHA256',None)
go=str(cache/'runtime-comparison/go/bin/go');commands={};print(str(out),flush=True)
for name,selection in [('frozen','^TestComposeCLIMidBootFrozenHelperExecutionTransition$')]:
 argv=[go,'test','-race','-tags=agentmux_bootstrap_docker','-count=1','-json','./launcher','-run',selection];started=time.time();commands[name]={'argv':argv,'cwd':str(src/'platform'),'env':{k:env[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'startedUnix':started};(out/'invocation.json').write_text(json.dumps(commands,indent=2)+'\n')
 with (out/(name+'-events.jsonl')).open('wb') as stdout,(out/(name+'-stderr.log')).open('wb') as stderr:result=subprocess.run(argv,cwd=src/'platform',env=env,stdout=stdout,stderr=stderr)
 commands[name].update({'exit':result.returncode,'endedUnix':time.time()});(out/(name+'-exit.txt')).write_text(str(result.returncode)+'\n');(out/'invocation.json').write_text(json.dumps(commands,indent=2)+'\n');print(name+' exit '+str(result.returncode),flush=True)
 if result.returncode:break
(out/'current-after.json').write_text(json.dumps(manifest(),indent=2)+'\n')
print('complete',flush=True)