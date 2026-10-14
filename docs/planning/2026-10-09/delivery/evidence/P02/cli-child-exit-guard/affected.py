from pathlib import Path
import json,subprocess,os
out=Path('/home/ryan/.cache/agentmux-governance/p02-cli-child-guard-305b4b1e');go='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go';commands={'affected':[go,'test','-race','-count=1','-json','./cmd/agentmux-runtime'],'vet':[go,'vet','./cmd/agentmux-runtime']};fixed={'GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0'};env=os.environ.copy();env.update(fixed);(out/'affected-invocation.json').write_text(json.dumps({'cwd':str(out/'platform'),'commands':commands,'fixedEnvironment':fixed},indent=2)+'\n');exits={}
for name,args in commands.items():
 with(out/(name+'.stdout')).open('wb')as stdout,(out/(name+'.stderr')).open('wb')as stderr:r=subprocess.run(args,cwd=out/'platform',env=env,stdout=stdout,stderr=stderr)
 exits[name]=r.returncode;(out/'affected-exits.json').write_text(json.dumps(exits)+'\n')
print(json.dumps(exits))