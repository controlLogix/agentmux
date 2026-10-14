from pathlib import Path
import subprocess,os,json
out=Path('/home/ryan/.cache/agentmux-governance/p02-raw-cleanup-e6120d5e');go='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go';fixed=json.loads((out/'focused-invocation.json').read_text())['fixedEnvironment'];env=os.environ.copy();env.update(fixed);commands={'affected':[go,'test','-race','-count=1','-json','./deployment','-run','^Test(Team|Observe|Probe|Provision|LocalTLSProbe|RawTransportCleanup)'],'vet':[go,'vet','./deployment']};(out/'affected-invocation.json').write_text(json.dumps({'cwd':str(out/'platform'),'commands':commands,'fixedEnvironment':fixed},indent=2)+'\n');exits={}
for name,args in commands.items():
 with(out/(name+'.stdout')).open('wb')as stdout,(out/(name+'.stderr')).open('wb')as stderr:r=subprocess.run(args,cwd=out/'platform',env=env,stdout=stdout,stderr=stderr)
 exits[name]=r.returncode;(out/'affected-exits.json').write_text(json.dumps(exits)+'\n')
print(json.dumps(exits))