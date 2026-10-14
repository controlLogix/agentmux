from pathlib import Path
import json,hashlib,shutil,subprocess,os
root=Path('/home/ryan/.cache/agentmux-governance/p02-public-raw-fault-309a7780');shutil.copyfile('/home/ryan/.cache/agentmux-governance/public_raw_fault_producer.py',root/'initial-producer.py');binding=json.loads((root/'source-binding.json').read_text());(root/'originals').mkdir()
for name,m in binding['changes'].items():
 src=Path('/mnt/c/Users/RyanHelms/GitHub/agentmux/platform/deployment')/name;assert hashlib.sha256(src.read_bytes()).hexdigest()==m['originalSHA256'];shutil.copyfile(src,root/'originals'/name)
inv=json.loads((root/'small-invocation.json').read_text());env=os.environ.copy();env.update(inv['fixedEnvironment']);go=inv['args'][0]
def run(where,label,selector):
 args=[go,'test','-race','-count=1','-json','./deployment','-run',selector];(where/(label+'-invocation.json')).write_text(json.dumps({'args':args,'cwd':str(where/'platform'),'fixedEnvironment':inv['fixedEnvironment']},indent=2)+'\n')
 with(where/(label+'.jsonl')).open('wb')as out,(where/(label+'.stderr')).open('wb')as err:r=subprocess.run(args,cwd=where/'platform',env=env,stdout=out,stderr=err)
 (where/(label+'-exit.json')).write_text(json.dumps({'exitCode':r.returncode})+'\n');print(label,r.returncode,flush=True);return r.returncode
assert run(root,'all','^TestRawPublicCallerCleanupInvalidatesFacts$')==0
mutations=[('team','team_connection.go','out = TeamConnectionObservation{DomainAvailability: "unavailable", KernelAvailability: "unavailable", Code: "cleanup_failed"}'),('probe','probe.go','result = ProbeResult{}'),('observe','observe.go','result = Observation{PersistenceEvidence: PersistenceUnknown, Code: "observation_incomplete", Scope: "Read-only infrastructure observation; not write, recovery or application readiness proof."}')]
for kind,name,statement in mutations:
 mutant=root/('mutant-'+kind);mutant.mkdir();shutil.copytree(root/'platform',mutant/'platform');p=mutant/'platform/deployment'/name;text=p.read_text();pos=text.index('if failed {');idx=text.index(statement,pos);assert idx<text.index('\n\t\t}',pos);text=text[:idx]+'// Diagnostic mutant deliberately omits fact invalidation.'+text[idx+len(statement):];p.write_text(text);(mutant/'mutation.json').write_text(json.dumps({'file':'deployment/'+name,'removed':statement,'mutatedSHA256':hashlib.sha256(p.read_bytes()).hexdigest(),'expectedExit':1},indent=2)+'\n');assert run(mutant,'negative','^TestRawPublicCallerCleanupInvalidatesFacts/'+kind+'$')==1
print('complete',flush=True)