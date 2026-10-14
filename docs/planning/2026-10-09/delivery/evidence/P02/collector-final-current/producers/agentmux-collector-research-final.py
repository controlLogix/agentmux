import pathlib,shutil,tempfile,subprocess,json,hashlib,time
repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');root=pathlib.Path(tempfile.mkdtemp(prefix='p02-collector-research-final-',dir='/home/ryan/.cache/agentmux-governance'));p=root/'tests/platform/native_go.py';p.parent.mkdir(parents=True);shutil.copyfile(repo/'tests/platform/native_go.py',p);ci=root/'tests/contracts/ci.py';ci.parent.mkdir();shutil.copyfile(repo/'tests/contracts/ci.py',ci)
for label,args in [('focused',['-m','unittest','native_go.RunnerTests.test_research_refusal_claim_requires_stable_original_and_executed_source']),('selftest',[str(p),'--self-test'])]:
 cmd=['python3']+args;start=time.monotonic()
 with (root/(label+'.stdout')).open('w') as out,(root/(label+'.stderr')).open('w') as err:r=subprocess.run(cmd,cwd=p.parent,stdout=out,stderr=err)
 record={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start,'sourceSHA256':hashlib.sha256(p.read_bytes()).hexdigest(),'sourceStable':p.read_bytes()==(repo/'tests/platform/native_go.py').read_bytes()};(root/(label+'-result.json')).write_text(json.dumps(record,indent=2));print(json.dumps(record));print((root/(label+'.stderr')).read_text()[-500:])
 if r.returncode:raise SystemExit(r.returncode)
print(str(root))
