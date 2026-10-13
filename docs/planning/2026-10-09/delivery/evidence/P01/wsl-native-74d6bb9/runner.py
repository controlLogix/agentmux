import subprocess,pathlib,tempfile,tarfile,io,hashlib,json,time,shutil,datetime
commit='74d6bb9fa1375763517494b0cc2c361f5b6d7535'
repo='/mnt/c/Users/RyanHelms/GitHub/agentmux'
base=pathlib.Path(tempfile.mkdtemp(prefix='amx-p01-final-wsl-',dir='/tmp'))
out=pathlib.Path('/home/ryan/.cache/agentmux-governance')/('qualification-'+base.name);out.mkdir()
(out/'runner.py').write_bytes(pathlib.Path(__file__).read_bytes())
for name in ('repo','home','cache','tmp'): (base/name).mkdir()
raw=subprocess.check_output(['git','-C',repo,'archive',commit])
with tarfile.open(fileobj=io.BytesIO(raw)) as archive:archive.extractall(base/'repo',filter='data')
root=base/'repo'
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
env={'HOME':str(base/'home'),'XDG_CACHE_HOME':str(base/'cache'),'TMPDIR':str(base/'tmp'),'TMUX_TMPDIR':str(base/'tmp'),'PATH':'/home/ryan/.cache/agentmux-governance/venv/bin:/home/ryan/.cache/agentmux-governance/tools:/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
command=['/home/ryan/.cache/agentmux-governance/venv/bin/python','-m','hub.tests.run_local','--profile','full']
report={'recordedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sourceCommit':commit,'checkout':str(root),'archiveSha256':hashlib.sha256(raw).hexdigest(),'environment':env,'sourceHashes':files,'command':command,'limits':['Actual WSL Linux runtime on native Linux filesystem; no Windows client or provider inference qualification.','Scoped source reuse must be reviewed against future candidate changes.']}
(out/'setup.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(str(out),flush=True)
start=time.monotonic()
with (out/'full.log').open('wb') as log: result=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=600)
results=list((base/'cache').rglob('result.json'))
assert len(results)==1
shutil.copyfile(results[0],out/'full-result.json')
report.update(exitCode=result.returncode,durationSeconds=time.monotonic()-start,sourceUnchangedDuringRun=all((root/n).is_file() and hashlib.sha256((root/n).read_bytes()).hexdigest()==sha for n,sha in files.items()),fixtureStateRetained=str(base))
(out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'output':str(out),'exitCode':result.returncode,'sourceUnchangedDuringRun':report['sourceUnchangedDuringRun'],'result':json.loads((out/'full-result.json').read_text())['status']}),flush=True)
raise SystemExit(result.returncode)
