import hashlib,io,json,os,pathlib,subprocess,tarfile,tempfile
P=pathlib.Path; root=P(__file__).resolve().parent; source=P('/mnt/c/Users/RyanHelms/GitHub/agentmux');commit='c370290d6711b8f41d131723dc6a775334f03ccd'
base=P(tempfile.mkdtemp(prefix='original-team-',dir='/home/ryan/.cache/agentmux-governance'));native=base/'snapshot';native.mkdir();home=base/'home';home.mkdir();state=base/'state';state.mkdir()
paths=['agentmux.sh','agentmux.cmd','agentmux_windows.py','hub','taskmgmt'];blob=subprocess.check_output(['git','-C',str(source),'archive',commit,*paths]);tarfile.open(fileobj=io.BytesIO(blob)).extractall(native,filter='data');(native/'agentmux.sh').chmod(0o700)
hashes={str(p.relative_to(native)):hashlib.sha256(p.read_bytes()).hexdigest() for p in native.rglob('*') if p.is_file()}
(home/'.local/bin').mkdir(parents=True);(home/'.local/bin/agentmux').symlink_to(native/'agentmux.sh');bridge=root/'callback bin';bridge.mkdir()
for name in ('agentmux.cmd','agentmux_windows.py'):(bridge/name).write_bytes((native/name).read_bytes())
win=lambda p:subprocess.check_output(['wslpath','-w',str(p)],text=True).strip()
manifest={'commit':commit,'linuxFixture':str(base),'nativeSnapshot':str(native),'home':str(home),'state':str(state),'ntfsFixture':str(root),'windowsNtfsFixture':win(root),'demoBase':str(root/'original demo repos'),'windowsDemoBase':win(root/'original demo repos'),'helperDirectory':win(bridge),'sourceHashes':hashes,'originalCommand':['/home/ryan/.cache/agentmux-governance/venv/bin/python',str(native/'hub/demo/orchestrate.py'),'team'],'outerTimeoutSeconds':2700,'originalDrainSeconds':120,'modelExecuted':False,'acceptance':False}
(root/'fixture.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps({'fixture':str(root/'fixture.json'),'linuxFixture':str(base),'sourceReferences':len(hashes)}))
