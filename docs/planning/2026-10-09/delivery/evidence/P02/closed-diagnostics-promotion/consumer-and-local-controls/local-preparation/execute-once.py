import pathlib,hashlib,json,os,stat,subprocess,tempfile,time
prep=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-policy-local-preparation-current')
r=json.loads((prep/'preparation.json').read_bytes());snapshot=pathlib.Path(r['snapshot']);repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');working=snapshot/'src/platform';pins=json.loads((snapshot/'source-before.json').read_bytes());H=lambda b:hashlib.sha256(b).hexdigest()
out=pathlib.Path(tempfile.mkdtemp(prefix='p02-local-preparation-once-',dir='/home/ryan/.cache/agentmux-governance'));out.chmod(0o700)
def save(name,value,private=False):
 p=out/name;p.write_bytes(value if isinstance(value,bytes) else (json.dumps(value,indent=2)+'\n').encode());p.chmod(0o600);return H(p.read_bytes())
def sources():return {k:{'current':H((repo/k).read_bytes()),'prepared':H((snapshot/'src'/k).read_bytes())} for k in pins}
before=sources();assert len(pins)==133 and all(v['current']==pins[k]==v['prepared'] for k,v in before.items());assert H((snapshot/'main.go').read_bytes())==r['programSHA256'];save('source-before.json',before)
fixture=pathlib.Path('/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3887681337')
def inventory():
 rows={};total=0
 for folder in ['installed','profile','release']:
  root=fixture/folder
  for p in [root]+sorted(root.rglob('*')):
   s=p.lstat();row={'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode,'nlink':s.st_nlink,'size':s.st_size,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns}
   assert stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)
   if stat.S_ISREG(s.st_mode):
    total+=s.st_size;assert s.st_size<=128*1024*1024 and total<=512*1024*1024
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
     held=os.fstat(f.fileno());assert held.st_dev==s.st_dev and held.st_ino==s.st_ino
     digest=hashlib.sha256()
     for chunk in iter(lambda:f.read(65536),b''):digest.update(chunk)
    row['sha256']=digest.hexdigest()
   rows[str(p.relative_to(fixture))]=row
 return rows
fb=inventory();save('fixture-before.private.json',fb);env=os.environ.copy();settings=dict(GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOENV='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0',AMX_BOOTSTRAP_DOCKER_AUTHORIZED='0');env.update(settings);calls=[]
def run(name,args,limit):
 started=time.monotonic()
 # Capture private bounded streams to regular cache files, never fixture files.
 paths=[out/(name+'.'+stream+'.private') for stream in ['stdout','stderr']]
 files=[open(p,'xb') for p in paths]
 for p in paths:p.chmod(0o600)
 p=subprocess.Popen(args,cwd=working,env=env,stdout=files[0],stderr=files[1]);timeout=False
 try:p.wait(timeout=limit)
 except subprocess.TimeoutExpired:
  timeout=True;p.terminate()
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 finally:
  for f in files:f.close()
 blobs=[p.read_bytes() for p in paths];row={'name':name,'argv':args,'cwd':str(working),'exitCode':p.returncode,'timedOut':timeout,'seconds':time.monotonic()-started,'exactOwnedHandleJoined':True,'stdoutBytes':len(blobs[0]),'stderrBytes':len(blobs[1]),'stdoutSHA256':H(blobs[0]),'stderrSHA256':H(blobs[1])};calls.append(row);save(name+'-exit.json',row)
 assert all(len(b)<=65536 for b in blobs),'private_capture_limit'
 return row,blobs
save('invocation.json',{'environment':settings,'compile':['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','build','-o',str(out/'helper'),str(snapshot/'main.go')],'helper':[str(out/'helper')]})
compile,blobs=run('compile',['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','build','-o',str(out/'helper'),str(snapshot/'main.go')],60)
value=None;execution=None
if compile['exitCode']==0 and not compile['timedOut']:
 assert sources()==before and inventory()==fb
 execution,blobs=run('helper',[str(out/'helper')],30)
 value=json.loads(blobs[0]);assert set(value)=={'schemaVersion','kind','stages'} and value['schemaVersion']=='1.0.0' and value['kind']=='local-preparation-diagnostic'
 names=['admission','local_invocation_constructor','receipt_binding','installed_image_preparation','installed_image_close'];assert len(value['stages'])==5
 for row,name in zip(value['stages'],names):assert set(row)=={'stage','status','refusalCode'} and row['stage']==name and row['status'] in ['passed','refused','unexecuted'] and row['refusalCode'] in r['closedRefusalWhitelist']
 assert not execution['timedOut'] and execution['exitCode']==(0 if all(x['status']=='passed' for x in value['stages']) else 1)
after=sources();fa=inventory();save('source-after.json',after);save('fixture-after.private.json',fa)
result={'scope':'One local preparation helper; no original failure cause or host ownership claim','programSHA256':r['programSHA256'],'preparationSHA256':H((prep/'preparation.json').read_bytes()),'sourceCount':len(pins),'calls':calls,'closedOutput':value,'currentAndPreparedSourcesUnchanged':before==after,'fixtureBytesAndOwnershipUnchanged':fb==fa,'fixtureEntryCount':len(fb),'imageCloseObservation':('Close returned nil and original context remained active' if value and value['stages'][4]['status']=='passed' else 'No separate actual Close error conclusion from a context refusal row; inspect closed status only'),'limits':['No StartHost/Probe/Request/engine/NATS/process discovery/signals or fixture writes.','Only exact newly created compiler/helper processes owned; no fixture process authority.','Synchronous filesystem, crypto and image Close calls are not hard-preemptible.','Private stream size checked before projection; no timeout occurred unless explicitly recorded.','Passing current preparation cannot establish the original frontend failure stage.']}
sha=save('review.json',result);manifest={str(p.relative_to(out)):H(p.read_bytes()) for p in out.iterdir() if p.is_file() and p.name!='helper'};save('artifact-manifest.json',manifest)
print(json.dumps({'review':str(out/'review.json'),'sha256':sha,'calls':[{k:c[k] for k in ['name','exitCode','seconds','stdoutBytes','stderrBytes']} for c in calls],'closedOutput':value,'sourceStable':before==after,'fixtureStable':fb==fa}),flush=True)
