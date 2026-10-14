import asyncio, pathlib, tempfile, socket, subprocess, sys, json, hashlib, time, platform, shutil, importlib.metadata
SOURCE=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
OUT=pathlib.Path(__file__).parent
SERVER=pathlib.Path.home()/'.cache/agentmux-governance/tools/nats-server'
paths=['hub/__init__.py','hub/fed/__init__.py','hub/fed/admin.py','hub/fed/conn.py']
FROZEN=OUT/'source';FROZEN.mkdir()
source={}
for rel in paths:
 p=FROZEN/rel;p.parent.mkdir(parents=True,exist_ok=True);raw=(SOURCE/rel).read_bytes();p.write_bytes(raw);source[rel]=hashlib.sha256(raw).hexdigest()
sys.path.insert(0,str(FROZEN))
from hub.fed import admin,conn
import nats
report={'sourceCommit':subprocess.check_output(['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip(),'sourceSha256':source,'platform':platform.platform(),'python':sys.version,'natsPy':importlib.metadata.version('nats-py'),'brokerVersion':subprocess.check_output([str(SERVER),'--version'],text=True).strip(),'brokerSha256':hashlib.sha256(SERVER.read_bytes()).hexdigest(),'cases':[],'limits':['Native Linux filesystem fixture on WSL2, not a separate native Linux host or macOS.','Synthetic token-authenticated loopback broker; no JWT operator/TLS enrollment production qualification.','Only listed failures executed; missing credentials, revoked account and full failure matrix remain not-run.','No Docker/user configuration/live account or private credential reads; generated test TLS keys stay private and are removed.','Original provision source copied unchanged. External connection wrapper adds synthetic broker token and records handles; original connect path remains unchanged.']}
class Broker:
 def __init__(self,root,tls=False):
  self.root=root;root.mkdir();self.proc=None;self.log=None;self.token=__import__('secrets').token_hex(32)
  with socket.socket() as s:s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
  self.url=('tls' if tls else 'nats')+'://127.0.0.1:'+str(self.port)
  config=f'host: "127.0.0.1"\nport: {self.port}\nauthorization {{ token: "{self.token}" }}\njetstream {{ store_dir: "{root / "store"}" }}\n'
  if tls:
   for name in ['server','wrong']:
    args=['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.pem')),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1']
    subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)
   config+=f'tls {{ cert_file: "{root / "server.pem"}" key_file: "{root / "server.key"}" timeout: 2 }}\n'
  self.config=root/'server.conf';self.config.write_text(config);self.config.chmod(0o600)
 async def start(self):
  self.log=(self.root/'server.log').open('wb');self.proc=subprocess.Popen([str(SERVER),'-c',str(self.config)],stdout=self.log,stderr=self.log)
  for _ in range(100):
   if self.proc.poll() is not None:raise RuntimeError('owned broker stopped')
   try:
    reader,writer=await asyncio.open_connection('127.0.0.1',self.port);line=await asyncio.wait_for(reader.readline(),1);writer.close();await writer.wait_closed()
    if line.startswith(b'INFO '):return
   except (OSError,TimeoutError):pass
   await asyncio.sleep(.03)
  raise RuntimeError('owned broker not ready')
 async def client(self):return await nats.connect(self.url,token=self.token,allow_reconnect=False,connect_timeout=2)
 def stop(self):
  if self.proc and self.proc.poll() is None:
   self.proc.terminate()
   try:self.proc.wait(timeout=5)
   except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=5)
  if self.log:self.log.close()
async def inspect(js):
 streams={}
 for name in conn.STREAMS:
  c=(await js.stream_info(name)).config
  streams[name]={'subjects':c.subjects,'retention':str(c.retention),'storage':str(c.storage),'discard':str(c.discard),'maxAgeSeconds':c.max_age,'replicas':c.num_replicas,'duplicateWindowSeconds':c.duplicate_window,'maxBytes':c.max_bytes,'maxMessages':c.max_msgs}
 kv={}
 for bucket in conn.BUCKETS:
  c=(await js.stream_info('KV_'+bucket)).config
  kv[bucket]={'subjects':c.subjects,'history':c.max_msgs_per_subject,'ttlSeconds':c.max_age,'storage':str(c.storage),'replicas':c.num_replicas,'discard':str(c.discard)}
 return {'streams':streams,'kv':kv}
async def main():
 brokers=[];handles=[];original=conn.connect
 async def errors(e):pass
 try:
  with tempfile.TemporaryDirectory(prefix='runtime-',dir=OUT) as tmp:
   root=pathlib.Path(tmp);broker=Broker(root/'twice');brokers.append(broker);await broker.start()
   async def connect(url,creds,ca,name,**kw):
    nc=await original(url,creds,ca,name,token=broker.token,error_cb=errors,**kw);handles.append(nc);return nc
   conn.connect=connect
   first=await asyncio.wait_for(admin.provision(broker.url,None,None),15);nc=await broker.client();handles.append(nc);js=nc.jetstream(timeout=3)
   await js.publish('am.msg.p02_baseline',b'safe-probe');kv=await js.key_value('am_board');rev=await kv.put('p02_baseline',b'safe-probe');one=await inspect(js);before=(await js.stream_info('AM_MSG')).state.messages
   second=await asyncio.wait_for(admin.provision(broker.url,None,None),15);two=await inspect(js)
   msg=await js.get_last_msg('AM_MSG','am.msg.p02_baseline');value=await kv.get('p02_baseline')
   report['cases'].append({'id':'provision-twice','firstActions':first,'secondActions':second,'firstPolicies':one,'secondPolicies':two,'policiesIdentical':one==two,'retainedSafeProbe':msg.data==b'safe-probe' and value.value==b'safe-probe' and value.revision==rev,'messageCountUnchanged':before==(await js.stream_info('AM_MSG')).state.messages,'adminHandlesClosed':[x.is_closed for x in handles if x is not nc]})
   await nc.close()
   # Keep the chosen wrong endpoint reserved but non-listening, to avoid an unrelated listener race.
   with socket.socket() as endpoint:
    endpoint.bind(('127.0.0.1',0));url='nats://127.0.0.1:'+str(endpoint.getsockname()[1]);start=time.monotonic()
    try:await asyncio.wait_for(original(url,None,None,'baseline-wrong-endpoint',error_cb=errors),12)
    except Exception as e:report['cases'].append({'id':'wrong-endpoint','exceptionType':type(e).__name__,'seconds':round(time.monotonic()-start,4),'fixtureDeadlineSeconds':12,'configuredConnectTimeoutSeconds':5})
    else:raise AssertionError('wrong endpoint connected')
   tls=Broker(root/'tls',tls=True);brokers.append(tls);await tls.start();start=time.monotonic()
   try:await asyncio.wait_for(original(tls.url,None,str(tls.root/'wrong.pem'),'baseline-wrong-ca',token=tls.token,error_cb=errors),12)
   except Exception as e:report['cases'].append({'id':'wrong-ca','exceptionType':type(e).__name__,'seconds':round(time.monotonic()-start,4),'fixtureDeadlineSeconds':12,'configuredConnectTimeoutSeconds':5,'caKind':'valid synthetic unrelated self-signed certificate'})
   else:raise AssertionError('wrong CA connected')
   partial=Broker(root/'partial');brokers.append(partial);await partial.start();partial_nc=None
   class JS:
    def __init__(self,js):self.js=js;self.created=0
    def __getattr__(self,k):return getattr(self.js,k)
    async def add_stream(self,cfg):
     if self.created==1:raise RuntimeError('injected after first resource')
     result=await self.js.add_stream(cfg);self.created+=1;return result
   class NC:
    def __init__(self,nc):self.nc=nc
    def jetstream(self):return JS(self.nc.jetstream())
    async def close(self):return await self.nc.close()
   async def interrupted_connect(url,creds,ca,name):
    nonlocal partial_nc
    partial_nc=await original(url,creds,ca,name,token=partial.token,error_cb=errors);handles.append(partial_nc);return NC(partial_nc)
   conn.connect=interrupted_connect;start=time.monotonic()
   try:await asyncio.wait_for(admin.provision(partial.url,None,None),15)
   except RuntimeError as e:
    if str(e)!='injected after first resource':raise
   else:raise AssertionError('injected interruption did not fire')
   names=[i.config.name async for i in partial_nc.jetstream().streams_info()]
   report['cases'].append({'id':'interrupted-after-first-resource','seconds':round(time.monotonic()-start,4),'createdResources':names,'adminClosedConnectionOnError':partial_nc.is_closed,'observation':'Provision leaves first stream and open connection after exception; driver owns cleanup.'})
   await partial_nc.close();report['cases'][-1]['driverClosedConnection']=partial_nc.is_closed
 finally:
  conn.connect=original
  for nc in handles:
   if not nc.is_closed:await conn.close(nc)
  for b in brokers:b.stop()
  report['cleanup']={'allOwnedBrokerProcessesExited':all(b.proc.poll() is not None for b in brokers),'allCapturedConnectionsClosed':all(n.is_closed for n in handles),'runtimeDirectoryRemoved':not any(OUT.glob('runtime-*'))}
missing="import sys;sys.path.insert(0,"+repr(str(FROZEN))+");from hub.fed.conn import nats_mod,MissingDependency\ntry:nats_mod()\nexcept MissingDependency as e:print(type(e).__name__+': '+str(e));sys.exit(7)\n"
start=time.monotonic();child=subprocess.run(['/usr/bin/python3','-S','-c',missing],capture_output=True,text=True,timeout=5)
report['cases'].append({'id':'missing-dependency','command':'/usr/bin/python3 -S isolated frozen module','exitCode':child.returncode,'diagnostic':child.stdout.strip(),'stderrEmpty':not child.stderr,'seconds':round(time.monotonic()-start,4)})
asyncio.run(main())
report['sourcesUnchanged']=all(hashlib.sha256((SOURCE/p).read_bytes()).hexdigest()==s for p,s in source.items())
report['status']='characterized';(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'evidenceDirectory':str(OUT),'caseIds':[x['id'] for x in report['cases']],'cleanup':report['cleanup'],'sourcesUnchanged':report['sourcesUnchanged']}))
