import asyncio,copy,datetime,hashlib,json,os,pathlib,re,secrets,socket,subprocess,tempfile,time
import nats
from nats.js.api import StorageType
EXE='/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
CONTEXT='desktop-linux';ENDPOINT='npipe:////./pipe/dockerDesktopLinuxEngine';ENGINE='e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c'
IMAGE='docker.io/library/nats@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c'
BUILDER=pathlib.Path('/home/ryan/.cache/agentmux-governance/p02-config-content-builder')
ROOT=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
CONFIG_SOURCE=ROOT/'platform/kernel/communication/config.go'
CONFIG_HASH='b54e90bbf5d5c37fa7e60ffdc878ddd4204bfba411665e2c35311c1fe5b9a883'
def sha(b):return hashlib.sha256(b).hexdigest()
class Refusal(Exception):pass
result={'scope':'One disposable configs.content qualification. No production adoption or broader Docker qualification.','recordedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'guards':[],'cleanup':{},'findings':[]}
fixture=secrets.token_hex(8);project='amx-p02-config-'+fixture;volume=project+'_data'
out=pathlib.Path(tempfile.mkdtemp(prefix=project+'-',dir='/home/ryan/.cache/agentmux-governance'));out.chmod(0o700)
result.update(project=project,outputDirectory=str(out),sourceHashes={'fixtureCaller':sha(pathlib.Path(__file__).read_bytes()),'communicationBuilder':CONFIG_HASH,'builderBinary':sha(BUILDER.read_bytes())})
container=None;baseline=None;config_bytes=None;credentials=None;health_password=None
env=os.environ.copy();env['COMPOSE_DISABLE_ENV_FILE']='1';env['AMX_CONFIG_INTERPOLATION_MARKER']='ambient-must-not-substitute'
for key in ['DOCKER_HOST','DOCKER_CONTEXT','COMPOSE_FILE','COMPOSE_ENV_FILES','COMPOSE_PROFILES','COMPOSE_REMOVE_ORPHANS']:env.pop(key,None)
def call(args,body=None,timeout=30):
 try:r=subprocess.run([EXE,'--context',CONTEXT]+args,input=body,capture_output=True,timeout=timeout,env=env)
 except subprocess.TimeoutExpired:raise Refusal('docker_command_timeout_outcome_unknown') from None
 if r.returncode:raise Refusal('docker_command_failed_'+args[0])
 return r.stdout
def parsed(args):
 try:return json.loads(call(args))
 except (ValueError,UnicodeDecodeError):raise Refusal('docker_invalid_json') from None
def identity():
 endpoint=parsed(['context','inspect',CONTEXT,'--format','{{json .Endpoints.docker.Host}}'])
 info=parsed(['info','--format','{"ID":{{json .ID}},"OS":{{json .OSType}}}'])
 versions=parsed(['version','--format','{"Client":{{json .Client.Version}},"Server":{{json .Server.Version}}}'])
 compose=call(['compose','version','--short']).decode().strip().removeprefix('v')
 if endpoint!=ENDPOINT or info!={'ID':ENGINE,'OS':'linux'} or versions!={'Client':'29.8.0','Server':'29.8.0'} or compose!='5.5.1':raise Refusal('engine_or_version_identity_changed')
 return {'context':CONTEXT,'endpoint':ENDPOINT,'engineID':ENGINE,'versions':dict(versions,Compose=compose)}
def snapshot():
 ids=call(['ps','--all','--quiet','--no-trunc']).decode().split()
 if not all(re.fullmatch('[0-9a-f]{64}',x) for x in ids):raise Refusal('container_identity_unverifiable')
 observations={}
 for i in ids:
  if i==container:continue
  o=parsed(['container','inspect',i,'--format','{"id":{{json .Id}},"status":{{json .State.Status}},"running":{{json .State.Running}},"ports":{{json .NetworkSettings.Ports}}}'])
  observations[i]=o
 return observations
def guard(stage):
 identity();current=snapshot();same=current==baseline
 result['guards'].append({'stage':stage,'existingContainerCount':len(current),'IDsStatesPortsEqualFreshBaseline':same})
 if not same:raise Refusal('external_container_state_changed_during_fixture')
def labels():return {'agentmux.instance.id':fixture,'agentmux.release.digest':'sha256:'+sha(b'p02-config-content-fixture-v1'),'com.docker.compose.project':project}
def own_container():
 identity()
 o=parsed(['container','inspect',container,'--format','{"id":{{json .Id}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}}}'])
 if o['id']!=container or any(o['labels'].get(k)!=v for k,v in labels().items()):raise Refusal('fixture_container_ownership_changed')
 return o
def owned_exec(args):own_container();return call(['container','exec',container]+args)
def source_windows_path(source):
 if re.match(r'^[A-Za-z]:[\\/]',source):return source
 for prefix in ['/run/desktop/mnt/host/','/host_mnt/']:
  if source.startswith(prefix):
   rest=source[len(prefix):]
   if re.match(r'^[a-zA-Z]/',rest):return rest[0].upper()+':\\'+rest[2:].replace('/','\\')
 raise Refusal('private_cache_source_not_qualifiable_by_local_windows_acl')
ACL_SCRIPT=r'''$ErrorActionPreference='Stop'; try {
$p=[Console]::In.ReadToEnd() | ConvertFrom-Json
$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed=@($me,'S-1-5-18','S-1-5-32-544')
$item=Get-Item -LiteralPath $p.path -Force
$acl=Get-Acl -LiteralPath $p.path
$owner=$acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
$private=$allowed -contains $owner
$readMask=[System.Security.AccessControl.FileSystemRights]::ReadData
foreach($a in $acl.Access){if($a.AccessControlType -eq 'Allow' -and ($a.FileSystemRights -band $readMask)){
$sid=$a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
if($allowed -notcontains $sid){$private=$false}}}
@{regularFile=(-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint));ownerAllowed=($allowed -contains $owner);readAllowlistOnly=$private} | ConvertTo-Json -Compress
} catch { [Console]::Write('{"unavailable":true}'); exit 1 }'''
def cache_acl(source):
 path=source_windows_path(source)
 powershell='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
 r=subprocess.run([powershell,'-NoProfile','-NonInteractive','-Command',ACL_SCRIPT],input=json.dumps({'path':path}).encode(),capture_output=True,timeout=20)
 try:o=json.loads(r.stdout.decode('utf-8-sig'))
 except (ValueError,UnicodeDecodeError):raise Refusal('private_cache_acl_unverifiable') from None
 if r.returncode or o.get('unavailable') or not all(o.get(k) for k in ['regularFile','ownerAllowed','readAllowlistOnly']):raise Refusal('private_cache_acl_not_private')
 return o
async def probe(password,marker,stream,subject):
 errors=[]
 async def error_cb(e):errors.append(type(e).__name__)
 nc=await nats.connect(servers=['nats://127.0.0.1:'+str(port)],user='fixture-health',password=password,connect_timeout=5,max_reconnect_attempts=0,allow_reconnect=False,error_cb=error_cb)
 try:
  await nc.flush(timeout=5)
  if nc._server_info.get('version')!='2.15.0' or nc._server_info.get('server_name')!=marker:raise Refusal('broker_version_or_literal_marker_mismatch')
  js=nc.jetstream(timeout=5)
  info=await js.add_stream(name=stream,subjects=[subject],storage=StorageType.FILE,max_bytes=1048576,max_msgs=8)
  if info.config.storage!=StorageType.FILE:raise Refusal('file_storage_not_observed')
  data=b'owned-config-content-durable-probe'
  ack=await js.publish(subject,data,timeout=5)
  msg=await js.get_msg(stream,seq=ack.seq)
  if msg.data!=data:raise Refusal('durable_record_mismatch')
  return {'nativeWSLAuthenticatedConnect':True,'brokerVersion':'2.15.0','serverNameLiteralMarkerEqual':True,'streamStorageObserved':'file','publishSequence':ack.seq,'retainedRecordBytesEqual':True,'callbackErrorCount':len(errors)}
 finally:await nc.close()
try:
 if sha(CONFIG_SOURCE.read_bytes())!=CONFIG_HASH:raise Refusal('builder_source_changed')
 result['engine']=identity();baseline=snapshot();result['freshBaseline']=list(baseline.values())
 for kind,name in [('volume',volume),('network',project+'_default')]:
  if call([kind,'ls','--quiet','--filter','name='+name]).strip():raise Refusal('fresh_project_resource_collision')
 if call(['ps','--all','--quiet','--filter','name='+project]).strip():raise Refusal('fresh_project_container_collision')
 image=parsed(['image','inspect',IMAGE,'--format','{"id":{{json .Id}},"digests":{{json .RepoDigests}}}'])
 expected_manifest=IMAGE.split('@')[1]
 if not any(x.split('@')[0] in ['nats','library/nats','docker.io/library/nats'] and x.split('@')[-1]==expected_manifest for x in image['digests']):raise Refusal('cached_repo_digest_mismatch')
 result['image']={'pinnedManifest':IMAGE,'imageID':image['id'],'RepoDigestMatched':True}
 names=['deployment-admin','ordinary-plugin','boot','kernel-lifecycle','internal-communication','exported-status']
 credentials={name:secrets.token_urlsafe(40) for name in names}
 r=subprocess.run([str(BUILDER)],input=json.dumps({'Hub':'fixture-'+fixture,'Credentials':credentials}).encode(),capture_output=True,timeout=10)
 if r.returncode:raise Refusal('private_builder_failed')
 config=json.loads(r.stdout);original_accounts=copy.deepcopy(config['accounts']);health_password=secrets.token_urlsafe(40)
 marker='fixture-'+fixture+'-$AMX_CONFIG_INTERPOLATION_MARKER-$SYS-$JS';stream='CONFIG_'+fixture.upper();subject='fixture.config.'+fixture
 config['jetstream']={'store_dir':'/data','max_memory_store':0,'max_file_store':16777216}
 config['server_name']=marker
 config['accounts']['FIXTURE_HEALTH']={'jetstream':True,'users':[{'user':'fixture-health','password':health_password,'permissions':{'publish':{'allow':[subject,'$JS.API.STREAM.CREATE.'+stream,'$JS.API.STREAM.INFO.'+stream,'$JS.API.STREAM.MSG.GET.'+stream]},'subscribe':{'allow':['_INBOX.>']}}}]}
 if any(config['accounts'].get(k)!=v for k,v in original_accounts.items()):raise Refusal('builder_accounts_or_acl_changed')
 config_bytes=json.dumps(config,separators=(',',':'),ensure_ascii=False).encode();expected=sha(config_bytes)
 input_labels={k:v for k,v in labels().items() if not k.startswith('com.docker.compose.')}
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 compose={'services':{'nats':{'image':IMAGE,'labels':input_labels,'command':['--config','/etc/nats/private.conf'],'ports':['127.0.0.1:'+str(port)+':4222'],'volumes':['data:/data'],'configs':[{'source':'broker_config','target':'/etc/nats/private.conf','mode':256}]}},'volumes':{'data':{'labels':input_labels}},'networks':{'default':{'labels':input_labels}},'configs':{'broker_config':{'content':config_bytes.decode().replace('$','$$')}}}
 body=json.dumps(compose,separators=(',',':')).encode()
 result['configStructuralDelta']={'originalThreeAccountsAndACLsUnchanged':True,'addedAccount':'FIXTURE_HEALTH','fixtureOnlyJetStream':True,'globalStorageDirectory':'/data','maxFileBytes':16777216,'streamMaxBytes':1048576,'streamMaxMessages':8,'privateConfigDigestRetainedInPrivateResult':True,'literalDollarEscapingApplied':True,'secretConfigBytesStoredInEvidence':False}
 result['expectedMountedConfigSha256']=expected
 guard('before_compose_up')
 call(['compose','--project-name',project,'--file','-','up','--detach','--pull','never','--no-build'],body,45)
 ids=call(['ps','--all','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+project]).decode().split()
 if len(ids)!=1 or not re.fullmatch('[0-9a-f]{64}',ids[0]):raise Refusal('fixture_container_identity_not_exact')
 container=ids[0];result['fixtureContainerID']=container;own_container();guard('after_compose_up')
 mounts=parsed(['container','inspect',container,'--format','{{json .Mounts}}'])
 cfg=[m for m in mounts if m.get('Destination')=='/etc/nats/private.conf'];data=[m for m in mounts if m.get('Destination')=='/data']
 if len(cfg)!=1 or cfg[0].get('RW') or len(data)!=1 or data[0].get('Type')!='volume' or data[0].get('Name')!=volume:raise Refusal('config_or_data_mount_shape_mismatch')
 v=parsed(['volume','inspect',volume,'--format','{{json .Labels}}'])
 if any(v.get(k)!=x for k,x in labels().items()):raise Refusal('data_volume_owner_mismatch')
 result['cachePrivacy']=cache_acl(cfg[0]['Source'])
 stat=owned_exec(['stat','-c','%a %u %g','/etc/nats/private.conf']).decode().strip().split()
 if len(stat)!=3 or stat[0]!='400':raise Refusal('mounted_config_mode_not_private')
 mounted=owned_exec(['sha256sum','/etc/nats/private.conf']).decode().split()[0]
 if mounted!=expected:raise Refusal('mounted_config_byte_mismatch')
 result['mount']={'readOnly':True,'mode':stat[0],'uid':stat[1],'gid':stat[2],'exactExpectedByteDigestEqual':True,'privateSourcePathOmitted':True,'dataVolume':volume}
 result['probe']=asyncio.run(asyncio.wait_for(probe(health_password,marker,stream,subject),timeout=25))
 guard('after_authenticated_file_probe');result['qualificationPassed']=True
except BaseException as e:
 result['qualificationPassed']=False;result['failureCode']=str(e) if isinstance(e,Refusal) else type(e).__name__
finally:
 if container is None:
  try:
   identity()
   ids=call(['ps','--all','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+project]).decode().split()
   if len(ids)==1 and re.fullmatch('[0-9a-f]{64}',ids[0]):container=ids[0];result['fixtureContainerID']=container
  except BaseException:result['cleanup']['ownedDiscoveryUnavailable']=True
 if container:
  try:
   own_container();call(['container','stop','--time','10',container],timeout=25)
   state=own_container();result['cleanup']['exactOwnedContainerStopped']=not state['running'];result['cleanup']['containerRetained']=True
   parsed(['volume','inspect',volume,'--format','{{json .Name}}']);result['cleanup']['dataVolumeRetained']=True
  except BaseException as e:result['cleanup']['failureCode']=str(e) if isinstance(e,Refusal) else type(e).__name__
 else:result['cleanup']['ownedContainerNotConfirmed']=True
 if baseline is not None:
  try:guard('final_after_exact_stop');result['cleanup']['originalIDsStatesPortsPreserved']=True
  except BaseException as e:result['cleanup']['preservationFailureCode']=str(e) if isinstance(e,Refusal) else type(e).__name__
 result['limits']=['No production adoption.','No full driver config admission changes.','No broker restart or power-loss durability proof.','No WSL integration, engine or settings changes.','No raw secret config, cache source paths or provider output retained.']
 (out/'result.json').write_bytes((json.dumps(result,indent=2)+'\n').encode());(out/'result.json').chmod(0o600)
 print(json.dumps({'project':project,'output':str(out/'result.json'),'resultSha256':sha((out/'result.json').read_bytes()),'qualificationPassed':result.get('qualificationPassed'),'failureCode':result.get('failureCode'),'cleanup':result['cleanup']}))
