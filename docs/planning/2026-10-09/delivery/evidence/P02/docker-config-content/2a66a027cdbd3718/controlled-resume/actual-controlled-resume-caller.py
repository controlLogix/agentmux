import ast,asyncio,copy,hashlib,io,json,os,pathlib,re,subprocess,tarfile,tempfile,datetime
import nats
from nats.js.api import StorageType
SOURCE=pathlib.Path('/mnt/c/Users/RyanHelms/AppData/Local/Temp/p02-config-content-reviewed-windows-port.py')
SOURCE_HASH='768ffefadd0ad7bbff5b5dc118f349709098fe9519a30e4210d14d95a5daa339'
PREVIOUS=pathlib.Path('/home/ryan/.cache/agentmux-governance/amx-p02-config-2a66a027cdbd3718-xxbs3w6x/result.json')
def sha(b):return hashlib.sha256(b).hexdigest()
assert sha(SOURCE.read_bytes())==SOURCE_HASH
assert sha(PREVIOUS.read_bytes())=='4375ab9d05dd0a2a5423d07b242a4e67b941167b197c297ac111ecc4aea96bc5'
previous=json.loads(PREVIOUS.read_bytes())
EXE='/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe';CONTEXT='desktop-linux';ENDPOINT='npipe:////./pipe/dockerDesktopLinuxEngine';ENGINE='e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c'
IMAGE='docker.io/library/nats@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c'
fixture='2a66a027cdbd3718';project='amx-p02-config-'+fixture;volume=project+'_data';port=40765
container='92ebb7b277baa7264adbc265d8221f34e884ee7c2baa0ec12bcc7438263db607';OLD_CONTAINER=container
baseline=None;credentials=None;health_password=None;config_bytes=None;started=False
out=pathlib.Path(tempfile.mkdtemp(prefix=project+'-controlled-resume-',dir='/home/ryan/.cache/agentmux-governance'));out.chmod(0o700)
result={'scope':'One authorized exact-container resume completing interrupted fixture qualification; not production warm reuse or adoption.','recordedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'project':project,'containerID':container,'declaredPort':port,'sourceHashes':{'resumeCaller':sha(pathlib.Path(__file__).read_bytes()),'approvedPureFunctionsCaller':SOURCE_HASH,'previousRawResult':sha(PREVIOUS.read_bytes())},'guards':[],'cleanup':{}}
env=os.environ.copy()
for k in ['DOCKER_HOST','DOCKER_CONTEXT','COMPOSE_FILE','COMPOSE_ENV_FILES','COMPOSE_PROFILES','COMPOSE_REMOVE_ORPHANS']:env.pop(k,None)
names=['Refusal','sensitive_values','sanitize_error','verify_redaction_controls','call','parsed','identity','snapshot','guard','labels','own_container','probe']
tree=ast.parse(SOURCE.read_bytes());nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and n.name in names]
exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),globals())
def call(args,body=None,timeout=30):
 try:r=subprocess.run([EXE,'--context',CONTEXT]+args,input=body,capture_output=True,timeout=timeout,env=env)
 except subprocess.TimeoutExpired:raise Refusal('docker_command_timeout_outcome_unknown') from None
 if r.returncode:
  # Failed cp stdout can contain a partial private archive; never expose it.
  data=r.stderr if args[0]=='cp' else r.stderr+b'\n'+r.stdout
  try:safe=sanitize_error(data.decode('utf-8','replace'),sensitive_values())
  except Refusal:
   fd=os.open(out/'private-unverified-error.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:os.write(fd,data)
   finally:os.close(fd)
   result['unsafeErrorPrivatelyPreserved']=True
   raise
  result['sanitizedCommandFailure']={'commandFamily':args[0],'exitCode':r.returncode,'stderrBytes':len(r.stderr),'sanitizedError':safe,'rawOutputStored':False}
  raise Refusal('docker_command_failed_'+args[0])
 return r.stdout
FIXED_PORT_SCRIPT=r'''$ErrorActionPreference='Stop';try{
$port=40765;$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,$port);$l.Server.ExclusiveAddressUse=$true
try{$l.Start();$bound=$true}finally{$l.Stop()}
$raw=& "$env:SystemRoot\System32\netsh.exe" interface ipv4 show excludedportrange protocol=tcp
if($LASTEXITCODE -ne 0){throw 'range unavailable'}
$ranges=@($raw | ForEach-Object {if($_ -match '^\s*(\d+)\s+(\d+)'){@{start=[int]$Matches[1];end=[int]$Matches[2]}}})
if($ranges.Count -eq 0){throw 'range unavailable'}
$excluded=@($ranges | Where-Object {$port -ge $_.start -and $port -le $_.end}).Count -gt 0
$occupied=@(Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.LocalPort -eq $port}).Count -gt 0
@{port=$port;host='127.0.0.1';bindApproved=$bound;listenerClosed=$true;excluded=$excluded;occupied=$occupied}|ConvertTo-Json -Compress
}catch{[Console]::Write('{"unavailable":true}');exit 1}'''
def stopped_config():
 b=call(['cp',container+':/etc/nats/private.conf','-'])
 if len(b)>1048576:raise Refusal('private_config_archive_size_unexpected')
 with tarfile.open(fileobj=io.BytesIO(b),mode='r:*') as t:
  members=t.getmembers()
  if len(members)!=1 or not members[0].isfile() or members[0].mode!=0o400 or members[0].uid!=0 or members[0].gid!=0:raise Refusal('private_config_file_metadata_mismatch')
  data=t.extractfile(members[0]).read()
 if sha(data)!=previous['expectedMountedConfigSha256']:raise Refusal('existing_config_byte_identity_changed')
 return data
def exact_resources():
 own_container()
 o=parsed(['container','inspect',container,'--format','{"ports":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}}}'])
 if o['ports'].get('4222/tcp')!=[{'HostIp':'127.0.0.1','HostPort':str(port)}]:raise Refusal('fixed_port_binding_changed')
 data=[m for m in o['mounts'] if m.get('Destination')=='/data']
 if len(data)!=1 or data[0].get('Type')!='volume' or data[0].get('Name')!=volume:raise Refusal('retained_data_volume_identity_changed')
 v=parsed(['volume','inspect',volume,'--format','{{json .Labels}}'])
 if any(v.get(k)!=x for k,x in labels().items()):raise Refusal('retained_volume_owner_changed')
 ids=call(['ps','--all','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+project]).decode().split()
 if ids!=[container]:raise Refusal('exact_project_container_roster_changed')
 ids=call(['network','ls','--quiet','--no-trunc','--filter','label=com.docker.compose.project='+project]).decode().split()
 if len(ids)!=1:raise Refusal('exact_network_roster_changed')
 n=parsed(['network','inspect',ids[0],'--format','{"name":{{json .Name}},"labels":{{json .Labels}}}'])
 if n['name']!=project+'_default' or any(n['labels'].get(k)!=v for k,v in labels().items()):raise Refusal('exact_network_owner_changed')
try:
 result['redactionControls']=verify_redaction_controls();result['engine']=identity();exact_resources()
 o=own_container()
 if o['running']:raise Refusal('expected_stopped_fixture_already_running')
 image=parsed(['image','inspect',IMAGE,'--format','{"id":{{json .Id}},"digests":{{json .RepoDigests}}}'])
 if image['id']!=previous['image']['imageID'] or not any(x.split('@')[-1]==IMAGE.split('@')[1] for x in image['digests']):raise Refusal('cached_image_identity_changed')
 baseline=snapshot();result['freshBaseline']=list(baseline.values())
 for i in baseline:
  ports=parsed(['container','inspect',i,'--format','{{json .HostConfig.PortBindings}}']) or {}
  if any(b.get('HostPort')==str(port) for rows in ports.values() for b in rows or []):raise Refusal('declared_port_has_other_container_claim')
 r=subprocess.run(['/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-NonInteractive','-Command',FIXED_PORT_SCRIPT],capture_output=True,timeout=30)
 try:fixed=json.loads(r.stdout.decode('utf-8-sig'))
 except (ValueError,UnicodeDecodeError):raise Refusal('fixed_windows_port_observation_unverifiable') from None
 if r.returncode or fixed.get('unavailable') or fixed.get('port')!=port or fixed.get('host')!='127.0.0.1' or not fixed.get('bindApproved') or not fixed.get('listenerClosed') or fixed.get('excluded') or fixed.get('occupied'):raise Refusal('fixed_windows_port_not_approved')
 result['fixedPortPreflight']=fixed
 config_bytes=stopped_config();cfg=json.loads(config_bytes)
 marker='fixture-'+fixture+'-$AMX_CONFIG_INTERPOLATION_MARKER-$SYS-$JS'
 if cfg['server_name']!=marker or cfg['listen']!='0.0.0.0:4222':raise Refusal('declared_marker_or_listener_changed')
 kernel=cfg['accounts']['KERNEL']['users'];app=cfg['accounts']['APPLICATION']['users']
 acl=all('$SYS.>' in u['permissions'][d].get('deny',[]) and '$JS.>' in u['permissions'][d].get('deny',[]) for u in kernel for d in ['publish','subscribe']) and all(u['permissions']['publish'].get('deny')==['>'] and '$SYS.>' in u['permissions']['subscribe'].get('deny',[]) and '$JS.>' in u['permissions']['subscribe'].get('deny',[]) for u in app)
 if not acl:raise Refusal('builder_acl_changed')
 credentials={u['user']:u['password'] for a in cfg['accounts'].values() for u in a['users']}
 health=cfg['accounts']['FIXTURE_HEALTH']['users']
 if len(health)!=1 or health[0]['user']!='fixture-health':raise Refusal('fixture_health_membership_changed')
 health_password=health[0]['password'];result['privateConfigObservation']={'exactExistingBytesEqual':True,'regularFile':True,'mode':'0400','uid':0,'gid':0,'literalDollarMarkerUnchanged':True,'protectedBuilderACLsUnchanged':True,'rawSecretBytesPersistedOrPrinted':False,'materialization':'container filesystem file; no config bind mount required'}
 guard('before_exact_start');exact_resources();started=True
 call(['container','start',container],timeout=30)
 if not own_container()['running']:raise Refusal('exact_started_fixture_not_running')
 guard('after_exact_start')
 stream='CONFIG_'+fixture.upper();subject='fixture.config.'+fixture
 result['probe']=asyncio.run(asyncio.wait_for(probe(health_password,marker,stream,subject),timeout=25))
 guard('after_authenticated_file_probe');result['qualificationPassed']=True
except BaseException as e:
 result['qualificationPassed']=False;result['failureCode']=str(e) if isinstance(e,Refusal) else type(e).__name__
finally:
 if started:
  try:
   exact_resources();call(['container','stop','--time','10',container],timeout=25);result['cleanup']['exactOwnedContainerNotRunning']=not own_container()['running'];result['cleanup']['containerRetained']=True
   if stopped_config()!=config_bytes:raise Refusal('config_changed_during_resume')
   result['cleanup']['configBytesUnchangedAfterStop']=True;parsed(['volume','inspect',volume,'--format','{{json .Name}}']);result['cleanup']['sameDataVolumeRetained']=True
  except BaseException as e:result['cleanup']['failureCode']=str(e) if isinstance(e,Refusal) else type(e).__name__
 else:result['cleanup']['no_start_attempted']=True
 if baseline is not None:
  try:guard('final_after_exact_stop');result['cleanup']['originalIDsStatesPortsPreserved']=True
  except BaseException as e:result['cleanup']['preservationFailureCode']=str(e) if isinstance(e,Refusal) else type(e).__name__
 if result.get('qualificationPassed') and not all(result['cleanup'].get(k) for k in ['exactOwnedContainerNotRunning','configBytesUnchangedAfterStop','sameDataVolumeRetained','originalIDsStatesPortsPreserved']):
  result['qualificationPassed']=False;result['failureCode']='required_cleanup_or_preservation_failed'
 result['limits']=['This completes an interrupted fixture qualification, not production warm reuse.','Inline content remains a private writable-layer file; container root and Docker administrators can read or alter it.','Container export/commit can retain synthetic credentials; no export/commit used.','Official inline-content injection rejects read-only service root filesystems.','No broker power-loss or durable restart proof.','No Compose up, pull, recreation, config change, new port/project, settings change or retry loop.']
 p=out/'result.json';p.write_bytes((json.dumps(result,indent=2)+'\n').encode());p.chmod(0o600)
 print(json.dumps({'project':project,'containerID':container,'declaredPort':port,'output':str(p),'resultSha256':sha(p.read_bytes()),'qualificationPassed':result.get('qualificationPassed'),'failureCode':result.get('failureCode'),'cleanup':result['cleanup']}))
