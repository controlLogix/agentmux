import asyncio, datetime, hashlib, json, os, pathlib, re, secrets, subprocess, time, uuid
import nats
import platform, importlib.metadata
from nats.js.api import StreamConfig, StorageType
DOCKER='/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
CONTEXT='desktop-linux'
EXPECTED_ENGINE='e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c'
DIGEST='sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c'
IMAGE='docker.io/library/nats@'+DIGEST
INDEX='sha256:cd3fcd4ecdda44e3a66728a5334af0a959bc3979b32810e033d1c547241cd0f4'
fixture=uuid.uuid4().hex[:16];project='amx-p02-interop-'+fixture;volume=project+'-data'
out=pathlib.Path('/home/ryan/.cache/agentmux-governance')/project;out.mkdir()
report={'recordedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'fixtureId':fixture,'project':project,'volume':volume,'sourceCommit':'2740e31d79c6b63fca54137b191c151afca91be5','qualification':'Disposable Windows-owned Docker CLI interop from native WSL Python; not approved production backend or phase acceptance.','dockerExecutable':DOCKER,'context':CONTEXT,'networkMode':None,'nativePythonPlatform':platform.platform(),'natsPyVersion':importlib.metadata.version('nats-py'),'image':IMAGE,'observedTagIndexDigest':INDEX,'expectedEngineId':EXPECTED_ENGINE,'commands':[],'phaseAccepted':False,'mountedNativeLinuxDockerIntegration':'unavailable','tokensStored':False,'composeSecretConfigStored':False,'fixtureSourceSha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'status':'preparing'}
cid=None;client=None;before=None;compose=None

def emit(stage,**values):print(json.dumps({'stage':stage,**values}),flush=True)
def call(args,input_=None,timeout=30,check=True,record=True):
    if record:report['commands'].append({'argv':[DOCKER,'--context',CONTEXT,*args],'stdin':'private Compose JSON; authentication value omitted' if input_ is not None else None})
    result=subprocess.run([DOCKER,'--context',CONTEXT,*args],input=input_,capture_output=True,timeout=timeout)
    if check and result.returncode:raise RuntimeError('DockerCommandFailed:'+args[0]+':'+str(result.returncode))
    return result

def text(args,**kw):return call(args,**kw).stdout.decode('utf-8-sig').strip()
def snapshot():
    output=text(['ps','--no-trunc','--format','{{json .ID}}\t{{json .Names}}\t{{json .State}}\t{{json .Ports}}'])
    return [dict(zip(['id','name','state','ports'],[json.loads(x) for x in line.split('\t')])) for line in output.splitlines() if line]
def inspect_container(identity):
    output=text(['inspect','--format','{{json .Id}}\t{{json .State.Status}}\t{{json .Image}}\t{{json .Config.Image}}\t{{json .NetworkSettings.Ports}}\t{{json .Mounts}}\t{{json (index .Config.Labels "agentmux.fixture.id")}}\t{{json (index .Config.Labels "com.docker.compose.project")}}',identity])
    data=dict(zip(['id','state','imageId','imageReference','ports','mounts','fixtureLabel','projectLabel'],[json.loads(x) for x in output.split('\t')]))
    # Keep only fixture mount identities, not arbitrary Docker host paths.
    data['mounts']=[{k:m[k] for k in ['Type','Name','Destination','RW'] if k in m} for m in data['mounts']]
    return data

def owned(identity):
    data=inspect_container(identity)
    if data['fixtureLabel']!=fixture or data['projectLabel']!=project or data['imageReference']!=IMAGE:raise RuntimeError('ExactFixtureOwnershipRefused')
    return data

async def probe(port):
    global client
    observations=[]
    async def on_error(exc):observations.append({'errorType':type(exc).__name__,'errno':getattr(exc,'errno',None)})
    started=time.monotonic()
    try:
        client=await asyncio.wait_for(nats.connect(servers=['nats://127.0.0.1:'+str(port)],token=token,connect_timeout=3,allow_reconnect=False,max_reconnect_attempts=0,error_cb=on_error),timeout=5)
        await client.flush(timeout=3)
    except Exception as exc:
        report['nativeWslConnection']={'host':'127.0.0.1','port':port,'authenticatedFixtureConnect':False,'errorType':type(exc).__name__,'errno':getattr(exc,'errno',None),'transportErrors':observations,'seconds':round(time.monotonic()-started,3),'retries':0}
        emit('native_wsl_connection_failed',errorType=type(exc).__name__,transportErrors=observations)
        return False
    report['nativeWslConnection']={'host':'127.0.0.1','port':port,'authenticatedFixtureConnect':True,'flushPassed':True,'serverVersion':client._server_info.get('version'),'seconds':round(time.monotonic()-started,3),'retries':0}
    assert client._server_info.get('version')=='2.15.0'
    js=client.jetstream();stream='AMX_P02_'+fixture.upper();subject='amx.fixture.'+fixture
    await js.add_stream(StreamConfig(name=stream,subjects=[subject],storage=StorageType.FILE,max_msgs=10,max_bytes=1048576))
    body=b'agentmux-p02-disposable-durable-probe';ack=await js.publish(subject,body,timeout=3);message=await js.get_msg(stream,seq=ack.seq)
    assert message.data==body
    report['durableProbe']={'stream':stream,'sequence':ack.seq,'fileBacked':True,'payloadSha256':hashlib.sha256(body).hexdigest(),'readBackMatches':True,'restartDurabilityNotTested':True}
    original=owned(cid);call(['compose','--project-name',project,'--file','-','up','--detach','--wait','--wait-timeout','30'],input_=compose,timeout=60)
    current=owned(cid);assert original['id']==current['id'] and original['mounts']==current['mounts']
    message=await js.get_msg(stream,seq=ack.seq);assert message.data==body
    report['warmReuse']={'sameContainerId':True,'sameNamedVolume':True,'sameProbeRecord':True,'recreated':False}
    await client.close()
    emit('native_wsl_probe_and_reuse_passed')
    return True

try:
    # Snapshot unrelated running containers before any image pull or fixture mutation.
    network=subprocess.run(['wslinfo','--networking-mode'],capture_output=True,text=True,timeout=5,check=True).stdout.strip();report['networkMode']=network;assert network.lower()=='nat'
    before=snapshot();report['originalContainersBefore']=before
    assert len(before)==12 and all(x['state']=='running' for x in before)
    engine=text(['info','--format','{{json .ID}}\t{{json .OSType}}\t{{json .Architecture}}']);parts=[json.loads(x) for x in engine.split('\t')]
    report['engine']={'id':parts[0],'os':parts[1],'architecture':parts[2]};assert parts[0]==EXPECTED_ENGINE and parts[1]=='linux' and parts[2] in ['x86_64','amd64']
    report['clientServerVersions']=text(['version','--format','{{.Client.Version}} {{.Server.Version}}']);report['composeVersion']=text(['compose','version','--short'])
    # Verify exact official platform-manifest bytes before accepting a digest pin.
    raw=call(['buildx','imagetools','inspect',IMAGE,'--raw']).stdout
    expected=DIGEST.split(':',1)[1];normalization='none'
    if hashlib.sha256(raw).hexdigest()!=expected:
        assert hashlib.sha256(raw.rstrip(b'\r\n')).hexdigest()==expected
        raw=raw.rstrip(b'\r\n');normalization='CLI trailing line ending removed'
    manifest=json.loads(raw);report['imageManifest']={'sha256':hashlib.sha256(raw).hexdigest(),'matchesPinnedDigest':True,'cliOutputNormalization':normalization,'mediaType':manifest['mediaType'],'configDigest':manifest['config']['digest'],'layerDigests':[l['digest'] for l in manifest['layers']]}
    inspected=call(['image','inspect',IMAGE,'--format','{{json .Id}}\t{{json .RepoDigests}}'],check=False)
    if inspected.returncode:
        emit('pulling_pinned_fixture_image',image=IMAGE)
        call(['pull','--platform','linux/amd64',IMAGE],timeout=180)
        report['imageDependencyPulled']=True
    else:report['imageDependencyPulled']=False
    image=json.loads(text(['image','inspect',IMAGE,'--format','{{json .Id}}']));report['localImageId']=image;assert image==manifest['config']['digest']
    token=secrets.token_urlsafe(32)
    config={'services':{'nats':{'image':IMAGE,'platform':'linux/amd64','command':['-js','-sd','/data','-p','4222','--auth',token],'ports':['127.0.0.1::4222'],'volumes':[volume+':/data'],'labels':{'agentmux.fixture.id':fixture,'agentmux.fixture.phase':'P02'},'restart':'no','mem_limit':'128m','cpus':0.5}},'volumes':{volume:{'name':volume,'labels':{'agentmux.fixture.id':fixture,'agentmux.fixture.phase':'P02'}}}}
    compose=json.dumps(config).encode();report['composeShape']={'service':'nats','image':IMAGE,'command':['-js','-sd','/data','-p','4222','--auth','<ephemeral fixture token omitted>'],'hostBinding':'127.0.0.1','containerPort':4222,'volume':volume,'mountDestination':'/data','hostPathMounts':False,'labels':{'agentmux.fixture.id':fixture,'agentmux.fixture.phase':'P02'},'restartPolicy':'no'}
    emit('starting_one_owned_fixture',project=project)
    call(['compose','--project-name',project,'--file','-','up','--detach','--wait','--wait-timeout','30'],input_=compose,timeout=60)
    ids=text(['compose','--project-name',project,'--file','-','ps','--all','--quiet','nats'],input_=compose).splitlines();assert len(ids)==1;cid=ids[0]
    state=owned(cid);report['fixtureStarted']=state;assert state['state']=='running' and len(state['mounts'])==1 and state['mounts'][0]['Type']=='volume' and state['mounts'][0]['Name']==volume
    bindings=state['ports']['4222/tcp'];assert len(bindings)==1 and bindings[0]['HostIp']=='127.0.0.1';port=int(bindings[0]['HostPort']);report['hostPort']=port
    report['brokerBinaryVersion']=text(['exec',cid,'/nats-server','--version']);assert 'v2.15.0' in report['brokerBinaryVersion']
    deadline=time.monotonic()+10;ready=False
    while time.monotonic()<deadline:
        observed_logs=call(['logs',cid],record=False);logs=observed_logs.stdout+observed_logs.stderr
        if b'Server is ready' in logs:ready=True;break
        time.sleep(0.2)
    report['fixtureRecognizedServerReady']=ready;assert ready
    report['composeWaitMeaning']='Container running only; recognized NATS ready log and separate authenticated client probe determine application observations.'
    emit('fixture_ready_for_one_native_wsl_connection',containerId=cid,hostPort=port)
    passed=asyncio.run(probe(port));report['status']='interop_and_probe_passed' if passed else 'native_wsl_loopback_connectivity_failed'
except Exception as exc:
    report['status']='fixture_error';report['failure']={'type':type(exc).__name__,'stageCode':str(exc) if isinstance(exc,RuntimeError) and str(exc).startswith(('DockerCommandFailed:','ExactFixtureOwnershipRefused')) else None}
    emit('fixture_error',errorType=type(exc).__name__)
finally:
    if client is not None and not client.is_closed:
        try:asyncio.run(client.close())
        except Exception:report['clientCloseError']=True
    # Even a failed compose invocation may have created this project's resources.
    if cid is None and compose is not None:
        try:
            ids=text(['compose','--project-name',project,'--file','-','ps','--all','--quiet','nats'],input_=compose,check=False).splitlines()
            if len(ids)==1:cid=ids[0]
        except Exception:report['ownershipDiscoveryError']=True
    if cid is not None:
        try:
            owned(cid);call(['stop','--time','10',cid],timeout=30);after=owned(cid);report['fixtureCleanup']={'exactOwnedContainerId':cid,'stateAfterStop':after['state'],'stopped':after['state']=='exited','volumePreserved':True,'containerPreserved':True,'downOrPruneInvoked':False}
            v=text(['volume','inspect','--format','{{json .Name}}\t{{json (index .Labels "agentmux.fixture.id")}}',volume]);vp=[json.loads(x) for x in v.split('\t')];assert vp==[volume,fixture];report['fixtureCleanup']['volumeOwnershipVerified']=True
        except Exception as exc:report['fixtureCleanup']={'failed':True,'errorType':type(exc).__name__};emit('owned_fixture_cleanup_failed',errorType=type(exc).__name__)
    after=snapshot();report['allRunningContainersAfter']=after
    original_ids={x['id'] for x in before or []};filtered=[x for x in after if x['id'] in original_ids];report['originalContainersAfter']=filtered;report['originalContainerStateAndPortsUnchanged']=sorted(before or [],key=lambda x:x['id'])==sorted(filtered,key=lambda x:x['id']);report['additionalRunningContainersAfter']=[x['id'] for x in after if x['id'] not in original_ids]
    report['limits']=['Windows-owned CLI and shared Desktop engine only; mounted Linux Docker integration remains unavailable.','NAT/native WSL loopback locality is observed, not assumed. No proxy/firewall/network/settings/service changes or alternative endpoint retry.','Only one disposable project/container; named volume and stopped container retained. No unrelated container mutation.','JetStream probe/reuse is unrun if native connection fails; no mock or backend acceptance substitutes.','No engine restart, native client/engine install, host bind mount or destructive volume removal.','A file-backed probe and warm reuse do not establish process-crash, power-loss or production durability.']
    (out/'result.json').write_bytes((json.dumps(report,indent=2)+'\n').encode());print(json.dumps({'output':str(out),'status':report['status'],'fixtureId':fixture,'containerId':cid,'originalContainerStateAndPortsUnchanged':report['originalContainerStateAndPortsUnchanged'],'cleanup':report.get('fixtureCleanup'),'resultSha256':hashlib.sha256((out/'result.json').read_bytes()).hexdigest()}),flush=True)
