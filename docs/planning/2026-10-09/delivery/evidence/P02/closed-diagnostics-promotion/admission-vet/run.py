import pathlib,json,hashlib,os,time,subprocess,shutil
p=pathlib.Path('/home/ryan/.cache/agentmux-governance/p02-host-policy-history-parity-x9y2c317');s=p/'snapshot/platform';pins=json.loads((p/'preparation.json').read_text())['sourcePins'];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();assert all(sha(s/'launcher'/n)==v for n,v in pins.items())
out=p/'admission-vet';out.mkdir();env=os.environ.copy()
for key in list(env):
 if (key.startswith('AMX_')and('FIXTURE'in key or key in ['AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']))or key in ['AGENTMUX_TEST_NATS','AGENTMUX_NATS_SERVER']:env.pop(key)
env.update({'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GOENV':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'})
go='/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go';cmds={'admission':[go,'test','-race','-count=1','-json','./launcher','-run','^TestInstalledHostPolicy(BridgeBindingsBeforeFactoryLoad|NullableOwnerAndBoundFiles|RejectsPrivateBoundaryAndDeclarations)$'],'vet':[go,'vet','./launcher']};inv={'cwd':str(s),'environment':{k:env[k]for k in ['GOPROXY','GOSUMDB','GOWORK','GOENV','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'AMX_DOCKER_FIXTUREAbsent':'AMX_DOCKER_FIXTURE'not in env,'candidateBefore':{n:sha(s/'launcher'/n)for n in pins},'commands':{},'startedUnix':time.time()};(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');shutil.copyfile('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-host-policy-admission-vet.py',out/'run.py');print(out,flush=True)
for name,argv in cmds.items():
 start=time.time()
 with(out/(name+'.stdout')).open('wb')as a,(out/(name+'.stderr')).open('wb')as b:r=subprocess.run(argv,cwd=s,env=env,stdout=a,stderr=b)
 inv['commands'][name]={'argv':argv,'startedUnix':start,'endedUnix':time.time(),'directExit':r.returncode};(out/(name+'-exit.txt')).write_text(str(r.returncode)+'\n');(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');print(name,'exit',r.returncode,flush=True)
 if r.returncode!=0:break
inv['candidateAfter']={n:sha(s/'launcher'/n)for n in pins};inv['candidateUnchanged']=inv['candidateBefore']==inv['candidateAfter'];(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n')