import pathlib,json,subprocess,sys,shutil,hashlib
P=pathlib.Path;root=P(r'C:/Users/RyanHelms/AppData/Local/Temp/agentmux original TEAM preparation _fwm3fqa');g=root/'provider-supervisor';m=json.loads((root/'fixture.json').read_text());results=[]
original=subprocess.check_output(['git','-C',r'C:/Users/RyanHelms/GitHub/agentmux','show','c370290:agentmux.sh'],text=True)
block=original.split("<<'PYCFG'\n",1)[1].split('\nPYCFG\n',1)[0]
linuxout=m['ntfsFixture']+'/original-generated-claude-settings.json'
p=subprocess.run(['wsl','-d','Ubuntu-26.04','--','python3','-',m['home']+'/.claude/settings.json',linuxout,'unrestricted','','',''],input=block,capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
generated=json.loads((root/'original-generated-claude-settings.json').read_text());assert generated=={'permissions':{'defaultMode':'bypassPermissions','allow':[],'deny':[]}}
(root/'original-claude-generator-proof.json').write_text(json.dumps({'sourceCommit':m['commit'],'sourceFile':'agentmux.sh','sourcePythonBlockSha256':hashlib.sha256(block.encode()).hexdigest(),'privateSourceSettingsAbsent':True,'posture':'unrestricted','tools':'','denyTools':'','federationGate':'','generatedSettings':generated,'generatedSettingsSha256':hashlib.sha256((root/'original-generated-claude-settings.json').read_bytes()).hexdigest(),'modelExecuted':False},indent=2)+'\n')
for provider in ['claude','grok','codex']:
 old=root/(provider+'-prepare-probe');folder=root/(provider+'-preflight-prepare-probe');folder.mkdir()
 for name in ['supervisor.py','observer.py','observer_api.py','launch-preflight.py']:shutil.copyfile(g/name,folder/name)
 req=json.loads((old/'input-request.json').read_text())
 if provider=='claude':req.update(generatedClaudeSettings=generated,generatedClaudeSettingsSha256=hashlib.sha256((root/'original-generated-claude-settings.json').read_bytes()).hexdigest())
 if provider=='grok':
  shutil.copyfile(root/'grok-readiness-review.json',folder/'grok-readiness-review.json');req['grokReadinessSha256']=hashlib.sha256((root/'grok-readiness-review.json').read_bytes()).hexdigest()
 (folder/'input-request.json').write_text(json.dumps(req,indent=2)+'\n')
 p=subprocess.run([sys.executable,str(folder/'supervisor.py'),'--prepare',str(folder/'input-request.json')],capture_output=True,text=True,timeout=20);(folder/'prepare.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr
 prepared=json.loads((folder/'prepared-request.json').read_text());assert prepared['provider']==provider and prepared['maxSeconds']==2700
 for item in prepared['files']:assert hashlib.sha256(P(item['path']).read_bytes()).hexdigest()==item['sha256']
 results.append({'provider':provider,'prepareExitCode':p.returncode,'preparedRequestSha256':hashlib.sha256((folder/'prepared-request.json').read_bytes()).hexdigest(),'filesPinned':len(prepared['files']),'modelExecuted':False})
(root/'preflight-prepare-results.json').write_text(json.dumps({'passed':True,'checks':results,'canonicalProfileChanged':False,'modelExecuted':False},indent=2)+'\n');print(json.dumps(results,indent=2))