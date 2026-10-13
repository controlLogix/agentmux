import pathlib,tempfile,json,hashlib,importlib.util,os,shutil,subprocess,sys
P=pathlib.Path;root=P(r'C:/Users/RyanHelms/AppData/Local/Temp/agentmux original TEAM active JSON retry f1bj61xm');g=root/'provider-supervisor';spec=importlib.util.spec_from_file_location('preflight',g/'launch-preflight.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);test=root/'synthetic-discovery-checks';test.mkdir();profile=test/'profile';hooks=profile/'hooks';hooks.mkdir(parents=True)
active=hooks/'active.json';active.write_text('{}');config=profile/'config.toml';config.write_text('[cli]\n');cmd=test/'hook.cmd';cmd.write_text('@exit /b 0\n');doc=test/'doc.md';doc.write_text('synthetic docs');client=test/'client.bin';client.write_bytes(b'synthetic')
item=lambda p:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
base=json.loads((root/'grok-readiness-review.json').read_text());proof={**base,'canonicalProfile':str(profile),'config':{**base['config'],**item(config)},'hookProgram':{**base['hookProgram'],**item(cmd)},'nativeHookFiles':[item(active)],'documentation':[item(doc)],'clients':[item(client)]};proofpath=test/'proof.json';proofpath.write_text(json.dumps(proof,indent=2)+'\n');proofsha=hashlib.sha256(proofpath.read_bytes()).hexdigest();env={'GROK_HOME':str(profile),**base['documentedProcessOnlyGrokEnv']};results=[]
def check(name,expected):
 passed=False
 try:mod.verify_grok(proofpath,proofsha,env);passed=True
 except AssertionError:passed=False
 assert passed==expected,name;results.append({'case':name,'expectedAccepted':expected,'observedAccepted':passed,'passed':True})
check('unchanged active source',True)
backup=hooks/'active.json.bak';backup.write_text('backup ignored');check('backup ignored',True)
nested=hooks/'nested';nested.mkdir();(nested/'nested.json').write_text('{}');check('nested JSON ignored',True)
uppercase=hooks/'uppercase.JSON';uppercase.write_text('{}');check('uppercase suffix ignored',True)
added=hooks/'new.json';added.write_text('{}');check('added active JSON refused',False);added.unlink()
active.write_text('{"changed":true}');check('changed active JSON refused',False);active.write_text('{}')
cmd.write_text('changed');check('changed hook program refused',False);cmd.write_text('@exit /b 0\n')
env['ORCA_PANE_KEY']='synthetic';check('ORCA instrumentation refused',False);del env['ORCA_PANE_KEY']
actualenv={key:value for key,value in os.environ.items() if not key.startswith('ORCA_') and key not in ['GROK_CONFIG','GROK_CONFIG_PATH']};actualenv.update(GROK_HOME=r'C:/Users/RyanHelms/.grok',**base['documentedProcessOnlyGrokEnv']);actual=mod.verify_launch({'provider':'grok','cwd':str(root/'original demo repos/calc'),'grokReadinessSha256':hashlib.sha256((root/'grok-readiness-review.json').read_bytes()).hexdigest()},root,actualenv)
record={'scope':'Focused active-hook selection regression and read-only immediate native Grok preflight. No provider or model launch.','helperSha256':hashlib.sha256((g/'launch-preflight.py').read_bytes()).hexdigest(),'cases':results,'nativePreflight':actual,'modelExecuted':False,'authRead':False,'canonicalProfilesChanged':False};(root/'focused-discovery-preflight-result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))