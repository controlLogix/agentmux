import os,pathlib,hashlib,json,subprocess
root=pathlib.Path(__file__).resolve().parent;profile=root/'synthetic-profile';profile.mkdir();config=profile/'config.toml';config.write_text('[mcp_servers.agent-browser]\ncommand = "cmd.exe"\nargs = ["/c", "echo", "synthetic not invoked"]\nenabled = true\n',encoding='utf-8')
node=pathlib.Path('C:/nvm4w/nodejs/node.exe');js=pathlib.Path('C:/nvm4w/nodejs/node_modules/@openai/codex/bin/codex.js');env=dict(os.environ,CODEX_HOME=str(profile));records=[]
for label,key in [('quoted','mcp_servers."agent-browser".enabled=false'),('bare','mcp_servers.agent-browser.enabled=false')]:
 args=[str(node),str(js),'-c',key,'mcp','list','--json'];p=subprocess.run(args,env=env,capture_output=True,text=True,timeout=25)
 result={'case':label,'argv':args,'exitCode':p.returncode,'stderr':p.stderr,'namesAndEnabled':[]}
 if p.returncode==0:
  data=json.loads(p.stdout)
  assert isinstance(data,list)
  result['namesAndEnabled']=[{'name':item['name'],'enabled':item['enabled']} for item in data]
 records.append(result)
assert records[0]['exitCode']!=0 and 'invalid transport' in records[0]['stderr']
assert records[1]['exitCode']==0 and records[1]['namesAndEnabled']==[{'name':'agent-browser','enabled':False}]
report={'scope':'Synthetic private Windows config; installed CLI config listing only. No personal config/auth access, model inference or MCP server execution.','records':records,'syntheticConfigSha256':hashlib.sha256(config.read_bytes()).hexdigest(),'sourceHashes':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in [node,js,pathlib.Path(__file__)]},'passed':True}
(root/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'path':str(root/'result.json'),'sha256':hashlib.sha256((root/'result.json').read_bytes()).hexdigest(),'records':records}))
