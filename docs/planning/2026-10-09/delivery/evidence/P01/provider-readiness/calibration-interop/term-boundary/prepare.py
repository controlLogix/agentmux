import pathlib,sys,json,hashlib
root=pathlib.Path(sys.argv[1]);original=pathlib.Path(r'C:\Users\RyanHelms\AppData\Local\Temp\agentmux-calib-supervisor-f5e9adc41b3949e788a8b7096c47dd99\supervisor.py')
s=original.read_text();(root/'previous-calib-supervisor.py').write_bytes(original.read_bytes())
s=s.replace("toolenv={**env,'PATH':windows_path}","terminal=req.get('terminalEnvironment',{})\n    assert isinstance(terminal,dict) and set(terminal).issubset({'TERM','COLORTERM'}) and all(isinstance(value,str) and value and '\\0' not in value for value in terminal.values())\n    if terminal:assert terminal.get('TERM') and terminal['TERM']!='dumb'\n    toolenv={**env,**terminal,'PATH':windows_path}")
s=s.replace("'PATH':windows_path,'mcpNames'","'PATH':windows_path,'terminalEnvironment':terminal,'mcpNames'")
s=s.replace("env=dict(os.environ);env.update(req['callbackEnvironment']);env['PATH']=req['PATH']","env=dict(os.environ);env.update(req['callbackEnvironment']);env.update(req.get('terminalEnvironment',{}));env['PATH']=req['PATH']")
(root/'updated-calib-supervisor.py').write_text(s)
# Narrow proof uses the same validated console inheritance, with harmless synthetic argv only.
console=pathlib.Path(r'C:\Users\RyanHelms\AppData\Local\Temp\agentmux-console-job-46a04b568cb24935a16d1c3c8e649a5a\supervisor.py').read_text()
console=console.replace("assert sys.argv[1] in ['synthetic-request.json','help-request.json']","assert sys.argv[1] in ['default-request.json','forward-request.json']")
console=console.replace("if request['kind']=='help':","if request['kind'] in ['default','forward']:")
(root/'console-supervisor.py').write_text(console)
(root/'terminal-child.py').write_text("import os,json,pathlib,sys\nroot=pathlib.Path(__file__).resolve().parent\ndata={'pid':os.getpid(),'TERM':os.environ.get('TERM'),'COLORTERM':os.environ.get('COLORTERM'),'case':sys.argv[1]}\n(root/(sys.argv[1]+'-term.json')).write_text(json.dumps(data,indent=2)+'\\n')\nprint('WINDOWS_TERM:'+str(data['TERM']),flush=True)\n")
manifest={}
for kind in ['default','forward']:
    argv=[sys.executable,str(root/'terminal-child.py'),kind]
    manifest[kind]={'argv':argv,'files':[{'path':x,'sha256':hashlib.sha256(pathlib.Path(x).read_bytes()).hexdigest()} for x in argv[:2]]}
    (root/(kind+'-request.json')).write_text(json.dumps({'kind':kind,'argv':argv,'cwd':str(root)}))
(root/'allowlist.json').write_text(json.dumps(manifest,indent=2))
print(root)
print('Updated source SHA '+hashlib.sha256((root/'updated-calib-supervisor.py').read_bytes()).hexdigest())