import pathlib,json,sys,ast,hashlib
root=pathlib.Path(sys.argv[1]);p=root/'updated-calib-supervisor.py';ast.parse(p.read_text())
old=pathlib.Path(r'C:\Users\RyanHelms\AppData\Local\Temp\agentmux-calib-supervisor-f5e9adc41b3949e788a8b7096c47dd99\input-request.json')
req=json.loads(old.read_text());proof=json.loads((root/'result.json').read_text());req['terminalEnvironment']={'TERM':proof['cases'][1]['windowsTERM']}
(root/'input-request.json').write_text(json.dumps(req,indent=2)+'\n')
print(hashlib.sha256(p.read_bytes()).hexdigest())