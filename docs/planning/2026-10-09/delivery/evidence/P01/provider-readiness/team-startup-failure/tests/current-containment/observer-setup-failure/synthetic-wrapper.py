import importlib.util,pathlib,sys,uuid,hashlib
root=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('calibsupervisor',root/'supervisor.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.CONFIG=root/'synthetic-config.toml'
argv=[sys.executable,str(root/'synthetic.py'),'parent']
req={'maxSeconds':2700,'configPath':str(root/'synthetic-config.toml'),'jobUid':str(uuid.uuid4()),'originalArgv':argv,'argv':argv,'cwd':str(root),'files':[{'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in [pathlib.Path(sys.executable),root/'synthetic.py']],'callbackEnvironment':{},'PATH':__import__('os').environ['PATH']}
result=module.launch(req,synthetic=True)
raise SystemExit(0 if result['passed'] else 1)
