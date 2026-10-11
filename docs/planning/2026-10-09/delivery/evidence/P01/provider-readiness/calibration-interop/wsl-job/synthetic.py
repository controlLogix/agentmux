import json,os,pathlib,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parent
selected=['AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_CWD','AGENTMUX_HUB_URL','AGENTMUX_FIXTURE_MARKER']
data={'pid':os.getpid(),'parentPid':os.getppid(),'cwd':os.getcwd(),'argv':sys.argv,'environment':{key:os.environ.get(key) for key in selected}}
if sys.argv[1]=='parent':
    child=subprocess.Popen([sys.executable,str(__file__),'child'],cwd=root)
    data['childPid']=child.pid
(root/('parent-ready.json' if sys.argv[1]=='parent' else 'child-ready.json')).write_text(json.dumps(data,indent=2),encoding='utf-8')
time.sleep(45)
