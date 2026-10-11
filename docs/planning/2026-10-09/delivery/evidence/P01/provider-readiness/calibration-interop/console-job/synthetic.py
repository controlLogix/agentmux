import json,os,pathlib,subprocess,sys,time
root=pathlib.Path(__file__).resolve().parent
if sys.argv[1]=='parent':
    print('CONSOLE_READY',flush=True)
    line=input().strip()
    print('CONSOLE_ACK:'+line,flush=True)
    child=subprocess.Popen([sys.executable,str(__file__),'child'],cwd=root)
    (root/'parent-ready.json').write_text(json.dumps({'pid':os.getpid(),'childPid':child.pid,'input':line}))
else:
    (root/'child-ready.json').write_text(json.dumps({'pid':os.getpid(),'parentPid':os.getppid()}))
time.sleep(45)
