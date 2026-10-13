import pathlib,os,sys,time,json,subprocess
root=pathlib.Path(__file__).resolve().parent
if sys.argv[1]=='parent':
 child=subprocess.Popen([sys.executable,str(__file__),'child'],cwd=root,creationflags=0x08000000)
 (root/'parent-ready.json').write_text(json.dumps({'pid':os.getpid(),'childPid':child.pid}))
else:(root/'child-ready.json').write_text(json.dumps({'pid':os.getpid(),'parentPid':os.getppid()}))
time.sleep(25)
