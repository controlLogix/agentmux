import os,json,subprocess,sys,pathlib
out=pathlib.Path(sys.argv[1]);bridge=pathlib.Path(sys.argv[2]);own,other=sys.argv[3:5]
context={k:os.environ.get(k) for k in ['AGENTMUX_WINDOWS_CALLBACK','AGENTMUX_AGENT','AGENTMUX_HUB_URL','AGENTMUX_HUB_TOKEN_FILE','AGENTMUX_WSL_DISTRO','AGENTMUX_WSL_BIN','AGENTMUX_WSL_CWD','AGENTMUX_HOME','TMUX_TMPDIR']}
result={'argv':sys.argv,'cwd':os.getcwd(),'userProfile':os.environ.get('USERPROFILE'),'context':context,'inlineTokenPresent':bool(os.environ.get('AGENTMUX_HUB_TOKEN')),'calls':[]}
def invoke(*args):
 argv=[str(bridge/'agentmux.cmd'),'hub',*args]; command='cmd.exe /d /s /c "'+subprocess.list2cmdline(argv)+'"';p=subprocess.run(command,capture_output=True,text=True,timeout=20);result['calls'].append({'argv':argv,'command':command,'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});return p
try:
 assert context['AGENTMUX_WINDOWS_CALLBACK']=='1' and not result['inlineTokenPresent']; p=invoke('whoami'); assert p.returncode==0 and p.stdout.startswith(context['AGENTMUX_AGENT']), (p.stdout,p.stderr)
 p=invoke('done',other,'--result','wrong synthetic worker');assert p.returncode!=0
 p=invoke('--json','claim',own);assert p.returncode==0,(p.stdout,p.stderr)
 pathlib.Path('windows-synthetic-'+context['AGENTMUX_AGENT']+'.bin').write_bytes(b'Windows selected cwd proof\x00\xff')
 p=invoke('done',own,'--result','Synthetic Windows callback prerequisite complete');assert p.returncode==0,(p.stdout,p.stderr)
 result['passed']=True
except Exception as e:result['passed']=False;result['failure']=repr(e)
out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
