import hashlib,json,pathlib,runpy,shlex,subprocess,time,os
root=pathlib.Path(__file__).resolve().parent
forward=pathlib.Path('/home/ryan/.local/share/agentmux/windows-clients/forward.py')
module=runpy.run_path(str(forward))
source=forward.read_bytes();(root/'original-forward.py').write_bytes(source)
windows_root=subprocess.check_output(['wslpath','-w',str(root)],text=True).strip()
exe='/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe'
socket='agentmux-job-'+root.name.rsplit('-',1)[-1]
selected={'AGENTMUX_WSL_DISTRO':'Ubuntu-26.04','AGENTMUX_WSL_CWD':str(root),'AGENTMUX_HUB_URL':'tcp://127.0.0.1:9','AGENTMUX_FIXTURE_MARKER':'synthetic-job-only'}
wslenv='AGENTMUX_WSL_DISTRO/w:AGENTMUX_WSL_CWD/pw:AGENTMUX_HUB_URL/w:AGENTMUX_FIXTURE_MARKER/w'
invocation=[exe,windows_root+'\\supervisor.py',windows_root+'\\request.json']
command=' '.join('export '+k+'='+shlex.quote(v)+';' for k,v in {**selected,'WSLENV':wslenv}.items())+' cd '+shlex.quote(str(root))+'; '+shlex.join(invocation)+' > '+shlex.quote(str(root/'run.log'))+' 2>&1; echo $? > '+shlex.quote(str(root/'supervisor.exit'))
report={'scope':'Actual private WSL tmux launch with synthetic Windows children only.','passed':False,'forwardSourceSha256':hashlib.sha256(source).hexdigest(),'forwardCodexExample':module['command']('codex',['--cd',str(root)]),'invocation':invocation,'tmuxSocket':socket,'namedEnvironment':selected,'WSLENV':wslenv,'tmuxShellCommand':command}
start=time.monotonic()
try:
    subprocess.run(['tmux','-L',socket,'-f','/dev/null','new-session','-d','-s','fixture',command],check=True)
    deadline=time.monotonic()+15
    while not (root/'supervisor-ready.json').exists():
        if (root/'supervisor.exit').exists():raise RuntimeError('Supervisor exited before readiness')
        if time.monotonic()>deadline:raise RuntimeError('Supervisor readiness timeout')
        time.sleep(.05)
    report['ready']=json.loads((root/'supervisor-ready.json').read_text())
    report['pane']=subprocess.check_output(['tmux','-L',socket,'list-panes','-t','fixture','-F','#{pane_pid} #{pane_current_command}'],text=True).strip()
    (root/'cancel.request').write_text('Cancel this synthetic fixture job only.\n')
    deadline=time.monotonic()+10
    while not (root/'supervisor.exit').exists():
        if time.monotonic()>deadline:raise RuntimeError('Supervisor exit timeout')
        time.sleep(.05)
    report['supervisorExit']=int((root/'supervisor.exit').read_text().strip())
    result=json.loads((root/'result.json').read_text())
    assert report['supervisorExit']==0 and result['passed']
    for role in ['parent','child']:
        env=result[role]['environment']
        assert env['AGENTMUX_WSL_DISTRO']==selected['AGENTMUX_WSL_DISTRO']
        assert env['AGENTMUX_FIXTURE_MARKER']==selected['AGENTMUX_FIXTURE_MARKER']
        assert env['AGENTMUX_HUB_URL']==selected['AGENTMUX_HUB_URL']
        assert pathlib.PureWindowsPath(env['AGENTMUX_WSL_CWD'])==pathlib.PureWindowsPath(windows_root)
        assert pathlib.PureWindowsPath(result[role]['cwd'])==pathlib.PureWindowsPath(windows_root)
    report['passed']=True
except Exception as exc:
    report['error']={'type':type(exc).__name__,'message':str(exc)}
finally:
    if not (root/'cancel.request').exists():(root/'cancel.request').write_text('Cancel this synthetic fixture job only.\n')
    # Only the unique fixture socket is addressed; no process-name cleanup.
    subprocess.run(['tmux','-L',socket,'kill-server'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    report['forwardSourceUnchanged']=hashlib.sha256(forward.read_bytes()).hexdigest()==report['forwardSourceSha256']
    report['elapsedSeconds']=round(time.monotonic()-start,4)
    (root/'wsl-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
raise SystemExit(0 if report['passed'] else 1)