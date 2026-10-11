import pathlib,json,subprocess,shlex,time,hashlib
root=pathlib.Path(__file__).resolve().parent
winroot=subprocess.check_output(['wslpath','-w',str(root)],text=True).strip()
exe='/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe'
socket='agentmux-console-'+root.name.rsplit('-',1)[-1]
report={'passed':False,'socket':socket,'cases':[],'callbackEnvironmentLimit':'No callback context tested here. Prior /pw CWD probe is not the actual callback contract: AGENTMUX_WSL_CWD must stay Linux absolute via /w.'}
def capture(session):
    return subprocess.check_output(['tmux','-L',socket,'capture-pane','-p','-S','-1000','-t',session],text=True)
def wait_for(action,predicate,seconds=15):
    deadline=time.monotonic()+seconds
    while not predicate():
        if time.monotonic()>deadline:raise RuntimeError(action+' timeout')
        time.sleep(.05)
start=time.monotonic()
try:
    for kind in ['synthetic','help']:
        argv=[exe,winroot+'\\supervisor.py',kind+'-request.json']
        command='cd '+shlex.quote(str(root))+'; '+shlex.join(argv)+'; echo $? > '+shlex.quote(str(root/(kind+'.exit')))+'; sleep 25'
        subprocess.run(['tmux','-L',socket,'-f','/dev/null','new-session','-d','-s',kind,'-x','140','-y','45',command],check=True)
        case={'kind':kind,'invocation':argv,'shellCommand':command}
        if kind=='synthetic':
            wait_for('Console ready',lambda:'CONSOLE_READY' in capture(kind))
            subprocess.run(['tmux','-L',socket,'send-keys','-t',kind,'-l','agentmux-console-handshake'],check=True)
            subprocess.run(['tmux','-L',socket,'send-keys','-t',kind,'Enter'],check=True)
            wait_for('Child readiness',lambda:(root/'supervisor-ready.json').exists())
            pane=capture(kind);(root/'synthetic-pane.log').write_text(pane)
            assert 'CONSOLE_ACK:agentmux-console-handshake' in pane
            (root/'cancel.request').write_text('Cancel only this synthetic job.\n')
        wait_for(kind+' result',lambda:(root/(kind+'.exit')).exists())
        case['exitCode']=int((root/(kind+'.exit')).read_text().strip())
        result=json.loads((root/(kind+'-result.json')).read_text())
        case['resultPassed']=result['passed'];assert case['exitCode']==0 and result['passed']
        pane=capture(kind);(root/(kind+'-pane-final.log')).write_text(pane)
        if kind=='help':
            assert 'Codex CLI' in pane and 'Usage:' in pane and '--no-daemon' in pane
            case['helpVisibleInPane']=True
        report['cases'].append(case)
    report['passed']=True
except Exception as exc:
    report['error']={'type':type(exc).__name__,'message':str(exc)}
    for kind in ['synthetic','help']:
        try:(root/(kind+'-failure-pane.log')).write_text(capture(kind))
        except Exception:pass
finally:
    if not (root/'cancel.request').exists():(root/'cancel.request').write_text('Cancel only this synthetic job.\n')
    subprocess.run(['tmux','-L',socket,'kill-server'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    report['elapsedSeconds']=round(time.monotonic()-start,4)
    (root/'wsl-result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
raise SystemExit(0 if report['passed'] else 1)