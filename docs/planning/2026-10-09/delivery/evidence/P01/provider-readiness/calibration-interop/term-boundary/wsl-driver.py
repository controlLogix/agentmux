import pathlib,subprocess,shlex,json,time,os
root=pathlib.Path(__file__).resolve().parent
winroot=subprocess.check_output(['wslpath','-w',str(root)],text=True).strip()
exe='/mnt/c/Users/RyanHelms/AppData/Local/Programs/Python/Python314/python.exe'
socket='agentmux-term-'+root.name.rsplit('-',1)[-1]
report={'passed':False,'scope':'Synthetic TERM propagation through tmux and Windows Job Object console supervisor only.','cases':[],'noRealClientOrModel':True}
start=time.monotonic()
try:
    for kind in ['default','forward']:
        termforward='TERM/w' if kind=='forward' else ''
        argv=[exe,winroot+'\\console-supervisor.py',kind+'-request.json']
        command='printf "%s" "$TERM" > '+shlex.quote(str(root/(kind+'-linux-term.txt')))+'; export WSLENV='+shlex.quote(termforward)+'; cd '+shlex.quote(str(root))+'; '+shlex.join(argv)+'; echo $? > '+shlex.quote(str(root/(kind+'.exit')))+'; sleep 20'
        subprocess.run(['tmux','-L',socket,'-f','/dev/null','new-session','-d','-s',kind,command],check=True)
        deadline=time.monotonic()+15
        while not (root/(kind+'.exit')).exists():
            if time.monotonic()>deadline:raise RuntimeError(kind+' timeout')
            time.sleep(.05)
        pane=subprocess.check_output(['tmux','-L',socket,'capture-pane','-p','-S','-100','-t',kind],text=True)
        (root/(kind+'-pane.log')).write_text(pane)
        windows=json.loads((root/(kind+'-term.json')).read_text());linux=(root/(kind+'-linux-term.txt')).read_text()
        result=json.loads((root/(kind+'-result.json')).read_text());exitcode=int((root/(kind+'.exit')).read_text())
        assert result['passed'] and exitcode==0 and 'WINDOWS_TERM:' in pane
        report['cases'].append({'case':kind,'linuxTERM':linux,'windowsTERM':windows['TERM'],'windowsPid':windows['pid'],'WSLENV':termforward,'argv':argv,'command':command,'supervisorExit':exitcode})
    assert report['cases'][0]['linuxTERM']!='dumb'
    assert report['cases'][0]['windowsTERM']=='dumb'
    assert report['cases'][1]['windowsTERM']==report['cases'][1]['linuxTERM'] and report['cases'][1]['windowsTERM']!='dumb'
    report['passed']=True
except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
finally:
    subprocess.run(['tmux','-L',socket,'kill-server'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    report['elapsedSeconds']=round(time.monotonic()-start,4)
    report['limit']='This proves TERM propagation only. It does not prove that actual Codex startup will bypass its dumb-terminal modal or pass calibration.'
    (root/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
raise SystemExit(0 if report['passed'] else 1)