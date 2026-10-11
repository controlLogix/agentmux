#!/usr/bin/python3
"""Forward to the Windows installation; keep its Windows home and credentials."""
import json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def windows_path(value):
    if value.startswith('/'):
        return subprocess.check_output(['/usr/bin/wslpath','-w',value],text=True).rstrip(chr(10))
    return value

def command(client,args):
    config=json.loads((ROOT/'clients.json').read_text())[client]
    output=[config['exe']]
    if 'script' in config:output.append(windows_path(config['script']))
    variadic=set(config.get('variadicPaths',[]))
    comma=set(config.get('commaPaths',[]))
    active=None
    literal=False
    def convert(value,key):
        return ','.join(windows_path(v) for v in value.split(',')) if key in comma else windows_path(value)
    for arg in args:
        if literal:
            output.append(arg);continue
        if arg=='--':
            output.append(arg);literal=True;active=None;continue
        key,sep,value=arg.partition('=')
        attached=False
        if key not in config['paths'] and len(arg)>2 and arg[:2] in config['paths'] and arg[:2].startswith('-') and not arg.startswith('--'):
            key,sep,value=arg[:2],'',arg[2:];attached=True
        if key in config['paths']:
            if sep or attached:
                output.append(key+sep+convert(value,key))
                active=key if key in variadic else None
            else:
                output.append(arg);active=key
        elif active is not None and not arg.startswith('-'):
            output.append(convert(arg,active))
            if active not in variadic:active=None
        else:
            output.append(arg)
            if arg.startswith('-'):active=None
    return output

def environment(original):
    result=dict(original)
    entries=[x for x in result.get('WSLENV','').split(':') if x]
    for key in ('CODEX_HOME','CLAUDE_CONFIG_DIR'):
        value=result.get(key)
        if not value:
            continue
        # Preserve other entries; an explicit config path must reach Windows.
        entries=[x for x in entries if x.split('/',1)[0] != key]
        windows_value=(len(value)>2 and value[1]==':' and value[2] in ('/',chr(92))) or value.startswith(chr(92)*2)
        entries.append(key+('/w' if windows_value else '/pw'))
    if entries:
        result['WSLENV']=':'.join(entries)
    return result

if __name__=='__main__':
    client=Path(sys.argv[0]).name
    argv=command(client,sys.argv[1:])
    os.execve(argv[0],argv,environment(os.environ))
