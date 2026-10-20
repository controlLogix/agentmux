"""Fixed task-container programs; no caller supplies executable arguments."""
# These programs run only in the selected pinned image. Task output is discarded.
BOOT = r'''
import hashlib,json,os,signal,stat,sys,time
p=json.loads(sys.argv[1]); root='/run/agentmux'; os.umask(0o077)
def read_recipe():
    fd=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parts=p['recipe']['path'].split('/')
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        source=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            info=os.fstat(source)
            if not stat.S_ISREG(info.st_mode) or info.st_size>45000:raise ValueError()
            data=os.read(source,45001)
            if len(data)!=info.st_size or 'sha256:'+hashlib.sha256(data).hexdigest()!=p['recipe']['sha256']:raise ValueError()
            return data
        finally:os.close(source)
    finally:os.close(fd)
try:
    data=read_recipe()
    with open(root+'/ready','x') as f:f.write('ready')
    end=p['end']
    while not os.path.exists(root+'/start'):
        if time.time()>=end:sys.exit(124)
        time.sleep(.02)
    if time.time()>=end:sys.exit(124)
    child=os.fork()
    if child==0:
        os.setsid()
        null=os.open('/dev/null',os.O_RDWR)
        for i in (0,1,2):os.dup2(null,i)
        os.closerange(3,1024)
        sys.argv=[p['recipe']['path']]
        try:exec(compile(data,p['recipe']['path'],'exec'),{'__name__':'__main__','__file__':p['recipe']['path']})
        except BaseException:os._exit(1)
        os._exit(0)
    while True:
        done,status=os.waitpid(child,os.WNOHANG)
        if done:sys.exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 125)
        if time.time()>=end:
            try:os.killpg(child,signal.SIGKILL)
            except ProcessLookupError:
                try:os.kill(child,signal.SIGKILL)
                except ProcessLookupError:pass
            os.waitpid(child,0);sys.exit(124)
        time.sleep(.02)
except BaseException as error:
    if isinstance(error,SystemExit):raise
    sys.exit(126)
'''

READY = r'''
import os,sys,time
end=time.monotonic()+2
while not os.path.isfile('/run/agentmux/ready'):
    if time.monotonic()>=end:sys.exit(1)
    time.sleep(.01)
'''
NETWORK_READY = READY.replace("'/run/agentmux/ready'", "'/run/agentmux/network'").replace('os.path.isfile','os.path.exists')
START = "import os;f=os.open('/run/agentmux/start',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(f)"
# Private delivery is write-once and never prints its input. A repeated/uncertain
# delivery is reconciled by C; it is never silently overwritten here.
DELIVER = r'''
import os,sys
os.umask(0o077)
data=sys.stdin.buffer.read(16385)
if not 0<len(data)<=16384:sys.exit(2)
f=os.open('/run/agentmux/credential',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    view=memoryview(data)
    while view:
        n=os.write(f,view);view=view[n:]
    os.fsync(f)
finally:os.close(f)
'''

# The untrusted task uses this socket. Every request is still checked by the
# host; neither the task nor this relay can choose an arbitrary URL or header.
RELAY = r'''
import json,os,socket,sys
os.umask(0o077)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.bind('/run/agentmux/network');s.listen(4)
while True:
    c,_=s.accept();c.settimeout(3)
    try:
        raw=b''
        while not raw.endswith(b'\n') and len(raw)<=8192:
            part=c.recv(min(1024,8193-len(raw)))
            if not part:break
            raw+=part
        if len(raw)>8192 or not raw.endswith(b'\n'):raise ValueError()
        value=json.loads(raw)
        if type(value)!=dict or set(value)!={'destinationRef'}:raise ValueError()
        sys.stdout.write(json.dumps(value,separators=(',',':'))+'\n');sys.stdout.flush()
        response=sys.stdin.buffer.readline(65537)
        if not response.endswith(b'\n') or len(response)>65536:raise ValueError()
        c.sendall(response)
    except Exception:
        try:c.sendall(b'{"status":"denied"}\n')
        except Exception:pass
    finally:c.close()
'''
