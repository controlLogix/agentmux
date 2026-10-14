# Spy on an actual builtin owned child's wait without changing its timing contract.
import importlib.util,json,subprocess,sys,time
from pathlib import Path
p=Path(__file__).parent
source=p/sys.argv[1]
spec=importlib.util.spec_from_file_location('collector',source);c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],start_new_session=True)
actual_wait=child.wait;seen=[]
def spy(*args,**kwargs):seen.append(kwargs.copy());return actual_wait(*args,**kwargs)
child.wait=spy
try:
    deadline=time.monotonic()+.5
    code=c.stop_owned(child) if sys.argv[1]=='original.py' else c.stop_owned(child,deadline)
    bounded=bool(seen) and all('timeout' in call and 0<=call['timeout']<=.5 for call in seen)
    print(json.dumps({'boundedWaitAPI':bounded,'actualChildReaped':child.returncode==-9,'waitCalls':len(seen)}))
finally:
    if child.returncode is None:child.kill();actual_wait(timeout=2)
sys.exit(0 if bounded and code==-9 else 1)
