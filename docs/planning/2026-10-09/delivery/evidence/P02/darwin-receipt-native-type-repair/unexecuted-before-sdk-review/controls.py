import pathlib,re,json,hashlib,subprocess,shutil,os
b=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-darwin-receipt-pipe-controls');p=b/'src/platform/runtime';go=pathlib.Path('/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go');repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');results=[]
def run(name,argv,env=None,cwd=None):
 r=subprocess.run(argv,capture_output=True,env=env,cwd=cwd);(b/(name+'.stdout')).write_bytes(r.stdout);(b/(name+'.stderr')).write_bytes(r.stderr);results.append({'name':name,'argv':argv,'cwd':str(cwd) if cwd else None,'exitCode':r.returncode});return r.returncode
if run('format',[str(go.parent/'gofmt'),'-w']+[str(x) for x in p.glob('*.go')]):raise SystemExit(1)
c=(p/'bootstrap_receipt_descriptor_darwin.go').read_text();c=c[c.index('/*')+2:c.index('*/')];c=re.sub(r'^#include.*\n','',c,flags=re.M)
model='''#include <stddef.h>
#include <string.h>
#include <stdio.h>
#define PROC_PIDFDPIPEINFO 6
struct pipe_fdinfo { struct {unsigned long long pipe_handle,pipe_peerhandle;} pipeinfo; };
static int scenario;
static int getpid(void){return 41;}
static int proc_pidfdinfo(int pid,int flavor,int fd,void *buffer,int size){
 if(pid!=41||flavor!=6||fd!=7)return -1;
 struct pipe_fdinfo *p=buffer;p->pipeinfo.pipe_handle=scenario==3?0:10;p->pipeinfo.pipe_peerhandle=scenario==4?0:11;
 if(scenario==0)return size;if(scenario==1)return -1;if(scenario==2)return size-1;if(scenario==5)return 0;if(scenario==6)return size+1;return size;
}
'''+c+'''int main(void){for(scenario=0;scenario<7;scenario++){int expected=scenario==0;int got=agentmux_receipt_anonymous_pipe(7);if(got!=expected){printf("scenario=%d unexpected_admission\\n",scenario);return 1;}}if(agentmux_receipt_anonymous_pipe(8))return 1;puts("8 modeled native-type/result controls passed");return 0;}
'''
(b/'native-api-control.c').write_text(model)
if run('native-model-compile',['cc','-std=c11','-Werror=implicit-function-declaration',str(b/'native-api-control.c'),'-o',str(b/'native-api-control')])==0:run('native-model-execute',[str(b/'native-api-control')])
unit=b/'predicate-only';unit.mkdir(exist_ok=True)
for x in p.glob('bootstrap_receipt_descriptor*.go'):shutil.copyfile(x,unit/x.name)
(unit/'go.mod').write_text('module receiptcontrol\n\ngo 1.27.2\n\nrequire golang.org/x/sys v0.48.0\n');(unit/'go.sum').write_text('\n'.join(x for x in (repo/'platform/go.sum').read_text().splitlines() if x.startswith('golang.org/x/sys '))+'\n')
env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0')
if run('linux-preservation',[str(go),'test','-race','-count=1','-json','.','-run','^TestReceiptLinuxDescriptorPreservesAdmission$'],env,unit)==0:
 env.update(GOOS='darwin',GOARCH='arm64',CGO_ENABLED='0');run('darwin-no-cgo-compile',[str(go),'test','-c','-o',str(b/'darwin-no-cgo.test')],env,unit)
record={'scope':'Standalone exact descriptor helpers and modeled C APIs; not full receipt/native platform proof','results':results,'sourcePins':{str(x.relative_to(b)):hashlib.sha256(x.read_bytes()).hexdigest() for x in p.glob('*.go')},'limits':['C APIs are modeled; no native macOS pipe creation/query by this worker.','Linux standalone helper uses actual owned os.Pipe; historical Linux named FIFO metadata allowance remains unchanged, not newly qualified.','Darwin nocgo is crosscompile only; actual refusal test must execute on native CI.','Native authored tests prove pipe/regular/socket/namedFIFO type only when actually run later.','No adoption/close/lifecycle behavior changed by helpers.']}
(b/'controls.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))