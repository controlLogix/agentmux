import pathlib,hashlib,json,difflib,subprocess,os
b=pathlib.Path('/mnt/c/Users/RyanHelms/.cache/agentmux-governance/p02-survival-poll-diagnostic-controls');repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux');p=b/'src/platform/runtime';p.mkdir(parents=True,exist_ok=True);go=pathlib.Path('/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go')
helper='''//go:build linux

package runtime

import (
 "errors"
 "fmt"
 "syscall"
)

// This explains a refused test observation; it never declares child liveness.
func pidfdSurvivalDiagnostic(count int, err error, revents int16) string {
 code := "none"
 if err != nil { code = "kernel_error"; if errors.Is(err, syscall.EINTR) { code = "interrupted" } }
 return fmt.Sprintf("pidfd_survival_observation_refused: count=%d error=%s revents=%d", count, code, revents)
}
'''
controls='''//go:build linux

package runtime

import (
 "errors"
 "fmt"
 "syscall"
 "testing"
)

func TestPidfdSurvivalDiagnosticKeepsClosedFacts(t *testing.T) {
 cases := []struct{name string; count int; err error; revents int16; expected string}{
  {"zero",0,nil,0,"pidfd_survival_observation_refused: count=0 error=none revents=0"},
  {"interrupted",-1,syscall.EINTR,0,"pidfd_survival_observation_refused: count=-1 error=interrupted revents=0"},
  {"wrapped_interrupted",-1,fmt.Errorf("private detail: %w",syscall.EINTR),0,"pidfd_survival_observation_refused: count=-1 error=interrupted revents=0"},
  {"kernel_error",-1,syscall.EBADF,32,"pidfd_survival_observation_refused: count=-1 error=kernel_error revents=32"},
  {"spoofed_error",-1,errors.New("EINTR private detail"),0,"pidfd_survival_observation_refused: count=-1 error=kernel_error revents=0"},
  {"event",1,nil,1,"pidfd_survival_observation_refused: count=1 error=none revents=1"},
  {"error_and_event",1,syscall.EINTR,1,"pidfd_survival_observation_refused: count=1 error=interrupted revents=1"},
  {"negative_without_error",-1,nil,0,"pidfd_survival_observation_refused: count=-1 error=none revents=0"},
  {"flags_without_count",0,nil,32,"pidfd_survival_observation_refused: count=0 error=none revents=32"},
 }
 for _,c:=range cases { t.Run(c.name,func(t *testing.T){if got:=pidfdSurvivalDiagnostic(c.count,c.err,c.revents);got!=c.expected{t.Fatal("closed observation facts changed")}}) }
}
'''
(p/'pidfd_survival_diagnostic_linux_test.go').write_text(helper);(p/'pidfd_survival_diagnostic_controls_linux_test.go').write_text(controls);pins=[]
for name,needle,replacement in [('installed_host_linux_test.go','t.Fatal("detached child exited with its frontend")','t.Fatal(pidfdSurvivalDiagnostic(count, err, poll[0].Revents))'),('bootstrap_receipt_linux_test.go','t.Fatal("receipt child exited with frontend")','t.Fatal(pidfdSurvivalDiagnostic(n, e, poll[0].Revents))')]:
 old=(repo/'platform/runtime'/name).read_bytes();text=old.decode().replace('\r\n','\n');assert text.count(needle)==1;new=text.replace(needle,replacement);(b/(name+'.before')).write_bytes(old);(p/name).write_text(new);pins.append({'path':'platform/runtime/'+name,'beforeSHA256':hashlib.sha256(old).hexdigest()});(b/(name+'.diff')).write_text(''.join(difflib.unified_diff(text.splitlines(True),new.splitlines(True),fromfile=name+' before',tofile=name+' diagnostic')))
argv=[str(go.parent/'gofmt'),'-w']+[str(x) for x in p.glob('*.go')];subprocess.run(argv,check=True)
unit=b/'formatter-only';unit.mkdir(exist_ok=True)
for name in ['pidfd_survival_diagnostic_linux_test.go','pidfd_survival_diagnostic_controls_linux_test.go']:(unit/name).write_bytes((p/name).read_bytes())
(unit/'go.mod').write_text('module survivaldiagnostic\n\ngo 1.27.2\n');env=os.environ.copy();env.update(GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',GOWORK='off',GOFLAGS='-mod=readonly',GORACE='atexit_sleep_ms=0');argv=[str(go),'test','-race','-count=1','-json','.','-run','^TestPidfdSurvivalDiagnosticKeepsClosedFacts$'];r=subprocess.run(argv,cwd=unit,env=env,capture_output=True);(b/'events.jsonl').write_bytes(r.stdout);(b/'stderr.log').write_bytes(r.stderr);(b/'invocation.json').write_text(json.dumps({'argv':argv,'cwd':str(unit),'env':{k:env[k] for k in ['GOTOOLCHAIN','GOPROXY','GOSUMDB','GOWORK','GOFLAGS','GORACE']}},indent=2)+'\n');(b/'exit.json').write_text(json.dumps({'exitCode':r.returncode})+'\n');ev=[json.loads(x) for x in r.stdout.decode().splitlines()];record={'scope':'Test diagnostics only; no survival assertion/retry/deadline changes and no live child/native qualification','originalPins':pins,'sourcePins':{str(x.relative_to(b)):hashlib.sha256(x.read_bytes()).hexdigest() for x in p.glob('*.go')},'namedPass':sum(x['Action']=='pass' and bool(x.get('Test')) for x in ev),'fail':sum(x['Action']=='fail' for x in ev),'skip':sum(x['Action']=='skip' for x in ev),'directExit':r.returncode,'limits':['Only two standalone formatter/control files compiled, no runtime TestMain/product/integration imports.','Pure fixed inputs prove exact fact formatting and private error-text exclusion only; no actual pidfd observation.','Both singlePoll100 calls/originalerror-or-count failure predicates and3000 exit-after-signal checks remain unchanged.','Actual failure causes remain unknown until diagnostic native execution; no retry behavior added.']};manifest={str(x.relative_to(b)):hashlib.sha256(x.read_bytes()).hexdigest() for x in b.rglob('*') if x.is_file() and x.name not in ['review.json','manifest.json']};(b/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');record['manifestSHA256']=hashlib.sha256((b/'manifest.json').read_bytes()).hexdigest();(b/'review.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'reviewSHA256':hashlib.sha256((b/'review.json').read_bytes()).hexdigest(),**record}))