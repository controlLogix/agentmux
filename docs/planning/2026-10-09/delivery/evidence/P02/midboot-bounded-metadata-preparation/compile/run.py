import pathlib,hashlib,json,shutil,tempfile,subprocess,os,time
repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux/platform')
draft=pathlib.Path('/home/ryan/.cache/agentmux-governance/p02-midboot-bounded-metadata-caller-dyls1op6')
out=pathlib.Path(tempfile.mkdtemp(prefix='p02-midboot-bounded-caller-compile-',dir='/home/ryan/.cache/agentmux-governance')); (out/'src').mkdir()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def manifest(root):return {str(p.relative_to(root)):digest(p) for p in sorted(root.rglob('*')) if p.is_file() and (p.suffix=='.go' or p.name in ['go.mod','go.sum'])}
before=manifest(repo);shutil.copytree(repo,out/'src/platform');copied=manifest(out/'src/platform');after=manifest(repo)
assert before==copied==after,'source_snapshot_drift'
pins={'installed_cli_midboot_compose_integration_linux_test.go':'d1ea990d646e9a8e91bc88fea91e87dc89704460b5ac6cd5cd870c3e28cdfc5f','installed_cli_midboot_metadata_predicate_test.go':'2ff0cd87051d8a25263ea2ba59ced3cb83f0148ecf6f73bd046f5a52aad83e16','installed_cli_midboot_metadata_controls_test.go':'531d4751a0824e9bd5538ba1b242d89304eb0a1023bcaad686fcb5e02011d80c'}
for name,pin in pins.items():
 assert digest(draft/name)==pin
 shutil.copyfile(draft/name,out/'src/platform/launcher'/name)
 assert digest(out/'src/platform/launcher'/name)==pin
(out/'source-before.json').write_text(json.dumps(before,indent=2)+'\n');(out/'source-copy.json').write_text(json.dumps(copied,indent=2)+'\n');(out/'source-after.json').write_text(json.dumps(after,indent=2)+'\n');(out/'candidate-source.json').write_text(json.dumps(manifest(out/'src/platform'),indent=2)+'\n')
controls='''//go:build linux && agentmux_bootstrap_docker

package launcher

import (
 "bytes"
 "os"
 "path/filepath"
 "testing"

 "github.com/controlLogix/agentmux/platform/kernel/protocol"
 "github.com/controlLogix/agentmux/platform/runtime/protected"
)

// These inputs are owned regular files, not live process metadata.
func TestMidBootBoundedEnvironmentRegularFiles(t *testing.T) {
 dir:=t.TempDir()
 if raw,readErr,closeErr:=composeCLIMidBootBoundedEnvironment(filepath.Join(dir,"missing"));len(raw)!=0||readErr==nil||closeErr!=nil {t.Fatal("missing file must refuse without owned close")}
 scope:=protocol.Scope{InstanceID:"local_instance",ProfileID:"local_profile"}
 var roles [4]protected.RoleOptions
 names:=protocol.Roles()
 for i,role:=range names {roles[i]=protected.RoleOptions{Role:role,Environment:map[string]string{"AGENTMUX_INSTANCE_ID":scope.InstanceID,"AGENTMUX_PROFILE_ID":scope.ProfileID,"AGENTMUX_NATS_CREDS_FILE":filepath.Join(dir,role+".json")}}}
 // Use the existing pure contract fixture's field layout for the tuple.
 _=roles
 _=scope
 for _,size:=range []int{64*1024,64*1024+1,64*1024+32} {
  path:=filepath.Join(dir,"metadata")
  want:=bytes.Repeat([]byte{'x'},size)
  if os.WriteFile(path,want,0600)!=nil {t.Fatal("owned fixture write failed")}
  got,readErr,closeErr:=composeCLIMidBootBoundedEnvironment(path)
  expectedSize:=size;if expectedSize>64*1024+1 {expectedSize=64*1024+1}
  if readErr!=nil||closeErr!=nil||len(got)!=expectedSize||!bytes.Equal(got,want[:expectedSize]) {t.Fatal("read bound or close failed")}
  if size>64*1024 {if _,eligible:=composeCLIMidBootDeclaredMetadata(got,roles,scope);eligible {t.Fatal("oversized input must refuse")}}
 }
}
'''
# Draft controls are deliberately outside the compiled source until review.
(out/'reader-controls-draft.go').write_text(controls)
cmd=['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','test','-c','-tags','agentmux_bootstrap_docker','-o',str(out/'launcher.test'),'./launcher']
env=os.environ.copy();env.update({'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GOENV':'off','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'})
for key in ['AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']:env.pop(key,None)
inv={'argv':cmd,'cwd':str(out/'src/platform'),'environment':{k:env[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GOENV','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'compileOnly':True,'testBinaryExecuted':False,'draftControlsIncluded':False,'sourceCount':len(before),'candidatePins':pins,'startedUnix':time.time()}
(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');shutil.copyfile('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-midboot-bounded-compile.py',out/'run.py')
print(out,flush=True)
with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:r=subprocess.run(cmd,cwd=out/'src/platform',env=env,stdout=stdout,stderr=stderr)
inv.update({'endedUnix':time.time(),'directExit':r.returncode,'sharedSourceUnchanged':manifest(repo)==before,'candidatePinsUnchanged':all(digest(out/'src/platform/launcher'/n)==p for n,p in pins.items())});(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');(out/'exit.txt').write_text(str(r.returncode)+'\n');print('exit',r.returncode,flush=True)