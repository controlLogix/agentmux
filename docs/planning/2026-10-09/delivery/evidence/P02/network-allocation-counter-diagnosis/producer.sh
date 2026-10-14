set -eu
out=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-retained-network-lifecycle-XXXXXX)
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-retained-lifecycle.sh "$out/producer.sh"
cp -a /home/ryan/.cache/agentmux-governance/p02-repaired-pending-real-nmnCXf/src "$out/src"
cat > "$out/src/platform/launcher/retained_network_lifecycle_test.go" <<'GO'
//go:build linux && agentmux_bootstrap_docker
package launcher
import("bytes";"context";"crypto/sha256";"encoding/json";"encoding/hex";"os";"path/filepath";"reflect";"sort";"strings";"testing";"time";"github.com/controlLogix/agentmux/platform/kernel/protocol")
func TestRetainedNetworkExactLifecycleDiagnostic(t *testing.T){
 if os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED")!="1"{t.Fatal("explicit lifecycle authorization missing")}
 selected,pin:=loadBootstrapFixtureSelection(t);driver,e:=NewDocker(selected.dockerConfig());if e!=nil{t.Fatal("actual selection refused")}
 root:="/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-2710354147";out:=os.Getenv("AMX_RETAINED_LIFECYCLE_OUTPUT")
 var creation struct {NetworkID string `json:"networkId"`;Name string `json:"name"`;Created string `json:"created"`;ContainerID string `json:"containerId"`;EndpointID string `json:"endpointId"`;ImmutableDigest string `json:"immutableDigest"`;BaselineExcluded bool `json:"baselineExcluded"`;Scope protocol.Scope `json:"scope"`}
 raw,e:=os.ReadFile(filepath.Join(root,"network-provenance.json"));if e!=nil||protocol.DecodeClosedJSON(raw,&creation,65536)!=nil||!fullID.MatchString(creation.NetworkID)||!fullID.MatchString(creation.ContainerID)||!strings.HasSuffix(creation.Name,"_default"){t.Fatal("actual creation pin refused")}
 workspace,e:=filepath.EvalSymlinks(selected.WorkspaceRoot);if e!=nil{t.Fatal("actual workspace refused")}
 h,e:=LoadEnrolledHostPolicy(HostPolicySelection{Path:filepath.Join(root,"installed/host-policy.json"),OwnerUID:uint32(os.Geteuid()),WorkspaceRoots:[]string{workspace}});if e!=nil{t.Fatal("actual retained enrollment refused")}
 c,_,e:=h.Load();if e!=nil{t.Fatal("actual private config refused")};loaded,e:=LoadProfile(c.ProfilePolicy);if e!=nil{t.Fatal("actual profile refused")};profile:=loaded.Declaration()
 body,e:=hex.DecodeString(strings.TrimPrefix(profile.ConfigDigest,"sha256:"));if e!=nil||len(body)!=32{t.Fatal("config pin refused")};var digest [32]byte;copy(digest[:],body)
 owner:=OwnershipPreflight{Project:strings.TrimSuffix(creation.Name,"_default"),InstanceID:profile.InstanceID,ProfileID:profile.ProfileID,ReleaseDigest:profile.ReleaseFingerprint,ConfigDigest:digest,LockHeld:true}
 f:=&bootstrapDockerFixture{Driver:driver,Profile:profile,Config:c,Owner:owner,Project:owner.Project,EvidenceDirectory:out,ownedIDs:map[string]bool{}}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 rows:=map[string]any{"selectionPin":pin,"networkId":creation.NetworkID,"containerId":creation.ContainerID,"newResourcesAllowed":false,"networkRemovalAllowed":false,"onlyBrokerLifecycle":true,"stoppedAtEnd":false}
 write:=func(name string,value any){b,e:=json.MarshalIndent(value,"","  ");if e!=nil||os.WriteFile(filepath.Join(out,name),append(b,'\n'),0600)!=nil{t.Fatal("private diagnostic archive failed")}}
 defer func(){write("lifecycle.json",rows)}()
 ids:=append([]string{profile.Docker.EngineID,"owner-status-service"},bootstrapFixtureRoleLeaseIDs(profile.Docker.EngineID)...)
 var leases []*BootstrapLock
 defer func(){for _,lease:=range leases{if lease.Close()!=nil{t.Error("exact lifecycle lease close failed")}}}()
 for _,id:=range ids{lease,e:=AcquireBootstrapLock(ctx,profile.ProfileDirectory,profile.InstanceID,id);if e!=nil{t.Fatal("actual lifecycle lease unavailable")};leases=append(leases,lease)}
 rows["actualLeaseCount"]=len(leases)
 inspect:=func() OwnedBroker{port,e:=urlPort(profile.NATSEndpoint);if e!=nil{t.Fatal("actual port refused")};b,e:=driver.InspectOwnedTLSBroker(ctx,owner,c.BrokerImage,port,c.BrokerConfigDigest,sha256.Sum256(c.LocalTLS.ServerCertificatePEM()),sha256.Sum256(c.LocalTLS.ServerKeyPEM()));if e!=nil||b.ContainerID!=creation.ContainerID{t.Fatal("full exact broker identity unavailable")};return b}
 broker:=inspect();if broker.State!="stopped"{t.Fatal("retained broker no longer stopped")}
 beforeVolume,e:=f.volume(ctx);if e!=nil{t.Fatal("exact retained volume unavailable")}
 originalContainers,e:=f.inventory(ctx);if e!=nil{t.Fatal("complete original container baseline unavailable")}
 originalNetworks,e:=f.networkInventory(ctx);if e!=nil{t.Fatal("complete original network baseline unavailable")}
 n:=originalNetworks[creation.NetworkID];if n.ID!=creation.NetworkID||n.Name!=creation.Name||n.Created!=creation.Created||!owner.matches(n.Labels){t.Fatal("exact current network identity refused")}
 archive:=func(phase string)map[string]string{
  raw,e:=driver.run(ctx,nil,"network","inspect",creation.NetworkID);if e!=nil{t.Fatal("exact lifecycle network read failed")}
  networks,e:=decodeBootstrapNetworks(raw,[]string{creation.NetworkID});if e!=nil{t.Fatal("exact lifecycle projection refused")}
  current:=networks[creation.NetworkID];if current.ID!=n.ID||current.Name!=n.Name||current.Created!=n.Created||!owner.matches(current.Labels){t.Fatal("lifecycle network identity drift")}
  if os.WriteFile(filepath.Join(out,"private-network-"+phase+".json"),raw,0600)!=nil{t.Fatal("private full projection archive failed")}
  dec:=json.NewDecoder(bytes.NewReader(raw));dec.UseNumber();var values []map[string]any;if dec.Decode(&values)!=nil||len(values)!=1{t.Fatal("exact precise projection failed")}
  hashes:=map[string]string{};for key,value:=range values[0]{b,e:=json.Marshal(value);if e!=nil{t.Fatal("precise field hash failed")};hashes[key]=releaseDigest(b)}
  write("field-hashes-"+phase+".json",hashes);write("network-"+phase+"-identity.json",map[string]any{"id":current.ID,"created":current.Created,"immutableDigest":current.ImmutableDigest,"endpointCount":len(current.Endpoints)});return hashes
 }
 before:=archive("before")
 if _,e=driver.Inspect(ctx);e!=nil{t.Fatal("actual engine revalidation failed")}
 start,e:=driver.run(ctx,nil,"container","start",creation.ContainerID);rows["literalStartCode"]=bootstrapFixtureFailureCode(e);rows["literalStartReturnedExactId"]=string(bytes.TrimSpace(start))==creation.ContainerID
 // A command error never authorizes guessing or a blind second mutation.
 broker=inspect();if broker.State!="running"{t.Fatal("exact broker did not become running")}
 // Register only the exact admitted broker stop after fresh running identity.
 defer func(){
  if rows["stoppedAtEnd"]==true{return}
  fresh:=inspect();if fresh.State=="running"{if driver.StopOwned(ctx,owner,creation.ContainerID)!=nil{t.Error("exact diagnostic broker stop failed");return}}
  fresh=inspect();rows["stoppedAtEnd"]=fresh.State=="stopped"
 }()
 if e!=nil||string(bytes.TrimSpace(start))!=creation.ContainerID{t.Fatal("literal start outcome failed exact result control")}
 running:=archive("running")
 attachments,e:=f.networkAttachments(ctx,creation.ContainerID);if e!=nil||len(attachments)!=1||attachments[creation.Name].NetworkID!=creation.NetworkID||!fullID.MatchString(attachments[creation.Name].EndpointID){t.Fatal("actual running reciprocal attachment refused")}
 rows["sameRunningBrokerQualified"]=true
 if driver.StopOwned(ctx,owner,creation.ContainerID)!=nil{t.Fatal("exact lifecycle broker stop failed")}
 broker=inspect();if broker.State!="stopped"{t.Fatal("same exact broker stopped state unavailable")};rows["stoppedAtEnd"]=true
 stopped:=archive("stopped")
 changed:=[]string{};for key,value:=range running{if stopped[key]!=value{changed=append(changed,key)}};for key:=range stopped{if _,ok:=running[key];!ok{changed=append(changed,key)}};sort.Strings(changed);rows["changedRunningToStoppedFields"]=changed;rows["beforeProjectionRestored"]=reflect.DeepEqual(before,stopped)
 afterVolume,e:=f.volume(ctx);if e!=nil||!reflect.DeepEqual(beforeVolume,afterVolume){t.Fatal("retained volume changed")};rows["sameVolumeRetained"]=true
 afterContainers,e:=f.inventory(ctx);if e!=nil{t.Fatal("complete after container roster unavailable")};afterNetworks,e:=f.networkInventory(ctx);if e!=nil{t.Fatal("complete after network roster unavailable")}
 rows["completeContainerBaselineUnchanged"]=reflect.DeepEqual(originalContainers,afterContainers);rows["completeNetworkBaselineUnchanged"]=reflect.DeepEqual(originalNetworks,afterNetworks)
 if rows["completeContainerBaselineUnchanged"]!=true||rows["completeNetworkBaselineUnchanged"]!=true{t.Fatal("complete lifecycle baseline changed")}
 write("private-volume-before.json",beforeVolume);write("private-volume-after.json",afterVolume)
}
GO
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_BOOTSTRAP_DOCKER_AUTHORIZED=1
export AMX_RETAINED_LIFECYCLE_OUTPUT="$out"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt -w launcher/retained_network_lifecycle_test.go
python3 - "$out" <<'PY'
import json,sys,datetime
from pathlib import Path
out=Path(sys.argv[1]);(out/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','-tags=agentmux_bootstrap_docker','./launcher','-run','^TestRetainedNetworkExactLifecycleDiagnostic$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'1','AMX_RETAINED_LIFECYCLE_OUTPUT':str(out)},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'allowedMutations':['literal container start exact archived fullCID','StopOwned same fullCID under six actual leases'],'forbiddenMutations':['creation','detach','removal','pull','settings','role/host launch']},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json -tags=agentmux_bootstrap_docker ./launcher -run '^TestRetainedNetworkExactLifecycleDiagnostic$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"