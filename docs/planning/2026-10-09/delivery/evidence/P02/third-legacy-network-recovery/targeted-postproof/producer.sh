set -eu
out=$(mktemp -d /home/ryan/.cache/agentmux-governance/p02-third-legacy-post-XXXXXX)
printf '%s\n' "$out"
cp /mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-third-legacy-post.sh "$out/producer.sh"
mkdir "$out/src"
python3 - "$out" <<'PY'
from pathlib import Path
import sys,shutil,json,hashlib
out=Path(sys.argv[1]);basis=Path('/home/ryan/.cache/agentmux-governance/p02-third-legacy-rm-08Fe1w/src');sources={}
for p in basis.rglob('*'):
 if p.is_file() and not p.name.endswith('_test.go'):
  rel=p.relative_to(basis);target=out/'src'/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target);sources[str(rel)]=hashlib.sha256(p.read_bytes()).hexdigest()
(out/'sources.json').write_text(json.dumps(sources,indent=2)+'\n')
PY
cat > "$out/src/platform/launcher/exact_legacy_post_test.go" <<'GO'
package launcher
import("bytes";"context";"crypto/sha256";"encoding/json";"fmt";"net/url";"os";"path/filepath";"reflect";"strconv";"testing";"time";"github.com/controlLogix/agentmux/platform/kernel/protocol")
func TestExactRemovedNetworkRetainedBrokerPostProof(t *testing.T){
 const cid="066bd3c2cd6698d5a6eae5e650b71acd7ff0754c3f9871c343b30f558387c306";const nid="d6696c0a7b1e8bf34fc308b63c8162521f6c17d879aa700af554a699325ec621";const old="/home/ryan/.cache/agentmux-governance/p02-third-legacy-rm-08Fe1w";const root="/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3411499751"
 out:=os.Getenv("AMX_POST_OUTPUT");r:=map[string]any{"engineMutation":false,"networkId":nid,"containerId":cid,"qualified":false,"foreignFullPreservationClaim":false};var locks []*BootstrapLock
 write:=func(name string,b []byte){if os.WriteFile(filepath.Join(out,name),b,0600)!=nil{t.Fatal("private postproof archive failed")}}
 defer func(){failures:=0;for _,l:=range locks{if l.Close()!=nil{failures++}};r["actualLeasesReleased"]=len(locks);r["leaseCloseFailureCount"]=failures;b,_:=json.MarshalIndent(r,"","  ");write("postproof.json",append(b,'\n'))}()
 guard:=func(stage string,e error){r["stage"]=stage;if e!=nil{t.Fatal("fixed exact postproof stage failed")}}
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 h,e:=LoadEnrolledHostPolicy(HostPolicySelection{Path:filepath.Join(root,"installed/host-policy.json"),OwnerUID:uint32(os.Geteuid()),WorkspaceRoots:[]string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"}});guard("private_signed_enrollment",e);c,status,e:=h.Load();guard("private_full_admission",e);if status==nil{t.Fatal("actual owner missing")};p,e:=LoadProfile(c.ProfilePolicy);guard("profile",e);decl:=p.Declaration();sel,local:=p.LocalDocker();if !local||sel.EngineID!="e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c"{t.Fatal("exact selected engine refused")}
 ids:=[]string{sel.EngineID,"owner-status-service"};for _,role:=range protocol.Roles(){ids=append(ids,sel.EngineID+":runtime:"+role)};for _,id:=range ids{l,e:=AcquireBootstrapLock(ctx,decl.ProfileDirectory,decl.InstanceID,id);guard("actual_six_leases",e);locks=append(locks,l)};r["actualLeasesHeld"]=len(locks)
 d,e:=NewDocker(DockerConfig{Executable:sel.Executable,Context:sel.Context,Endpoint:sel.Endpoint,EngineID:sel.EngineID,Versions:DockerVersions{sel.ClientVersion,sel.ServerVersion,sel.ComposeVersion},Timeout:4*time.Second,Backend:sel.Backend});guard("actual_selected_driver",e);_,e=d.Inspect(ctx);guard("actual_engine",e)
 u,e:=url.Parse(decl.NATSEndpoint);guard("enrolled_endpoint",e);port,e:=strconv.Atoi(u.Port());guard("enrolled_port",e)
 b,e:=d.InspectOwnedTLSBroker(ctx,OwnershipPreflight{Project:decl.ComposeProject,InstanceID:decl.InstanceID,ProfileID:decl.ProfileID,ReleaseDigest:decl.ReleaseFingerprint,ConfigDigest:sha256.Sum256(c.Compose)},c.BrokerImage,port,c.BrokerConfigDigest,sha256.Sum256(c.LocalTLS.ServerCertificatePEM()),sha256.Sum256(c.LocalTLS.ServerKeyPEM()));guard("full_same_stopped_broker",e);if b.ContainerID!=cid||b.State!="stopped"{t.Fatal("exact stopped broker changed")};r["fullStoppedBrokerIdentityAccepted"]=true
 read:=func(stage string,args...string)[]byte{raw,e:=d.run(ctx,nil,args...);guard(stage,e);return raw}
 decode:=func(raw []byte)map[string]any{var rows []json.RawMessage;guard("private_full_array",json.Unmarshal(raw,&rows));if len(rows)!=1{t.Fatal("exact full object count refused")};var fields map[string]any;guard("closed_private_row",protocol.DecodeClosedJSON(rows[0],&fields,65536));decoder:=json.NewDecoder(bytes.NewReader(rows[0]));decoder.UseNumber();guard("precise_private_row",decoder.Decode(&fields));return fields}
 raw:=read("exact_full_container","container","inspect",cid);write("private-current-container.json",raw);current:=decode(raw);before,e:=os.ReadFile(filepath.Join(old,"private-container-before.json"));guard("archived_full_before",e);var rows []json.RawMessage;guard("archived_full_rows",json.Unmarshal(before,&rows));matched:=false;for _,row:=range rows{var header struct{ID string `json:"Id"`};guard("archived_row_id",json.Unmarshal(row,&header));if header.ID==cid{matched=reflect.DeepEqual(current,decode(append(append([]byte{'['},row...),']')))}};if !matched{t.Fatal("exact retained full container differs from before removal")};r["targetFullContainerMatchesBeforeRemoval"]=true
 networks,ok:=current["NetworkSettings"].(map[string]any);if !ok{t.Fatal("actual retained network settings missing")};relation,ok:=networks["Networks"].(map[string]any);if !ok||len(relation)!=1{t.Fatal("exact retained stopped relation changed")};entry,ok:=relation[decl.ComposeProject+"_default"].(map[string]any);if !ok||entry["NetworkID"]!=nid||entry["EndpointID"]!=""{t.Fatal("dangling stopped network reference changed")};r["danglingStoppedReferenceRetained"]=true
 volumeRaw:=read("exact_full_volume","volume","inspect",decl.ComposeProject+"_data");write("private-current-volume.json",volumeRaw);beforeVolume,e:=os.ReadFile(filepath.Join(old,"private-volume-before.json"));guard("archived_full_volume",e);if !reflect.DeepEqual(decode(volumeRaw),decode(beforeVolume)){t.Fatal("retained full volume differs from before removal")};r["fullVolumeMatchesBeforeRemoval"]=true
 roster:=read("actual_network_absence","network","ls","--quiet","--no-trunc");for _,id:=range bytes.Fields(roster){if string(id)==nid{t.Fatal("exact removed network reappeared")}};r["removedNetworkAbsent"]=true;r["networkCount"]=len(bytes.Fields(roster));r["qualified"]=true;r["stage"]="targeted_readonly_postproof_complete";r["currentContainerSHA256"]=fmt.Sprintf("%x",sha256.Sum256(raw));r["currentVolumeSHA256"]=fmt.Sprintf("%x",sha256.Sum256(volumeRaw))
}
GO
cd "$out/src/platform"
export GOPROXY=off GOSUMDB=off GOWORK=off GORACE=atexit_sleep_ms=0 AMX_POST_OUTPUT="$out"
GO=/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go
/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/gofmt -w launcher/exact_legacy_post_test.go
python3 - "$out" <<'PY'
import json,sys,datetime
from pathlib import Path
out=Path(sys.argv[1]);(out/'invocation.json').write_text(json.dumps({'argv':['go','test','-race','-count=1','-json','./launcher','-run','^TestExactRemovedNetworkRetainedBrokerPostProof$'],'environment':{'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GORACE':'atexit_sleep_ms=0','AMX_POST_OUTPUT':str(out)},'startedUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'engineMutations':0},indent=2)+'\n')
PY
set +e
"$GO" test -race -count=1 -json ./launcher -run '^TestExactRemovedNetworkRetainedBrokerPostProof$' > "$out/events.jsonl" 2> "$out/stderr.log"
code=$?
printf '%s\n' "$code" > "$out/exit.txt"
exit "$code"