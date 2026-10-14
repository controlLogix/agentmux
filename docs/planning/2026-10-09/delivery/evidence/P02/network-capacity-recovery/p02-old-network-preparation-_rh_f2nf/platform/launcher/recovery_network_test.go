package launcher
import("context";"crypto/sha256";"encoding/json";"fmt";"os";"path/filepath";"regexp";"testing";"time";"net/url";"strconv";"github.com/controlLogix/agentmux/platform/kernel/protocol")
var recoverySafeCode=regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
func recoveryCode(e error)string{if e==nil{return ""};s:=e.Error();if recoverySafeCode.MatchString(s){return s};return "closed_diagnostic_failure"}
func TestRecoveryNetworkPreparation(t *testing.T){
 out:=os.Getenv("RECOVERY_OUTPUT");if out==""{t.Fatal("diagnostic output missing")}
 candidates:=[]struct{directory,network,container string}{{"p02-bootstrap-private-445772231","7321bac5c2e346e5cb0eb98a76aab58b0f7a43261a4fe22bd9c423284e4b7ae4","389c32a884dd6999a8a098ad1a8babe1387d0fe07a34963ae4a44caea25e508a"},{"p02-bootstrap-private-2557942521","119efa115928b9ccca3ade12d02d829f192f4e0bd3fc2318da2a4288d448ab36","d4a83e1a6f24320889051f64c323a5d40d6fdcecb415f236d1964eedcf336695"}}
 for _,x:=range candidates{func(){
  r:=map[string]any{"directory":x.directory,"networkId":x.network,"containerId":x.container,"mutationExecuted":false,"startedAt":time.Now().UTC()};var locks []*BootstrapLock
  defer func(){var failures []string;for _,l:=range locks{if e:=l.Close();e!=nil{failures=append(failures,recoveryCode(e))}};r["leasesReleased"]=len(locks);r["leaseCloseErrors"]=failures;r["finishedAt"]=time.Now().UTC();raw,_:=json.MarshalIndent(r,"","  ");if os.WriteFile(filepath.Join(out,x.directory+".json"),append(raw,'\n'),0600)!=nil{t.Error("report write failed")};fmt.Println(x.directory,r["stage"],r["errorCode"])}()
  guard:=func(s string,e error)bool{r["stage"]=s;r["errorCode"]=recoveryCode(e);return e==nil}
  ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
  root:=filepath.Join("/home/ryan/.cache/agentmux-governance",x.directory)
  h,e:=LoadEnrolledHostPolicy(HostPolicySelection{Path:filepath.Join(root,"installed","host-policy.json"),OwnerUID:uint32(os.Geteuid()),WorkspaceRoots:[]string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"}});if !guard("host_policy_admission",e){return}
  c,owner,e:=h.Load();if !guard("private_admission",e){return};if owner==nil{guard("owner_admission",fmt.Errorf("owner_missing"));return}
  p,e:=LoadProfile(c.ProfilePolicy);if !guard("profile_admission",e){return};decl:=p.Declaration();sel,local:=p.LocalDocker();if !local{guard("local_selection",fmt.Errorf("local_missing"));return}
  r["profileId"]=decl.ProfileID;r["instanceId"]=decl.InstanceID;r["project"]=decl.ComposeProject;r["releaseDigest"]=decl.ReleaseFingerprint;r["composeDigest"]=fmt.Sprintf("sha256:%x",sha256.Sum256(c.Compose));r["configDigest"]=fmt.Sprintf("sha256:%x",c.BrokerConfigDigest);r["certificateDigest"]=fmt.Sprintf("sha256:%x",sha256.Sum256(c.LocalTLS.ServerCertificatePEM()));r["keyDigest"]=fmt.Sprintf("sha256:%x",sha256.Sum256(c.LocalTLS.ServerKeyPEM()))
  ids:=[]string{sel.EngineID};for _,role:=range protocol.Roles(){ids=append(ids,sel.EngineID+":runtime:"+role)};ids=append(ids,"owner-status-service")
  for _,id:=range ids{l,e:=AcquireBootstrapLock(ctx,decl.ProfileDirectory,decl.InstanceID,id);if !guard("actual_lease_acquisition",e){return};locks=append(locks,l)};r["leaseCountHeldDuringChecks"]=len(locks)
  d,e:=NewDocker(DockerConfig{Executable:sel.Executable,Context:sel.Context,Endpoint:sel.Endpoint,EngineID:sel.EngineID,Versions:DockerVersions{sel.ClientVersion,sel.ServerVersion,sel.ComposeVersion},Timeout:10*time.Second,Backend:sel.Backend});if !guard("selected_driver",e){return}
  engine,e:=d.Inspect(ctx);if !guard("selected_engine",e){return};r["engine"]=engine
  var network any;e=d.read(ctx,&network,"network","inspect",x.network,"--format",`{"Id":{{json .Id}},"Name":{{json .Name}},"Created":{{json .Created}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Internal":{{json .Internal}},"Attachable":{{json .Attachable}},"Ingress":{{json .Ingress}},"ConfigOnly":{{json .ConfigOnly}},"Containers":{{json .Containers}},"Labels":{{json .Labels}},"Options":{{json .Options}},"IPAM":{{json .IPAM}}}`);if !guard("exact_network_read",e){return};r["network"]=network
  var container any;e=d.read(ctx,&container,"container","inspect",x.container,"--format",`{"Id":{{json .Id}},"Created":{{json .Created}},"Name":{{json .Name}},"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}},"FinishedAt":{{json .State.FinishedAt}}},"Networks":{{json .NetworkSettings.Networks}}}`);if !guard("exact_container_relation_read",e){return};r["container"]=container
  var volume any;e=d.read(ctx,&volume,"volume","inspect",decl.ComposeProject+"_data","--format",`{"Name":{{json .Name}},"CreatedAt":{{json .CreatedAt}},"Driver":{{json .Driver}},"Labels":{{json .Labels}},"Options":{{json .Options}}}`);if !guard("exact_volume_read",e){return};r["volume"]=volume
  u,e:=url.Parse(decl.NATSEndpoint);if !guard("selected_endpoint",e){return};port,e:=strconv.Atoi(u.Port());if !guard("selected_port",e){return}
  broker,e:=d.InspectOwnedTLSBroker(ctx,OwnershipPreflight{Project:decl.ComposeProject,InstanceID:decl.InstanceID,ProfileID:decl.ProfileID,ReleaseDigest:decl.ReleaseFingerprint,ConfigDigest:sha256.Sum256(c.Compose)},c.BrokerImage,port,c.BrokerConfigDigest,sha256.Sum256(c.LocalTLS.ServerCertificatePEM()),sha256.Sum256(c.LocalTLS.ServerKeyPEM()));if !guard("full_owned_tls_broker",e){return};r["broker"]=broker
  if broker.ContainerID!=x.container||broker.State!="stopped"{guard("exact_stopped_guard",fmt.Errorf("exact_stopped_mismatch"));return};guard("all_admission_and_read_checks_completed",nil)
 }()}
}
