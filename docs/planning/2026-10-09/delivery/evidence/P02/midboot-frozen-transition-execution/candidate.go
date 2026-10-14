//go:build linux && agentmux_bootstrap_docker

package launcher

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "bytes"
 "os"
 "path/filepath"
 "reflect"
 "strings"
 "testing"
 "time"

 "github.com/controlLogix/agentmux/platform/deployment"
 "github.com/controlLogix/agentmux/platform/kernel/protocol"
 "golang.org/x/sys/unix"
)

// The pause is an explicit disposable failure-injection control on the exact
// creator-held host. Actual signed children and NATS evidence qualify the phase;
// a scheduling miss fails instead of treating a ready host as mid-boot.
func TestInstalledCLIRealComposeMidBootCreatorCrash(t *testing.T) {
 f := newBootstrapDockerFixtureWithHost(t, true)
 s, r := composeCLIPolicy(t, f)
 expectedMembers:=map[string]string{}
 for _,role:=range protocol.Roles(){member,e:=os.ReadFile(filepath.Join(f.HostPolicy.ExternalRelease.PackageDirectory,"bin",role));if e!=nil||len(member)==0||len(member)>128*1024*1024{t.Fatal("mid-boot expected signed member unavailable")};expectedMembers[role]=releaseDigest(member)}
 ctx, cancel := context.WithTimeout(context.Background(), time.Second)
 gate, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, f.Profile.Docker.EngineID)
 cancel()
 if err != nil { t.Fatal("mid-boot actual arbitration gate unavailable") }
 defer func() { if gate != nil && gate.Close() != nil { f.RetainForRecovery(t); t.Error("mid-boot gate cleanup failed") } }()
 owner := f.Owner
 owner.LockHeld = true
 ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
 err = f.Driver.StartOwned(ctx, owner, f.Config.Compose)
 cancel()
 if err != nil { t.Fatal("mid-boot exact broker start failed") }
 original := composeCLIStart(t, f, s, r, "ensure")
 original.mustOwnHost = true
 paused := false
 // Register resume before pausing. LIFO cleanup resumes the exact live host
 // before the existing creator-owned stop/join cleanup can run on any refusal.
 t.Cleanup(func() {
  if paused && original.hostFD >= 0 {
   if unix.PidfdSendSignal(original.hostFD, unix.SIGCONT, nil, 0) != nil {
    f.RetainForRecovery(t)
    t.Error("mid-boot exact paused-host resume refused")
   }
  }
 })
 startupDeadline := original.started.Add(f.Config.StartupTimeout)
 entryRaw := composeCLIWait(t, f, original, s, r, "midboot-entry")
 f.WriteEvidence(t,"midboot-entry-creator-expected.json",map[string]any{"source":"Actual creating frontend child arguments and admitted runtime image","coldInvocationId":original.hostAttempt,"runtimeDigest":r.RuntimeExecutable.Digest,"scope":f.Config.Kernel.Scope,"enrollmentDigest":releaseDigest(mustStatusJSON(f.BridgeEnrollment.Owner)),"creatorHandlePinned":original.hostFD>=0})
 out := composeCLIObservation(t, f, original, r, entryRaw, "midboot-entry", true)
 // A validated creator receipt remains historical. Only the actual owner
 // response can authorize releasing the gate into the partial-start phase.
 out = composeCLIMidBootAwaitStarting(t, f, original, out, startupDeadline)
 f.WriteEvidence(t, "midboot-authenticated-entry.json", out)
 entryPoll:=[]unix.PollFd{{Fd:int32(original.hostFD),Events:unix.POLLIN}};entryExited,entryPollError:=unix.Poll(entryPoll,0)
 if time.Now().After(startupDeadline)||entryPollError!=nil||entryExited!=0 {t.Fatal("midboot_original_creator_or_deadline_changed_before_gate_release")}
 if gate.Close() != nil { t.Fatal("mid-boot arbitration gate release failed") }
 gate = nil
 // A child observation is only a synchronization trigger. It grants no
 // process authority; this diagnostic pauses only our original creator fd.
 var triggerPIDs []int
 for len(triggerPIDs)==0 {
  triggerPIDs=installedCLIChildren(original.hostPID)
  if len(triggerPIDs)>0 {break}
  if time.Now().After(startupDeadline) {t.Fatal("midboot_child_trigger_deadline")}
  poll:=[]unix.PollFd{{Fd:int32(original.hostFD),Events:unix.POLLIN}}
  if n,e:=unix.Poll(poll,0);e!=nil||n!=0 {t.Fatal("midboot_creator_exited_before_child_trigger")}
  time.Sleep(time.Millisecond)
 }
 triggerPoll:=[]unix.PollFd{{Fd:int32(original.hostFD),Events:unix.POLLIN}};triggerExited,triggerError:=unix.Poll(triggerPoll,0)
 if time.Now().After(startupDeadline)||triggerError!=nil||triggerExited!=0 {t.Fatal("midboot_original_creator_or_deadline_changed_before_pause")}
 // No child PID is signaled. Only the original creator-proven host descriptor
 // grants this explicit disposable pause injection.
 if unix.PidfdSendSignal(original.hostFD, unix.SIGSTOP, nil, 0) != nil { t.Fatal("mid-boot exact creator pause refused") }
 paused = true
 // SIGSTOP delivery must be observed before the partial-child roster is used.
 for {
  status, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", original.hostPID))
  if e != nil { t.Fatal("mid-boot exact paused-host state unavailable") }
  if strings.Contains(string(status), "State:\tT (stopped)") { break }
  if time.Now().After(startupDeadline) { t.Fatal("mid-boot pause exceeded original startup budget") }
  time.Sleep(time.Millisecond)
 }
 f.WriteEvidence(t,"midboot-observed-child-trigger.json",map[string]any{"observedDirectChildCount":len(triggerPIDs),"phaseQualified":false,"signalAuthority":"Original creator-owned host pidfd only"})
 roles, partialPIDs := composeCLIWaitFrozenMidBootRoles(t, f, original, triggerPIDs, expectedMembers, startupDeadline)
 phaseContext, phaseCancel := context.WithDeadline(context.Background(), startupDeadline)
 defer phaseCancel()
 ctx, cancel = context.WithTimeout(phaseContext, 500*time.Millisecond)
 kernel, observeErr := ObserveKernel(ctx, f.Config.Kernel)
 cancel()
 if observeErr != nil && observeErr.Error() != "kernel_status_unavailable" { t.Fatal("mid-boot actual kernel authority refused") }
 if observeErr == nil && kernel.KernelReadiness == "ready" { t.Fatal("mid-boot actual kernel is already ready") }
 // The actual startup exclusion is still held by this paused host. A negative
 // acquisition proves exclusion; it does not grant signal or recovery authority.
 ctx, cancel = context.WithTimeout(phaseContext, 80*time.Millisecond)
 unexpected, exclusionErr := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, f.Profile.Docker.EngineID)
 cancel()
 if unexpected != nil { unexpected.Close(); t.Fatal("mid-boot startup exclusion was not retained") }
 var waitingError *StartingElsewhereError
 if !errors.As(exclusionErr, &waitingError) || !errors.Is(exclusionErr, context.DeadlineExceeded) || phaseContext.Err()!=nil { t.Fatal("mid-boot startup exclusion unproven") }
 ctx, cancel = context.WithDeadline(phaseContext, startupDeadline)
 broker, brokerErr := f.ObserveBroker(ctx)
 cancel()
 if brokerErr != nil || broker.State!="running" { t.Fatal("mid-boot exact running broker unavailable") }
 ctx, cancel = context.WithDeadline(phaseContext, startupDeadline)
 volume, volumeErr := f.volume(ctx)
 cancel()
 if volumeErr != nil { t.Fatal("mid-boot exact volume unavailable") }
 ctx, cancel = context.WithTimeout(phaseContext, 5*time.Second)
 record, recordErr := deployment.Observe(ctx, deployment.ObserveOptions{ProbeOptions: f.Config.Health, ReadExistingRecord: true})
 cancel()
 if recordErr != nil || record.RecordSequence == 0 || !digest.MatchString(record.RecordDigest) { t.Fatal("mid-boot actual provisioned record unavailable") }
 savedRecord := record.RecordDigest
 beforeContainers, baselineErr := f.inventory(phaseContext)
 beforeNetworks, networkErr := f.networkInventory(phaseContext)
 if baselineErr != nil || networkErr != nil { t.Fatal("mid-boot foreign inventory unavailable within original deadline") }
 // Exclude only the freshly fully inspected current broker and its original
 // exclusive creation-pinned network; names or labels alone grant no exclusion.
 currentBroker, brokerErr := f.ObserveBroker(phaseContext)
 if brokerErr != nil || currentBroker.State!="running" || currentBroker.ContainerID!=broker.ContainerID || beforeContainers[currentBroker.ContainerID].ID!=currentBroker.ContainerID || f.baseline[currentBroker.ContainerID].ID!="" { t.Fatal("mid-boot exact created broker exclusion unqualified") }
 f.mu.Lock()
 creationPin:=f.networkProvenance
 f.mu.Unlock()
 if creationPin==nil || creationPin.containerID!=currentBroker.ContainerID { t.Fatal("mid-boot original network creation pin unavailable") }
 attachments, attachmentErr:=f.networkAttachments(phaseContext,currentBroker.ContainerID)
 actualNetwork, networkErr:=f.networkByID(phaseContext,creationPin.network.ID)
 if attachmentErr!=nil || networkErr!=nil || !validBootstrapNetworkCreation(f.networkBaseline,f.Owner,currentBroker.ContainerID,actualNetwork,attachments) || !sameBootstrapNetworkIdentity(creationPin.network,actualNetwork) || !validBootstrapCounterTransition(creationPin.network,actualNetwork,currentBroker.ContainerID) || actualNetwork.Endpoints[currentBroker.ContainerID]!=creationPin.endpointID || beforeNetworks[actualNetwork.ID].Digest!=actualNetwork.Digest { t.Fatal("mid-boot exact created network exclusion unqualified") }
 delete(beforeContainers,currentBroker.ContainerID)
 delete(beforeNetworks,actualNetwork.ID)
 if !reflect.DeepEqual(f.baseline,beforeContainers) || !sameBootstrapNetworkBaseline(f.networkBaseline,beforeNetworks) { t.Fatal("mid-boot every foreign baseline entry must remain unchanged") }
 f.WriteEvidence(t, "midboot-before-crash.json", map[string]any{"authenticStarting": true, "exactHostPaused": true, "actualStartedRoles": roles, "actualReady": false, "startupLeaseHeld": true, "recordSequence": record.RecordSequence})
 // A second actual terminal requests status while the admitted creator is
 // paused mid-boot. It must fail within the unchanged five-second status budget
 // without spawning another host, claiming readiness or leaking unknown output.
 waiting := composeCLIStart(t, f, s, r, "status")
 waiting.captureName = "midboot-waiting"
 select {
 case result := <-waiting.done:
  waiting.joined = true
  composeCLICaptureJoined(t, f, waiting)
  f.WriteEvidence(t, "midboot-waiting-joined-diagnostic.json", composeCLIJoinedDiagnostic(waiting, result))
  elapsed := result.at.Sub(waiting.started)
  var diagnostic RequestDiagnostic
  if result.err == nil || elapsed > 5*time.Second || waiting.hostFD >= 0 || waiting.stdout.Len()!=0 || protocol.DecodeClosedJSON(waiting.stderr.Bytes(), &diagnostic, 16*1024)!=nil || !ValidRequestDiagnostic(diagnostic) || diagnostic.Code!="request_deadline" {
   t.Fatal("mid-boot waiting terminal lacks bounded fixed failure")
  }
  f.WriteEvidence(t, "midboot-waiting.json", map[string]any{"boundNanoseconds":int64(5*time.Second), "elapsedNanoseconds":elapsed.Nanoseconds(), "nonzeroExit":true, "diagnostic":diagnostic, "stdoutBytes":0, "newHostSpawned":false})
 case <-time.After(time.Until(waiting.started.Add(5*time.Second))):
  f.RetainForRecovery(t)
  t.Fatal("mid-boot waiting terminal exceeded original status budget")
 }
 if phaseContext.Err()!=nil || time.Now().After(startupDeadline) { t.Fatal("mid-boot phase qualification exceeded original startup budget") }
 composeCLIRevalidateMidBootRoles(t, f, original, partialPIDs, roles, expectedMembers)
 if phaseContext.Err()!=nil || time.Now().After(startupDeadline) { t.Fatal("mid-boot final identity revalidation exceeded original startup budget") }
 killedAt := time.Now()
 if unix.PidfdSendSignal(original.hostFD, unix.SIGKILL, nil, 0) != nil { t.Fatal("mid-boot exact creator crash refused") }
 paused = false
 shutdownDeadline := killedAt.Add(f.Config.Deadlines.StopGrace + f.Config.Deadlines.ReapTimeout)
 for _, fd := range append([]int{original.hostFD}, original.roleFDs...) {
  remaining := time.Until(shutdownDeadline)
  if remaining <= 0 { f.RetainForRecovery(t); t.Fatal("mid-boot shared shutdown budget expired") }
  poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
  if n, e := unix.Poll(poll, int(remaining/time.Millisecond)); e != nil || n != 1 {
   f.RetainForRecovery(t); t.Fatal("mid-boot exact descendant did not exit after parent lifetime EOF")
  }
 }
 // All exclusions are reacquired within the SAME shutdown deadline. Hold each
 // acquired lock until the complete set has been proved, then close exact owners.
 leaseIDs := append([]string{f.Profile.Docker.EngineID}, bootstrapFixtureRoleLeaseIDs(f.Profile.Docker.EngineID)...)
 leaseIDs = append(leaseIDs, "owner-status-service")
 held := []*BootstrapLock{}
 defer func() { for _, lease := range held { lease.Close() } }()
 for _, id := range leaseIDs {
  ctx, cancel = context.WithDeadline(context.Background(), shutdownDeadline)
  lease, e := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, id)
  cancel()
  if e != nil { f.RetainForRecovery(t); t.Fatal("mid-boot actual exclusion did not release within shared budget") }
  held = append(held, lease)
 }
 for _, lease := range held { if lease.Close() != nil { f.RetainForRecovery(t); t.Fatal("mid-boot released exclusion close failed") } }
 held = nil
 f.WriteEvidence(t, "midboot-crash-exit.json", map[string]any{"injection": "SIGKILL to the held creator-proven host pidfd only", "exactHostExited": true, "exactStartedRoleExitCount": len(original.roleFDs), "sixExclusionsReleased": true, "sharedShutdownBudgetNanoseconds": int64(f.Config.Deadlines.StopGrace+f.Config.Deadlines.ReapTimeout), "elapsedNanoseconds": time.Since(killedAt).Nanoseconds()})
 recovered := composeCLIStart(t, f, s, r, "ensure")
 recovered.mustOwnHost = true
 composeCLIObservation(t, f, recovered, r, composeCLIWait(t, f, recovered, s, r, "midboot-recovery"), "midboot-recovery", true)
 f.WriteEvidence(t, "midboot-recovery-status.json", composeCLIRefresh(t, f, recovered.started.Add(f.Config.StartupTimeout)))
 composeCLIPinRoles(t, f, recovered)
 if recovered.hostAttempt == original.hostAttempt || recovered.hostPID == original.hostPID { t.Fatal("mid-boot recovery reused dead creator") }
 ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
 afterVolume, err := f.volume(ctx)
 cancel()
 if err != nil || !reflect.DeepEqual(volume, afterVolume) || bootstrapFixtureBroker(t, f).ContainerID != broker.ContainerID || "sha256:"+bootstrapFixtureRecord(t, f.Config, record.RecordSequence) != savedRecord {
  t.Fatal("mid-boot recovery changed broker, volume or original record")
 }
 bootstrapFixtureRoleLeases(t, f, true)
 f.AssertBaselineUnchanged(t)
 f.WriteEvidence(t, "midboot-recovery-preservation.json", map[string]any{"newCreatorProvenHost": true, "newActualFourRoleAssembly": len(recovered.roleFDs)==4, "sameBroker": true, "sameVolume": true, "originalRecordRetained": true, "foreignBaselinePreserved": true})
}

func composeCLIPinPartialMidBootRoles(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront, expected map[string]string, candidate *composeCLIMidBootCandidate) ([]string, []int) {
 t.Helper()
 seen := map[string]bool{}
 pids := installedCLIChildren(x.hostPID)
 for i,pid:=range pids{if pid==candidate.pid{pids[0],pids[i]=pids[i],pids[0];break}}
 for _, pid := range pids {
  fd:=candidate.fd
  if pid!=candidate.pid{var e error;fd,e=unix.PidfdOpen(pid,0);if e!=nil{t.Fatal("mid-boot creator child descriptor unavailable")};x.roleFDs=append(x.roleFDs,fd)}
  image, ie := os.ReadFile(fmt.Sprintf("/proc/%d/exe", pid))
  status, se := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
  env, ee := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
  args, ae := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
  role := ""
  for _, candidate := range protocol.Roles() {
   for _, item := range strings.Split(string(env), "\x00") {
    if item == "AGENTMUX_NATS_CREDS_FILE="+filepath.Join(f.Profile.ProfileDirectory, candidate+".json") { role = candidate }
   }
  }
  poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
  n, pe := unix.Poll(poll, 0)
  predicates:=map[string]bool{"imageReadable":ie==nil,"executedImageMatches":ie==nil&&expected[role]!=""&&releaseDigest(image)==expected[role],"statusReadable":se==nil,"credentialsReadable":ee==nil,"argumentsReadable":ae==nil,"liveDescriptor":pe==nil&&n==0,"credentialBoundRole":role!="","distinctRole":!seen[role],"parentMatches":strings.Contains(string(status),fmt.Sprintf("PPid:\t%d\n",x.hostPID)),"noArguments":len(strings.Split(strings.TrimSuffix(string(args),"\x00"),"\x00"))==1}
  f.WriteEvidence(t,"midboot-role-predicate-"+bootstrapFixtureRandom(t,4)+".json",map[string]any{"stage":"frozen_role_admission","predicates":predicates,"admittedRoleCount":len(seen)})
  if ie != nil || se != nil || ee != nil || ae != nil || pe != nil || n != 0 || role == "" || seen[role] || !strings.Contains(string(status), fmt.Sprintf("PPid:\t%d\n", x.hostPID)) || len(strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")) != 1 {
   t.Fatal("mid-boot actual creator child identity refused")
  }
  if expected[role]==""||expected[role]!=releaseDigest(image){t.Fatal("mid-boot actual child image mismatch")}
  seen[role] = true
 }
 if len(seen)==0 || len(seen)>=len(protocol.Roles()) { t.Fatal("mid-boot partial-start boundary was missed") }
 roles := []string{}
 for _, role := range protocol.Roles() { if seen[role] { roles=append(roles,role) } }
 return roles, pids
}

// The paused creator cannot fork another role. Recheck the same direct-child
// roster, each previously held live pidfd and actual image/credential binding
// after every fallible read and immediately before the crash injection.
func composeCLIRevalidateMidBootRoles(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront, pids []int, roles []string, expected map[string]string) {
 t.Helper()
 hostState, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", x.hostPID))
 if e!=nil || !strings.Contains(string(hostState), "State:\tT (stopped)") || !composeCLIMidBootSamePIDs(pids, installedCLIChildren(x.hostPID)) || len(pids)!=len(x.roleFDs) { t.Fatal("mid-boot phase changed before crash") }
 seen := map[string]bool{}
 for i,pid := range pids {
  role,predicates:=composeCLIMidBootRevalidationPredicates(f,x,pid,x.roleFDs[i],roles,expected)
  if role=="" || seen[role] || !predicates["liveDescriptor"] || !predicates["executedImageMatches"] || !predicates["parentMatches"] || !predicates["noArguments"] { t.Fatal("mid-boot original child binding changed before crash") }
  seen[role]=true
 }
 if len(seen)!=len(roles) { t.Fatal("mid-boot original role roster changed before crash") }
}

// Candidate observation is not adoption. The descriptor is retained only after
// direct creator ancestry, fixed credential binding, no-argument entrypoint,
// live pidfd and actual executed member digest all agree.
type composeCLIMidBootCandidate struct{pid,fd int;role string}
func composeCLIDiscoverExecutedMidBootRole(t *testing.T,f *bootstrapDockerFixture,x *composeCLIFront,expected map[string]string)(*composeCLIMidBootCandidate,map[string]bool){
 last:=map[string]bool{"anyDirectChild":false,"credentialBoundRole":false,"parentMatches":false,"noArguments":false,"liveDescriptor":false,"executedImageMatches":false}
 inspect:=func(pid int)(candidate *composeCLIMidBootCandidate,predicates map[string]bool){
  predicates=map[string]bool{"anyDirectChild":true,"descriptorAcquired":false,"credentialBoundRole":false,"parentMatches":false,"noArguments":false,"liveDescriptor":false,"executedImageMatches":false}
  fd,e:=unix.PidfdOpen(pid,0);if e!=nil{return nil,predicates};predicates["descriptorAcquired"]=true
  keep:=false
  defer func(){if !keep&&unix.Close(fd)!=nil{f.RetainForRecovery(t);t.Fatal("mid-boot candidate descriptor close refused")}}()
  // All authority observations occur while this exact process descriptor is
  // held. A reused numeric PID cannot qualify if the original descriptor exits.
  env,ee:=os.ReadFile(fmt.Sprintf("/proc/%d/environ",pid));role:=""
  for _,name:=range protocol.Roles(){for _,item:=range strings.Split(string(env),"\x00"){if item=="AGENTMUX_NATS_CREDS_FILE="+filepath.Join(f.Profile.ProfileDirectory,name+".json"){role=name}}}
  predicates["credentialBoundRole"]=ee==nil&&role!="";if !predicates["credentialBoundRole"]{return nil,predicates}
  status,se:=os.ReadFile(fmt.Sprintf("/proc/%d/status",pid));args,ae:=os.ReadFile(fmt.Sprintf("/proc/%d/cmdline",pid))
  predicates["parentMatches"]=se==nil&&strings.Contains(string(status),fmt.Sprintf("PPid:\t%d\n",x.hostPID));predicates["noArguments"]=ae==nil&&len(strings.Split(strings.TrimSuffix(string(args),"\x00"),"\x00"))==1
  image,ie:=os.ReadFile(fmt.Sprintf("/proc/%d/exe",pid));predicates["executedImageMatches"]=ie==nil&&expected[role]!=""&&releaseDigest(image)==expected[role]
  // Check the SAME held descriptor after the final executable read.
  poll:=[]unix.PollFd{{Fd:int32(fd),Events:unix.POLLIN}};n,pe:=unix.Poll(poll,0);predicates["liveDescriptor"]=pe==nil&&n==0
  if predicates["parentMatches"]&&predicates["noArguments"]&&predicates["executedImageMatches"]&&predicates["liveDescriptor"]{keep=true;return &composeCLIMidBootCandidate{pid,fd,role},predicates}
  return nil,predicates
 }
 for _,pid:=range installedCLIChildren(x.hostPID){candidate,predicates:=inspect(pid);last=predicates;if candidate!=nil{return candidate,predicates}}
 return nil,last
}

func composeCLIMidBootSamePIDs(a,b []int)bool{if len(a)!=len(b){return false};seen:=map[int]bool{};for _,pid:=range a{if seen[pid]{return false};seen[pid]=true};for _,pid:=range b{if !seen[pid]{return false};delete(seen,pid)};return len(seen)==0}

// Final role revalidation holds the original descriptor throughout every read
// and checks that same descriptor only after the last authority observation.
func composeCLIMidBootRevalidationPredicates(f *bootstrapDockerFixture,x *composeCLIFront,pid,fd int,roles []string,expected map[string]string)(string,map[string]bool){
 image,ie:=os.ReadFile(fmt.Sprintf("/proc/%d/exe",pid))
 status,se:=os.ReadFile(fmt.Sprintf("/proc/%d/status",pid))
 env,ee:=os.ReadFile(fmt.Sprintf("/proc/%d/environ",pid))
 args,ae:=os.ReadFile(fmt.Sprintf("/proc/%d/cmdline",pid))
 role:=""
 if ee==nil { for _,name:=range roles { for _,item:=range strings.Split(string(env),"\x00") { if item=="AGENTMUX_NATS_CREDS_FILE="+filepath.Join(f.Profile.ProfileDirectory,name+".json") { role=name } } } }
 predicates:=map[string]bool{"credentialBoundRole":role!="","executedImageMatches":ie==nil&&expected[role]!=""&&releaseDigest(image)==expected[role],"parentMatches":se==nil&&strings.Contains(string(status),fmt.Sprintf("PPid:\t%d\n",x.hostPID)),"noArguments":ae==nil&&len(strings.Split(strings.TrimSuffix(string(args),"\x00"),"\x00"))==1}
 poll:=[]unix.PollFd{{Fd:int32(fd),Events:unix.POLLIN}};n,pe:=unix.Poll(poll,0);predicates["liveDescriptor"]=pe==nil&&n==0
 return role,predicates
}

func composeCLIMidBootStartingCode(out *StartupStatusObservation,attempt string)string{
 if out==nil {return "midboot_authenticated_starting_missing"}
 if out.Disposition!="starting" {return "midboot_starting_phase_missed"}
 if out.StartupAttemptID==nil||*out.StartupAttemptID!=attempt {return "midboot_starting_attempt_mismatch"}
 if !bridgeStartingUnknown(*out) {return "midboot_starting_readiness_overclaimed"}
 return ""
}

// The caller retains the original creator and real arbitration gate. These
// status reads cannot create another owner, and each uses the original startup
// deadline. A receipt never satisfies this current authenticated status gate.
func composeCLIMidBootAwaitStarting(t *testing.T,f *bootstrapDockerFixture,x *composeCLIFront,initial *StartupStatusObservation,deadline time.Time)*StartupStatusObservation{
 t.Helper()
 phase,cancel:=context.WithDeadline(context.Background(),deadline);defer cancel()
 if initial!=nil {if code:=composeCLIMidBootStartingResultCode(phase,initial,x.hostAttempt,nil);code!=""{t.Fatal(code)};return initial}
 client,e:=LoadOwnerBridgeClient(f.Config,*f.BridgeEnrollment);if e!=nil{t.Fatal("midboot_starting_client_refused")}
 for phase.Err()==nil {
  request,stop:=context.WithTimeout(phase,5*time.Second)
  observed,e:=client.Request(request,"status","attempt_"+bootstrapFixtureRandom(t,16));stop()
  code:="none"
  if e!=nil { switch e.Error(){case "owner_bridge_connection_unavailable","owner_bridge_reply_unavailable","owner_bridge_deadline":code=e.Error();default:code="closed_authority_or_cleanup_failure"} }
  f.WriteEvidence(t,"midboot-entry-status-"+bootstrapFixtureRandom(t,4)+".json",map[string]any{"errorCode":code,"startupDeadlineExpired":phase.Err()!=nil,"disposition":observed.Disposition})
  outcome:=composeCLIMidBootStartingResultCode(phase,&observed,x.hostAttempt,e)
  if outcome=="" {return &observed}
  if outcome!="midboot_starting_retry" {t.Fatal(outcome)}
  timer:=time.NewTimer(25*time.Millisecond);select{case <-phase.Done():timer.Stop();case <-timer.C:}
 }
 t.Fatal("midboot_starting_deadline")
 return nil
}

// Only known availability errors permit another status read. An actual current
// starting result must match the original attempt without claiming readiness.
func composeCLIMidBootStartingResultCode(ctx context.Context,out *StartupStatusObservation,attempt string,failure error)string{
 if ctx==nil||ctx.Err()!=nil{return "midboot_starting_deadline"}
 if failure!=nil {switch failure.Error(){case "owner_bridge_connection_unavailable","owner_bridge_reply_unavailable","owner_bridge_deadline":return "midboot_starting_retry";default:return "midboot_starting_authority_or_cleanup_refused"}}
 return composeCLIMidBootStartingCode(out,attempt)
}

// Every frozen child must execute a genuine expected role before the phase is
// accepted. Helpers and pre-exec children never satisfy this gate.
func composeCLIWaitFrozenMidBootRoles(t *testing.T,f *bootstrapDockerFixture,x *composeCLIFront,trigger []int,expected map[string]string,deadline time.Time)([]string,[]int){
 t.Helper()
 pids:=installedCLIChildren(x.hostPID)
 if !composeCLIMidBootSamePIDs(trigger,pids)||len(pids)==0||len(pids)>=len(protocol.Roles()) {t.Fatal("midboot_frozen_partial_roster_missed")}
 for _,pid:=range pids {fd,e:=unix.PidfdOpen(pid,0);if e!=nil{t.Fatal("midboot_frozen_child_descriptor_refused")};x.roleFDs=append(x.roleFDs,fd)}
 last:=[]byte(nil)
 for {
  state,e:=os.ReadFile(fmt.Sprintf("/proc/%d/status",x.hostPID))
  hostPoll:=[]unix.PollFd{{Fd:int32(x.hostFD),Events:unix.POLLIN}};hostExited,hostPollError:=unix.Poll(hostPoll,0)
  if e!=nil||!strings.Contains(string(state),"State:\tT (stopped)")||hostPollError!=nil||hostExited!=0||!composeCLIMidBootSamePIDs(pids,installedCLIChildren(x.hostPID)) {t.Fatal("midboot_frozen_roster_or_creator_changed")}
  roles,facts,ready,code:=composeCLIMidBootFrozenRoles(f,x,pids,expected)
  encoded,_:=json.Marshal(facts)
  if !bytes.Equal(encoded,last){f.WriteEvidence(t,"midboot-frozen-child-"+bootstrapFixtureRandom(t,4)+".json",map[string]any{"stage":"frozen_child_execution","childPredicates":facts,"genuineRoleCount":len(roles),"phaseQualified":ready,"refusalCode":code});last=encoded}
  if code!=""{t.Fatal(code)}
  if time.Now().After(deadline){t.Fatal("midboot_frozen_role_execution_deadline")}
  if ready {return roles,pids}
  time.Sleep(time.Millisecond)
 }
}

func composeCLIMidBootFrozenRoles(f *bootstrapDockerFixture,x *composeCLIFront,pids []int,expected map[string]string)([]string,[]map[string]bool,bool,string){
 if len(pids)==0||len(pids)>=len(protocol.Roles())||len(pids)!=len(x.roleFDs){return nil,nil,false,"midboot_frozen_partial_roster_missed"}
 roles:=[]string{};facts:=[]map[string]bool{};seen:=map[string]bool{};ready:=true;names:=protocol.Roles()
 for i,pid:=range pids {
  role,predicate:=composeCLIMidBootRevalidationPredicates(f,x,pid,x.roleFDs[i],names[:],expected);facts=append(facts,predicate)
  if !predicate["liveDescriptor"] {return roles,facts,false,"midboot_frozen_child_exited"}
  if !predicate["parentMatches"] {return roles,facts,false,"midboot_frozen_child_parent_changed"}
  if !predicate["credentialBoundRole"]||!predicate["executedImageMatches"]||!predicate["noArguments"] {ready=false;continue}
  if seen[role] {return roles,facts,false,"midboot_frozen_role_duplicate"};seen[role]=true;roles=append(roles,role)
 }
 return roles,facts,ready&&len(roles)==len(pids),""
}
