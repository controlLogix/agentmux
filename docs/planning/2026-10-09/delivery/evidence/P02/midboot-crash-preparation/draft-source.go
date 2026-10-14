//go:build linux && agentmux_bootstrap_docker

package launcher

import (
 "context"
 "errors"
 "fmt"
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
 out := composeCLIObservation(t, f, original, r, composeCLIWait(t, f, original, s, r, "midboot-entry"), "midboot-entry", false)
 if out == nil || out.Disposition != "starting" || out.StartupAttemptID == nil || *out.StartupAttemptID != original.hostAttempt {
  t.Fatal("mid-boot lacks authentic entered attempt")
 }
 if gate.Close() != nil { t.Fatal("mid-boot arbitration gate release failed") }
 gate = nil
 startupDeadline := original.started.Add(f.Config.StartupTimeout)
 for len(installedCLIChildren(original.hostPID)) == 0 {
  if time.Now().After(startupDeadline) {
   t.Fatal("mid-boot genuine child did not start within original budget")
  }
  poll := []unix.PollFd{{Fd: int32(original.hostFD), Events: unix.POLLIN}}
  if n, e := unix.Poll(poll, 0); e != nil || n != 0 { t.Fatal("mid-boot creator exited before actual child") }
  time.Sleep(time.Millisecond)
 }
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
 roles, partialPIDs := composeCLIPinPartialMidBootRoles(t, f, original)
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
 composeCLIRevalidateMidBootRoles(t, f, original, partialPIDs, roles)
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

func composeCLIPinPartialMidBootRoles(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront) ([]string, []int) {
 t.Helper()
 seen := map[string]bool{}
 pids := installedCLIChildren(x.hostPID)
 for _, pid := range pids {
  fd, e := unix.PidfdOpen(pid, 0)
  if e != nil { t.Fatal("mid-boot creator child descriptor unavailable") }
  // Existing owned cleanup receives the exact descriptor before any assertion.
  x.roleFDs = append(x.roleFDs, fd)
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
  if ie != nil || se != nil || ee != nil || ae != nil || pe != nil || n != 0 || role == "" || seen[role] || !strings.Contains(string(status), fmt.Sprintf("PPid:\t%d\n", x.hostPID)) || len(strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")) != 1 {
   t.Fatal("mid-boot actual creator child identity refused")
  }
  member, e := os.ReadFile(filepath.Join(f.HostPolicy.ExternalRelease.PackageDirectory, "bin", role))
  if e != nil || releaseDigest(member) != releaseDigest(image) { t.Fatal("mid-boot actual child image mismatch") }
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
func composeCLIRevalidateMidBootRoles(t *testing.T, f *bootstrapDockerFixture, x *composeCLIFront, pids []int, roles []string) {
 t.Helper()
 hostState, e := os.ReadFile(fmt.Sprintf("/proc/%d/status", x.hostPID))
 if e!=nil || !strings.Contains(string(hostState), "State:\tT (stopped)") || !reflect.DeepEqual(pids, installedCLIChildren(x.hostPID)) || len(pids)!=len(x.roleFDs) { t.Fatal("mid-boot phase changed before crash") }
 seen := map[string]bool{}
 for i,pid := range pids {
  poll:=[]unix.PollFd{{Fd:int32(x.roleFDs[i]),Events:unix.POLLIN}}
  n,pe:=unix.Poll(poll,0)
  image,ie:=os.ReadFile(fmt.Sprintf("/proc/%d/exe",pid))
  status,se:=os.ReadFile(fmt.Sprintf("/proc/%d/status",pid))
  env,ee:=os.ReadFile(fmt.Sprintf("/proc/%d/environ",pid))
  args,ae:=os.ReadFile(fmt.Sprintf("/proc/%d/cmdline",pid))
  role:=""
  for _,candidate:=range roles { for _,item:=range strings.Split(string(env),"\x00") { if item=="AGENTMUX_NATS_CREDS_FILE="+filepath.Join(f.Profile.ProfileDirectory,candidate+".json") { role=candidate } } }
  if pe!=nil || n!=0 || ie!=nil || se!=nil || ee!=nil || ae!=nil || role=="" || seen[role] || !strings.Contains(string(status),fmt.Sprintf("PPid:\t%d\n",x.hostPID)) || len(strings.Split(strings.TrimSuffix(string(args),"\x00"),"\x00"))!=1 { t.Fatal("mid-boot original child binding changed before crash") }
  member,e:=os.ReadFile(filepath.Join(f.HostPolicy.ExternalRelease.PackageDirectory,"bin",role))
  if e!=nil || releaseDigest(member)!=releaseDigest(image) { t.Fatal("mid-boot original child image changed before crash") }
  seen[role]=true
 }
 if len(seen)!=len(roles) { t.Fatal("mid-boot original role roster changed before crash") }
}
