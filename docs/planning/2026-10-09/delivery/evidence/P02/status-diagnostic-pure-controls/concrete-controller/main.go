package main
import (
 "context"
 "encoding/json"
 "os"

 "time"
 "github.com/controlLogix/agentmux/platform/launcher"
)
type report struct { SchemaVersion string `json:"schemaVersion"`; Kind string `json:"kind"`; Classification string `json:"classification"`; Retained bool `json:"errorRetained"`; Authenticated bool `json:"authenticated"`; Disposition string `json:"disposition"`; Readiness string `json:"readiness"` }
func known(value string, choices ...string) bool {for _,x:=range choices{if value==x{return true}};return false}
// Keep only the original returned error graph alive. This policy never follows
// unknown wrappers or invokes a caller-provided cleanup operation.
func needsRecovery(err error) bool { return err!=nil }
func main(){
 entered:=time.Now()
 total,cancel:=context.WithDeadline(context.Background(),entered.Add(5*time.Second));defer cancel()
 // Preserve the actual frontend's one-second cleanup and 500ms response reserve.
 work,stop:=context.WithDeadline(total,entered.Add(3500*time.Millisecond));defer stop()
 out:=report{"1.0.0","retained-status-diagnostic","unknown",false,false,"unknown","unknown"}
 h,err:=launcher.LoadEnrolledHostPolicy(launcher.HostPolicySelection{Path:"/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3887681337/installed/host-policy.json",OwnerUID:1000,WorkspaceRoots:[]string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"}})
 if err==nil && work.Err()!=nil {err=work.Err()}
 if err==nil {
  invocation,e:=h.BeginEnsure();err=e
  if err==nil && work.Err()!=nil {err=work.Err()}
  if err==nil {
   // Only the literal status operation. Never ensure, Probe or any host constructor.
   observation,e:=invocation.Request(work,"status");err=e
   if err==nil {
    if known(observation.Disposition,"started","reused","starting","failed") && known(observation.Instance.Readiness,"ready","degraded","not_ready","unknown") {
     out.Classification="validated_observation";out.Authenticated=true;out.Disposition=observation.Disposition;out.Readiness=observation.Instance.Readiness
    }
   }
  }
 }
 if err!=nil {
  d:=launcher.ProjectRequestDiagnostic(err)
  if launcher.ValidRequestDiagnostic(d) && d.Code!="request_failed" {out.Classification=d.Code}
 }
 out.Retained=needsRecovery(err)
 stop()
 if !out.Retained {cancel()}
 // No raw error, broker fields, owner, nonce, IDs, scope or endpoint is emitted.
 if json.NewEncoder(os.Stdout).Encode(out)!=nil {
  if needsRecovery(err){retainRecovery(total,err)}
  os.Exit(2)
 }
 if needsRecovery(err){retainRecovery(total,err)}
 if !out.Authenticated {os.Exit(1)}
}
