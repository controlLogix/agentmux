package main

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "time"
 "github.com/controlLogix/agentmux/platform/launcher"
)

type row struct { Stage string `json:"stage"`; Status string `json:"status"`; Refusal string `json:"refusalCode"` }
// Use only the actual source-reviewed closed diagnostic projection.
// Unknown errors, wrappers and text grant no category or authority.
func refusal(err error) string {
 if err==nil {return "none"}
 diagnostic:=launcher.ProjectRequestDiagnostic(err)
 if !launcher.ValidRequestDiagnostic(diagnostic) {return "unknown"}
 switch diagnostic.Code {
 case "docker_command_failed",
"docker_command_timeout_outcome_unknown",
"docker_configuration_mismatch",
"docker_environment_conflict",
"docker_resource_conflict",
"docker_selection_mismatch",
"docker_versions_unqualified",
"host_enrollment_invalid",
"host_executable_invalid",
"host_policy_invalid",
"host_profile_invalid",
"owned_cleanup_incomplete",
"request_deadline",
"runtime_authority_rejected":
  return diagnostic.Code
 }
 return "unknown"
}
func record(ctx context.Context, stage *row, original error) bool {
 if original!=nil {stage.Status="refused";stage.Refusal=refusal(original);return false}
 if ctx.Err()!=nil {stage.Status="refused";stage.Refusal=refusal(ctx.Err());return false}
 stage.Status="passed";return true
}
func ready(ctx context.Context, stage *row) bool { if ctx.Err()!=nil {record(ctx,stage,ctx.Err());return false};return true }
func main(){
 // One diagnostic context. Synchronous private file reads are not preemptible.
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 stages:=[5]row{{"admission","unexecuted","none"},{"local_invocation_constructor","unexecuted","none"},{"receipt_binding","unexecuted","none"},{"installed_image_preparation","unexecuted","none"},{"installed_image_close","unexecuted","none"}}
 // Original errors stay private. No binding, ID, owner, config or image data is emitted.
 var originals [5]error
 if ctx.Err()==nil {
  h,e:=launcher.LoadEnrolledHostPolicy(launcher.HostPolicySelection{Path:"/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3887681337/installed/host-policy.json",OwnerUID:1000,WorkspaceRoots:[]string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"}})
  originals[0]=e
  if record(ctx,&stages[0],e) && ready(ctx,&stages[1]) {
   invocation,e:=h.BeginEnsure();originals[1]=e
   if e==nil&&invocation==nil {originals[1]=errors.New("unexpected empty local invocation")}
   if record(ctx,&stages[1],originals[1]) && ready(ctx,&stages[2]) {
    _,e=h.BootstrapReceiptBinding(invocation.ID());originals[2]=e
    if record(ctx,&stages[2],e) && ready(ctx,&stages[3]) {
     image,e:=h.PrepareHost(ctx);originals[3]=e
     if e==nil&&image==nil {originals[3]=errors.New("unexpected empty installed image")}
     record(ctx,&stages[3],originals[3])
     // Always close the exact freshly minted image, even if preparation or
     // the original diagnostic context has failed. No child was started.
     if image!=nil {originals[4]=image.Close();record(ctx,&stages[4],originals[4])}
    }
   }
  }
 } else {record(ctx,&stages[0],ctx.Err())}
 cancel()
 report:=struct{SchemaVersion string `json:"schemaVersion"`;Kind string `json:"kind"`;Stages [5]row `json:"stages"`}{"1.0.0","local-preparation-diagnostic",stages}
 code:=0;for _,stage:=range stages {if stage.Status!="passed" {code=1}}
 if json.NewEncoder(os.Stdout).Encode(report)!=nil {os.Exit(2)}
 os.Exit(code)
}
