package main

import (
 "encoding/json"
 "errors"
 "os"
 "reflect"
 "github.com/controlLogix/agentmux/platform/launcher"
)

type row struct { Stage string `json:"stage"`; Status string `json:"status"`; Refusal string `json:"refusalCode"` }
var plainFailure = reflect.TypeOf(errors.New("fixed type control"))

// Only the actual standard error-string implementation may be read. Unknown
// methods and unknown text are never emitted or used as runtime authority.
func refusal(err error) string {
 if err == nil { return "none" }
 if reflect.TypeOf(err) != plainFailure || reflect.ValueOf(err).IsNil() { return "unknown" }
 switch code := err.Error(); code {
 case "host_policy_ancestor_access_denied",
"host_policy_ancestor_changed",
"host_policy_ancestor_invalid",
"host_policy_ancestor_untrusted",
"host_policy_bootstrap_config_invalid",
"host_policy_bridge_binding_invalid",
"host_policy_bridge_credential_invalid",
"host_policy_bridge_fields_invalid",
"host_policy_bridge_private_root_invalid",
"host_policy_bridge_reference_invalid",
"host_policy_bridge_unconfigured",
"host_policy_context_invalid",
"host_policy_declarations_invalid",
"host_policy_decode_invalid",
"host_policy_executable_changed",
"host_policy_executable_invalid",
"host_policy_executable_root_invalid",
"host_policy_executable_unqualified",
"host_policy_fields_invalid",
"host_policy_inside_workspace",
"host_policy_invocation_failed",
"host_policy_owner_binding_invalid",
"host_policy_owner_enrollment_invalid",
"host_policy_private_policy_invalid",
"host_policy_private_policy_root_invalid",
"host_policy_private_root_changed",
"host_policy_private_root_invalid",
"host_policy_private_root_unavailable",
"host_policy_profile_binding_invalid",
"host_policy_profile_invalid",
"host_policy_selection_invalid",
"host_policy_unconfigured",
"host_policy_workspace_invalid":
  return code
 }
 return "unknown"
}

func main() {
 stages:= [2]row{{"enrolled_policy_admission","unexecuted","none"},{"repeated_config_load","unexecuted","none"}}
 h,err:=launcher.LoadEnrolledHostPolicy(launcher.HostPolicySelection{
  Path:"/home/ryan/.cache/agentmux-governance/p02-bootstrap-private-3887681337/installed/host-policy.json",
  OwnerUID:1000,
  WorkspaceRoots:[]string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"},
 })
 code:=0
 if err != nil { stages[0].Status="refused";stages[0].Refusal=refusal(err);code=1
 } else {
  stages[0].Status="passed"
  _,_,err=h.Load()
  if err != nil {stages[1].Status="refused";stages[1].Refusal=refusal(err);code=1} else {stages[1].Status="passed"}
 }
 // Config and owner objects are deliberately discarded without formatting.
 report:=struct { SchemaVersion string `json:"schemaVersion"`;Kind string `json:"kind"`;Stages [2]row `json:"stages"` }{"1.0.0","read-only-policy-admission",stages}
 if json.NewEncoder(os.Stdout).Encode(report)!=nil {os.Exit(2)}
 os.Exit(code)
}
