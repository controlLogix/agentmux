//go:build linux && agentmux_bootstrap_docker

package launcher

import (
 "path/filepath"
 "strings"
 "unicode/utf8"
 "github.com/controlLogix/agentmux/platform/kernel/protocol"
 protected "github.com/controlLogix/agentmux/platform/runtime"
)

// This checks metadata only. It may select an observation trigger, but cannot
// establish a genuine role image, readiness or authority to signal a process.
func composeCLIMidBootDeclaredMetadata(raw []byte,declared [4]protected.RoleOptions,scope protocol.Scope)(string,bool){
 if len(raw)==0||len(raw)>64*1024||!utf8.Valid(raw)||scope.InstanceID==""||scope.ProfileID=="" {return "",false}
 keys:=[]string{"AGENTMUX_KERNEL_ROLE","AGENTMUX_KERNEL_API_MAJOR","AGENTMUX_INSTANCE_ID","AGENTMUX_PROFILE_ID","AGENTMUX_NATS_CREDS_FILE"}
 fields:=map[string]string{}
 entries:=strings.Split(string(raw),"\x00")
 if entries[len(entries)-1]=="" {entries=entries[:len(entries)-1]}
 for _,entry:=range entries {
  key,value,ok:=strings.Cut(entry,"=");if !ok||key=="" {return "",false}
  if _,duplicate:=fields[key];duplicate {return "",false}
  for _,required:=range keys {if key!=required&&strings.EqualFold(key,required){return "",false}}
  fields[key]=value
 }
 for _,key:=range keys {if fields[key]==""{return "",false}}
 if fields["AGENTMUX_KERNEL_API_MAJOR"]!="1"||fields["AGENTMUX_INSTANCE_ID"]!=scope.InstanceID||fields["AGENTMUX_PROFILE_ID"]!=scope.ProfileID{return "",false}
 roles:=map[string]bool{};refs:=map[string]bool{};match:=""
 for _,option:=range declared {
  known:=false;for _,role:=range protocol.Roles(){if option.ID==role{known=true}}
  ref:=option.Env["AGENTMUX_NATS_CREDS_FILE"]
  if !known||roles[option.ID]||ref==""||!filepath.IsAbs(ref)||filepath.Clean(ref)!=ref||refs[ref]||option.Env["AGENTMUX_INSTANCE_ID"]!=scope.InstanceID||option.Env["AGENTMUX_PROFILE_ID"]!=scope.ProfileID{return "",false}
  roles[option.ID]=true;refs[ref]=true
  if fields["AGENTMUX_KERNEL_ROLE"]==option.ID&&fields["AGENTMUX_NATS_CREDS_FILE"]==ref {if match!=""{return "",false};match=option.ID}
 }
 return match,match!=""
}
