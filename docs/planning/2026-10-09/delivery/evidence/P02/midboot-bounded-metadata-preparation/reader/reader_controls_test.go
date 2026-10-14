//go:build linux && agentmux_bootstrap_docker

package launcher

import (
 "bytes"
 "os"
 "path/filepath"
 "testing"
 "github.com/controlLogix/agentmux/platform/kernel/protocol"
 protected "github.com/controlLogix/agentmux/platform/runtime"
)

// These are owned regular files and fixed source-defined tuples, never live
// process metadata. Oversize data must not be truncated into acceptance.
func TestMidBootBoundedEnvironmentRegularFiles(t *testing.T) {
 dir:=t.TempDir()
 scope:=protocol.Scope{InstanceID:"instance_unit",ProfileID:"profile_unit"}
 var declared [4]protected.RoleOptions
 for i,role:=range protocol.Roles(){declared[i]=protected.RoleOptions{ID:role,Env:map[string]string{"AGENTMUX_NATS_CREDS_FILE":filepath.Join("/private/unit",role+".json"),"AGENTMUX_INSTANCE_ID":scope.InstanceID,"AGENTMUX_PROFILE_ID":scope.ProfileID}}}
 raw:=[]byte("AGENTMUX_KERNEL_ROLE=boot\x00AGENTMUX_KERNEL_API_MAJOR=1\x00AGENTMUX_INSTANCE_ID=instance_unit\x00AGENTMUX_PROFILE_ID=profile_unit\x00AGENTMUX_NATS_CREDS_FILE=/private/unit/boot.json\x00")
 exact:=append(append([]byte(nil),raw...),[]byte("PADDING="+string(bytes.Repeat([]byte{'x'},64*1024-len(raw)-9))+"\x00")...)
 t.Run("missing",func(t *testing.T){
  got,readErr,closeErr:=composeCLIMidBootBoundedEnvironment(filepath.Join(dir,"missing"))
  if len(got)!=0||readErr==nil||closeErr!=nil {t.Fatal("missing file must refuse without an owned close")}
 })
 for name,size:=range map[string]int{"exact_limit":64*1024,"one_byte_over":64*1024+1,"beyond_read_limit":64*1024+32} {t.Run(name,func(t *testing.T){
  data:=append([]byte(nil),exact...)
  if size>len(data){data=append(data[:len(data)-1],bytes.Repeat([]byte{'x'},size-len(data))...);data=append(data,0)}
  path:=filepath.Join(dir,name)
  if os.WriteFile(path,data,0600)!=nil {t.Fatal("owned fixture write failed")}
  got,readErr,closeErr:=composeCLIMidBootBoundedEnvironment(path)
  limit:=size;if limit>64*1024+1 {limit=64*1024+1}
  if readErr!=nil||closeErr!=nil||len(got)!=limit||!bytes.Equal(got,data[:limit]) {t.Fatal("bounded read or exact close failed")}
  role,eligible:=composeCLIMidBootDeclaredMetadata(got,declared,scope)
  if size==64*1024 {if !eligible||role!="boot"{t.Fatal("valid exact-limit tuple refused")}} else if eligible {t.Fatal("oversize tuple accepted")}
 })}
}
