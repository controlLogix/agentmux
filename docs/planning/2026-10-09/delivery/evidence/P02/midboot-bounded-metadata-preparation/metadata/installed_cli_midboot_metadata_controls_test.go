//go:build linux && agentmux_bootstrap_docker

package launcher

import (
 "bytes"
 "path/filepath"
 "strings"
 "testing"
 "github.com/controlLogix/agentmux/platform/kernel/protocol"
 protected "github.com/controlLogix/agentmux/platform/runtime"
)

// These fixed tuples reproduce the source-defined supervisor environment.
// No actual child environment was saved by the earlier failed integration run.
func TestComposeCLIMidBootDeclaredMetadata(t *testing.T){
 scope:=protocol.Scope{InstanceID:"instance_unit",ProfileID:"profile_unit"}
 var declared [4]protected.RoleOptions
 for i,role:=range protocol.Roles(){declared[i]=protected.RoleOptions{ID:role,Env:map[string]string{"AGENTMUX_NATS_CREDS_FILE":filepath.Join("/private/unit",role+".json"),"AGENTMUX_INSTANCE_ID":scope.InstanceID,"AGENTMUX_PROFILE_ID":scope.ProfileID}}}
 raw:=[]byte("AGENTMUX_KERNEL_ROLE=boot\x00AGENTMUX_KERNEL_API_MAJOR=1\x00AGENTMUX_INSTANCE_ID=instance_unit\x00AGENTMUX_PROFILE_ID=profile_unit\x00AGENTMUX_NATS_CREDS_FILE=/private/unit/boot.json\x00AGENTMUX_KERNEL_PARENT_FD=4\x00AGENTMUX_KERNEL_LEASE_FD=5\x00")
 role,ok:=composeCLIMidBootDeclaredMetadata(raw,declared,scope);if !ok||role!="boot"{t.Fatal("source-defined matching role metadata refused")}
 variants:=map[string][]byte{
  "unrelated_child":[]byte("PATH=/usr/bin\x00HOME=/unit\x00"),
  "missing_role":bytes.Replace(raw,[]byte("AGENTMUX_KERNEL_ROLE=boot\x00"),nil,1),
  "missing_api":bytes.Replace(raw,[]byte("AGENTMUX_KERNEL_API_MAJOR=1\x00"),nil,1),
  "wrong_role":bytes.Replace(raw,[]byte("ROLE=boot"),[]byte("ROLE=host"),1),
  "wrong_api":bytes.Replace(raw,[]byte("MAJOR=1"),[]byte("MAJOR=2"),1),
  "wrong_instance":bytes.Replace(raw,[]byte("INSTANCE_ID=instance_unit"),[]byte("INSTANCE_ID=instance_other"),1),
  "wrong_profile":bytes.Replace(raw,[]byte("PROFILE_ID=profile_unit"),[]byte("PROFILE_ID=profile_other"),1),
  "other_credential":bytes.Replace(raw,[]byte("/private/unit/boot.json"),[]byte("/private/other/boot.json"),1),
  "inverted_credential":bytes.Replace(raw,[]byte("/private/unit/boot.json"),[]byte("/private/unit/file.json"),1),
  "duplicate_role":append(append([]byte(nil),raw...),[]byte("AGENTMUX_KERNEL_ROLE=boot\x00")...),
  "duplicate_profile":append(append([]byte(nil),raw...),[]byte("AGENTMUX_PROFILE_ID=profile_unit\x00")...),
  "duplicate_credential":append(append([]byte(nil),raw...),[]byte("AGENTMUX_NATS_CREDS_FILE=/private/unit/boot.json\x00")...),
  "case_alias":append(append([]byte(nil),raw...),[]byte("agentmux_kernel_role=boot\x00")...),
  "malformed_entry":append(append([]byte(nil),raw...),[]byte("broken\x00")...),
  "oversized":bytes.Repeat([]byte("a"),64*1024+1),
  "invalid_utf8":append(append([]byte(nil),raw...),0xff),
 }
 for name,bad:=range variants{t.Run(name,func(t *testing.T){if _,ok:=composeCLIMidBootDeclaredMetadata(bad,declared,scope);ok{t.Fatal("ambiguous or foreign child metadata accepted")}})}
 for _,key:=range []string{"AGENTMUX_INSTANCE_ID","AGENTMUX_PROFILE_ID","AGENTMUX_NATS_CREDS_FILE"}{t.Run("missing_"+strings.ToLower(key),func(t *testing.T){prefix:=key+"=";entries:=strings.Split(string(raw),"\x00");kept:=[]string{};for _,entry:=range entries{if !strings.HasPrefix(entry,prefix){kept=append(kept,entry)}};if _,ok:=composeCLIMidBootDeclaredMetadata([]byte(strings.Join(kept,"\x00")),declared,scope);ok{t.Fatal("missing required context accepted")}})}
 badDeclaration:=declared;badDeclaration[1].ID=badDeclaration[0].ID
 if _,ok:=composeCLIMidBootDeclaredMetadata(raw,badDeclaration,scope);ok{t.Fatal("duplicate declared role accepted")}
}


// These additional tuples check declaration and input boundaries before any
// caller uses metadata to select an observation. They grant no process authority.
func TestComposeCLIMidBootMetadataExpandedBoundaries(t *testing.T) {
 scope:=protocol.Scope{InstanceID:"instance_unit",ProfileID:"profile_unit"}
 fixture:=func(role string)([]byte,[4]protected.RoleOptions){
  var declared [4]protected.RoleOptions
  for i,id:=range protocol.Roles(){declared[i]=protected.RoleOptions{ID:id,Env:map[string]string{"AGENTMUX_NATS_CREDS_FILE":filepath.Join("/private/unit",id+".json"),"AGENTMUX_INSTANCE_ID":scope.InstanceID,"AGENTMUX_PROFILE_ID":scope.ProfileID}}}
  raw:=[]byte("AGENTMUX_KERNEL_ROLE="+role+"\x00AGENTMUX_KERNEL_API_MAJOR=1\x00AGENTMUX_INSTANCE_ID=instance_unit\x00AGENTMUX_PROFILE_ID=profile_unit\x00AGENTMUX_NATS_CREDS_FILE=/private/unit/"+role+".json\x00")
  return raw,declared
 }
 for _,role:=range protocol.Roles(){t.Run("positive_"+role,func(t *testing.T){raw,d:=fixture(role);got,ok:=composeCLIMidBootDeclaredMetadata(raw,d,scope);if !ok||got!=role{t.Fatal("matching declared role refused")}})}
 declarations:=[]struct{name string; mutate func(*[4]protected.RoleOptions)}{
  {"unknown_declared_role",func(d *[4]protected.RoleOptions){d[3].ID="foreign_role"}},
  {"empty_declared_role",func(d *[4]protected.RoleOptions){d[3].ID=""}},
  {"duplicate_declared_reference",func(d *[4]protected.RoleOptions){d[3].Env["AGENTMUX_NATS_CREDS_FILE"]=d[0].Env["AGENTMUX_NATS_CREDS_FILE"]}},
  {"relative_declared_reference",func(d *[4]protected.RoleOptions){d[3].Env["AGENTMUX_NATS_CREDS_FILE"]="relative/file.json"}},
  {"noncanonical_declared_reference",func(d *[4]protected.RoleOptions){d[3].Env["AGENTMUX_NATS_CREDS_FILE"]="/private/unit/../file.json"}},
  {"missing_declared_reference",func(d *[4]protected.RoleOptions){delete(d[3].Env,"AGENTMUX_NATS_CREDS_FILE")}},
  {"foreign_declared_instance",func(d *[4]protected.RoleOptions){d[3].Env["AGENTMUX_INSTANCE_ID"]="foreign_instance"}},
  {"missing_declared_instance",func(d *[4]protected.RoleOptions){delete(d[3].Env,"AGENTMUX_INSTANCE_ID")}},
  {"foreign_declared_profile",func(d *[4]protected.RoleOptions){d[3].Env["AGENTMUX_PROFILE_ID"]="foreign_profile"}},
  {"missing_declared_profile",func(d *[4]protected.RoleOptions){delete(d[3].Env,"AGENTMUX_PROFILE_ID")}},
 }
 for _,c:=range declarations{t.Run(c.name,func(t *testing.T){raw,d:=fixture("boot");c.mutate(&d);if role,ok:=composeCLIMidBootDeclaredMetadata(raw,d,scope);ok||role!=""{t.Fatal("invalid complete declaration set admitted")}})}
 for _,name:=range []string{"instance","profile"}{t.Run("empty_supplied_"+name,func(t *testing.T){raw,d:=fixture("boot");bad:=scope;if name=="instance"{bad.InstanceID=""}else{bad.ProfileID=""};if role,ok:=composeCLIMidBootDeclaredMetadata(raw,d,bad);ok||role!=""{t.Fatal("empty supplied scope admitted")}})}
 keys:=[]string{"AGENTMUX_KERNEL_ROLE","AGENTMUX_KERNEL_API_MAJOR","AGENTMUX_INSTANCE_ID","AGENTMUX_PROFILE_ID","AGENTMUX_NATS_CREDS_FILE"}
 for _,key:=range keys{
  t.Run("empty_value_"+strings.ToLower(key),func(t *testing.T){raw,d:=fixture("boot");entries:=strings.Split(string(raw),"\x00");for i,e:=range entries{if strings.HasPrefix(e,key+"="){entries[i]=key+"="}};if role,ok:=composeCLIMidBootDeclaredMetadata([]byte(strings.Join(entries,"\x00")),d,scope);ok||role!=""{t.Fatal("empty required value admitted")}})
  t.Run("alias_"+strings.ToLower(key),func(t *testing.T){raw,d:=fixture("boot");raw=append(raw,[]byte(strings.ToLower(key)+"=foreign\x00")...);if role,ok:=composeCLIMidBootDeclaredMetadata(raw,d,scope);ok||role!=""{t.Fatal("required-key case alias admitted")}})
 }
 for _,key:=range []string{"AGENTMUX_KERNEL_API_MAJOR","AGENTMUX_INSTANCE_ID"}{t.Run("duplicate_"+strings.ToLower(key),func(t *testing.T){raw,d:=fixture("boot");entries:=strings.Split(string(raw),"\x00");for _,e:=range entries{if strings.HasPrefix(e,key+"="){raw=append(raw,[]byte(e+"\x00")...);break}};if role,ok:=composeCLIMidBootDeclaredMetadata(raw,d,scope);ok||role!=""{t.Fatal("duplicate required key admitted")}})}
}
