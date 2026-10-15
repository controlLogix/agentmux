package main
import (
 "errors"
 "testing"
 "github.com/controlLogix/agentmux/platform/launcher"
)
func TestRecoveryParkingPolicy(t *testing.T){
 cases:=[]struct{name string;err error;want bool}{
  {"nil",nil,false},
  {"ordinary_error",errors.New("ordinary"),true},
  {"spoofed_text",errors.New("owned_cleanup_incomplete"),true},
  {"unknown_wrapper",opaqueCleanup{},true},
  {"concrete_pointer",&launcher.TransportCleanupError{},true},
  {"concrete_value",launcher.TransportCleanupError{},true},
  {"reviewed_join",errors.Join(errors.New("other"),&launcher.TransportCleanupError{}),true},
 }
 oversized:=make([]error,80);for i:=range oversized{oversized[i]=errors.New("ordinary")};oversized[len(oversized)-1]=&launcher.TransportCleanupError{}
 cases=append(cases,struct{name string;err error;want bool}{"oversized_joined_cleanup",errors.Join(oversized...),true})
 for _,c:=range cases{t.Run(c.name,func(t *testing.T){if needsRecovery(c.err)!=c.want{t.Fatal("recovery_parking_policy_mismatch")}})}
}
type opaqueCleanup struct{}
func(opaqueCleanup)Error()string{return "owned_cleanup_incomplete"}
func(opaqueCleanup)Unwrap()error{panic("unknown_unwrap_invoked")}
