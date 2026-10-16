package main
import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"
 "github.com/controlLogix/agentmux/platform/launcher"
)
func TestRecoveryCommandFrame(t *testing.T){
 for _,c:=range []struct{name,frame string;want bool}{
 {"exact",recoveryFrame,true},{"empty","",false},{"missing_newline",strings.TrimSuffix(recoveryFrame,"\n"),false},{"other_command","{\"command\":\"status\"}\n",false},{"extra_field","{\"command\":\"retry_transport_cleanup\",\"x\":1}\n",false},{"oversized",strings.Repeat("x",65)+"\n",false}}{
 t.Run(c.name,func(t *testing.T){_,ok:=readRecoveryFrame(strings.NewReader(c.frame));if ok!=c.want{t.Fatal("recovery_frame_policy_mismatch")}})
 }
}
func TestRecoveryExactControllerDispatch(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
 for _,c:=range []struct{name string;err error;attempt bool}{
 {"nil",nil,false},{"unknown",forbiddenRecovery{},false},{"value",launcher.TransportCleanupError{},false},{"joined",errors.Join(&launcher.TransportCleanupError{}),false},{"typed_nil",(*launcher.TransportCleanupError)(nil),false},{"exact_zero_pointer",&launcher.TransportCleanupError{},true}}{
 t.Run(c.name,func(t *testing.T){out:=dispatchRecovery(ctx,c.err);if out.Attempted!=c.attempt || !out.OriginalErrorRetained{t.Fatal("exact_controller_policy_mismatch")};if c.attempt && out.Result!="controller_close_returned_nil"{t.Fatal("zero_controller_result_mismatch")}})
 }
 if validRecoveryFrame([]byte(recoveryFrame+recoveryFrame)){t.Fatal("duplicate_frame_admitted")}
 large:=make([]error,80);for i:=range large{large[i]=errors.New("other")};large[79]=&launcher.TransportCleanupError{};if dispatchRecovery(ctx,errors.Join(large...)).Attempted{t.Fatal("oversized_graph_admitted")}
 canceled,stop:=context.WithCancel(ctx);stop()
 out:=dispatchRecovery(canceled,&launcher.TransportCleanupError{});if out.Attempted || out.Result!="budget_expired_or_missing"{t.Fatal("expired_budget_admitted")}
}
type forbiddenRecovery struct{}
func(forbiddenRecovery)Error()string{panic("unknown_error_invoked")}
func(forbiddenRecovery)Unwrap()error{panic("unknown_unwrap_invoked")}
func(forbiddenRecovery)Close()error{panic("unknown_close_invoked")}
