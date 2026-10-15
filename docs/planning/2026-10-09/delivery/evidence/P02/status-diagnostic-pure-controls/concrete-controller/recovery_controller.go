package main
import (
 "context"
 "io"
 "os"
 "runtime"
 "time"
 "encoding/json"
 "github.com/controlLogix/agentmux/platform/launcher"
)
const recoveryFrame="{\"command\":\"retry_transport_cleanup\"}\n"
const recoveryFrameLimit=64
type recoveryReply struct { SchemaVersion string `json:"schemaVersion"`; Kind string `json:"kind"`; Result string `json:"result"`; Attempted bool `json:"attempted"`; OriginalErrorRetained bool `json:"originalErrorRetained"` }
func validRecoveryFrame(frame []byte)bool{return len(frame)<=recoveryFrameLimit && string(frame)==recoveryFrame}
func dispatchRecovery(ctx context.Context,original error) recoveryReply {
 reply:=recoveryReply{"1.0.0","transport-cleanup-controller-attempt","refused",false,true}
 if ctx==nil || ctx.Err()!=nil {reply.Result="budget_expired_or_missing";return reply}
 if _,bounded:=ctx.Deadline();!bounded {reply.Result="budget_expired_or_missing";return reply}
 controller,ok:=original.(*launcher.TransportCleanupError)
 if !ok || controller==nil {reply.Result="top_level_controller_unavailable";return reply}
 // Exact concrete method only. No errors.As, unknown Unwrap or Close callback.
 reply.Attempted=true
 err:=controller.Close()
 if err!=nil {reply.Result="controller_retry_failed"} else {reply.Result="controller_close_returned_nil"}
 if ctx.Err()!=nil {reply.Result="budget_expired_after_attempt"}
 runtime.KeepAlive(original)
 return reply
}
func readRecoveryFrame(reader io.Reader)([]byte,bool){
 frame:=make([]byte,0,recoveryFrameLimit)
 for len(frame)<recoveryFrameLimit {
  var one [1]byte
  n,err:=reader.Read(one[:])
  if n==1 {frame=append(frame,one[0]);if one[0]=='\n'{return frame,validRecoveryFrame(frame)}}
  if err!=nil || n!=1{return nil,false}
 }
 return nil,false
}
func retainRecovery(ctx context.Context,original error){
 // One fixed command may be observed. EOF or malformed input never grants
 // cleanup or exit authority. The existing total deadline is not extended.
 if _,valid:=readRecoveryFrame(os.Stdin);valid{
  reply:=dispatchRecovery(ctx,original)
  _=json.NewEncoder(os.Stdout).Encode(reply)
 }
 // Even a nil Close result covers only that concrete controller attempt.
 // Retain the original graph; aggregate cleanup/exit remains unapproved.
 for {time.Sleep(time.Hour);runtime.KeepAlive(original)}
}
