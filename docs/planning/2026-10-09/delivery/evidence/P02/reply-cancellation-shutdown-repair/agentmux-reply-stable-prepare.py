import pathlib,shutil,subprocess,difflib,hashlib,json
root=pathlib.Path('/home/ryan/.cache/agentmux-governance');out=root/'p02-reply-cancel-stable';out.mkdir();old=root/'p02-reply-cancel-repair';shutil.copytree(old/'instrumented/src',out/'src')
shared=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux/platform/launcher/owner_bridge.go');original=shared.read_text();needle='''if nc.Publish(s.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw) != nil || nc.FlushWithContext(ctx) != nil {
					cancel()
					return bridgeError("reply_failed")
				}''';assert original.count(needle)==1
replacement='''beforePublish := nc.LastError()
                if beforePublish != nil {
                    cancel()
                    return ownerBridgeReplyOutcome(lifetime, beforePublish, nil, nil, nil, bootErr)
                }
                publishErr := nc.Publish(s.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw)
                var flushErr error
                if publishErr == nil { flushErr = nc.FlushWithContext(ctx) }
                afterFlush := nc.LastError()
                outcome := ownerBridgeReplyOutcome(lifetime, beforePublish, publishErr, flushErr, afterFlush, bootErr)
                if outcome != nil { cancel(); return outcome }
                if flushErr != nil { cancel(); return nil }'''
helper='''
// Each recorded error is a snapshot from this reply boundary. Cancellation is
// shutdown only; it does not confirm that Flush completed or a caller accepted a reply.
func ownerBridgeReplyOutcome(lifetime context.Context, beforePublish, publishErr, flushErr, afterFlush, bootErr error) error {
    if authority := ownerBridgeRecordedAuthorityError(beforePublish); authority != nil { return authority }
    if beforePublish != nil || publishErr != nil { return bridgeError("reply_failed") }
    if authority := ownerBridgeRecordedAuthorityError(afterFlush); authority != nil { return authority }
    if flushErr != nil && !(errors.Is(flushErr, context.Canceled) && lifetime.Err() == context.Canceled) { return bridgeError("reply_failed") }
    if bootErr != nil { return bridgeError("startup_failed") }
    return nil
}
'''
s=original.replace(needle,replacement);s=s.replace('err := nc.LastError()\n\tif errors.Is(err, nats.ErrPermissionViolation)', 'return ownerBridgeRecordedAuthorityError(nc.LastError())\n}\n\nfunc ownerBridgeRecordedAuthorityError(err error) error {\n\tif errors.Is(err, nats.ErrPermissionViolation)',1);s+=helper
production=out/'owner_bridge.go';production.write_text(s)
# Apply identical earlier instrumentation to this production candidate.
instrumented=s.replace('publishErr := nc.Publish(s.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw)','publishErr := nc.Publish(s.subjects.ReplyPrefix+request.RequestID[len("request_"):], raw)\n if publishErr == nil && observation.Disposition == "reused" { <-ownerBridgeReplyReleaseControl }',1)
instrumented=instrumented.replace('afterFlush := nc.LastError()', 'afterFlush := nc.LastError()\n if observation.Disposition == "reused" { ownerBridgeReplyFactsControl <- replyCancelFacts{publishErr == nil, errors.Is(flushErr,context.Canceled),ctx.Err()==context.Canceled,ownerBridgeRecordedAuthorityError(afterFlush)!=nil} }',1)
(out/'src/platform/launcher/owner_bridge.go').write_text(instrumented)
tests='''package launcher
import("context";"errors";"io";"testing";"github.com/nats-io/nats.go")
func TestOwnerBridgeReplyCancellationKeepsFailures(t *testing.T) {
 canceled,cancel:=context.WithCancel(context.Background());cancel()
 cases:=[]struct{name string; lifetime context.Context; before,publish,flush,after,boot error;code string}{
 {"cancel_late_eof",canceled,nil,nil,context.Canceled,io.EOF,nil,""},
 {"cancel_late_closed",canceled,nil,nil,context.Canceled,nats.ErrConnectionClosed,nil,""},
 {"preexisting_eof",canceled,io.EOF,nil,context.Canceled,nil,nil,"owner_bridge_reply_failed"},
 {"publish_failure",canceled,nil,nats.ErrConnectionClosed,context.Canceled,nil,nil,"owner_bridge_reply_failed"},
 {"authority_before",canceled,nats.ErrPermissionViolation,nil,context.Canceled,nil,nil,"owner_bridge_authority_rejected"},
 {"authority_after",canceled,nil,nil,context.Canceled,nats.ErrPermissionViolation,nil,"owner_bridge_authority_rejected"},
 {"deadline",canceled,nil,nil,context.DeadlineExceeded,nil,nil,"owner_bridge_reply_failed"},
 {"disconnected_flush",canceled,nil,nil,nats.ErrConnectionClosed,nil,nil,"owner_bridge_reply_failed"},
 {"unknown_flush",canceled,nil,nil,errors.New("unknown private failure"),nil,nil,"owner_bridge_reply_failed"},
 {"only_request_canceled",context.Background(),nil,nil,context.Canceled,nil,nil,"owner_bridge_reply_failed"},
 {"startup_failure",canceled,nil,nil,context.Canceled,io.EOF,errors.New("actual startup failure"),"owner_bridge_startup_failed"},
 }
 for _,c:=range cases{t.Run(c.name,func(t *testing.T){err:=ownerBridgeReplyOutcome(c.lifetime,c.before,c.publish,c.flush,c.after,c.boot);if c.code==""{if err!=nil{t.Fatal("shutdown became failure")}}else if err==nil||err.Error()!=c.code{t.Fatal("required hard failure lost")}})}
}
'''
(out/'owner_bridge_reply_cancellation_test.go').write_text(tests);(out/'src/platform/launcher/owner_bridge_reply_cancellation_test.go').write_text(tests)
go=root/'runtime-comparison/go/bin/go';subprocess.run([str(go.with_name('gofmt')),'-w',str(production),str(out/'src/platform/launcher/owner_bridge.go'),str(out/'owner_bridge_reply_cancellation_test.go'),str(out/'src/platform/launcher/owner_bridge_reply_cancellation_test.go')],check=True)
(out/'production.diff').write_text(''.join(difflib.unified_diff(original.splitlines(True),production.read_text().splitlines(True),fromfile='shared/owner_bridge.go',tofile='candidate/owner_bridge.go')))
(out/'candidate-pins.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [production,out/'owner_bridge_reply_cancellation_test.go',out/'production.diff']},indent=2)+'\n')
print(str(out));print((out/'candidate-pins.json').read_text())