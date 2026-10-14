//go:build linux || darwin

package launcher

import (
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// BridgeServerForInvocation binds only the installed host's concrete inherited
// lifecycle writer. The default server and all NATS authority checks stay intact.
func (host *EnrolledHostPolicy) BridgeServerForInvocation(invocationID string) (*OwnerBridgeServer, time.Duration, error) {
	if host == nil || !ownerBridgeInvocation.MatchString(invocationID) {
		return nil, 0, hostPolicyError("receipt_invocation_invalid")
	}
	server, timeout, err := host.BridgeServer()
	if err != nil {
		return nil, 0, err
	}
	binding, err := host.BootstrapReceiptBinding(invocationID)
	if err != nil {
		return nil, 0, err
	}
	// Every policy/binding check precedes descriptor adoption. After Open succeeds
	// this factory returns the exact writer owner without a later failure path.
	if !ownerBridgeReceiptBindingMatches(binding, server, invocationID) {
		return nil, 0, hostPolicyError("receipt_binding_invalid")
	}
	server.history = newOwnerBridgeHistoryState(binding)
	if !protected.BootstrapReceiptRequested() {
		return server, timeout, nil
	}
	writer, err := protected.OpenBootstrapReceiptWriter(binding)
	if err != nil {
		return nil, 0, hostPolicyError("receipt_descriptor_invalid")
	}
	state := &ownerBridgeReceiptState{writer: writer, binding: binding}
	server.receipt = state
	return server, timeout, nil
}
