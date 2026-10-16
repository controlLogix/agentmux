//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// This uses a genuine sealed owned child and receipt pipe. Its fixed fixture
// receipt is transport proof, not an admitted Bootstrap or NATS observation.
func TestFrontendNearExpiryOwnedReceiptRetainsUnknownFactsAndCleanup(t *testing.T) {
	binary := childExitGuardBinary(t)
	child, receipt := childExitGuardStart(t, binary, true)
	parent, cancelParent := context.WithTimeout(context.Background(), 1800*time.Millisecond)
	defer cancelParent()
	total, cancelTotal := frontendTotalContext(parent, "ensure", time.Now())
	defer cancelTotal()
	work, cancelWork := frontendWorkContext(total)
	defer cancelWork()
	<-work.Done()
	var output bytes.Buffer
	if emitOwnedBootstrapProgress(total, &output, child, receipt) != nil {
		t.Fatal("near-expiry work consumed the genuine receipt response allowance")
	}
	cleanup, cancelCleanup := frontendCleanupContext(total)
	defer cancelCleanup()
	if child.CloseBootstrapReceipt(cleanup) != nil || total.Err() != nil {
		t.Fatal("actual owned receipt cleanup failed or exhausted the total deadline")
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(output.Bytes(), &document) != nil || string(document["instanceState"]) != `"unknown"` || string(document["requestDisposition"]) != `"accepted"` {
		t.Fatal("receipt invented current readiness")
	}
	if _, exists := document["disposition"]; exists {
		t.Fatal("receipt became an authenticated L04 observation")
	}
	select {
	case <-child.Done():
		t.Fatal("frontend response or receipt cleanup stopped its detached child")
	default:
	}
	for _, hard := range []error{errors.New("owner_bridge_authority_rejected"), errors.New("host_policy_owner_enrollment_invalid"), errors.Join(errors.New("owner_bridge_deadline"), errors.New("owner_bridge_owned_connection_cleanup_failed"))} {
		if progressObservationUnavailable(hard) {
			t.Fatal("response reserve converted a hard failure into accepted progress")
		}
	}
}
