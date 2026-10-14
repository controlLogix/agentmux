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

func TestFrontendBudgetReservesResponseAndCleanup(t *testing.T) {
	parent, cancelParent := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelParent()
	total, cancelTotal := frontendTotalContext(parent, "ensure", time.Now())
	defer cancelTotal()
	work, cancelWork := frontendWorkContext(total)
	defer cancelWork()
	workDeadline, _ := work.Deadline()
	totalDeadline, _ := total.Deadline()
	if totalDeadline.Sub(workDeadline) < frontendReceiptCleanupLimit+frontendResponseAllowance {
		t.Fatal("request work consumes the response and owned receipt cleanup allowance")
	}
	<-work.Done()
	if total.Err() != nil {
		t.Fatal("work expiration exhausted the original caller total deadline")
	}
}

func TestFrontendCleanupNeverExtendsTotal(t *testing.T) {
	total, cancelTotal := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancelTotal()
	cleanup, cancelCleanup := frontendCleanupContext(total)
	defer cancelCleanup()
	originalDeadline, _ := total.Deadline()
	cleanupDeadline, _ := cleanup.Deadline()
	if cleanupDeadline.After(originalDeadline) {
		t.Fatal("owned receipt cleanup extends the original caller deadline")
	}
	<-cleanup.Done()
	if total.Err() == nil {
		t.Fatal("cleanup deadline is independent of the original caller")
	}
}

func TestFrontendStatusUsesOriginalFiveSecondTotal(t *testing.T) {
	entered := time.Now().Add(-100 * time.Millisecond)
	total, cancel := frontendTotalContext(context.Background(), "status", entered)
	defer cancel()
	deadline, _ := total.Deadline()
	if !deadline.Equal(entered.Add(frontendStatusLimit)) {
		t.Fatal("status total budget is reset or exceeds five seconds from entry")
	}
}

func TestFrontendEarlierCancelledCallerDoesNotGainTime(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	total, stopTotal := frontendTotalContext(parent, "ensure", time.Now())
	defer stopTotal()
	work, stopWork := frontendWorkContext(total)
	defer stopWork()
	cleanup, stopCleanup := frontendCleanupContext(total)
	defer stopCleanup()
	if total.Err() == nil || work.Err() == nil || cleanup.Err() == nil {
		t.Fatal("cancelled caller gained an independent work or cleanup lifetime")
	}
}

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
