//go:build linux || (darwin && arm64)

package main

import (
	"context"
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
