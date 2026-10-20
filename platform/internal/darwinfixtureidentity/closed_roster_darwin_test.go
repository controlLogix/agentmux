//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClosedRosterRequiresExactExitBeforeCompleteFirstScan(t *testing.T) {
	known := []identity{{PID: 41, Unique: 51, ParentUnique: 50, Version: 2, UID: 501, RealUID: 501}}
	initialFailure := errors.New("original_incomplete_scan")
	for _, test := range []struct {
		name     string
		initial  bool
		anchor   error
		roster   []identity
		expected int
		scanErr  error
		frozen   bool
	}{
		{"complete after exact exit", true, ErrExited, known, 1, nil, true},
		{"initially live", true, nil, known, 1, nil, false},
		{"wrapped exit", true, errors.Join(ErrExited, initialFailure), known, 1, nil, false},
		{"failed first scan", true, ErrExited, known, 1, initialFailure, false},
		{"extra child", true, ErrExited, append(append([]identity{}, known...), identity{PID: 42, Unique: 52}), 1, nil, false},
		{"missing child", true, ErrExited, nil, 1, nil, false},
		{"no expectation", true, ErrExited, nil, 0, nil, false},
		{"ordinary roster", false, ErrExited, known, 1, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := freezeCompletedChildRoster(test.initial, test.anchor, test.roster, test.expected, test.scanErr); got != test.frozen {
				t.Fatal("an incomplete, live or unqualified first scan changed roster policy")
			}
		})
	}
}

func TestClosedRosterIgnoresLaterUnrelatedChurnButRechecksEveryKnownChild(t *testing.T) {
	known := []identity{{PID: 41, Unique: 51, ParentUnique: 50, Version: 2, UID: 501, RealUID: 501}}
	frozen := freezeCompletedChildRoster(true, ErrExited, known, 1, nil)
	scans, checks := 0, 0
	scan := func() ([]identity, error) { scans++; return nil, errors.New("unrelated_uid_query_failed") }
	// Pending initial-exec refresh, ready refresh and final admission must all
	// keep the same complete creation roster after the original parent exited.
	for range 2 {
		refreshed, err := refreshChildRoster(frozen, known, scan)
		if err != nil || !sameRoster(known, refreshed) {
			t.Fatal("closed initial-exec roster depended on unrelated PID activity")
		}
		refreshed[0].Unique++
		if known[0].Unique != 51 {
			t.Fatal("roster refresh allowed mutation of the original creation snapshot")
		}
	}
	err := verifyFinalChildRoster(known, frozen, scan, func() error { checks++; return nil })
	if err != nil || scans != 0 || checks != 1 {
		t.Fatal("closed roster skipped known child verification or rescanned unrelated processes")
	}
}

func TestClosedRosterKeepsKnownChildFailuresTerminal(t *testing.T) {
	known := []identity{{PID: 41, Unique: 51, ParentUnique: 50, Version: 2, UID: 501, RealUID: 501}}
	for _, reason := range []string{"exit", "exec", "replacement", "credentials", "watch", "unknown_identity"} {
		t.Run(reason, func(t *testing.T) {
			original := errors.New("original_known_child_" + reason)
			checks := 0
			err := verifyFinalChildRoster(known, true, func() ([]identity, error) {
				t.Error("closed roster performed a global scan")
				return nil, nil
			}, func() error { checks++; return original })
			if checks != 1 || err != original {
				t.Fatal("closed roster hid a known child verification failure")
			}
		})
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := verifyFinalChildRoster(known, true, nil, ctx.Err); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("closed roster hid cancellation of final child verification")
	}
}

func TestLiveRosterStillRescansWhenAnchorExitsLater(t *testing.T) {
	known := []identity{{PID: 41, Unique: 51, ParentUnique: 50, Version: 2, UID: 501, RealUID: 501}}
	anchorBeforeScan := error(nil)
	frozen := freezeCompletedChildRoster(true, anchorBeforeScan, known, 1, nil)
	anchorBeforeScan = ErrExited
	original := errors.New("original_later_query_refused")
	scans, checks := 0, 0
	scan := func() ([]identity, error) {
		scans++
		if anchorBeforeScan != ErrExited {
			t.Error("regression did not model exit after the initial scan")
		}
		return nil, original
	}
	if _, err := refreshChildRoster(frozen, known, scan); err != original {
		t.Fatal("initial-exec refresh skipped a live anchor's required full scan")
	}
	err := verifyFinalChildRoster(known, frozen, scan, func() error { checks++; return nil })
	if scans != 2 || checks != 0 || !errors.Is(err, original) {
		t.Fatal("later anchor exit hid an unresolved full-roster query")
	}
}

func TestLiveRosterStillRefusesChangedCompleteRoster(t *testing.T) {
	known := []identity{{PID: 41, Unique: 51, ParentUnique: 50, Version: 2, UID: 501, RealUID: 501}}
	changedVersion := append([]identity(nil), known...)
	changedVersion[0].Version++
	for _, roster := range [][]identity{nil, append(append([]identity{}, known...), identity{PID: 42, Unique: 52}), changedVersion} {
		checked := false
		err := verifyFinalChildRoster(known, false, func() ([]identity, error) { return roster, nil }, func() error { checked = true; return nil })
		if err == nil || checked {
			t.Fatal("live-anchor scan accepted a missing, extra or changed child")
		}
	}
}
