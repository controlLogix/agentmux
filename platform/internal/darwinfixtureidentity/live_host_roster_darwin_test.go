//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func liveHostRosterTestFamily() (identity, []identity) {
	host := identity{PID: 40, ParentPID: 30, Version: 2, UID: 501, RealUID: 501, Status: 2, Unique: 140, ParentUnique: 130}
	var children []identity
	for i := range 4 {
		children = append(children, identity{PID: int32(41 + i), ParentPID: host.PID, Version: 3, UID: host.UID, RealUID: host.RealUID, Status: 2, Unique: uint64(141 + i), ParentUnique: host.Unique})
	}
	return host, children
}

func TestLiveHostRosterExcludesUnrelatedUIDChurnAndRescansActualChildren(t *testing.T) {
	host, children := liveHostRosterTestFamily()
	hostChecks, lists, reads := 0, 0, 0
	scan := func() ([]identity, error) {
		return scanLiveHostChildren(context.Background(), host, func() (identity, error) {
			hostChecks++
			return host, nil
		}, func(parent int32) ([]int32, error) {
			lists++
			if parent != host.PID {
				t.Fatal("enumeration did not use the retained host's current PID")
			}
			return []int32{41, 42, 43, 44}, nil
		}, func(pid int) (identity, error) {
			reads++
			for _, child := range children {
				if int(child.PID) == pid {
					return child, nil
				}
			}
			// Unrelated UID processes are absent from PPID enumeration. Reading
			// one would reproduce the terminal query failure from the live run.
			t.Error("queried an unrelated UID process")
			return identity{}, failed("fixture_native_query_refused", unix.ESRCH)
		})
	}
	initial, err := scan()
	if err != nil || !sameRoster(children, initial) {
		t.Fatal("initial live-host child scan failed")
	}
	checks := 0
	err = verifyFinalChildRoster(initial, false, scan, func() error { checks++; return nil })
	if err != nil || lists != 2 || reads != 8 || hostChecks != 4 || checks != 1 {
		t.Fatal("live host skipped its final complete scan or a host/child check")
	}
}

func TestLiveHostRosterRefusesUnknownActualChild(t *testing.T) {
	host, children := liveHostRosterTestFamily()
	for _, name := range []string{"query", "pid", "creation", "version", "parent_pid", "parent_creation", "uid", "real_uid", "status", "zombie"} {
		t.Run(name, func(t *testing.T) {
			child := children[0]
			var original error
			switch name {
			case "query":
				original = failed("fixture_native_query_refused", unix.EPERM)
			case "pid":
				child.PID++
			case "creation":
				child.Unique = 0
			case "version":
				child.Version = 0
			case "parent_pid":
				child.ParentPID++
			case "parent_creation":
				child.ParentUnique++
			case "uid":
				child.UID++
			case "real_uid":
				child.RealUID++
			case "status":
				child.Status = 0
			case "zombie":
				child.Status = 5
			}
			roster, err := scanLiveHostChildren(context.Background(), host,
				func() (identity, error) { return host, nil },
				func(int32) ([]int32, error) { return []int32{41}, nil },
				func(int) (identity, error) { return child, original })
			if err == nil || roster != nil || (original != nil && !errors.Is(err, original)) {
				t.Fatal("unknown actual child was skipped or accepted")
			}
		})
	}
}

func TestLiveHostRosterRefusesHostExitChangeAndWatchFailure(t *testing.T) {
	host, children := liveHostRosterTestFamily()
	for _, when := range []int{1, 2} {
		for _, name := range []string{"exit", "watch", "pid", "version", "creation", "parent_creation", "uid", "real_uid", "status", "zombie"} {
			t.Run(name+string(rune('0'+when)), func(t *testing.T) {
				checks, lists := 0, 0
				var original error
				roster, err := scanLiveHostChildren(context.Background(), host, func() (identity, error) {
					checks++
					current := host
					if checks != when {
						return current, nil
					}
					switch name {
					case "exit":
						original = ErrExited
					case "watch":
						original = failed("fixture_watch_failed", unix.EBADF)
					case "pid":
						current.PID++
					case "version":
						current.Version++
						if !sameCreation(host, current) {
							t.Fatal("test lost the weaker creation-only match")
						}
					case "creation":
						current.Unique++
					case "parent_creation":
						current.ParentUnique++
					case "uid":
						current.UID++
					case "real_uid":
						current.RealUID++
					case "status":
						current.Status = 0
					case "zombie":
						current.Status = 5
					}
					return current, original
				}, func(int32) ([]int32, error) { lists++; return []int32{41}, nil },
					func(int) (identity, error) { return children[0], nil })
				if roster != nil || err == nil || checks != when || lists != when-1 || (original != nil && !errors.Is(err, original)) {
					t.Fatal("host exit, replacement, exec or watch failure allowed a scan result or fallback")
				}
			})
		}
	}
}

func TestLiveHostRosterKeepsEnumerationAndCancellationFailuresTerminal(t *testing.T) {
	host, children := liveHostRosterTestFamily()
	original := errors.New("original_child_enumeration_failure")
	for _, phase := range []string{"enumeration", "before", "during", "after"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			checks := 0
			if phase == "before" {
				cancel()
			}
			roster, err := scanLiveHostChildren(ctx, host, func() (identity, error) {
				checks++
				if phase == "after" && checks == 2 {
					cancel()
				}
				return host, nil
			}, func(int32) ([]int32, error) {
				if phase == "enumeration" {
					return nil, original
				}
				if phase == "during" {
					cancel()
				}
				return []int32{41}, nil
			}, func(int) (identity, error) { return children[0], nil })
			if roster != nil || err == nil || (phase == "enumeration" && err != original) || (phase != "enumeration" && !errors.Is(err, context.Canceled)) {
				t.Fatal("failed or cancelled scan returned an admitted roster")
			}
		})
	}
}

func TestLiveHostRosterRefusesDuplicateExtraMissingAndChangedChildren(t *testing.T) {
	host, children := liveHostRosterTestFamily()
	for _, pids := range [][]int32{{41, 41}, {0}, {-1}} {
		if roster, err := scanLiveHostChildren(context.Background(), host,
			func() (identity, error) { return host, nil },
			func(int32) ([]int32, error) { return pids, nil },
			func(int) (identity, error) { return children[0], nil }); err == nil || roster != nil {
			t.Fatal("duplicate or invalid native PID list was accepted")
		}
	}
	extra := children[0]
	extra.PID, extra.Unique = 50, 150
	changed := append([]identity(nil), children...)
	changed[0].Version++
	for _, roster := range [][]identity{children[:3], append(append([]identity{}, children...), extra), changed} {
		checked := false
		err := verifyFinalChildRoster(children, false,
			func() ([]identity, error) { return roster, nil },
			func() error { checked = true; return nil })
		if err == nil || checked {
			t.Fatal("live-host final scan accepted an extra, missing or changed child")
		}
	}
}
