//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type offlineProfileCoreOwner struct {
	offlineProfileClientOwner
	arguments []string
}

func (o *offlineProfileCoreOwner) ExecCoreClient(ctx context.Context, arguments []string) error {
	if ctx.Err() != nil || o.closes != 0 {
		return errors.New("original core owner unavailable")
	}
	o.execs++
	o.arguments = slices.Clone(arguments)
	return o.execErr
}

func profileCoreArgs(command ...string) []string {
	return append([]string{"profile-core", "--profile-id", "profile_" + strings.Repeat("a", 32), "--repository-root", "/approved/repo 'quotes' $(literal)", "--"}, command...)
}

func TestProfileCoreLiteralCommandAndOriginalOwner(t *testing.T) {
	for _, command := range [][]string{{"start"}, {"spawn", "falcon", "worker", "one", "--operation-id", "original-spawn"}, {"kill", "falcon-worker-one", "--operation-id", "original-stop"}, {"post", "--to", "role:falcon/worker", "--", "literal $(body); 'quotes'"}} {
		owner := &offlineProfileCoreOwner{}
		args := profileCoreArgs(command...)
		calls := 0
		err := runProfileCoreWith(context.Background(), args, func(ctx context.Context, id, repository string) (profileCoreOwner, error) {
			calls++
			if id != args[2] || repository != args[4] {
				t.Fatal("literal profile or repository changed")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("resolution has no deadline")
			}
			return owner, nil
		})
		if err != nil || calls != 1 || owner.execs != 1 || owner.closes != 1 || !slices.Equal(owner.arguments, command) || owner.operation != "" {
			t.Fatal("core handoff changed or used the generic client operation", err)
		}
	}
}

func TestProfileCoreFailureRetainsOwnerAndClosesOnce(t *testing.T) {
	for _, mode := range []string{"resolve", "exec", "close", "exec-and-close", "missing-owner"} {
		t.Run(mode, func(t *testing.T) {
			owner := &offlineProfileCoreOwner{}
			original, cleanup := errors.New("original failure"), errors.New("close failure")
			if mode == "exec" || mode == "exec-and-close" {
				owner.execErr = original
			}
			if mode == "close" || mode == "exec-and-close" {
				owner.closeErr = cleanup
			}
			err := runProfileCoreWith(context.Background(), profileCoreArgs("agents"), func(context.Context, string, string) (profileCoreOwner, error) {
				if mode == "missing-owner" {
					return nil, original
				}
				if mode == "resolve" {
					return owner, original
				}
				return owner, nil
			})
			failure, ok := err.(*profileClientFailure)
			if !ok {
				t.Fatal("failure lost its typed owner", err)
			}
			if mode == "missing-owner" {
				if failure.owner != nil || owner.closes != 0 || failure.cause != original {
					t.Fatal("missing owner was invented")
				}
				return
			}
			if failure.owner != owner || owner.closes != 1 {
				t.Fatal("exact owner lost or cleanup replayed")
			}
			if mode == "resolve" && owner.execs != 0 {
				t.Fatal("refused resolution reached exec")
			}
			if mode == "exec" || mode == "resolve" {
				if failure.cause != original {
					t.Fatal("original refusal lost")
				}
			}
			if owner.closeErr != nil {
				if !failure.cleanup || !errors.Is(failure.cause, cleanup) {
					t.Fatal("cleanup failure lost")
				}
				if mode == "exec-and-close" {
					joined, ok := failure.cause.(interface{ Unwrap() []error })
					if !ok {
						t.Fatal("original and close failures were not retained")
					}
					prior, ok := joined.Unwrap()[0].(*profileClientFailure)
					if !ok || prior.owner != owner || prior.cause != original {
						t.Fatal("original exec failure lost")
					}
				}
			}
		})
	}
}

func TestProfileCoreInvalidInputsDoNotResolve(t *testing.T) {
	base := profileCoreArgs("agents")
	variants := [][]string{nil, {"profile-core"}, base[:6]}
	for _, change := range []struct {
		index int
		value string
	}{{0, "profile-client"}, {1, "--profile"}, {2, "profile_../escape"}, {3, "--repository"}, {4, "relative"}, {4, "/approved/../repo"}, {4, "/"}, {4, "/approved/\nrepo"}, {5, "--operation"}} {
		args := slices.Clone(base)
		args[change.index] = change.value
		variants = append(variants, args)
	}
	for _, args := range variants {
		calls := 0
		if err := runProfileCoreWith(context.Background(), args, func(context.Context, string, string) (profileCoreOwner, error) { calls++; return nil, nil }); err == nil || calls != 0 {
			t.Fatal("invalid core arguments reached resolution")
		}
	}
	if err := runProfileCoreWith(nil, base, func(context.Context, string, string) (profileCoreOwner, error) {
		t.Fatal("nil context reached resolution")
		return nil, nil
	}); err == nil {
		t.Fatal("nil context accepted")
	}
}
