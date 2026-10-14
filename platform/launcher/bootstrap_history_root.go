//go:build linux || darwin

package launcher

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

// The pathname and retained root must keep the original directory and
// ancestor identities. Equivalent declarations in a replacement are refused.
type historyRootGuard struct {
	policy    ProfilePolicy
	rootInfo  os.FileInfo
	ancestors []os.FileInfo
}

func captureHistoryRoot(ctx context.Context, root *os.Root, policy ProfilePolicy) (*historyRootGuard, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, historyError("context_invalid", nil)
	}
	info, err := root.Stat(".")
	if err != nil {
		return nil, historyError("binding_invalid", err)
	}
	ancestors, err := trustedHostAncestors(policy.Directory, policy.OwnerUID)
	if err != nil {
		return nil, historyError("binding_invalid", err)
	}
	guard := &historyRootGuard{policy: policy, rootInfo: info, ancestors: ancestors}
	if err := guard.check(ctx, root); err != nil {
		return nil, err
	}
	return guard, nil
}
func historyDirectoryIdentity(before, after os.FileInfo) bool {
	if before == nil || after == nil || !os.SameFile(before, after) || !after.IsDir() || before.Mode() != after.Mode() {
		return false
	}
	a, aok := before.Sys().(*syscall.Stat_t)
	b, bok := after.Sys().(*syscall.Stat_t)
	return aok && bok && a.Uid == b.Uid && a.Gid == b.Gid
}
func (g *historyRootGuard) check(ctx context.Context, root *os.Root) (failure error) {
	if ctx == nil || ctx.Err() != nil {
		return historyError("context_invalid", nil)
	}
	if g == nil || root == nil || !canonicalProfilePath(g.policy.Directory) {
		return historyError("binding_invalid", nil)
	}
	current, err := os.Lstat(g.policy.Directory)
	held, heldErr := root.Stat(".")
	if err != nil || heldErr != nil || !historyDirectoryIdentity(g.rootInfo, current) || !historyDirectoryIdentity(g.rootInfo, held) || !privateProfileInfo(held, g.policy.OwnerUID, true) {
		return historyError("binding_invalid", errors.Join(err, heldErr))
	}
	ancestors, err := trustedHostAncestors(g.policy.Directory, g.policy.OwnerUID)
	if err != nil || len(ancestors) != len(g.ancestors) {
		return historyError("binding_invalid", err)
	}
	for i := range ancestors {
		if !historyDirectoryIdentity(g.ancestors[i], ancestors[i]) {
			return historyError("binding_invalid", nil)
		}
	}
	if err := ctx.Err(); err != nil {
		return historyError("context_invalid", err)
	}
	directory, err := root.Open(".")
	if err != nil {
		return historyError("binding_invalid", err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			failure = joinHistoryCleanup(failure, err)
		}
	}()
	opened, err := directory.Stat()
	if err != nil || !historyDirectoryIdentity(g.rootInfo, opened) || privatefs.CheckDescriptor(directory, privatefs.PrivateObject) != nil {
		return historyError("binding_invalid", err)
	}
	// Check the current canonical path again after the actual held ACL query.
	after, err := os.Lstat(g.policy.Directory)
	if err != nil || !historyDirectoryIdentity(g.rootInfo, after) {
		return historyError("binding_invalid", err)
	}
	if err := ctx.Err(); err != nil {
		return historyError("context_invalid", err)
	}
	return nil
}
