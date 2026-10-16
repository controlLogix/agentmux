//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"sync"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// Assembly supplies the externally trusted release policy. Paths and digests
// come from verification; this API cannot bless arbitrary role paths.
type Assembly struct {
	Raw        []byte
	PackageDir string
	Trust      assembly.Trust
}
type assemblyOwner struct {
	mu       sync.Mutex
	input    Assembly
	prepared *protected.Prepared
	refs     int
	consumed bool
	cleanup  error
	// Retain attempted temporary handles and their failures; never retry an
	// uncertain descriptor close through a numeric descriptor or a fresh owner.
	checks []*protected.Prepared
}

func (a *assemblyOwner) retain() { a.mu.Lock(); defer a.mu.Unlock(); a.refs++ }
func (a *assemblyOwner) release() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.consumed {
		return a.cleanup
	}
	a.refs--
	if a.refs == 0 {
		a.consumed = true
		if err := a.prepared.Close(); err != nil {
			a.cleanup = errors.Join(a.cleanup, failed("fixture_role_images_close_failed", err))
		}
	}
	return a.cleanup
}
func (a *assemblyOwner) revalidate(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.consumed || a.cleanup != nil {
		return failed("fixture_role_images_unavailable", a.cleanup)
	}
	fresh, err := protected.Prepare(ctx, a.input.Raw, a.input.PackageDir, a.input.Trust, protected.Limits{MaxBinaryBytes: 128 * 1024 * 1024})
	if err != nil {
		return failed("fixture_role_images_revalidation_refused", err)
	}
	a.checks = append(a.checks, fresh)
	if err := fresh.Close(); err != nil {
		a.cleanup = errors.Join(a.cleanup, failed("fixture_role_image_check_close_failed", err))
		return a.cleanup
	}
	return nil
}
func snapshotRoleArguments(args map[string][]string) (map[string][]string, error) {
	if len(args) != 4 {
		return nil, failed("fixture_role_arguments_refused", nil)
	}
	copyArgs := make(map[string][]string, 4)
	for _, role := range protocol.Roles() {
		values, ok := args[role]
		if !ok {
			return nil, failed("fixture_role_arguments_refused", nil)
		}
		copyArgs[role] = append([]string(nil), values...)
	}
	return copyArgs, nil
}

// PinDirectRoles admits exactly the four verified assembly roles. Each proof
// retains the shared prepared images until the last unique proof closes.
func (p *Proof) PinDirectRoles(ctx context.Context, input Assembly, args map[string][]string) ([]*Proof, error) {
	return p.pinDirectRoles(ctx, input, args, true)
}

// Cooperative test executables use their image path as argv[0]. That private
// mode never broadens the exported runtime-role invocation contract.
func (p *Proof) pinDirectRoles(ctx context.Context, input Assembly, args map[string][]string, runtimeRoleArguments bool) (proofs []*Proof, result error) {
	if ctx == nil {
		return nil, failed("fixture_context_invalid", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, failed("fixture_role_admission_cancelled", err)
	}
	copiedArgs, err := snapshotRoleArguments(args)
	if err != nil {
		return nil, err
	}
	input.Raw = append([]byte(nil), input.Raw...)
	verified, err := assembly.Verify(input.Raw, input.PackageDir, input.Trust)
	if err != nil {
		return nil, failed("fixture_role_assembly_refused", err)
	}
	prepared, err := protected.Prepare(ctx, input.Raw, input.PackageDir, input.Trust, protected.Limits{MaxBinaryBytes: 128 * 1024 * 1024})
	if err != nil {
		return nil, failed("fixture_role_images_refused", err)
	}
	owner := &assemblyOwner{input: input, prepared: prepared, refs: 1}
	defer func() { result = errors.Join(result, owner.release()) }()
	expected := make([]expectedImage, 0, 4)
	for _, member := range verified.Members() {
		item := expectedImage{Path: member.Path, Digest: member.BinaryDigest, Args: copiedArgs[member.ID], assembly: owner}
		if runtimeRoleArguments {
			item.argv0 = "agentmux-" + member.ID
		}
		expected = append(expected, item)
	}
	return p.pinDirectChildren(ctx, expected)
}
