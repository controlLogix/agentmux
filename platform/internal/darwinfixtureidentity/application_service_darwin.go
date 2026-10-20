//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"path/filepath"
	"sync"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type clientImageOwner struct {
	mu        sync.Mutex
	admission interface {
		Recheck(context.Context) error
		Close() error
	}
	refs     int
	consumed bool
	cleanup  error
}

func (c *clientImageOwner) retain() { c.mu.Lock(); defer c.mu.Unlock(); c.refs++ }
func (c *clientImageOwner) recheck(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.consumed || c.cleanup != nil {
		return failed("fixture_client_image_unavailable", c.cleanup)
	}
	return c.admission.Recheck(ctx)
}
func (c *clientImageOwner) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.consumed {
		return c.cleanup
	}
	c.refs--
	if c.refs == 0 {
		c.consumed = true
		if err := c.admission.Close(); err != nil {
			c.cleanup = &failure{stage: "fixture_service_package_close_failed", cause: err, retained: c}
		}
	}
	return c.cleanup
}

// PinDirectRolesWithApplicationService admits the entire five-child roster.
// The service image and its fixed argv come only from package admission. No
// caller can select a Python path, arguments, process ID or a partial roster.
func (p *Proof) PinDirectRolesWithApplicationService(ctx context.Context, input Assembly, args map[string][]string, installationID string, inspection ...*InspectionSelection) (proofs []*Proof, result error) {
	if len(inspection) > 1 || (len(inspection) == 1 && inspection[0] == nil) {
		return nil, failed("fixture_inspection_selection_invalid", nil)
	}
	admission, err := protected.PrepareInstalledClient(ctx, installationID)
	if err != nil {
		return nil, failed("fixture_service_package_refused", err)
	}
	owner := &clientImageOwner{admission: admission, refs: 1}
	defer func() { result = errors.Join(result, owner.Close()) }()
	root := filepath.Join(protected.InstalledClientBase, installationID)
	item := expectedImage{Path: filepath.Join(root, protected.ClientInterpreter), Args: []string{"-I", "-S", filepath.Join(root, protected.ClientBootstrap), "application-services"}, clientImage: owner}
	if len(inspection) == 1 {
		return p.pinDirectRolesWithInspections(ctx, input, args, true, inspection[0], item)
	}
	return p.pinDirectRoles(ctx, input, args, true, item)
}
