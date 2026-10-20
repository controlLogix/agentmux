//go:build linux || darwin

package launcher

import (
	"context"
	"github.com/controlLogix/agentmux/platform/plugins"
)

// NativeContextProfile discloses only admitted identity bindings and display
// metadata. It supplies no authority, broker credentials or application grant.
func (r *CentralProfileResolution) NativeContextProfile(ctx context.Context) (plugins.NativeContextProfile, error) {
	selected, err := r.Selection(ctx)
	if err != nil {
		return plugins.NativeContextProfile{}, err
	}
	metadata := &plugins.ProfileContext{Environment: selected.Context.Environment, Project: selected.Context.Project}
	return plugins.NativeContextProfile{ProfileID: selected.ProfileID, InstanceID: selected.InstanceID, HubID: selected.HubID, Context: metadata}, nil
}

var _ plugins.NativeContextProfileOwner = (*CentralProfileResolution)(nil)
