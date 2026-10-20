//go:build (linux || darwin) && !((darwin && arm64) || agentmux_application_services)

package launcher

import (
	"context"
	"fmt"
	"io"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

// Keep the host-route API available on unqualified Unix targets. Explicit
// service selection is refused; the separate attestor-only route is unchanged.
type ApplicationServiceProcessSelection struct {
	InstallationID, Path, SHA256 string
	HostAccountPublicKey         string // Stale callers are refused by the supported route.
}

func (ApplicationServiceProcessSelection) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "[private application service process selection]")
}

func (*EnrolledHostPolicy) RunWithApplicationServices(context.Context, string, ApplicationAttestorHostSelection, ApplicationServiceProcessSelection) error {
	return protected.ErrPlatformUnqualified
}

func (*EnrolledHostPolicy) ProvisionIntegrationEffect(context.Context,
	ApplicationServiceProcessSelection, string, string, []byte, io.Writer) error {
	return protected.ErrPlatformUnqualified
}
