//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type servicePackageCloseControl struct {
	closes int
	err    error
}

func (*servicePackageCloseControl) Recheck(context.Context) error { return nil }
func (c *servicePackageCloseControl) Close() error                { c.closes++; return c.err }

func TestServicePackageOwnerKeepsOriginalAdmissionAndConsumedFailure(t *testing.T) {
	refused := errors.New("controlled_close_failure")
	admission := &servicePackageCloseControl{err: refused}
	owner := &clientImageOwner{admission: admission, refs: 1}
	owner.retain()
	if owner.Close() != nil || admission.closes != 0 {
		t.Fatal("package closed while a child proof still owned it")
	}
	err := owner.Close()
	var retained *failure
	if !errors.Is(err, refused) || !errors.As(err, &retained) || retained.retained != owner || owner.admission != admission || admission.closes != 1 {
		t.Fatal("consumed package failure lost its original owner")
	}
	if owner.Close() != err || admission.closes != 1 || owner.recheck(context.Background()) == nil {
		t.Fatal("consumed package admission was retried or reused")
	}
}

func TestClosedApplicationHostArgumentsRequireExactPins(t *testing.T) {
	application := &ExpectedApplication{AttestorPath: "/private/attestor ' literal.json", AttestorSHA256: "sha256:" + strings.Repeat("a", 64), InstallationID: strings.Repeat("b", 64), ServicesPath: "/private/services $(literal).json", ServicesSHA256: "sha256:" + strings.Repeat("c", 64)}
	tail, err := applicationArguments(application)
	if err != nil || len(tail) != 10 {
		t.Fatal("fixed application pins refused")
	}
	host := &ExpectedHost{Path: "/protected/host", PolicyPath: "/private/policy", WorkspaceRoots: []string{"/workspace"}, Application: application}
	item := expectedImage{Path: host.Path, host: host}
	args := append([]string{host.Path, "host", "--host-policy", host.PolicyPath, "--invocation-id", "attempt_" + strings.Repeat("d", 32), "--workspace", "/workspace"}, tail...)
	if !matchesArguments(item, host.Path, args) {
		t.Fatal("exact application host invocation refused")
	}
	for i := 8; i < len(args); i++ {
		changed := append([]string(nil), args...)
		changed[i] = "changed"
		if matchesArguments(item, host.Path, changed) {
			t.Fatal("changed application option admitted")
		}
	}
	if matchesArguments(item, host.Path, args[:len(args)-2]) || matchesArguments(item, host.Path, append(append([]string(nil), args...), "--application-services-host-account", strings.Repeat("A", 56))) {
		t.Fatal("partial or stale application grammar admitted")
	}
	application.InstallationID = strings.Repeat("B", 64)
	if _, err := applicationArguments(application); err == nil {
		t.Fatal("unqualified installation selection admitted")
	}
}
