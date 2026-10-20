//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/darwinfixtureidentity"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// The existing JWT fixture keeps its own broker process and wait. This case
// borrows only its explicitly enrolled listener and never starts or removes it.
type stableInstalledApplication struct {
	path              string
	raw               []byte
	selected          centralProfileSelectionFile
	expected          darwinfixtureidentity.ExpectedApplication
	allowQuery        bool
	expectUnavailable bool
	serviceCheck      func(*testing.T, *bootstrapDockerFixture, *composeDarwinCLIFront)
}

func stableInstalledApplicationLoss(t *testing.T, f *bootstrapDockerFixture, client *composeDarwinCLIFront) {
	t.Helper()
	lifetime := client.lifetime
	if lifetime == nil || lifetime.applicationService == nil || lifetime.applicationEnded || lifetime.admissionFailure == nil {
		t.Fatal("service-loss case requires original admitted host and application owners")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := lifetime.applicationService.Signal(syscall.SIGTERM); err != nil {
		lifetime.admissionFailure(err)
		return
	}
	if err := lifetime.applicationService.WaitExit(ctx); err != nil {
		lifetime.admissionFailure(err)
		return
	}
	// Lease release follows the host's sole process wait and protocol drain.
	// No replacement or PID-based cleanup is permitted while it remains held.
	lease, err := AcquireBootstrapLock(ctx, f.Profile.ProfileDirectory, f.Profile.InstanceID, "application-services")
	if err != nil {
		lifetime.admissionFailure(err)
		return
	}
	if err := lease.Close(); err != nil {
		lifetime.cleanupOwners = append(lifetime.cleanupOwners, lease)
		lifetime.admissionFailure(err)
		return
	}
	lifetime.applicationEnded = true
	lifetime.assertUnchanged(t, f)
	darwinScenarioRefresh(t, f, time.Now().Add(darwinScenarioRefusalBudget))
}

func stableInstalledApplicationPrerequisites(t *testing.T, clientID string) *stableInstalledApplication {
	t.Helper()
	if os.Getenv("AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT") == "" {
		if os.Getenv("AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT_SHA256") != "" {
			t.Fatal("service enrollment path missing")
		}
		return nil
	}
	if os.Getenv("AMX_INSTALLED_CLIENT_APPLICATION_BROKER_BORROW_AUTHORIZED") != "1" {
		t.Fatal("original application broker owner must authorize borrowing its enrolled listener")
	}
	raw := bootstrapDarwinPrivatePrerequisite(t, "AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT", "AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT_SHA256")
	var selected centralProfileSelectionFile
	if protocol.DecodeClosedJSON(raw, &selected, 16384) != nil || selected.SchemaVersion != protocol.Version || selected.ApplicationAttestor == nil || selected.ApplicationServices == nil || selected.Application == nil || selected.ApplicationServices.InstallationID != clientID {
		t.Fatal("complete three-service client enrollment required")
	}
	native, _ := loadBootstrapFixtureSelection(t)
	roots := []string{native.WorkspaceRoot}
	if selected.HostPolicy != os.Getenv("AMX_INSTALLED_CLIENT_HOST_POLICY") || !reflect.DeepEqual(selected.Workspaces, roots) {
		t.Fatal("service enrollment differs from the independently selected host or workspace")
	}
	s := HostPolicySelection{Path: selected.HostPolicy, OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: roots}
	host, err := LoadEnrolledHostPolicy(s)
	if err != nil || selected.InstanceID != host.record.InstanceID || selected.ProfileID != host.record.ProfileID || selected.HubID != host.record.Owner.Identity.OwnerHubID {
		t.Fatal("service client enrollment does not match the admitted host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	attestor, err := host.ReadApplicationAttestorHostSelection(ctx, selected.ApplicationAttestor.Selection, selected.ApplicationAttestor.SHA256)
	if err != nil {
		t.Fatal("explicit application endpoint or attestor enrollment refused")
	}
	prepared, err := prepareApplicationAttestorHost(ctx, host, attestor)
	if err != nil {
		t.Fatal("scoped application attestor credential refused")
	}
	if prepared.close() != nil {
		t.Fatal("attestor prerequisite ownership did not close")
	}
	services := ApplicationServiceProcessSelection{InstallationID: selected.ApplicationServices.InstallationID, Path: selected.ApplicationServices.Selection, SHA256: selected.ApplicationServices.SHA256}
	_, admission, err := host.prepareApplicationServices(ctx, services, &attestor, true)
	if err != nil {
		t.Fatal("selected service package, HOST descriptor or identity connection refused")
	}
	if admission.Close() != nil {
		t.Fatal("service package prerequisite ownership did not close")
	}
	serviceRaw := stableInstalledPrivateDocument(t, ctx, host, services.Path, 65536)
	defer clear(serviceRaw)
	sum := sha256.Sum256(serviceRaw)
	var header applicationServiceSelectionHeader
	if services.SHA256 != "sha256:"+hex.EncodeToString(sum[:]) || protocol.DecodeClosedJSON(serviceRaw, &header, 65536) != nil || len(header.Integration) == 0 {
		t.Fatal("identity, definitions and integration must all be explicitly selected")
	}
	keyRaw := stableInstalledPrivateDocument(t, ctx, host, selected.Application.ClientKey, 65536)
	defer clear(keyRaw)
	var key map[string]json.RawMessage
	if json.Unmarshal(keyRaw, &key) != nil {
		t.Fatal("enrolled application client key unavailable")
	}
	query, exists := key["integrationEffectQuery"]
	return &stableInstalledApplication{path: os.Getenv("AMX_INSTALLED_CLIENT_SERVICE_ENROLLMENT"), raw: raw, selected: selected,
		expected: darwinfixtureidentity.ExpectedApplication{AttestorPath: selected.ApplicationAttestor.Selection, AttestorSHA256: selected.ApplicationAttestor.SHA256, InstallationID: services.InstallationID, ServicesPath: services.Path, ServicesSHA256: services.SHA256}, allowQuery: exists && string(query) != "null"}
}

func stableInstalledPrivateDocument(t *testing.T, ctx context.Context, host *EnrolledHostPolicy, path string, limit int64) []byte {
	t.Helper()
	root, err := openPrivateHostRoot(filepath.Dir(path), host.selection.OwnerUID, host.selection.WorkspaceRoots)
	if err != nil {
		t.Fatal("private selected application input root refused")
	}
	raw, readErr := readApplicationPrivateFile(ctx, root, filepath.Base(path), host.selection.OwnerUID, limit)
	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		clear(raw)
		t.Fatal("private selected application input did not finish reading or closing")
	}
	return raw
}
