//go:build linux || darwin

package runtime

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestApplicationAttestorHostArgumentsPreserveLiteralSelection(t *testing.T) {
	selection := HostInvocation{InvocationID: "attempt_" + strings.Repeat("a", 32), PolicyPath: "/private/host policy.json", WorkspaceRoots: []string{"/workspace/quote ' and back\\slash"}}
	baseline := []string{"host", "--host-policy", selection.PolicyPath, "--invocation-id", selection.InvocationID, "--workspace", selection.WorkspaceRoots[0]}
	arguments, err := hostArguments(selection)
	if err != nil || !reflect.DeepEqual(arguments, baseline) {
		t.Fatal("default host arguments changed", err)
	}
	selection.ApplicationAttestorSelectionPath = "/private/app $(literal) ' quote \\ selection.json"
	selection.ApplicationAttestorSelectionSHA256 = "sha256:" + strings.Repeat("b", 64)
	expected := append(append([]string(nil), baseline...), "--application-attestor-selection", selection.ApplicationAttestorSelectionPath, "--application-attestor-selection-sha256", selection.ApplicationAttestorSelectionSHA256)
	arguments, err = hostArguments(selection)
	if err != nil || !reflect.DeepEqual(arguments, expected) {
		t.Fatal("application selection was split or rewritten", err)
	}
	if selection.WorkspaceRoots[0] != baseline[6] {
		t.Fatal("invocation mutated approved workspace roots")
	}
}

func applicationServicesForwardingSelection(t *testing.T) HostInvocation {
	t.Helper()
	return HostInvocation{
		InvocationID: "attempt_" + strings.Repeat("a", 32), PolicyPath: "/private/host-policy.json", WorkspaceRoots: []string{"/workspace"},
		ApplicationAttestorSelectionPath: "/private/attestor.json", ApplicationAttestorSelectionSHA256: "sha256:" + strings.Repeat("b", 64),
		ApplicationServicesInstallationID: strings.Repeat("c", 64), ApplicationServicesSelectionPath: "/private/services $(literal) ' quote \\ selection.json",
		ApplicationServicesSelectionSHA256: "sha256:" + strings.Repeat("d", 64),
	}
}

func TestApplicationServicesHostArgumentsPreserveLiteralSelection(t *testing.T) {
	selection := applicationServicesForwardingSelection(t)
	expected := []string{"host", "--host-policy", selection.PolicyPath, "--invocation-id", selection.InvocationID, "--workspace", selection.WorkspaceRoots[0],
		"--application-attestor-selection", selection.ApplicationAttestorSelectionPath, "--application-attestor-selection-sha256", selection.ApplicationAttestorSelectionSHA256,
		"--application-services-installation", selection.ApplicationServicesInstallationID,
		"--application-services-selection", selection.ApplicationServicesSelectionPath,
		"--application-services-selection-sha256", selection.ApplicationServicesSelectionSHA256}
	args, err := hostArguments(selection)
	if err != nil || !reflect.DeepEqual(args, expected) {
		t.Fatal("service selection was omitted, split or rewritten")
	}
}

func assertApplicationServicesRefusedBeforeSpawn(t *testing.T, selection HostInvocation) {
	t.Helper()
	image := &refusedInstalledHostImage{}
	host := &InstalledHostImage{image: image}
	defer host.Close()
	if child, err := host.StartHost(context.Background(), selection); err == nil || child != nil || err.Error() != "installed_host_invocation_invalid" || image.validated || host.consumed {
		t.Fatal("invalid service selection reached executable validation or spawn")
	}
}

func TestApplicationServicesHostArgumentsRefuseEveryPartialTriplet(t *testing.T) {
	valid := applicationServicesForwardingSelection(t)
	for mask := 1; mask < 7; mask++ {
		selection := valid
		if mask&1 == 0 {
			selection.ApplicationServicesInstallationID = ""
		}
		if mask&2 == 0 {
			selection.ApplicationServicesSelectionPath = ""
		}
		if mask&4 == 0 {
			selection.ApplicationServicesSelectionSHA256 = ""
		}
		assertApplicationServicesRefusedBeforeSpawn(t, selection)
	}
}

func TestApplicationServicesHostArgumentsRefuseInvalidPinsAndMissingAttestor(t *testing.T) {
	valid := applicationServicesForwardingSelection(t)
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal("test user unavailable")
	}
	defer user.Wipe()
	userPublic, _ := user.PublicKey()
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal("test account unavailable")
	}
	defer account.Wipe()
	accountPublic, _ := account.PublicKey()
	cases := map[string]func(*HostInvocation){
		"missing attestor": func(i *HostInvocation) {
			i.ApplicationAttestorSelectionPath, i.ApplicationAttestorSelectionSHA256 = "", ""
		},
		"partial attestor":       func(i *HostInvocation) { i.ApplicationAttestorSelectionSHA256 = "" },
		"uppercase installation": func(i *HostInvocation) { i.ApplicationServicesInstallationID = strings.Repeat("C", 64) },
		"short installation":     func(i *HostInvocation) { i.ApplicationServicesInstallationID = strings.Repeat("c", 63) },
		"relative path":          func(i *HostInvocation) { i.ApplicationServicesSelectionPath = "services.json" },
		"unclean path":           func(i *HostInvocation) { i.ApplicationServicesSelectionPath = "/private/../services.json" },
		"newline path":           func(i *HostInvocation) { i.ApplicationServicesSelectionPath = "/private/services\n.json" },
		"delete control path":    func(i *HostInvocation) { i.ApplicationServicesSelectionPath = "/private/services\x7f.json" },
		"long path":              func(i *HostInvocation) { i.ApplicationServicesSelectionPath = "/" + strings.Repeat("p", 4096) },
		"uppercase digest":       func(i *HostInvocation) { i.ApplicationServicesSelectionSHA256 = "sha256:" + strings.Repeat("D", 64) },
		"short digest":           func(i *HostInvocation) { i.ApplicationServicesSelectionSHA256 = "sha256:" + strings.Repeat("d", 63) },
		"user key":               func(i *HostInvocation) { i.ApplicationServicesHostAccountPublicKey = userPublic },
		"invalid account":        func(i *HostInvocation) { i.ApplicationServicesHostAccountPublicKey = strings.Repeat("A", 55) + "!" },
		"stale valid account":    func(i *HostInvocation) { i.ApplicationServicesHostAccountPublicKey = accountPublic },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			selection := valid
			change(&selection)
			assertApplicationServicesRefusedBeforeSpawn(t, selection)
		})
	}
}

func TestApplicationAttestorHostArgumentsRefusePartialAndInvalidSelectionBeforeSpawn(t *testing.T) {
	validPath := "/private/application-selection.json"
	validDigest := "sha256:" + strings.Repeat("b", 64)
	for _, pair := range [][2]string{{validPath, ""}, {"", validDigest}, {"relative.json", validDigest}, {"/private/../other.json", validDigest}, {"/private/control\nname", validDigest}, {validPath, "SHA256:" + strings.Repeat("b", 64)}, {validPath, "sha256:" + strings.Repeat("B", 64)}, {validPath, "sha256:" + strings.Repeat("b", 63)}} {
		image := &refusedInstalledHostImage{}
		host := &InstalledHostImage{image: image}
		selection := HostInvocation{InvocationID: "attempt_" + strings.Repeat("a", 32), PolicyPath: "/private/host-policy.json", WorkspaceRoots: []string{"/workspace"}, ApplicationAttestorSelectionPath: pair[0], ApplicationAttestorSelectionSHA256: pair[1]}
		if child, err := host.StartHost(context.Background(), selection); err == nil || child != nil || image.validated || host.consumed {
			t.Fatal("invalid application pair reached executable validation or spawn")
		}
		host.Close()
	}
}
