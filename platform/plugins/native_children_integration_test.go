package plugins

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func nativeTopologyRequest(packages []AdmittedPackage, input InstanceTopologyInput, behaviors map[string]string) ActivationRequest {
	request := ActivationRequest{Catalog: packages, Selected: []PackagePin{}, Topology: &input, Contracts: []ContractBinding{{Kind: "tool", ContractRef: "urn:fixture:tool"}}}
	for _, node := range input.Instances {
		raw, _ := json.Marshal(map[string]string{"behavior": behaviors[node.InstanceID]})
		request.InstanceConfigurations = append(request.InstanceConfigurations, InstanceConfigurationInput{InstanceID: node.InstanceID, Pin: node.Pin, Resources: []SchemaResource{{Ref: "schemas/config.json", File: "schemas/config.json"}}, Raw: raw})
	}
	return request
}

func nativeSnapshotOwner(t *testing.T, manager *Manager, id string) OwnerReference {
	t.Helper()
	for _, instance := range manager.Snapshot().Instances {
		if instance.Owner.InstanceID == id {
			return instance.Owner
		}
	}
	t.Fatal("expected live instance absent")
	return OwnerReference{}
}

func TestNativeLiveChildOwnershipAndParentRecovery(t *testing.T) {
	if os.Getenv("AGENTMUX_PLUGIN_NATS") == "" {
		t.Skip("prepared native NATS required")
	}
	grand := nativeFixturePackage(t, "grand", func(m *Manifest) { m.InstallationModes = []string{"private-child"} })
	private := nativeFixturePackage(t, "private", func(m *Manifest) {
		m.InstallationModes = []string{"private-child"}
		m.Children = []Child{{PackageID: "grand", Relationship: "private", Required: true}}
	})
	shared := nativeFixturePackage(t, "shared")
	parent := func(m *Manifest) {
		m.Children = []Child{{PackageID: "private", Relationship: "private", Required: true}, {PackageID: "shared", Relationship: "independent-reference", Required: true}}
	}
	a, b := nativeFixturePackage(t, "parenta", parent), nativeFixturePackage(t, "parentb", parent)
	input := InstanceTopologyInput{Roots: []string{"parenta", "parentb", "shared"}, Children: []ChildBinding{
		{"parenta", "privatea", "private"}, {"parentb", "privateb", "private"}, {"privatea", "granda", "private"}, {"privateb", "grandb", "private"}, {"parenta", "shared", "independent-reference"}, {"parentb", "shared", "independent-reference"},
	}, Dependencies: []DependencyBinding{}}
	bindings := []AdmittedPackage{a, b, shared, private, private, grand, grand}
	ids := []string{"parenta", "parentb", "shared", "privatea", "privateb", "granda", "grandb"}
	for index, pkg := range bindings {
		mode := "independent"
		if index >= 3 {
			mode = "private-child"
		}
		input.Instances = append(input.Instances, InstanceSpec{InstanceID: ids[index], Pin: pkg.Pin(), InstallationMode: mode, Placement: Placement{Kind: "local-process"}})
	}
	fixture := liveNativeBroker(t, bindings, ids...)
	driver, err := NewNativeDriver(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(context.Background(), driver, ManagerOptions{Platform: Platform{"darwin", "arm64"}, InstallationMode: "independent", ActivationTimeout: 8 * time.Second, CleanupTimeout: 5 * time.Second})
	if err != nil {
		_ = driver.Close(context.Background())
		t.Fatal(err)
	}
	defer closeNativeFixture(t, manager, driver)
	if _, err = manager.Activate(context.Background(), nativeTopologyRequest([]AdmittedPackage{a, b, shared, private, grand}, input, nil)); err != nil {
		t.Fatal(err)
	}
	aOwner, bOwner, sharedOwner := nativeSnapshotOwner(t, manager, "parenta"), nativeSnapshotOwner(t, manager, "parentb"), nativeSnapshotOwner(t, manager, "shared")
	privateOwner, grandOwner := nativeSnapshotOwner(t, manager, "privatea"), nativeSnapshotOwner(t, manager, "granda")
	if entry, err := manager.ResolveFor(aOwner, "privatea", "tool", "private"); err != nil || entry.Owner != privateOwner {
		t.Fatal("private contribution unavailable to its parent")
	}
	if _, err := manager.ResolveFor(bOwner, "privatea", "tool", "private"); err == nil {
		t.Fatal("private contribution visible to other parent")
	}
	if _, err := manager.Resolve("tool", "private"); err == nil {
		t.Fatal("private contribution globally visible")
	}
	assertChildBrokerBoundaries(t, fixture, 3, []string{"parenta", "privateb"})
	// Releasing the independent owner's claim preserves both consumer references.
	if _, err := manager.ReleaseRoot(context.Background(), sharedOwner); err != nil || manager.CheckActive(sharedOwner) != nil {
		t.Fatal("shared owner release ended consumers")
	}
	driver.mu.Lock()
	originalParent, originalChild, originalGrand := driver.owners["parenta"], driver.owners["privatea"], driver.owners["granda"]
	driver.mu.Unlock()
	if originalChild.command.ParentOwner == nil || *originalChild.command.ParentOwner != aOwner || originalGrand.command.ParentOwner == nil || *originalGrand.command.ParentOwner != privateOwner {
		t.Fatal("private startup lost parent binding")
	}
	if err := originalParent.cmd.Process.Kill(); err != nil {
		t.Fatal("owned parent fault injection failed")
	}
	select {
	case <-originalParent.LifetimeDone():
	case <-time.After(2 * time.Second):
		t.Fatal("parent lifetime loss not observed")
	}
	if manager.CheckActive(privateOwner) == nil || manager.CheckActive(grandOwner) == nil {
		t.Fatal("old parent lifetime still authorized private descendants")
	}
	until := time.Now().Add(8 * time.Second)
	var recovered OwnerReference
	for time.Now().Before(until) {
		for _, instance := range manager.Snapshot().Instances {
			if instance.Owner.InstanceID == "parenta" && instance.Owner.Generation > aOwner.Generation && manager.CheckActive(instance.Owner) == nil {
				recovered = instance.Owner
			}
		}
		if recovered.InstanceID != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if recovered.InstanceID == "" || !completed(originalParent.Done()) || !completed(originalChild.Done()) || !completed(originalGrand.Done()) {
		t.Fatal("parent recovery did not join original subtree")
	}
	if nativeSnapshotOwner(t, manager, "privatea").Generation <= privateOwner.Generation || nativeSnapshotOwner(t, manager, "granda").Generation <= grandOwner.Generation {
		t.Fatal("private recovery reused generation")
	}
	if manager.CheckActive(bOwner) != nil || manager.CheckActive(sharedOwner) != nil {
		t.Fatal("parent recovery interrupted unrelated independent work")
	}
	if _, err = manager.ReleaseRoot(context.Background(), aOwner); err == nil {
		t.Fatal("old parent generation released new owner")
	}
	if _, err = manager.ReleaseRoot(context.Background(), recovered); err != nil {
		t.Fatal(err)
	}
	if len(manager.Snapshot().Instances) != 4 || manager.CheckActive(bOwner) != nil || manager.CheckActive(sharedOwner) != nil {
		t.Fatal("parent removal ended shared or other private instances")
	}
	if _, err = manager.ReleaseRoot(context.Background(), bOwner); err != nil {
		t.Fatal(err)
	}
	if len(manager.Snapshot().Instances) != 0 {
		t.Fatal("unretained instance remained after last consumer")
	}
	driver.mu.Lock()
	owned := len(driver.owners)
	driver.mu.Unlock()
	if owned != 0 {
		t.Fatal("native instance ownership leaked")
	}
	entries, err := os.ReadDir(fixture.options.StateDirectory)
	if err != nil {
		t.Fatal("native state read failed")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "instance-") {
			t.Fatal("private stage leaked")
		}
	}
}

func assertChildBrokerBoundaries(t *testing.T, fixture nativeBrokerFixture, child int, targets []string) {
	t.Helper()
	denied, closed := make(chan error, len(targets)*2+2), make(chan struct{})
	client, err := nats.Connect(fixture.options.ServerURL, nats.UserCredentials(fixture.options.Bindings[child].CredentialsFile), nats.RootCAs(fixture.options.CAFile), nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
		select {
		case denied <- e:
		default:
		}
	}), nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
	if err != nil {
		t.Fatal("private negative client unavailable")
	}
	defer func() {
		client.Close()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Error("negative client callbacks not joined")
		}
	}()
	for _, target := range targets {
		control, _, _ := lifecycleSubjects("fixture", target)
		if client.Publish(control, []byte(`{"action":"stop"}`)) != nil {
			t.Fatal("negative publication did not reach broker")
		}
		if _, err := client.SubscribeSync(control); err != nil {
			t.Fatal("negative subscription did not reach broker")
		}
	}
	if client.FlushTimeout(time.Second) != nil {
		t.Fatal("negative client flush failed")
	}
	for range len(targets) * 2 {
		select {
		case err := <-denied:
			if !strings.Contains(err.Error(), "Permissions Violation") {
				t.Fatal("unexpected negative broker result")
			}
		case <-time.After(time.Second):
			t.Fatal("private child broker boundary not enforced")
		}
	}
}

func TestNativeLivePrivateReadinessRejectsWrongParent(t *testing.T) {
	if os.Getenv("AGENTMUX_PLUGIN_NATS") == "" {
		t.Skip("prepared native NATS required")
	}
	child := nativeFixturePackage(t, "child", func(m *Manifest) { m.InstallationModes = []string{"private-child"} })
	parent := nativeFixturePackage(t, "parent", func(m *Manifest) { m.Children = []Child{{PackageID: "child", Relationship: "private", Required: true}} })
	input := InstanceTopologyInput{Instances: []InstanceSpec{{"parent", parent.Pin(), "independent", Placement{"local-process"}}, {"child", child.Pin(), "private-child", Placement{"local-process"}}}, Roots: []string{"parent"}, Children: []ChildBinding{{"parent", "child", "private"}}, Dependencies: []DependencyBinding{}}
	fixture := liveNativeBroker(t, []AdmittedPackage{parent, child})
	driver, err := NewNativeDriver(context.Background(), fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(context.Background(), driver, ManagerOptions{Platform: Platform{"darwin", "arm64"}, InstallationMode: "independent", ActivationTimeout: 5 * time.Second, CleanupTimeout: 3 * time.Second})
	if err != nil {
		_ = driver.Close(context.Background())
		t.Fatal(err)
	}
	defer closeNativeFixture(t, manager, driver)
	if _, err = manager.Activate(context.Background(), nativeTopologyRequest([]AdmittedPackage{parent, child}, input, map[string]string{"child": "wrong-parent"})); err == nil {
		t.Fatal("wrong parent readiness accepted")
	}
	if len(manager.Snapshot().Instances) != 0 || manager.Snapshot().RetainedCleanup != 0 {
		t.Fatal("failed private candidate published or retained")
	}
	driver.mu.Lock()
	owned := len(driver.owners)
	driver.mu.Unlock()
	if owned != 0 {
		t.Fatal("failed private processes not joined")
	}
}
