package plugins

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLifecycleReportExactBinding(t *testing.T) {
	owner := OwnerReference{Pin: PackagePin{"example", "1.0.0", checksum([]byte("manifest")), checksum([]byte("package")), checksum([]byte("source"))}, InstanceID: "instance", Epoch: strings.Repeat("a", 64), Generation: 1}
	command := LifecycleControl{"1.0.0", "ordinary-plugin-control", "prepare", strings.Repeat("b", 64), owner, checksum([]byte("config")), checksum([]byte("contributions")), time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano), nil, ""}
	report := LifecycleReport{"1.0.0", "ordinary-plugin-report", command.CommandID, owner, command.ConfigurationChecksum, command.ContributionsChecksum, "ready", time.Now().UTC().Format(time.RFC3339Nano), nil, ""}
	raw, _ := json.Marshal(report)
	for _, accepted := range [][]byte{raw, bytes.Replace(raw, []byte(`"generation":1`), []byte(`"generation":1.0`), 1)} {
		if _, err := decodeLifecycleReport(accepted, command); err != nil {
			t.Fatal(err)
		}
	}
	for _, field := range []string{"schemaVersion", "kind", "commandId", "owner", "pin", "packageId", "version", "manifestChecksum", "packageChecksum", "provenanceChecksum", "instanceId", "epoch", "generation", "configurationChecksum", "contributionsChecksum", "status", "observedAt"} {
		bad := bytes.Replace(raw, []byte(`"`+field+`":`), []byte(`"`+strings.ToUpper(field[:1])+field[1:]+`":`), 1)
		if _, err := decodeLifecycleReport(bad, command); err == nil {
			t.Fatalf("case alias accepted: %s", field)
		}
	}
	for _, change := range []func(*LifecycleReport){func(r *LifecycleReport) { r.Owner.Generation++ }, func(r *LifecycleReport) { r.Owner.Epoch = strings.Repeat("c", 64) }, func(r *LifecycleReport) { r.CommandID = strings.Repeat("c", 64) }, func(r *LifecycleReport) { r.Owner.Pin.ProvenanceChecksum = checksum([]byte("other")) }, func(r *LifecycleReport) { r.Status = "running" }, func(r *LifecycleReport) { r.ObservedAt = time.Now().Add(-4 * time.Minute).Format(time.RFC3339Nano) }, func(r *LifecycleReport) { r.ObservedAt = time.Now().Add(time.Minute).Format(time.RFC3339Nano) }} {
		changed := report
		change(&changed)
		bad, _ := json.Marshal(changed)
		if _, err := decodeLifecycleReport(bad, command); err == nil {
			t.Fatal("wrong binding accepted")
		}
	}
	for _, bad := range [][]byte{[]byte(`null`), bytes.Replace(raw, []byte(`"status":"ready"`), []byte(`"status":null`), 1), append(raw, raw...), bytes.Replace(raw, []byte(`"status":"ready"`), []byte(`"status":"ready","status":"ready"`), 1)} {
		if _, err := decodeLifecycleReport(bad, command); err == nil {
			t.Fatal("invalid report accepted")
		}
	}
}

func TestPrivateLifecycleReportBindsParentGeneration(t *testing.T) {
	owner := OwnerReference{Pin: PackagePin{"child", "1.0.0", checksum([]byte("manifest")), checksum([]byte("package")), checksum([]byte("source"))}, InstanceID: "child", Epoch: strings.Repeat("a", 64), Generation: 2}
	parent := owner
	parent.InstanceID, parent.Pin.PackageID, parent.Generation = "parent", "parent", 7
	command := LifecycleControl{SchemaVersion: "1.1.0", Kind: "ordinary-plugin-control", Action: "prepare", CommandID: strings.Repeat("b", 64), Owner: owner, ConfigurationChecksum: checksum([]byte("config")), ContributionsChecksum: checksum([]byte("contributions")), Deadline: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano), ParentOwner: &parent}
	report := LifecycleReport{SchemaVersion: command.SchemaVersion, Kind: "ordinary-plugin-report", CommandID: command.CommandID, Owner: owner, ConfigurationChecksum: command.ConfigurationChecksum, ContributionsChecksum: command.ContributionsChecksum, Status: "ready", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), ParentOwner: &parent}
	raw, _ := json.Marshal(report)
	if _, err := decodeLifecycleReport(raw, command); err != nil {
		t.Fatal("exact private owner binding refused", err)
	}
	for _, change := range []func(*LifecycleReport){
		func(r *LifecycleReport) { r.ParentOwner = nil },
		func(r *LifecycleReport) { r.SchemaVersion = "1.0.0" },
		func(r *LifecycleReport) { r.ParentOwner.Generation-- },
		func(r *LifecycleReport) { r.ParentOwner.Epoch = strings.Repeat("c", 64) },
		func(r *LifecycleReport) { r.ParentOwner.InstanceID = "other" },
		func(r *LifecycleReport) { r.ParentOwner.Pin.ProvenanceChecksum = checksum([]byte("other")) },
	} {
		changed, copied := report, parent
		changed.ParentOwner = &copied
		change(&changed)
		bad, _ := json.Marshal(changed)
		if _, err := decodeLifecycleReport(bad, command); err == nil {
			t.Fatal("changed parent lifetime accepted")
		}
	}
	for _, field := range []string{"parentOwner", "generation", "provenanceChecksum"} {
		bad := bytes.ReplaceAll(raw, []byte(`"`+field+`":`), []byte(`"`+strings.ToUpper(field[:1])+field[1:]+`":`))
		if _, err := decodeLifecycleReport(bad, command); err == nil {
			t.Fatal("parent case alias accepted")
		}
	}
	command.SchemaVersion, command.ParentOwner = "1.0.0", nil
	if _, err := decodeLifecycleReport(raw, command); err == nil {
		t.Fatal("private extension accepted by independent protocol")
	}
}

func TestContextLifecycleReportBindsContextAndParent(t *testing.T) {
	owner := OwnerReference{Pin: PackagePin{"example", "1.0.0", checksum([]byte("manifest")), checksum([]byte("package")), checksum([]byte("source"))}, InstanceID: "instance", Epoch: strings.Repeat("a", 64), Generation: 1}
	for _, private := range []bool{false, true} {
		command := LifecycleControl{SchemaVersion: "1.2.0", Kind: "ordinary-plugin-control", Action: "prepare", CommandID: strings.Repeat("b", 64), Owner: owner, ConfigurationChecksum: checksum([]byte("config")), ContributionsChecksum: checksum([]byte("contributions")), Deadline: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano), ContextChecksum: checksum([]byte("context"))}
		if private {
			parent := owner
			parent.InstanceID = "parent"
			command.ParentOwner = &parent
		}
		report := LifecycleReport{SchemaVersion: command.SchemaVersion, Kind: "ordinary-plugin-report", CommandID: command.CommandID, Owner: owner, ConfigurationChecksum: command.ConfigurationChecksum, ContributionsChecksum: command.ContributionsChecksum, Status: "ready", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), ParentOwner: command.ParentOwner, ContextChecksum: command.ContextChecksum}
		raw, _ := json.Marshal(report)
		if _, err := decodeLifecycleReport(raw, command); err != nil {
			t.Fatal("bound context refused", err)
		}
		for _, change := range []func(*LifecycleReport){
			func(r *LifecycleReport) { r.ContextChecksum = "" },
			func(r *LifecycleReport) { r.ContextChecksum = checksum([]byte("another context")) },
			func(r *LifecycleReport) { r.SchemaVersion = "1.0.0" },
			func(r *LifecycleReport) { r.SchemaVersion = "1.1.0" },
			func(r *LifecycleReport) { r.Owner.Generation++ },
			func(r *LifecycleReport) {
				if private {
					r.ParentOwner = nil
				} else {
					parent := owner
					parent.InstanceID = "parent"
					r.ParentOwner = &parent
				}
			},
		} {
			changed := report
			change(&changed)
			bad, _ := json.Marshal(changed)
			if _, err := decodeLifecycleReport(bad, command); err == nil {
				t.Fatal("unbound context or parent accepted")
			}
		}
		alias := bytes.Replace(raw, []byte(`"contextChecksum":`), []byte(`"ContextChecksum":`), 1)
		if _, err := decodeLifecycleReport(alias, command); err == nil {
			t.Fatal("context field alias accepted")
		}
		command.SchemaVersion, command.ContextChecksum = "1.0.0", ""
		if private {
			command.SchemaVersion = "1.1.0"
		}
		if _, err := decodeLifecycleReport(raw, command); err == nil {
			t.Fatal("context extension accepted by legacy protocol")
		}
	}
}
