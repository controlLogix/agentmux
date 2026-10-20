package plugins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func nativeObservationFixture(t *testing.T) (*os.File, string, NativeObservabilityOptions, ContextTags) {
	t.Helper()
	f := newNativeAuthorityFixture(t)
	path := filepath.Join(privateTestDirectory(t), "diagnostics.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	options := NativeObservabilityOptions{HubID: "context_hub", Bindings: map[string]PackagePin{f.binding.Owner.InstanceID: f.binding.Owner.Pin}, EventCodes: []string{"started"}, SpanCodes: []string{"execute"}, MetricCodes: []string{"attempts"}, MaxBytes: 65536}
	tags := ContextTags{Owner: f.binding.Owner, HubID: options.HubID, OperationID: "original_operation", PrincipalID: "original_principal", OrganizationID: "original_org", AuthenticatedIdentityRef: &ContextReference{"caller_identity", "context_hub", 1}, EffectiveActorRef: &ContextReference{"effective_actor", "context_hub", 1}}
	return file, path, options, tags
}

func TestNativeObservabilityWritesAdmittedRecordsThroughOwnedDescriptor(t *testing.T) {
	file, path, options, tags := nativeObservationFixture(t)
	owner, err := NewNativeObservability(context.Background(), file, options)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// Mutating caller-owned declarations cannot change the admitted code set.
	options.EventCodes[0] = "substituted"
	delete(options.Bindings, tags.Owner.InstanceID)
	span := "span_" + strings.Repeat("a", 64)
	checks := []error{owner.Log(context.Background(), ContextLogRecord{Tags: tags, EventCode: "started"}), owner.Trace(context.Background(), ContextTraceRecord{Tags: tags, SpanCode: "execute", SpanHandle: span, Action: "start"}), owner.Trace(context.Background(), ContextTraceRecord{Tags: tags, SpanCode: "execute", SpanHandle: span, Action: "finish", OutcomeCode: "completed"}), owner.Metric(context.Background(), ContextMetricRecord{Tags: tags, MetricCode: "attempts", Value: 1})}
	for _, err := range checks {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	count := 0
	for scanner.Scan() {
		var record nativeObservation
		if json.Unmarshal(scanner.Bytes(), &record) != nil || !nativeCapabilityEqual(contextJSON(record.Tags), contextJSON(tags)) || record.SchemaVersion != "1.0.0" || record.RecordedAt == "" {
			t.Fatal("diagnostic lost admitted attribution")
		}
		count++
	}
	if scanner.Err() != nil || count != 4 {
		t.Fatal("diagnostic records were lost or split")
	}
	if owner.Log(context.Background(), ContextLogRecord{Tags: tags, EventCode: "started"}) == nil {
		t.Fatal("closed owner accepted a diagnostic")
	}
}

func TestNativeObservabilityRefusesUndeclaredOrCanceledRecords(t *testing.T) {
	file, path, options, tags := nativeObservationFixture(t)
	owner, err := NewNativeObservability(context.Background(), file, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wrong := tags
	wrong.HubID = "another_hub"
	for _, err := range []error{owner.Log(context.Background(), ContextLogRecord{Tags: tags, EventCode: "private arbitrary text"}), owner.Log(ctx, ContextLogRecord{Tags: tags, EventCode: "started"}), owner.Log(context.Background(), ContextLogRecord{Tags: wrong, EventCode: "started"}), owner.Trace(context.Background(), ContextTraceRecord{Tags: tags, SpanCode: "execute", SpanHandle: "child_chosen", Action: "start"}), owner.Metric(context.Background(), ContextMetricRecord{Tags: tags, MetricCode: "attempts", Value: 1e13})} {
		if err == nil {
			t.Fatal("unadmitted diagnostic accepted")
		}
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) != 0 {
		t.Fatal("refused diagnostic wrote private data")
	}
}

func TestNativeObservabilityRetainsFullOrNoLongerPrivateDestination(t *testing.T) {
	for _, kind := range []string{"full", "mode"} {
		t.Run(kind, func(t *testing.T) {
			file, path, options, tags := nativeObservationFixture(t)
			if kind == "full" {
				if _, err := file.Write(bytes.Repeat([]byte{'x'}, int(options.MaxBytes)-1)); err != nil {
					t.Fatal(err)
				}
			}
			owner, err := NewNativeObservability(context.Background(), file, options)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "mode" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			if owner.Log(context.Background(), ContextLogRecord{Tags: tags, EventCode: "started"}) == nil || owner.Close(context.Background()) == nil {
				t.Fatal("failed destination reported successful cleanup")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed sink changed or removed retained diagnostics")
			}
			if !owner.CleanupComplete() {
				t.Fatal("joined original sink still reported unfinished cleanup")
			}
			if owner.Close(context.Background()) == nil {
				t.Fatal("original sink failure was forgotten")
			}
		})
	}
}

func TestNativeObservabilityConcurrentCloseJoinsOriginalWriter(t *testing.T) {
	file, path, options, tags := nativeObservationFixture(t)
	owner, err := NewNativeObservability(context.Background(), file, options)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_ = owner.Log(context.Background(), ContextLogRecord{Tags: tags, EventCode: "started"})
		}()
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if !completed(owner.done) || !owner.closed {
		t.Fatal("close abandoned original writer")
	}
	before, _ := os.ReadFile(path)
	if owner.Metric(context.Background(), ContextMetricRecord{Tags: tags, MetricCode: "attempts", Value: 1}) == nil {
		t.Fatal("joined owner accepted new work")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("joined writer changed retained output")
	}
}
