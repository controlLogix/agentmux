package plugins

import (
	"context"
	"strings"
	"testing"
)

func TestContextMetricNamesAndLabelsStayBounded(t *testing.T) {
	f := newContextTestFixture(t, nil)
	handle, result := f.dispatch(t, context.Background(), "a")
	for _, parameters := range []map[string]any{
		{"metricCode": "undeclared", "value": 1},
		{"metricCode": strings.Repeat("a", 97), "value": 1},
		{"metricCode": "calls", "value": 1, "labels": map[string]any{"tenant": "forged"}},
		{"metricCode": "calls", "value": 1000000000001},
	} {
		if f.call(t, "metrics", "add", &handle, parameters).Outcome != "rejected" {
			t.Fatal("unbounded or undeclared metric accepted")
		}
	}
	if f.call(t, "metrics", "add", &handle, map[string]any{"metricCode": "calls", "value": 1}).Code != "ok" {
		t.Fatal("declared metric rejected")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("operation failed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.metrics) != 1 || f.metrics[0].MetricCode != "calls" || f.metrics[0].Tags.Owner.Pin != f.lease.Owner().Pin {
		t.Fatal("metric name or host package identity changed")
	}
	contextTestActorTags(t, f.metrics[0].Tags, "a")
}
