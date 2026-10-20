package plugins

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

func TestContextClockElapsedSurvivesWallClockChange(t *testing.T) {
	var offset atomic.Int64
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		ports.Now = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	})
	readElapsed := func() int64 {
		t.Helper()
		reply := f.call(t, "clock", "elapsed", nil, map[string]any{})
		var value struct {
			ElapsedMS int64 `json:"elapsedMs"`
		}
		if reply.Code != "ok" || json.Unmarshal(reply.Value, &value) != nil || value.ElapsedMS < 0 || uint64(value.ElapsedMS) > maxGeneration {
			t.Fatal("invalid monotonic elapsed reply")
		}
		return value.ElapsedMS
	}
	handle, result := f.dispatch(t, context.Background(), "a")
	first := readElapsed()
	offset.Store(int64(-time.Hour))
	if reply := f.call(t, "clock", "wait", &handle, map[string]any{"durationMs": 20}); reply.Code != "ok" {
		t.Fatal("bounded clock wait failed")
	}
	second := readElapsed()
	if second-first < 20 {
		t.Fatal("elapsed clock did not include completed wait")
	}
	wall := f.call(t, "clock", "now", nil, map[string]any{})
	var value struct {
		Now string `json:"now"`
	}
	if wall.Code != "ok" || json.Unmarshal(wall.Value, &value) != nil {
		t.Fatal("UTC clock reply failed")
	}
	now, err := time.Parse(time.RFC3339Nano, value.Now)
	if err != nil || time.Since(now) < 59*time.Minute {
		t.Fatal("UTC clock ignored its source")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("operation failed")
	}
}

func TestContextClockElapsedRequiresCurrentAuthority(t *testing.T) {
	f := newContextTestFixture(t, nil)
	f.authority.deny.Store(true)
	if reply := f.call(t, "clock", "elapsed", nil, map[string]any{}); reply.Code != "context_authority_unavailable" {
		t.Fatal("elapsed service bypassed current authority")
	}
}

func TestContextClockElapsedRejectsChildOriginAndOperation(t *testing.T) {
	f := newContextTestFixture(t, nil)
	for _, raw := range [][]byte{
		f.request("clock", "elapsed", nil, map[string]any{"elapsedMs": 12}),
		f.request("clock", "elapsed", func() *string { value := contextTestNonce("operation"); return &value }(), map[string]any{}),
	} {
		if validateContextJSON("plugin-context-request", raw) == nil {
			t.Fatal("child selected elapsed clock origin or operation")
		}
	}
}

func TestContextClockWaitRechecksAuthorityAfterWake(t *testing.T) {
	entered := make(chan struct{})
	var calls atomic.Int32
	var armed atomic.Bool
	f := newContextTestFixture(t, func(_ *ContextBinding, ports *ContextPorts) {
		original := ports.Authority
		ports.Authority = contextBoundsAuthority{ContextAuthority: original, check: func(ctx context.Context, owner OwnerReference, instance ContextInstanceAdmission, operation *ContextOperationAdmission) error {
			if operation != nil && armed.Load() && calls.Add(1) == 1 {
				close(entered)
				return nil
			}
			if operation != nil && armed.Load() {
				return pluginError("fixture_revoked")
			}
			return original.Recheck(ctx, owner, instance, operation)
		}}
	})
	handle, result := f.dispatch(t, context.Background(), "a")
	armed.Store(true)
	reply := f.call(t, "clock", "wait", &handle, map[string]any{"durationMs": 1})
	<-entered
	if reply.Code != "context_authority_unavailable" {
		t.Fatal("clock wake reused prior authority")
	}
	if calls.Load() != 2 {
		t.Fatal("clock did not recheck after its initial admission")
	}
	f.lease.Invalidate()
	<-result
}
