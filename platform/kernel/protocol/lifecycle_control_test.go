package protocol

import (
	"strings"
	"testing"
	"time"
)

func lifecycleRequestFixture(now time.Time) LifecycleRequest {
	return LifecycleRequest{Version, "kernel-lifecycle-request", testScope(), strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32), "recover", "boot", 1, strings.Repeat("d", 32), now.UTC().Format(time.RFC3339Nano), now.Add(2 * time.Second).UTC().Format(time.RFC3339Nano)}
}

func TestLifecycleControlClosedScopeFreshnessAndAuthorityFields(t *testing.T) {
	now := time.Now()
	original := lifecycleRequestFixture(now)
	if _, err := DecodeLifecycleRequest(mustJSON(original), testScope(), now); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"scope", "epoch", "issuer", "request", "action", "role", "generation", "incarnation", "future", "expired", "long", "unknown", "duplicate", "pid"} {
		t.Run(kind, func(t *testing.T) {
			request := original
			switch kind {
			case "scope":
				request.Scope.InstanceID = "other"
			case "epoch":
				request.SupervisorEpoch = ""
			case "issuer":
				request.LifecycleIncarnation = ""
			case "request":
				request.RequestID = ""
			case "action":
				request.Action = "execute"
			case "role":
				request.Role = "outside-plugin"
			case "generation":
				request.ExpectedGeneration = MaxRevision + 1
			case "incarnation":
				request.ExpectedIncarnation = "arbitrary"
			case "future":
				request.IssuedAt = now.Add(time.Second).Format(time.RFC3339Nano)
			case "expired":
				request.ExpiresAt = now.Format(time.RFC3339Nano)
			case "long":
				request.ExpiresAt = now.Add(4 * time.Second).Format(time.RFC3339Nano)
			}
			data := mustJSON(request)
			switch kind {
			case "unknown":
				data = append(data[:len(data)-1], []byte(`,"authority":"invented"}`)...)
			case "duplicate":
				data = append(data[:len(data)-1], []byte(`,"action":"recover"}`)...)
			case "pid":
				data = append(data[:len(data)-1], []byte(`,"pid":123}`)...)
			}
			if _, err := DecodeLifecycleRequest(data, testScope(), now); err == nil {
				t.Fatal("invalid lifecycle request accepted")
			}
		})
	}
	if _, err := DecodeCommand(mustJSON(original), testScope(), "kernel-lifecycle"); err == nil {
		t.Fatal("lifecycle mutation became an observation command")
	}
}

func TestLifecycleInventoryAndResultsDoNotInventReadiness(t *testing.T) {
	now := time.Now()
	request := lifecycleRequestFixture(now)
	inventory := LifecycleInventory{Version, "kernel-lifecycle-inventory", testScope(), request.SupervisorEpoch, 1, nil, request.IssuedAt, request.ExpiresAt}
	for _, role := range Roles() {
		inventory.Members = append(inventory.Members, LifecycleMember{role, 1, "", "running"})
	}
	if _, err := DecodeLifecycleInventory(mustJSON(inventory), testScope(), now); err != nil {
		t.Fatal(err)
	}
	inventory.Members[0].State = "ready"
	if _, err := DecodeLifecycleInventory(mustJSON(inventory), testScope(), now); err == nil {
		t.Fatal("ownership inventory invented readiness")
	}
	inventory.Members[0] = inventory.Members[1]
	if _, err := DecodeLifecycleInventory(mustJSON(inventory), testScope(), now); err == nil {
		t.Fatal("duplicate owned role accepted")
	}
	result := LifecycleResult{Version, "kernel-lifecycle-result", testScope(), request.SupervisorEpoch, request.RequestID, request.Role, 2, "completed", "owned_operation_completed", request.IssuedAt, request.ExpiresAt}
	if _, err := DecodeLifecycleResult(mustJSON(result), testScope(), now); err != nil {
		t.Fatal(err)
	}
	result.Code = "private arbitrary detail"
	if _, err := DecodeLifecycleResult(mustJSON(result), testScope(), now); err == nil {
		t.Fatal("private error text entered lifecycle result")
	}
}
