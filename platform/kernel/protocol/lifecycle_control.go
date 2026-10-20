package protocol

import (
	"errors"
	"time"
)

// Lifecycle controls stay on the protected lifecycle command subject. They
// identify owned slots, never executable paths, arguments, PIDs or membership.
type LifecycleRequest struct {
	SchemaVersion        string `json:"schemaVersion"`
	Kind                 string `json:"kind"`
	Scope                Scope  `json:"scope"`
	SupervisorEpoch      string `json:"supervisorEpoch"`
	LifecycleIncarnation string `json:"lifecycleIncarnation"`
	RequestID            string `json:"requestId"`
	Action               string `json:"action"`
	Role                 string `json:"role"`
	ExpectedGeneration   uint64 `json:"expectedGeneration"`
	ExpectedIncarnation  string `json:"expectedIncarnation"`
	IssuedAt             string `json:"issuedAt"`
	ExpiresAt            string `json:"expiresAt"`
}

type LifecycleMember struct {
	Role        string `json:"role"`
	Generation  uint64 `json:"generation"`
	Incarnation string `json:"incarnation"`
	State       string `json:"state"`
}

// An inventory reports supervisor ownership, not broker or application readiness.
type LifecycleInventory struct {
	SchemaVersion   string            `json:"schemaVersion"`
	Kind            string            `json:"kind"`
	Scope           Scope             `json:"scope"`
	SupervisorEpoch string            `json:"supervisorEpoch"`
	Revision        uint64            `json:"revision"`
	Members         []LifecycleMember `json:"members"`
	IssuedAt        string            `json:"issuedAt"`
	ExpiresAt       string            `json:"expiresAt"`
}

type LifecycleResult struct {
	SchemaVersion   string `json:"schemaVersion"`
	Kind            string `json:"kind"`
	Scope           Scope  `json:"scope"`
	SupervisorEpoch string `json:"supervisorEpoch"`
	RequestID       string `json:"requestId"`
	Role            string `json:"role"`
	Generation      uint64 `json:"generation"`
	Outcome         string `json:"outcome"`
	Code            string `json:"code"`
	IssuedAt        string `json:"issuedAt"`
	ExpiresAt       string `json:"expiresAt"`
}

func lifecycleFresh(issued, expires string, now time.Time) bool {
	start, e1 := time.Parse(time.RFC3339Nano, issued)
	end, e2 := time.Parse(time.RFC3339Nano, expires)
	return e1 == nil && e2 == nil && !start.After(now) && now.Before(end) && end.After(start) && end.Sub(start) <= 3*time.Second
}

func DecodeLifecycleRequest(data []byte, scope Scope, now time.Time) (LifecycleRequest, error) {
	var request LifecycleRequest
	if decodeFrameJSON(data, &request) != nil || request.SchemaVersion != Version || request.Kind != "kernel-lifecycle-request" ||
		request.Scope != scope || !scope.valid() || !incarnation.MatchString(request.SupervisorEpoch) ||
		!incarnation.MatchString(request.LifecycleIncarnation) || !incarnation.MatchString(request.RequestID) ||
		!validRole(request.Role) || (request.Action != "recover" && request.Action != "stop") || request.ExpectedGeneration == 0 || request.ExpectedGeneration > MaxRevision ||
		(request.ExpectedIncarnation != "" && !incarnation.MatchString(request.ExpectedIncarnation)) ||
		!lifecycleFresh(request.IssuedAt, request.ExpiresAt, now) {
		return LifecycleRequest{}, errors.New("kernel_lifecycle_request_invalid")
	}
	return request, nil
}

func DecodeLifecycleInventory(data []byte, scope Scope, now time.Time) (LifecycleInventory, error) {
	var inventory LifecycleInventory
	if decodeFrameJSON(data, &inventory) != nil || inventory.SchemaVersion != Version || inventory.Kind != "kernel-lifecycle-inventory" ||
		inventory.Scope != scope || !scope.valid() || !incarnation.MatchString(inventory.SupervisorEpoch) || inventory.Revision == 0 || inventory.Revision > MaxRevision ||
		len(inventory.Members) != 4 || !lifecycleFresh(inventory.IssuedAt, inventory.ExpiresAt, now) {
		return LifecycleInventory{}, errors.New("kernel_lifecycle_inventory_invalid")
	}
	seen := map[string]bool{}
	for _, member := range inventory.Members {
		if !validRole(member.Role) || seen[member.Role] || member.Generation == 0 || member.Generation > MaxRevision ||
			(member.Incarnation != "" && !incarnation.MatchString(member.Incarnation)) ||
			(member.State != "running" && member.State != "exited" && member.State != "stopped" && member.State != "failed") {
			return LifecycleInventory{}, errors.New("kernel_lifecycle_inventory_invalid")
		}
		seen[member.Role] = true
	}
	return inventory, nil
}

func DecodeLifecycleResult(data []byte, scope Scope, now time.Time) (LifecycleResult, error) {
	var result LifecycleResult
	if decodeFrameJSON(data, &result) != nil || result.SchemaVersion != Version || result.Kind != "kernel-lifecycle-result" ||
		result.Scope != scope || !scope.valid() || !incarnation.MatchString(result.SupervisorEpoch) ||
		!incarnation.MatchString(result.RequestID) || !validRole(result.Role) || result.Generation == 0 || result.Generation > MaxRevision ||
		!lifecycleFresh(result.IssuedAt, result.ExpiresAt, now) ||
		!((result.Outcome == "completed" && result.Code == "owned_operation_completed") ||
			(result.Outcome == "failed" && result.Code == "owned_operation_failed") ||
			(result.Outcome == "refused" && result.Code == "owned_operation_refused")) {
		return LifecycleResult{}, errors.New("kernel_lifecycle_result_invalid")
	}
	return result, nil
}
