package launcher

import (
	"context"
	"reflect"
	"time"
)

// Failed reads are private diagnostic facts, never successful observations.
type bootstrapFailedRead struct {
	Kind                    string `json:"kind"`
	ElapsedNanoseconds      int64  `json:"elapsedNanoseconds"`
	RemainingNanoseconds    int64  `json:"remainingNanoseconds"`
	EffectiveCapNanoseconds int64  `json:"effectiveCapNanoseconds"`
}

func validBootstrapFailedRead(m *bootstrapFailedRead) bool {
	if m == nil || m.ElapsedNanoseconds < 0 || m.ElapsedNanoseconds > int64(120*time.Second) || m.RemainingNanoseconds <= 0 || m.RemainingNanoseconds > int64(60*time.Second) || m.EffectiveCapNanoseconds <= 0 || m.EffectiveCapNanoseconds > int64(4*time.Second) || m.EffectiveCapNanoseconds > m.RemainingNanoseconds {
		return false
	}
	switch m.Kind {
	case "endpoint", "version", "compose_version", "engine", "roster", "engine_stdio", "container_inspection", "image_inspection", "volume_inspection", "config_archive", "certificate_archive", "key_archive":
		return true
	}
	return false
}
func failedDockerRead(kind string, parent context.Context, started time.Time, remaining, effectiveCap time.Duration, cause error) error {
	if cause == nil || kind == "" || parent == nil {
		return cause
	}
	metric := &bootstrapFailedRead{kind, int64(time.Since(started)), int64(remaining), int64(effectiveCap)}
	if !validBootstrapFailedRead(metric) {
		return cause
	}
	failure := inspectionFailure("fixed_read", cause).(*dockerInspectionFailure)
	failure.failedRead = metric
	return failure
}
func copyBootstrapFailedRead(m *bootstrapFailedRead) *bootstrapFailedRead {
	if m == nil {
		return nil
	}
	copied := *m
	return &copied
}
func bootstrapFailedReadFromError(cause error) *bootstrapFailedRead {
	queue := []error{cause}
	var found *bootstrapFailedRead
	for inspected := 0; len(queue) > 0; inspected++ {
		if inspected >= 64 {
			return nil
		}
		current := queue[0]
		queue = queue[1:]
		if current == nil || (reflect.ValueOf(current).Kind() == reflect.Pointer && reflect.ValueOf(current).IsNil()) {
			continue
		}
		if e, ok := current.(*dockerInspectionFailure); ok && e.failedRead != nil {
			if !validBootstrapFailedRead(e.failedRead) || (found != nil && *found != *e.failedRead) {
				return nil
			}
			found = e.failedRead
		}
		if !diagnosticReviewedWrapper(current) {
			continue
		}
		switch known := current.(type) {
		case interface{ Unwrap() []error }:
			children := known.Unwrap()
			if len(children) > 63-inspected-len(queue) {
				return nil
			}
			queue = append(queue, children...)
		case interface{ Unwrap() error }:
			if len(queue) >= 63-inspected {
				return nil
			}
			queue = append(queue, known.Unwrap())
		}
	}
	return copyBootstrapFailedRead(found)
}
