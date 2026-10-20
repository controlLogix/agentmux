package plugins

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func profileTestString(value string) *string { return &value }

func TestProfileContextValidationAndCopies(t *testing.T) {
	for _, value := range []string{"", " leading", "trailing ", "a\nb", "a\u0085b", "a\u2028b", "a\u2029b", strings.Repeat("é", 65), string([]byte{0xff})} {
		if validProfileContext(&ProfileContext{Environment: &value}) {
			t.Fatal("invalid display value accepted")
		}
	}
	if validProfileContext(&ProfileContext{}) {
		t.Fatal("empty metadata accepted")
	}
	original := &ProfileContext{Environment: profileTestString("staging"), Project: profileTestString("Display project")}
	copied := cloneContextBinding(ContextBinding{ProfileContext: original})
	*original.Environment = "changed"
	*original.Project = "changed"
	if *copied.ProfileContext.Environment != "staging" || *copied.ProfileContext.Project != "Display project" {
		t.Fatal("binding retained mutable metadata")
	}
	if !validProfileContext(nil) || !validProfileContext(&ProfileContext{Project: profileTestString(strings.Repeat("é", 64))}) {
		t.Fatal("valid metadata refused")
	}
}

func TestProfileContextDescriptorOmissionAndSnapshot(t *testing.T) {
	for _, supplied := range []*ProfileContext{nil,
		{Environment: profileTestString("staging")},
		{Project: profileTestString("Display project")},
		{Environment: profileTestString("staging"), Project: profileTestString("Display project")},
	} {
		t.Run(string(contextJSON(supplied)), func(t *testing.T) {
			expected := contextJSON(supplied)
			f := newContextTestFixture(t, func(binding *ContextBinding, _ *ContextPorts) { binding.ProfileContext = supplied })
			if supplied != nil {
				if supplied.Environment != nil {
					*supplied.Environment = "changed"
				}
				if supplied.Project != nil {
					*supplied.Project = "changed"
				}
			}
			var descriptor map[string]json.RawMessage
			if err := json.Unmarshal(f.lease.Descriptor(), &descriptor); err != nil {
				t.Fatal(err)
			}
			raw, present := descriptor["profileContext"]
			if supplied == nil {
				if present {
					t.Fatal("absent metadata was inferred")
				}
			} else if string(raw) != string(expected) {
				t.Fatalf("metadata changed: %s", raw)
			}
			binding := cloneContextBinding(f.lease.binding)
			binding.ProfileContext = &ProfileContext{}
			if _, err := f.provider.Open(context.Background(), binding); err == nil {
				t.Fatal("empty profile admitted")
			}
		})
	}
}

func TestProfileContextDisplayProjectDoesNotAuthorizeOperation(t *testing.T) {
	f := newContextTestFixture(t, func(binding *ContextBinding, _ *ContextPorts) {
		binding.ProfileContext = &ProfileContext{Project: profileTestString("Display project")}
	})
	handle, result := f.dispatch(t, context.Background(), "a")
	if reply := f.call(t, "logger", "record", &handle, map[string]any{"eventCode": "operation_started"}); reply.Code != "ok" {
		t.Fatal("log rejected")
	}
	f.complete(handle)
	if contextTestResult(t, result).err != nil {
		t.Fatal("operation failed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.logs) != 1 || f.logs[0].Tags.ProjectID == nil || *f.logs[0].Tags.ProjectID != "project_a" {
		t.Fatal("display project changed signed authorization scope")
	}
}

func TestProfileContextCannotComeFromDriverJSON(t *testing.T) {
	var options NativeDriverOptions
	decoder := json.NewDecoder(strings.NewReader(`{"profileContext":{"project":"arbitrary"}}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&options) == nil {
		t.Fatal("composition JSON supplied host-only metadata")
	}
}
