//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCandidateLineageKeepsUnknownAndRelatedFailuresClosed(t *testing.T) {
	base := identity{PID: 41, Version: 2, UID: 501, RealUID: 501, Status: 2, Unique: 100, ParentUnique: 90}
	for _, test := range []struct {
		name    string
		change  func(*identity)
		include bool
		stage   string
	}{
		{"related live", func(*identity) {}, true, ""},
		{"unrelated live", func(id *identity) { id.ParentUnique = 91 }, false, ""},
		{"unrelated zombie", func(id *identity) { id.ParentUnique = 91; id.Status = 5 }, false, ""},
		{"related zombie", func(id *identity) { id.Status = 5 }, false, "fixture_native_process_exited"},
		{"unknown parent", func(id *identity) { id.ParentUnique = 0 }, false, "fixture_candidate_lineage_refused"},
		{"unknown zombie parent", func(id *identity) { id.ParentUnique = 0; id.Status = 5 }, false, "fixture_candidate_lineage_refused"},
		{"unknown creation", func(id *identity) { id.Unique = 0; id.ParentUnique = 91 }, false, "fixture_candidate_lineage_refused"},
		{"unknown version", func(id *identity) { id.Version = 0; id.ParentUnique = 91 }, false, "fixture_candidate_lineage_refused"},
		{"unknown status", func(id *identity) { id.ParentUnique = 91; id.Status = 0 }, false, "fixture_native_status_refused"},
		{"related credentials", func(id *identity) { id.RealUID = 502 }, false, "fixture_candidate_credentials_refused"},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := base
			test.change(&id)
			include, err := candidateBelongsToAnchor(id, 501, 90)
			if include != test.include {
				t.Fatal("candidate lineage changed the expected roster inclusion")
			}
			if test.stage == "" {
				if err != nil {
					t.Fatal("proven unrelated or live related candidate was refused")
				}
				return
			}
			want := []string{"fixture_child_scan_refused", "fixture_candidate_identity_refused", test.stage}
			got := FailureCategories(failed("fixture_child_scan_refused", failed("fixture_candidate_identity_refused", err)))
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("candidate failure: got %v, want %v", got, want)
			}
		})
	}
}

func TestNativeIdentityReadRequiresCompleteSuccessfulQuery(t *testing.T) {
	valid := identity{PID: 41, Version: 2, UID: 501, RealUID: 501, Status: 5, Unique: 100, ParentUnique: 91}
	for _, test := range []struct {
		name  string
		code  int
		id    identity
		stage string
	}{
		{"query error", nativeIdentityQueryRefused, valid, "fixture_native_query_refused"},
		{"short read", nativeIdentityLayoutRefused, valid, "fixture_native_layout_refused"},
		{"unknown result", 99, valid, "fixture_native_layout_refused"},
		{"missing identity", nativeIdentityReadOK, identity{}, "fixture_native_identity_refused"},
		{"wrong pid", nativeIdentityReadOK, identity{PID: 42, Version: 2, Unique: 100}, "fixture_native_identity_refused"},
	} {
		t.Run(test.name, func(t *testing.T) {
			id, err := nativeIdentityResult(41, test.code, int(unix.ESRCH), test.id)
			want := []string{test.stage}
			if test.code == nativeIdentityQueryRefused {
				want = append(want, "fixture_native_query_errno_esrch")
			}
			if id != (identity{}) || !reflect.DeepEqual(FailureCategories(err), want) {
				t.Fatal("failed native query exposed an identity or lost its fixed reason")
			}
			if test.code == nativeIdentityQueryRefused && !errors.Is(err, unix.ESRCH) {
				t.Fatal("query failure lost its private native error")
			}
		})
	}
	id, err := nativeIdentityResult(41, nativeIdentityReadOK, 0, valid)
	if err != nil || id != valid {
		t.Fatal("complete query lost immutable lineage for an unrelated zombie")
	}
	if err := liveIdentityStatus(id); !reflect.DeepEqual(FailureCategories(err), []string{"fixture_native_process_exited"}) {
		t.Fatal("ordinary process observation accepted a zombie")
	}
}
