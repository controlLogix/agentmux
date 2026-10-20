//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type unknownDiagnosticFailure struct{}

func (unknownDiagnosticFailure) Error() string { panic("unknown error method called") }
func (unknownDiagnosticFailure) Unwrap() error { panic("unknown unwrap method called") }

func TestFailureCategoriesKeepsPrivateCausesClosed(t *testing.T) {
	unknown := unknownDiagnosticFailure{}
	joined := errors.Join(failed("fixture_child_roster_count_refused", unknown), failed("fixture_role_images_close_failed", unknown))
	want := []string{"fixture_child_roster_count_refused", "fixture_role_images_close_failed"}
	if got := FailureCategories(joined); !reflect.DeepEqual(got, want) {
		t.Fatal("native failure categories lost an admission or cleanup category")
	}
	if got := FailureCategories(unknown); !reflect.DeepEqual(got, []string{"fixture_unclassified_failure"}) {
		t.Fatal("unknown error supplied a native failure category")
	}
	if got := FailureCategories(failed("private arbitrary text", unknown)); !reflect.DeepEqual(got, []string{"fixture_unclassified_failure"}) {
		t.Fatal("unknown private stage escaped the closed category list")
	}
}

type refusedCandidateAdmission struct{}

func (refusedCandidateAdmission) check() error { return unknownDiagnosticFailure{} }

func TestCandidateScanFailureCategories(t *testing.T) {
	for _, test := range []struct {
		parent    uint64
		admission admissionCheck
		category  string
	}{
		{0, nil, "fixture_candidate_parent_invalid"},
		{1, nil, "fixture_candidate_admission_invalid"},
		{1, refusedCandidateAdmission{}, "fixture_candidate_admission_refused"},
	} {
		_, err := nativeCandidates(501, test.parent, test.admission)
		want := []string{"fixture_child_scan_refused", test.category}
		if got := FailureCategories(failed("fixture_child_scan_refused", err)); !reflect.DeepEqual(got, want) {
			t.Fatalf("candidate refusal category: got %v, want %v", got, want)
		}
	}
	for _, wrapper := range []string{"fixture_child_scan_refused", "fixture_child_roster_changed"} {
		for _, detail := range []string{
			"fixture_native_query_refused", "fixture_native_layout_refused", "fixture_native_identity_refused",
			"fixture_native_status_refused", "fixture_native_process_exited", "fixture_candidate_lineage_refused", "fixture_candidate_credentials_refused",
		} {
			err := failed(wrapper, failed("fixture_candidate_identity_refused", failed(detail, unknownDiagnosticFailure{})))
			want := []string{wrapper, "fixture_candidate_identity_refused", detail}
			if detail == "fixture_native_query_refused" {
				want = append(want, "fixture_native_query_errno_unclassified")
			}
			if got := FailureCategories(err); !reflect.DeepEqual(got, want) {
				t.Fatal("scan lost a fixed observation reason or exposed its private cause")
			}
		}
		for _, cause := range []error{unknownDiagnosticFailure{}, failed("PRIVATE_NATIVE_DETAIL", unknownDiagnosticFailure{})} {
			err := failed(wrapper, failed("fixture_candidate_identity_refused", cause))
			if got := FailureCategories(err); !reflect.DeepEqual(got, []string{wrapper, "fixture_candidate_identity_refused"}) {
				t.Fatal("candidate observation exposed an unknown private cause")
			}
		}
		for _, stage := range []string{"fixture_candidate_enumeration_refused", "fixture_candidate_identity_refused"} {
			err := failed(wrapper, failed(stage, unknownDiagnosticFailure{}))
			if got := FailureCategories(err); !reflect.DeepEqual(got, []string{wrapper, stage}) {
				t.Fatal("scan lost a fixed candidate category")
			}
		}
		for _, cause := range []error{unknownDiagnosticFailure{}, failed("PRIVATE_CANDIDATE_DETAIL", unknownDiagnosticFailure{})} {
			if got := FailureCategories(failed(wrapper, cause)); !reflect.DeepEqual(got, []string{wrapper}) {
				t.Fatal("scan exposed an unknown private cause")
			}
		}
	}
}

func TestNativeQueryErrnoCategoriesPreserveOriginalRefusal(t *testing.T) {
	for _, test := range []struct {
		errno unix.Errno
		code  string
	}{
		{unix.ESRCH, "esrch"}, {unix.EPERM, "eperm"}, {unix.EACCES, "eacces"},
		{unix.EINVAL, "einval"}, {unix.EINTR, "eintr"}, {unix.EAGAIN, "eagain"},
		{unix.EIO, "eio"}, {unix.ENOMEM, "enomem"}, {unix.EFAULT, "efault"},
		{unix.ENOSYS, "enosys"}, {unix.ENOTSUP, "enotsup"}, {unix.ENOENT, "enoent"},
		{unix.Errno(65535), "other"},
	} {
		t.Run(test.code, func(t *testing.T) {
			id, original := nativeIdentityResult(41, nativeIdentityQueryRefused, int(test.errno), identity{PID: 41, Unique: 91, Version: 2})
			want := []string{"fixture_native_query_refused", "fixture_native_query_errno_" + test.code}
			if got := FailureCategories(original); !reflect.DeepEqual(got, want) {
				t.Fatal("original typed errno lost its fixed diagnostic category")
			}
			if id != (identity{}) || !errors.Is(original, test.errno) || ChildNotPresent(original) || NoSurvivingHost(original) {
				t.Fatal("query diagnostic changed its original refusal, cause or absence classification")
			}
			if proof, err := singleChildResult(nil, original); proof != nil || err != original {
				t.Fatal("query diagnostic gained a proof or replaced the original failure")
			}
		})
	}
}

func TestNativeQueryErrnoCategoriesNeverInspectUnknownCauses(t *testing.T) {
	for _, test := range []struct {
		cause error
		code  string
	}{
		{nil, "unavailable"}, {unix.Errno(0), "unavailable"},
		{unknownDiagnosticFailure{}, "unclassified"},
		{failed("PRIVATE_NATIVE_DETAIL", unix.EPERM), "unclassified"},
		{errors.Join(unix.ESRCH, unknownDiagnosticFailure{}), "unclassified"},
	} {
		original := failed("fixture_native_query_refused", test.cause)
		want := []string{"fixture_native_query_refused", "fixture_native_query_errno_" + test.code}
		if got := FailureCategories(original); !reflect.DeepEqual(got, want) {
			t.Fatal("unknown or wrapped cause supplied an errno through formatting or unwrapping")
		}
	}
}

func TestNativeQueryErrnoCategoriesReachExistingCheckpointWrappers(t *testing.T) {
	original := failed("fixture_native_query_refused", unix.EPERM)
	for _, wrapper := range []string{"fixture_child_scan_refused", "fixture_child_roster_changed"} {
		failure := failed(wrapper, failed("fixture_candidate_identity_refused", original))
		want := []string{wrapper, "fixture_candidate_identity_refused", "fixture_native_query_refused", "fixture_native_query_errno_eperm"}
		if got := FailureCategories(failure); !reflect.DeepEqual(got, want) {
			t.Fatal("existing checkpoint scan wrapper lost the original native errno")
		}
		if !errors.Is(failure, unix.EPERM) || ChildNotPresent(failure) || NoSurvivingHost(failure) {
			t.Fatal("scan wrapper changed native refusal or gained absence authority")
		}
	}
}

func TestArgumentQueryErrnoReachesInspectionCheckpoint(t *testing.T) {
	for _, test := range []struct {
		cause error
		code  string
	}{
		{unix.EINTR, "eintr"}, {unix.EINVAL, "einval"}, {unix.ESRCH, "esrch"},
		{nil, "unavailable"}, {unknownDiagnosticFailure{}, "unclassified"},
		{errors.Join(unix.ESRCH), "unclassified"},
	} {
		original := failed("fixture_arguments_query_refused", test.cause)
		wrapped := failed("fixture_child_roster_changed", failed("fixture_inspection_owner_retained", failed("fixture_inspection_arguments_refused", original)))
		want := []string{"fixture_child_roster_changed", "fixture_inspection_owner_retained", "fixture_inspection_arguments_refused", "fixture_arguments_query_refused", "fixture_native_query_errno_" + test.code}
		if got := FailureCategories(wrapped); !reflect.DeepEqual(got, want) {
			t.Fatal("inspection checkpoint lost the original query category or inspected an unknown cause")
		}
		if ChildNotPresent(wrapped) || NoSurvivingHost(wrapped) {
			t.Fatal("argument query diagnostic granted absence authority")
		}
	}
}

func TestChildRosterDiagnosticKeepsAnchorAndRedactsComparisons(t *testing.T) {
	parentImage := expectedImage{Path: "/private/parent-python", Args: []string{"PRIVATE_PARENT_ARGUMENT"}}
	parent := &Proof{proofState: &proofState{expected: parentImage}}
	expected := expectedImage{Path: "/private/expected-child", Args: []string{"PRIVATE_EXPECTED_ARGUMENT"}}
	for _, test := range []struct {
		path                           string
		args                           []string
		slot                           int
		reason                         string
		image, parentImage, parentArgs bool
		index                          int
	}{
		{parentImage.Path, parentImage.literalArguments(), -1, "executable_path_mismatch", false, true, true, 0},
		{expected.Path, []string{expected.Path, "PRIVATE_CHANGED_ARGUMENT"}, -1, "literal_arguments_mismatch", true, false, false, 1},
		{expected.Path, expected.literalArguments(), 0, "duplicate_expected_slot", true, false, false, -1},
	} {
		err := childRosterMismatch(parent, []expectedImage{expected}, test.path, test.args, test.slot)
		owner := err.(*failure).retained.(*childMismatchOwner)
		if owner.anchor != parent {
			t.Fatal("mismatch lost its original in-process anchor")
		}
		d := ChildRosterDiagnostics(errors.Join(err, unknownDiagnosticFailure{}))
		if len(d) != 1 || d[0].Reason != test.reason || d[0].ExpectedImageMatched != test.image || d[0].ParentImageMatched != test.parentImage || d[0].ParentArgumentsMatched != test.parentArgs || d[0].FirstDifferentArgument != test.index {
			t.Fatal("closed child comparison did not distinguish path, arguments or duplicate match")
		}
		raw, e := json.Marshal(d)
		if e != nil || strings.Contains(string(raw), "/private/") || strings.Contains(string(raw), "PRIVATE_") {
			t.Fatal("private image or argument escaped diagnostic")
		}
		d[0].Reason = "changed"
		if ChildRosterDiagnostics(err)[0].Reason != test.reason {
			t.Fatal("caller changed the retained diagnostic")
		}
	}
}
