//go:build linux || darwin

package launcher

import (
	"context"
	"testing"
)

func TestEnrolledDoctorRequiresCurrentPrivateAdmission(t *testing.T) {
	var absent *EnrolledHostPolicy
	if _, err := absent.Doctor(context.Background()); err == nil {
		t.Fatal("missing policy authorized diagnostics")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := absent.Doctor(ctx); err == nil {
		t.Fatal("canceled diagnostic was admitted")
	}
	selection, _ := installedHostPolicyFixture(t)
	host, err := LoadEnrolledHostPolicy(selection)
	if err != nil {
		t.Fatal(err)
	}
	// The enrolled selection reaches the read-only doctor, which refuses an
	// ambient context override before starting the client or any host process.
	t.Setenv("DOCKER_CONTEXT", "not-the-enrolled-context")
	report, err := host.Doctor(context.Background())
	if err != nil || report.DiagnosticsPassed || doctorCheck(t, report, "profile").Code != DoctorEnvironmentConflict {
		t.Fatal("enrolled doctor lost the explicit selection refusal")
	}
	for _, service := range []string{"broker", "persistence", "protected-roles"} {
		if doctorCheck(t, report, service).Status != DoctorUnknown {
			t.Fatal("unobserved service became healthy")
		}
	}
	// A change after initial policy admission must fail before Docker inspection.
	host.record.InstanceID = "instance_ffffffffffffffffffffffffffffffff"
	if _, err := host.Doctor(context.Background()); err == nil {
		t.Fatal("doctor reused admission after the profile binding changed")
	}
}
