//go:build linux

package deployment

import (
	"os"
	"testing"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

func TestTeamPrivateDescriptorAdmissionRejectsWrongOrClosedObject(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "credential")
	if err != nil {
		t.Fatal("held private fixture unavailable")
	}
	t.Cleanup(func() { file.Close() })
	if teamDescriptorAdmission(file, privatefs.PrivateObject, "private_file_invalid") != nil {
		t.Fatal("valid held private object refused")
	}
	if err := teamDescriptorAdmission(file, privatefs.PublicAncestor, "private_directory_invalid"); err == nil || err.Error() != "team_private_directory_invalid" {
		t.Fatal("regular credential file admitted as ancestor")
	}
	if file.Close() != nil {
		t.Fatal("owned fixture close failed")
	}
	if err := teamDescriptorAdmission(file, privatefs.PrivateObject, "private_file_invalid"); err == nil || err.Error() != "team_private_file_invalid" {
		t.Fatal("closed private descriptor admitted")
	}
	if err := teamDescriptorAdmission(nil, privatefs.PrivateObject, "private_file_invalid"); err == nil || err.Error() != "team_private_file_invalid" {
		t.Fatal("missing private descriptor admitted")
	}
}
