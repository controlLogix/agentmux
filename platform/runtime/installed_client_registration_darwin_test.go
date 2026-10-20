//go:build darwin && arm64

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func clientRegistrationFixture(t *testing.T, change func(map[string]any)) (*os.File, []byte) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("registered clients require an ordinary native account")
	}
	record := map[string]any{
		"schemaVersion": "1.0.0", "ownerUid": os.Getuid(),
		"profileId": "profile_" + strings.Repeat("a", 32), "instanceId": "instance_" + strings.Repeat("b", 32),
		"clientInstallationId": strings.Repeat("c", 64),
		"profileSha256":        "sha256:" + strings.Repeat("d", 64), "hostPolicySha256": "sha256:" + strings.Repeat("e", 64),
		"clientSelectionSha256": "sha256:" + strings.Repeat("f", 64), "environment": "development", "project": "Example project",
	}
	if change != nil {
		change(record)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registration.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file, raw
}

func nextClientRegistrationDescriptor(t *testing.T, original *os.File) int {
	t.Helper()
	fd, err := unix.FcntlInt(original.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestInstalledClientRegisteredExecFailureClosesOnlyDuplicate(t *testing.T) {
	original, raw := clientRegistrationFixture(t, nil)
	if _, err := original.Seek(5, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	originalFlags, err := unix.FcntlInt(original.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	duplicateFD := -1
	err = withClientRegistration(context.Background(), original, strings.Repeat("c", 64), ClientDigest(raw), func(duplicate *os.File) error {
		duplicateFD = int(duplicate.Fd())
		if duplicate.Fd() == original.Fd() {
			t.Fatal("original descriptor was selected for inheritance")
		}
		flags, err := unix.FcntlInt(duplicate.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("duplicate was inheritable before exec", err)
		}
		return execInstalledRegisteredClient(filepath.Join(t.TempDir(), "missing-executable"), []string{"missing-executable"}, []string{"PATH=/usr/bin:/bin"}, duplicate)
	})
	if err == nil || err.Error() != "installed_client_exec_failed" {
		t.Fatal("missing exec was not reported", err)
	}
	if _, err := unix.FcntlInt(uintptr(duplicateFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("failed exec leaked its duplicate", err)
	}
	if offset, err := original.Seek(0, io.SeekCurrent); err != nil || offset != 5 {
		t.Fatal("registration read changed the borrowed offset", offset, err)
	}
	if flags, err := unix.FcntlInt(original.Fd(), unix.F_GETFD, 0); err != nil || flags != originalFlags || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("failed exec changed or consumed the original", err)
	}
}

func TestInstalledClientRegisteredRefusalClosesDuplicate(t *testing.T) {
	changes := map[string]func(map[string]any){
		"unknown":            func(r map[string]any) { r["authority"] = "administrator" },
		"owner":              func(r map[string]any) { r["ownerUid"] = os.Getuid() + 1 },
		"owner_type":         func(r map[string]any) { r["ownerUid"] = true },
		"client":             func(r map[string]any) { r["clientInstallationId"] = strings.Repeat("a", 64) },
		"profile":            func(r map[string]any) { r["profileId"] = "profile" },
		"instance":           func(r map[string]any) { r["instanceId"] = "instance" },
		"selection_digest":   func(r map[string]any) { r["clientSelectionSha256"] = "sha256:bad" },
		"missing":            func(r map[string]any) { delete(r, "profileSha256") },
		"no_metadata":        func(r map[string]any) { delete(r, "environment"); delete(r, "project") },
		"null_metadata":      func(r map[string]any) { r["environment"] = nil },
		"control_metadata":   func(r map[string]any) { r["project"] = "Example\u0085project" },
		"separator_metadata": func(r map[string]any) { r["project"] = "Example\u2028project" },
		"long_metadata":      func(r map[string]any) { r["project"] = strings.Repeat("é", 65) },
		"oversize":           func(r map[string]any) { r["project"] = strings.Repeat("x", clientRegistrationLimit) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			original, raw := clientRegistrationFixture(t, change)
			available := nextClientRegistrationDescriptor(t, original)
			called := false
			err := withClientRegistration(context.Background(), original, strings.Repeat("c", 64), ClientDigest(raw), func(*os.File) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("malformed registration reached execution")
			}
			if nextClientRegistrationDescriptor(t, original) != available {
				t.Fatal("registration refusal leaked a duplicate")
			}
			if _, err := original.Stat(); err != nil {
				t.Fatal("registration refusal consumed the original", err)
			}
		})
	}
}

func TestInstalledClientRegisteredDescriptorAndDigestRefusal(t *testing.T) {
	original, raw := clientRegistrationFixture(t, nil)
	digest := ClientDigest(raw)
	refused := func(file *os.File, selectedDigest string) {
		t.Helper()
		available := nextClientRegistrationDescriptor(t, original)
		called := false
		err := withClientRegistration(context.Background(), file, strings.Repeat("c", 64), selectedDigest, func(*os.File) error { called = true; return nil })
		if err == nil || called || nextClientRegistrationDescriptor(t, original) != available {
			t.Fatal("invalid descriptor reached exec or leaked a duplicate", err)
		}
	}
	refused(nil, digest)
	refused(original, "sha256:"+strings.Repeat("a", 64))
	writer, err := os.OpenFile(original.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	refused(writer, digest)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	refused(writer, digest)
	if _, err := unix.FcntlInt(original.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	refused(original, digest)
	if _, err := unix.FcntlInt(original.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original.Name(), original.Name()+".alias"); err != nil {
		t.Fatal(err)
	}
	refused(original, digest)
}

func TestInstalledClientRegisteredCleanupFailureRetainsDuplicate(t *testing.T) {
	original, raw := clientRegistrationFixture(t, nil)
	cause := errors.New("selected exec failure")
	var consumed *os.File
	err := withClientRegistration(context.Background(), original, strings.Repeat("c", 64), ClientDigest(raw), func(duplicate *os.File) error {
		consumed = duplicate
		if err := duplicate.Close(); err != nil {
			t.Fatal(err)
		}
		return cause
	})
	var failure *clientFailure
	if !errors.As(err, &failure) || failure.code != "registration_cleanup_failed" || failure.owner != consumed || !errors.Is(err, cause) {
		t.Fatal("consumed-close uncertainty lost its original owner", err)
	}
	if _, err := original.Stat(); err != nil {
		t.Fatal("duplicate uncertainty consumed the caller's original", err)
	}
}

func TestInstalledClientRegisteredRequiresRetainedAdmission(t *testing.T) {
	original, raw := clientRegistrationFixture(t, nil)
	var admission *InstalledClientAdmission
	for _, operation := range []string{"startup", "startup-json", "startup-worker", "startup-worker-json", "mcp", "mcp-worker", "dashboard", "claude-code-hook", "claude-code-hook-worker"} {
		if err := admission.ExecRegistered(context.Background(), operation, "/private/selected.json", original, ClientDigest(raw)); err == nil || err.Error() != "installed_client_recheck_invalid" {
			t.Fatal("registered client bypassed installed admission", err)
		}
	}
	for _, operation := range []string{"registered-client", "repository-client", "application-services", "launch-claude-desktop", "client-setup", "mcp-json"} {
		if err := admission.ExecRegistered(context.Background(), operation, "/private/selected.json", original, ClientDigest(raw)); err == nil || err.Error() != "installed_client_command_invalid" {
			t.Fatal("unsupported registered command accepted", err)
		}
	}
	if err := admission.ExecRegistered(context.Background(), "startup", "relative", original, ClientDigest(raw)); err == nil || err.Error() != "installed_client_selection_invalid" {
		t.Fatal("noncanonical registered selection accepted", err)
	}
	if err := admission.ExecRegistered(context.Background(), "startup", "/private/selected.json", nil, ClientDigest(raw)); err == nil || err.Error() != "installed_client_registration_invalid" {
		t.Fatal("missing registration descriptor accepted", err)
	}
	if err := admission.ExecRegistered(context.Background(), "startup", "/private/selected.json", original, "sha256:bad"); err == nil || err.Error() != "installed_client_registration_invalid" {
		t.Fatal("malformed registration pin accepted", err)
	}
}
