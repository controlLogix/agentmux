//go:build linux || darwin

package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLauncherStagingFailureAndChangedDestinationPreserveInstalledBytes(t *testing.T) {
	for _, fault := range []string{"staging_admission", "expired_after_write", "replaced_same_bytes"} {
		t.Run(fault, func(t *testing.T) {
			p := prepareFixture(t, fixtureSelection(t))
			base, policy := privateDestination(t)
			path := filepath.Join(base.Name(), launcherName)
			original := []byte("previous admitted frontend")
			if err := os.WriteFile(path, original, 0555); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			admit := policy.file
			policy.file = func(file *os.File, mode os.FileMode) error {
				if err := admit(file, mode); err != nil {
					return err
				}
				if file.Name() != "installer-new-file" {
					return nil
				}
				switch fault {
				case "staging_admission":
					return errors.New("fixture_staging_refused")
				case "expired_after_write":
					cancel()
				case "replaced_same_bytes":
					replacement := filepath.Join(base.Name(), "external-replacement")
					if err := os.WriteFile(replacement, original, 0555); err != nil {
						return err
					}
					return os.Rename(replacement, path)
				}
				return nil
			}
			result, err := installLauncherAt(ctx, base, p, hash(original), policy)
			if err == nil || result != (LauncherResult{}) {
				t.Fatal("uncertain staging reported success")
			}
			raw, err := os.ReadFile(path)
			if err != nil || string(raw) != string(original) {
				t.Fatal("failed publication changed previous launcher")
			}
			after, err := os.Stat(path)
			if err != nil || (fault != "replaced_same_bytes" && !os.SameFile(before, after)) {
				t.Fatal("failed publication replaced previous inode")
			}
			stages, err := filepath.Glob(filepath.Join(base.Name(), ".agentmux-runtime-*"))
			if err != nil || len(stages) != 1 {
				t.Fatal("uncertain staging owner was not retained")
			}
		})
	}
}

func TestLauncherPublicInstallDoesNotElevate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("refusal check requires an ordinary user")
	}
	p := prepareFixture(t, fixtureSelection(t))
	result, err := InstallLauncher(context.Background(), p, "")
	if err == nil || err.Error() != "installer_administrator_required" || result != (LauncherResult{}) {
		t.Fatal("launcher installation did not require explicit administrator invocation")
	}
}
