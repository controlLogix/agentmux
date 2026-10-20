//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func interruptedOwnerPreparation(t *testing.T) (OwnerProfilePreparationRequest, ownerProfileDependencies, string, map[string][]byte, map[string]os.FileInfo) {
	t.Helper()
	q, deps, home, _ := ownerPreparationRequest(t)
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
	syncDirectory := deps.syncDirectory
	deps.syncDirectory = func(d *ownerProfilePreparationDirectory) error {
		if d.entry.path == directory {
			if _, err := os.Stat(filepath.Join(directory, "client-selection.json")); err == nil {
				return errors.New("injected interruption after selection publication")
			}
		}
		return syncDirectory(d)
	}
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if r == nil || err == nil || r.prepared {
		t.Fatal("interruption did not retain partial preparation")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	deps.syncDirectory = syncDirectory
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 14 {
		t.Fatal("unexpected interruption boundary")
	}
	raw, identities := map[string][]byte{}, map[string]os.FileInfo{}
	for _, entry := range entries {
		name := entry.Name()
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		raw[name] = data
		identities[name], err = entry.Info()
		if err != nil {
			t.Fatal(err)
		}
	}
	return q, deps, directory, raw, identities
}

func TestOwnerProfileRecoveryPreservesCredentialsAndRepeats(t *testing.T) {
	q, deps, directory, original, identities := interruptedOwnerPreparation(t)
	for attempt := 0; attempt < 2; attempt++ {
		r, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
		if r != nil {
			t.Cleanup(func() { r.Close() })
		}
		if err != nil || r == nil || !r.prepared {
			t.Fatalf("recovery failed: %v", err)
		}
		if _, err := r.Selection(context.Background()); err != nil {
			t.Fatal(err)
		}
		for name, before := range original {
			after, err := os.ReadFile(filepath.Join(directory, name))
			info, statErr := os.Stat(filepath.Join(directory, name))
			if err != nil || statErr != nil || centralDigest(after) != centralDigest(before) || !os.SameFile(identities[name], info) {
				t.Fatal("recovery replaced an original artifact")
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOwnerProfileRecoveryRefusesConflictingOrIncompleteState(t *testing.T) {
	for _, kind := range []string{"owner", "workspace", "runtime", "broker", "broker-permissions", "key-missing", "symlink", "mode", "stage", "registration", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			q, deps, directory, _, _ := interruptedOwnerPreparation(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "owner":
				q.Owner.PrincipalID = "different_owner"
			case "workspace":
				q.ApprovedWorkspaceRoots = append(q.ApprovedWorkspaceRoots, filepath.Dir(directory))
			case "runtime":
				q.MaxFileBytes++
			case "broker":
				if err := os.WriteFile(filepath.Join(directory, "broker.json"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "broker-permissions":
				path := filepath.Join(directory, "broker.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				value["authorization"] = map[string]any{"default_permissions": map[string]any{"publish": ">", "subscribe": ">"}}
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "key-missing":
				if err := os.Remove(filepath.Join(directory, localServerKeyFile)); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path := filepath.Join(directory, "runtime.json")
				if err := os.Rename(path, path+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+"-original", path); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(filepath.Join(directory, "runtime.json"), 0644); err != nil {
					t.Fatal(err)
				}
			case "stage":
				if err := os.WriteFile(filepath.Join(directory, ".prepare-retained"), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "registration":
				if err := os.WriteFile(filepath.Join(directory, centralProfileRegistrationName), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			r, err := prepareOwnerProfileMode(ctx, q, deps, true)
			if r != nil {
				defer r.Close()
			}
			if err == nil {
				t.Fatal("unsafe recovery succeeded")
			}
			if _, err := os.Lstat(filepath.Join(directory, "profile.json")); !os.IsNotExist(err) {
				t.Fatal("refused recovery published a profile")
			}
		})
	}
}

func TestOwnerProfileRecoveryRefusesReplacementBeforePublication(t *testing.T) {
	q, deps, directory, raw, _ := interruptedOwnerPreparation(t)
	account := deps.account
	checks := 0
	deps.account = func() (ownerProfileAccount, error) {
		checks++
		if checks == 4 {
			path := filepath.Join(directory, "runtime.json")
			if err := os.Rename(path, path+"-original"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw["runtime.json"], 0600); err != nil {
				t.Fatal(err)
			}
		}
		return account()
	}
	r, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
	if r != nil {
		defer r.Close()
	}
	if checks < 4 || err == nil {
		t.Fatal("replacement escaped retained file identity checks")
	}
	if _, err := os.Stat(filepath.Join(directory, "profile.json")); !os.IsNotExist(err) {
		t.Fatal("replacement was followed by publication")
	}
}

func TestOwnerProfileRecoveryCancellationAfterProfilePublication(t *testing.T) {
	q, deps, directory, _, _ := interruptedOwnerPreparation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncDirectory := deps.syncDirectory
	deps.syncDirectory = func(d *ownerProfilePreparationDirectory) error {
		if err := syncDirectory(d); err != nil {
			return err
		}
		if d.entry.path == directory {
			cancel()
		}
		return nil
	}
	r, err := prepareOwnerProfileMode(ctx, q, deps, true)
	if r == nil || !errors.Is(err, context.Canceled) || r.prepared {
		t.Fatal("canceled recovery lost original owner")
	}
	if _, err := os.Stat(filepath.Join(directory, "profile.json")); err != nil {
		t.Fatal("published profile was removed")
	}
	if _, err := os.Stat(filepath.Join(directory, centralProfileRegistrationName)); !os.IsNotExist(err) {
		t.Fatal("canceled recovery registered")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	deps.syncDirectory = syncDirectory
	r, err = prepareOwnerProfileMode(context.Background(), q, deps, true)
	if r != nil {
		defer r.Close()
	}
	if err != nil || r == nil || !r.prepared {
		t.Fatal("explicit recovery could not reconcile prior publication", err)
	}
}

func TestOwnerProfileRecoveryRespectsStoreLock(t *testing.T) {
	q, deps, directory, _, _ := interruptedOwnerPreparation(t)
	store, err := os.Open(filepath.Dir(directory))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := unix.Flock(int(store.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	r, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
	if r != nil {
		defer r.Close()
	}
	if err == nil {
		t.Fatal("recovery bypassed another store owner")
	}
	if _, err := os.Stat(filepath.Join(directory, "profile.json")); !os.IsNotExist(err) {
		t.Fatal("busy recovery published a profile")
	}
}

func TestOwnerProfileRecoveryRejectsChangedRegisteredClient(t *testing.T) {
	q, deps, directory, _, _ := interruptedOwnerPreparation(t)
	r, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
	if err != nil {
		if r != nil {
			r.Close()
		}
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, centralProfileRegistrationName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	q.ClientInstallationID = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	r, err = prepareOwnerProfileMode(context.Background(), q, deps, true)
	if r != nil {
		defer r.Close()
	}
	if err == nil {
		t.Fatal("changed registered client was accepted")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil || centralDigest(before) != centralDigest(after) {
		t.Fatal("registration was replaced")
	}
}
