//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownerCoreRequest(t *testing.T) (OwnerProfilePreparationRequest, ownerProfileDependencies, string) {
	t.Helper()
	q, deps, home, _ := ownerPreparationRequest(t)
	private := filepath.Join(home, "core-inputs")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "core selection.json")
	raw := []byte(`{"fixture":"core pin only; application enrollment is checked at use"}`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	q.CoreHub = &CoreHubSelection{Selection: path, SHA256: centralDigest(raw)}
	return q, deps, home
}

func ownerCoreArtifacts(t *testing.T, directory string) (map[string][]byte, map[string]os.FileInfo) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	raw, info := map[string][]byte{}, map[string]os.FileInfo{}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		raw[entry.Name()], err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info[entry.Name()], err = os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	return raw, info
}

func assertOwnerCoreArtifacts(t *testing.T, directory string, raw map[string][]byte, info map[string]os.FileInfo) {
	t.Helper()
	after, identities := ownerCoreArtifacts(t, directory)
	if len(after) != len(raw) {
		t.Fatal("recovery changed the retained inventory")
	}
	for name, original := range raw {
		if string(after[name]) != string(original) || !os.SameFile(info[name], identities[name]) {
			t.Fatalf("recovery replaced retained artifact %s", name)
		}
	}
}

func TestOwnerCorePinRegistersAndRecoversWithoutReplacingArtifacts(t *testing.T) {
	q, deps, home := ownerCoreRequest(t)
	wanted := *q.CoreHub
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if r != nil {
		t.Cleanup(func() { _ = r.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	if r.request.CoreHub == q.CoreHub || *r.registration.selected.CoreHub != wanted {
		t.Fatal("core pin was not copied into registration")
	}
	q.CoreHub.Selection = "/changed/by/caller"
	if *r.request.CoreHub != wanted {
		t.Fatal("caller changed retained preparation request")
	}
	q.CoreHub = &wanted
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
	var selection struct {
		CoreHub *CoreHubSelection `json:"coreHub"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "client-selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &selection) != nil || selection.CoreHub == nil || *selection.CoreHub != wanted {
		t.Fatal("published selection lost the exact core pin")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	original, identities := ownerCoreArtifacts(t, directory)
	for attempt := 0; attempt < 2; attempt++ {
		recovered, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
		if recovered != nil {
			t.Cleanup(func() { _ = recovered.Close() })
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := recovered.Selection(context.Background()); err != nil {
			t.Fatal(err)
		}
		if recovered.registration.selected.CoreHub == nil || *recovered.registration.selected.CoreHub != wanted {
			t.Fatal("recovery changed core pin")
		}
		if err := recovered.Close(); err != nil {
			t.Fatal(err)
		}
		assertOwnerCoreArtifacts(t, directory, original, identities)
	}
}

func TestOwnerCorePinRefusesInvalidInputsBeforePublication(t *testing.T) {
	for _, mode := range []string{"missing", "digest", "public-file", "public-parent", "workspace", "symlink", "relative"} {
		t.Run(mode, func(t *testing.T) {
			q, deps, home := ownerCoreRequest(t)
			switch mode {
			case "missing":
				if err := os.Remove(q.CoreHub.Selection); err != nil {
					t.Fatal(err)
				}
			case "digest":
				q.CoreHub.SHA256 = "sha256:" + strings.Repeat("0", 64)
			case "public-file":
				if err := os.Chmod(q.CoreHub.Selection, 0644); err != nil {
					t.Fatal(err)
				}
			case "public-parent":
				if err := os.Chmod(filepath.Dir(q.CoreHub.Selection), 0755); err != nil {
					t.Fatal(err)
				}
			case "workspace":
				q.CoreHub.Selection = filepath.Join(q.ApprovedWorkspaceRoots[0], "core.json")
			case "symlink":
				path := q.CoreHub.Selection
				q.CoreHub.Selection = path + ".alias"
				if err := os.Symlink(path, q.CoreHub.Selection); err != nil {
					t.Fatal(err)
				}
			case "relative":
				q.CoreHub.Selection = "core.json"
			}
			r, err := prepareOwnerProfile(context.Background(), q, deps)
			if r != nil {
				defer r.Close()
			}
			if err == nil {
				t.Fatal("unsafe core pin accepted")
			}
			if _, err := os.Stat(filepath.Join(home, "Library")); !os.IsNotExist(err) {
				t.Fatal("invalid core pin created profile state")
			}
		})
	}
}

func TestOwnerCorePinRecoveryRejectsChangedRequestAndFile(t *testing.T) {
	for _, mode := range []string{"omitted", "path", "digest", "changed-file"} {
		t.Run(mode, func(t *testing.T) {
			q, deps, home := ownerCoreRequest(t)
			r, err := prepareOwnerProfile(context.Background(), q, deps)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
			original, identities := ownerCoreArtifacts(t, directory)
			switch mode {
			case "omitted":
				q.CoreHub = nil
			case "path":
				raw, err := os.ReadFile(q.CoreHub.Selection)
				if err != nil {
					t.Fatal(err)
				}
				q.CoreHub.Selection += ".other"
				if err := os.WriteFile(q.CoreHub.Selection, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "digest":
				q.CoreHub.SHA256 = "sha256:" + strings.Repeat("0", 64)
			case "changed-file":
				raw := []byte(`{"fixture":"changed"}`)
				if err := os.WriteFile(q.CoreHub.Selection, raw, 0600); err != nil {
					t.Fatal(err)
				}
				q.CoreHub.SHA256 = centralDigest(raw)
			}
			recovered, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
			if recovered != nil {
				if closeErr := recovered.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
			if err == nil {
				t.Fatal("changed core pin recovered original profile")
			}
			assertOwnerCoreArtifacts(t, directory, original, identities)
		})
	}
}

func TestOwnerCorePinReplacementDuringPublicationRefusesRegistration(t *testing.T) {
	q, deps, home := ownerCoreRequest(t)
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
	syncDirectory := deps.syncDirectory
	changed := false
	deps.syncDirectory = func(d *ownerProfilePreparationDirectory) error {
		if !changed && d.entry.path == directory {
			if _, err := os.Stat(filepath.Join(directory, "client-selection.json")); err == nil {
				raw, err := os.ReadFile(q.CoreHub.Selection)
				if err != nil {
					return err
				}
				if err := os.WriteFile(q.CoreHub.Selection+".replacement", raw, 0600); err != nil {
					return err
				}
				if err := os.Rename(q.CoreHub.Selection+".replacement", q.CoreHub.Selection); err != nil {
					return err
				}
				changed = true
			}
		}
		return syncDirectory(d)
	}
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if r != nil {
		defer r.Close()
	}
	if !changed || err == nil || r == nil || r.prepared {
		t.Fatal("replacement did not retain refused preparation", err)
	}
	if _, err := os.Stat(filepath.Join(directory, centralProfileRegistrationName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("changed pin published registration", err)
	}
}

func TestOwnerCorePinInterruptedPreparationRecoversOriginalCredentials(t *testing.T) {
	q, deps, home := ownerCoreRequest(t)
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
	syncDirectory := deps.syncDirectory
	deps.syncDirectory = func(d *ownerProfilePreparationDirectory) error {
		if d.entry.path == directory {
			if _, err := os.Stat(filepath.Join(directory, "client-selection.json")); err == nil {
				return errors.New("interrupted after pinned selection publication")
			}
		}
		return syncDirectory(d)
	}
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if r == nil || err == nil || r.prepared {
		t.Fatal("interruption lost partial preparation", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	original, identities := ownerCoreArtifacts(t, directory)
	deps.syncDirectory = syncDirectory
	recovered, err := prepareOwnerProfileMode(context.Background(), q, deps, true)
	if recovered != nil {
		t.Cleanup(func() { _ = recovered.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	if recovered.registration.selected.CoreHub == nil || *recovered.registration.selected.CoreHub != *q.CoreHub {
		t.Fatal("recovery changed original core pin")
	}
	for name, before := range original {
		path := filepath.Join(directory, name)
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) || !os.SameFile(identities[name], info) {
			t.Fatalf("recovery replaced original artifact %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, centralProfileRegistrationName)); err != nil {
		t.Fatal("recovery did not complete registration", err)
	}
}
