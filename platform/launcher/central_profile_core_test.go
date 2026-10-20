//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type centralCoreTestOwner struct {
	centralTestOwner
	repository string
	arguments  []string
}

func (o *centralCoreTestOwner) ExecRegisteredCore(ctx context.Context, selection string, registration *os.File, digest, repository string, arguments []string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	o.registeredExecs++
	o.registeredFile, o.registeredDigest, o.registeredSelection = registration, digest, selection
	o.repository, o.arguments = repository, slices.Clone(arguments)
	return o.registeredFailure
}

func centralCoreFixture(t *testing.T) (*centralTestFixture, *CentralProfileResolution, *centralCoreTestOwner) {
	t.Helper()
	f := centralFixture(t)
	path := filepath.Join(f.directory, "client-selection.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var selection map[string]any
	if err := json.Unmarshal(raw, &selection); err != nil {
		t.Fatal(err)
	}
	selection["coreHub"] = map[string]string{"selection": filepath.Join(f.directory, "core.json"), "sha256": "sha256:" + strings.Repeat("e", 64)}
	raw, err = json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var client *centralCoreTestOwner
	f.deps.client = func(context.Context, string) (centralClientOwner, error) {
		client = &centralCoreTestOwner{}
		return client, nil
	}
	registered, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := registered.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return f, r, client
}

func TestCentralCorePreservesOriginalRegistrationAndLiteralIntent(t *testing.T) {
	f, r, client := centralCoreFixture(t)
	original := r.registrationFile.file
	before, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"spawn", "falcon", "worker", "one", "--cwd", "/private/a 'literal' $(directory)", "--operation-id", "original-intent"}
	execFailure := errors.New("test exec returned")
	client.registeredFailure = execFailure
	checks := client.checks
	if err := r.ExecCoreClient(context.Background(), arguments); err != execFailure {
		t.Fatal("exec failure changed", err)
	}
	if client.checks <= checks || client.closes != 0 || client.registeredExecs != 1 {
		t.Fatal("original client was not rechecked and retained")
	}
	if client.registeredFile != original || client.registeredDigest != r.registrationFile.digest || client.registeredSelection != filepath.Join(f.directory, "client-selection.json") || client.repository != f.repository || !slices.Equal(client.arguments, arguments) {
		t.Fatal("registered core handoff changed")
	}
	after, err := original.Stat()
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("borrowed registration was closed or replaced", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil || client.closes != 1 {
		t.Fatal("client cleanup replayed", err)
	}
	if _, err := original.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("registration remained open after owner cleanup", err)
	}
	if err := r.ExecCoreClient(context.Background(), arguments); err == nil || client.registeredExecs != 1 {
		t.Fatal("closed owner executed again")
	}
}

func TestCentralCoreRefusesBeforeInstalledHandoff(t *testing.T) {
	for _, mode := range []string{"cancelled", "empty-command", "missing-core", "missing-registration", "client-changed", "registration-replaced"} {
		t.Run(mode, func(t *testing.T) {
			f, r, client := centralCoreFixture(t)
			ctx := context.Background()
			arguments := []string{"kill", "falcon-worker-one", "--operation-id", "original-stop"}
			switch mode {
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "empty-command":
				arguments = nil
			case "missing-core":
				r.selected.CoreHub = nil
			case "missing-registration":
				r.registrationFile = nil
			case "client-changed":
				client.checkErr = errors.New("retained client changed")
			case "registration-replaced":
				path := filepath.Join(f.directory, centralProfileRegistrationName)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path+".replacement", raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path+".replacement", path); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.ExecCoreClient(ctx, arguments); err == nil || client.registeredExecs != 0 {
				t.Fatal("invalid selection reached installed handoff", err)
			}
			_ = r.Close()
			_ = r.Close()
			if client.closes != 1 {
				t.Fatal("refused owner cleanup replayed")
			}
		})
	}
}
