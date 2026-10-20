//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"golang.org/x/sys/unix"
)

// Reuse the signed release, profile declarations and installed-owner doubles.
// All writes remain in disposable test roots; no prepared enrollment is copied.
func ownerPreparationRequest(t *testing.T) (OwnerProfilePreparationRequest, ownerProfileDependencies, string, *[]*centralTestOwner) {
	t.Helper()
	release := signedReleaseFixture(t)
	policy, profile := profileFixture(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(release.policy.PackageDirectory, "agentmux-runtime")
	runtimeRaw := []byte("source test frontend; never executed")
	if os.WriteFile(runtimePath, runtimeRaw, 0700) != nil {
		t.Fatal("frontend fixture unavailable")
	}
	environment := "Development"
	q := OwnerProfilePreparationRequest{
		Owner:   OwnerEnrollment{SchemaVersion: protocol.Version, OwnerUID: policy.OwnerUID, PrincipalID: "fixture_owner", Identity: OwnerIdentityReference{ID: "fixture_owner_ref", OwnerHubID: "fixture_hub", Revision: 1}, Scope: OwnerScope{OrganizationID: "fixture_org"}, InstanceID: profile.InstanceID, ProfileID: profile.ProfileID, ReleaseFingerprint: release.policy.ReleaseManifestDigest},
		Context: CentralProfileContext{Environment: &environment}, ClientInstallationID: strings.Repeat("c", 64), ApprovedWorkspaceRoots: policy.WorkspaceRoots,
		Release: release.policy, RuntimeExecutablePath: runtimePath, RuntimeExecutableDigest: centralDigest(runtimeRaw), Docker: *profile.Docker,
		HostPort: 14222, ComposeProject: "agentmux_preparation_test", ServerName: "fixture_server", Domain: "fixture_domain", MaxMemoryBytes: 1024 * 1024, MaxFileBytes: 4 * 1024 * 1024,
		StartupTimeout: 10 * time.Second, ProbeTimeout: time.Second, Deadlines: protected.Deadlines{StartTimeout: 2 * time.Second, StopGrace: time.Second, ReapTimeout: time.Second},
	}
	q.Docker.ComposeVersion = release.manifest.Broker.ComposeVersion
	owners := []*centralTestOwner{}
	deps := ownerProfileDependencies{
		openDirectory: openOwnerProfileChild,
		account: func() (ownerProfileAccount, error) {
			return ownerProfileAccount{home, "Native Owner", policy.OwnerUID}, nil
		},
		syncDirectory: func(d *ownerProfilePreparationDirectory) error { return d.entry.file.Sync() },
		central: centralProfileDependencies{
			account: func() (string, uint32, error) { return home, policy.OwnerUID, nil }, host: LoadEnrolledHostPolicy,
			client: func(context.Context, string) (centralClientOwner, error) {
				o := &centralTestOwner{}
				owners = append(owners, o)
				return o, nil
			},
			clientDigest: func(context.Context, string, *CentralProfileResolution) (string, error) {
				return q.RuntimeExecutableDigest, nil
			},
			image: func(_ context.Context, path, digest string) (centralImageOwner, error) {
				if path != protected.StableFrontendPath || digest != q.RuntimeExecutableDigest {
					t.Fatal("setup frontend admission received the host image path or different digest")
				}
				o := &centralTestOwner{}
				owners = append(owners, o)
				return o, nil
			},
			hostImage: func(_ context.Context, path, digest string) (centralImageOwner, error) {
				if path != q.RuntimeExecutablePath || digest != q.RuntimeExecutableDigest {
					t.Fatal("setup host admission received the frontend path or different digest")
				}
				o := &centralTestOwner{}
				owners = append(owners, o)
				return o, nil
			},
		},
	}
	return q, deps, home, &owners
}

func TestOwnerProfilePreparationCreatesCompletePrivateProfile(t *testing.T) {
	q, deps, home, owners := ownerPreparationRequest(t)
	project := "Editor"
	q.Context.Project = &project
	second := filepath.Dir(q.ApprovedWorkspaceRoots[0]) + "/second-repository"
	if os.Mkdir(second, 0700) != nil {
		t.Fatal("second repository unavailable")
	}
	q.ApprovedWorkspaceRoots = append(q.ApprovedWorkspaceRoots, second)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USER", "Wrong ambient owner")
	t.Setenv("DOCKER_CONTEXT", "wrong-context")
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if err != nil {
		if r != nil {
			r.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	selection, err := r.Selection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
	host, err := LoadEnrolledHostPolicy(HostPolicySelection{Path: filepath.Join(directory, "host-policy.json"), OwnerUID: q.Owner.OwnerUID, WorkspaceRoots: q.ApprovedWorkspaceRoots})
	if err != nil {
		t.Fatal(err)
	}
	c, owner, err := host.Load()
	if err != nil || owner == nil || c.OwnerBridge == nil || c.Kernel.Scope.ProfileID != q.Owner.ProfileID || c.Kernel.Scope.InstanceID != q.Owner.InstanceID || selection.ClientSelectionPath != filepath.Join(directory, "client-selection.json") {
		t.Fatal("prepared host lost its admitted bindings")
	}
	p, err := LoadProfile(host.policy.Profile)
	if err != nil || p.profile.DisplayName != "Native Owner - Editor - Development" || p.profile.ProjectID != "" || !reflect.DeepEqual(host.record.Owner, q.Owner) || !reflect.DeepEqual(r.registration.selected.Workspaces, q.ApprovedWorkspaceRoots) {
		t.Fatal("display context changed owner authority or repository approval")
	}
	if r.registration.selected.Application != nil || r.registration.selected.ApplicationAttestor != nil || r.registration.selected.ApplicationServices != nil {
		t.Fatal("preparation manufactured application enrollment")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !centralFileMode(info, q.Owner.OwnerUID, 0600) || strings.HasPrefix(entry.Name(), ".prepare-") {
			t.Fatal("preparation left an unqualified artifact")
		}
	}
	for _, repo := range q.ApprovedWorkspaceRoots {
		if _, err := os.Stat(filepath.Join(repo, ".agentmux")); !os.IsNotExist(err) {
			t.Fatal("preparation changed a repository")
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, owner := range *owners {
		if owner.closes != 1 {
			t.Fatal("installed admission was not consumed exactly once")
		}
	}
	if _, err := r.Selection(context.Background()); err == nil {
		t.Fatal("closed preparation returned a selection")
	}
	// A second explicit invocation never replaces keys or creates a second stack.
	before, _ := os.ReadFile(filepath.Join(directory, "server-key.pem"))
	other, err := prepareOwnerProfile(context.Background(), q, deps)
	if other != nil {
		other.Close()
	}
	after, _ := os.ReadFile(filepath.Join(directory, "server-key.pem"))
	if err == nil || !reflect.DeepEqual(before, after) {
		t.Fatal("existing profile was replaced")
	}
}

func TestOwnerProfilePreparationInvalidInputsDoNotCreateState(t *testing.T) {
	for _, kind := range []string{"context", "empty-context", "owner", "release", "docker", "workspace", "runtime", "deadline", "label"} {
		t.Run(kind, func(t *testing.T) {
			q, deps, home, owners := ownerPreparationRequest(t)
			switch kind {
			case "context":
				q.Context = CentralProfileContext{}
			case "empty-context":
				v := ""
				q.Context.Environment = &v
			case "owner":
				q.Owner.Identity.Revision = 0
			case "release":
				q.Release.ReleaseManifestDigest = "sha256:" + strings.Repeat("0", 64)
			case "docker":
				q.Docker.ComposeVersion = "0.0.1"
			case "workspace":
				q.ApprovedWorkspaceRoots = []string{home}
			case "runtime":
				q.RuntimeExecutableDigest = "unbound"
			case "deadline":
				q.ProbeTimeout = 6 * time.Second
			case "label":
				deps.account = func() (ownerProfileAccount, error) {
					return ownerProfileAccount{home, "bad\nname", q.Owner.OwnerUID}, nil
				}
			}
			r, err := prepareOwnerProfile(context.Background(), q, deps)
			if r != nil {
				r.Close()
			}
			if err == nil {
				t.Fatal("invalid preparation accepted")
			}
			if _, err := os.Stat(filepath.Join(home, "Library")); !os.IsNotExist(err) {
				t.Fatal("invalid preparation created state")
			}
			for _, o := range *owners {
				if o.closes != 1 {
					t.Fatal("failed admission leaked an owner")
				}
			}
		})
	}
}

func TestOwnerProfilePreparationContextOmitsAbsentMetadata(t *testing.T) {
	q, deps, home, _ := ownerPreparationRequest(t)
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if err != nil {
		if r != nil {
			r.Close()
		}
		t.Fatal(err)
	}
	defer r.Close()
	raw, err := os.ReadFile(filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID, "registration.json"))
	var fields map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &fields) != nil || string(fields["environment"]) != `"Development"` {
		t.Fatal("explicit context was not preserved")
	}
	if _, ok := fields["project"]; ok {
		t.Fatal("absent project was serialized")
	}
}

func TestOwnerProfilePreparationDirectorySyncFailureRetainsOriginals(t *testing.T) {
	q, deps, home, owners := ownerPreparationRequest(t)
	deps.syncDirectory = func(*ownerProfilePreparationDirectory) error { return errors.New("failed directory durability") }
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if err == nil || r == nil || !r.mutated || r.prepared {
		t.Fatal("uncertain directory mutation lost its owner")
	}
	defer r.Close()
	var parent, child *centralProfileFile
	for _, f := range r.files.files {
		if f.path == home {
			parent = f
		}
		if f.path == filepath.Join(home, "Library") {
			child = f
		}
	}
	if parent == nil || child == nil || parent.file == nil || child.file == nil {
		t.Fatal("original parent and child were not retained")
	}
	if err := os.Rename(home, home+"-moved"); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(home+"-moved", home)
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(home)
	if info, err := child.file.Stat(); err != nil || !info.IsDir() {
		t.Fatal("original child descriptor was replaced")
	}
	if _, err := r.Selection(context.Background()); err == nil {
		t.Fatal("partial preparation returned a selection")
	}
	for _, o := range *owners {
		if o.closes != 0 {
			t.Fatal("uncertain mutation prematurely closed its admission")
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, o := range *owners {
		if o.closes != 1 {
			t.Fatal("retained admission close count changed")
		}
	}
}

func TestOwnerProfilePreparationCancellationRetainsPartialOwner(t *testing.T) {
	q, deps, home, owners := ownerPreparationRequest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps.syncDirectory = func(d *ownerProfilePreparationDirectory) error {
		if err := d.entry.file.Sync(); err != nil {
			return err
		}
		cancel()
		return nil
	}
	r, err := prepareOwnerProfile(ctx, q, deps)
	if r == nil || !errors.Is(err, context.Canceled) || !r.mutated || r.prepared {
		t.Fatal("canceled publication lost its cause or retained owner")
	}
	defer r.Close()
	if _, err := os.Stat(filepath.Join(home, "Library")); err != nil {
		t.Fatal("partial setup was removed")
	}
	for _, owner := range *owners {
		if owner.closes != 0 {
			t.Fatal("cancellation closed a retained admission")
		}
	}
	if _, err := r.Selection(context.Background()); err == nil {
		t.Fatal("canceled preparation returned a selection")
	}
}

func TestOwnerProfilePreparationFileSyncFailureRetainsPublication(t *testing.T) {
	q, deps, home, _ := ownerPreparationRequest(t)
	deps.syncDirectory = func(d *ownerProfilePreparationDirectory) error {
		if filepath.Base(d.entry.path) == q.Owner.ProfileID {
			return errors.New("failed publication durability")
		}
		return d.entry.file.Sync()
	}
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if err == nil || r == nil || len(r.stages) != 1 || !r.stages[0].published {
		t.Fatal("uncertain file publication lost its stage owner")
	}
	defer r.Close()
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID)
	if _, err := os.Stat(filepath.Join(directory, localServerTrustFile)); err != nil {
		t.Fatal("uncertain publication was removed")
	}
	if _, err := os.Stat(filepath.Join(directory, "registration.json")); !os.IsNotExist(err) {
		t.Fatal("partial setup was registered")
	}
	if _, err := r.stages[0].file.Stat(); err != nil {
		t.Fatal("published original was not retained")
	}
	store := r.files.files[len(r.files.files)-2]
	// Find the store rather than relying on descriptor ordering after file reads.
	for _, entry := range r.files.files {
		if entry.path == filepath.Dir(directory) {
			store = entry
		}
	}
	fd, err := unix.Open(store.path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
		unix.Flock(fd, unix.LOCK_UN)
		t.Fatal("uncertain preparation released the store lock")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("close did not release the store lock")
	}
	unix.Flock(fd, unix.LOCK_UN)
}

func TestOwnerProfilePreparationRejectsCreatedDirectoryReplacement(t *testing.T) {
	q, deps, home, _ := ownerPreparationRequest(t)
	replaced := false
	deps.openDirectory = func(fd int, name string) (int, error) {
		if name == q.Owner.ProfileID {
			if unix.Renameat(fd, name, fd, name+"-original") != nil || unix.Mkdirat(fd, name, 0700) != nil {
				t.Fatal("replacement control failed")
			}
			replaced = true
		}
		return openOwnerProfileChild(fd, name)
	}
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if err == nil || r == nil || !replaced || !r.mutated {
		t.Fatal("created directory replacement was accepted")
	}
	defer r.Close()
	for _, suffix := range []string{"", "-original"} {
		entries, err := os.ReadDir(filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", q.Owner.ProfileID+suffix))
		if err != nil || len(entries) != 0 {
			t.Fatal("preparation wrote into a replaced directory")
		}
	}
}

type ownerPreparationErrorOwner struct{ retained *centralTestOwner }

func (*ownerPreparationErrorOwner) Error() string { return "PRIVATE admission failure" }

type ownerPreparationRecheckOwner struct {
	centralTestOwner
	failure error
}

func (o *ownerPreparationRecheckOwner) Recheck(context.Context) error { return o.failure }

func TestOwnerProfilePreparationRetainsErrorOnlyAdmissionOwners(t *testing.T) {
	for _, boundary := range []string{"client", "image", "host-image", "digest", "recheck", "host-recheck"} {
		t.Run(boundary, func(t *testing.T) {
			q, deps, home, _ := ownerPreparationRequest(t)
			original := &ownerPreparationErrorOwner{retained: &centralTestOwner{}}
			switch boundary {
			case "client":
				deps.central.client = func(context.Context, string) (centralClientOwner, error) { return nil, original }
			case "image":
				deps.central.image = func(context.Context, string, string) (centralImageOwner, error) { return nil, original }
			case "host-image":
				deps.central.hostImage = func(context.Context, string, string) (centralImageOwner, error) { return nil, original }
			case "digest":
				deps.central.clientDigest = func(context.Context, string, *CentralProfileResolution) (string, error) { return "", original }
			case "recheck":
				deps.central.client = func(context.Context, string) (centralClientOwner, error) {
					return &ownerPreparationRecheckOwner{failure: original}, nil
				}
			case "host-recheck":
				deps.central.hostImage = func(context.Context, string, string) (centralImageOwner, error) {
					return &ownerPreparationRecheckOwner{failure: original}, nil
				}
			}
			r, err := prepareOwnerProfile(context.Background(), q, deps)
			if r == nil || err == nil || r.closed || !errors.Is(err, original) || r.retainedFailure == nil {
				t.Fatal("error-only admission owner was lost")
			}
			if strings.Contains(fmt.Sprintf("%+v", err), "PRIVATE") {
				t.Fatal("error formatting exposed admission cause")
			}
			if _, err := os.Stat(filepath.Join(home, "Library")); !os.IsNotExist(err) {
				t.Fatal("failed admission created profile state")
			}
			closed := r.Close()
			if closed == nil || !errors.Is(closed, original) || r.Close() != closed || original.retained.closes != 0 {
				t.Fatal("close lost or retried nested recovery ownership")
			}
		})
	}
}

func TestOwnerProfilePreparationRefusesFrontendHostBeforeMutation(t *testing.T) {
	q, deps, home, owners := ownerPreparationRequest(t)
	q.RuntimeExecutablePath = protected.StableFrontendPath
	r, err := prepareOwnerProfile(context.Background(), q, deps)
	if r != nil || err == nil || len(*owners) != 0 {
		t.Fatal("fixed frontend host request reached installed code admission")
	}
	if _, err := os.Stat(filepath.Join(home, "Library")); !os.IsNotExist(err) {
		t.Fatal("incompatible host request created profile files")
	}
}
