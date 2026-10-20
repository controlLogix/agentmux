//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type centralTestOwner struct {
	checks, closes, execs                                      int
	closeErr                                                   error
	registeredFile                                             *os.File
	registeredDigest, registeredOperation, registeredSelection string
	registeredFailure                                          error
	registeredExecs                                            int
	checkErr                                                   error
}

func (o *centralTestOwner) Recheck(context.Context) error { o.checks++; return o.checkErr }
func (o *centralTestOwner) Close() error                  { o.closes++; return o.closeErr }
func (o *centralTestOwner) ExecRegistered(_ context.Context, operation, selection string, registration *os.File, digest string) error {
	o.execs++
	o.registeredExecs++
	o.registeredFile = registration
	o.registeredDigest = digest
	o.registeredOperation = operation
	o.registeredSelection = selection
	return o.registeredFailure
}

type centralTestFixture struct {
	request                     CentralProfileRegistrationRequest
	deps                        centralProfileDependencies
	home, directory, repository string
	clients, images, hostImages []*centralTestOwner
}

func centralFixture(t *testing.T) *centralTestFixture {
	t.Helper()
	policy, declaration := profileFixture(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(home, "Library", "Application Support", "Agentmux", "profiles", declaration.ProfileID)
	if err = os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	policy.Directory = directory
	declaration.ProfileDirectory = directory
	if err = EnrollProfile(policy, declaration); err != nil {
		t.Fatal(err)
	}
	host := &EnrolledHostPolicy{policy: HostPolicy{Profile: policy}}
	host.record.ProfileID = declaration.ProfileID
	host.record.InstanceID = declaration.InstanceID
	host.record.ProfileDirectory = directory
	host.record.Owner.Identity.OwnerHubID = "hub_test"
	host.record.Release.PackageDirectory = "/private/test/release"
	host.record.RuntimeExecutable = hostPolicyExecutable{Path: "/private/test/release/agentmux-runtime", Digest: "sha256:" + strings.Repeat("d", 64)}
	selection := centralProfileSelectionFile{SchemaVersion: "1.0.0", HostPolicy: filepath.Join(directory, "host-policy.json"), Workspaces: policy.WorkspaceRoots, InstanceID: declaration.InstanceID, ProfileID: declaration.ProfileID, HubID: "hub_test"}
	raw, err := json.Marshal(selection)
	if err != nil {
		t.Fatal(err)
	}
	for name, bytes := range map[string][]byte{"host-policy.json": []byte(`{"fixture":true}`), "client-selection.json": raw} {
		if err = os.WriteFile(filepath.Join(directory, name), bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	environment := "Development"
	f := &centralTestFixture{home: home, directory: directory, repository: policy.WorkspaceRoots[0], request: CentralProfileRegistrationRequest{ProfileID: declaration.ProfileID, ClientInstallationID: strings.Repeat("c", 64), ApprovedWorkspaceRoots: policy.WorkspaceRoots, Context: CentralProfileContext{Environment: &environment}}}
	f.deps = centralProfileDependencies{
		account: func() (string, uint32, error) { return home, uint32(os.Geteuid()), nil },
		host: func(selection HostPolicySelection) (*EnrolledHostPolicy, error) {
			if selection.Path != filepath.Join(directory, "host-policy.json") {
				return nil, errors.New("unexpected policy")
			}
			return host, nil
		},
		client: func(context.Context, string) (centralClientOwner, error) {
			o := &centralTestOwner{}
			f.clients = append(f.clients, o)
			return o, nil
		},
		clientDigest: func(context.Context, string, *CentralProfileResolution) (string, error) {
			return host.record.RuntimeExecutable.Digest, nil
		},
		image: func(_ context.Context, path, digest string) (centralImageOwner, error) {
			if path != protected.StableFrontendPath || digest != host.record.RuntimeExecutable.Digest {
				t.Fatal("frontend admission received the host image path or different digest")
			}
			o := &centralTestOwner{}
			f.images = append(f.images, o)
			return o, nil
		},
		hostImage: func(_ context.Context, path, digest string) (centralImageOwner, error) {
			if path != host.record.RuntimeExecutable.Path || digest != host.record.RuntimeExecutable.Digest {
				t.Fatal("host admission received the frontend path or different digest")
			}
			o := &centralTestOwner{}
			f.hostImages = append(f.hostImages, o)
			return o, nil
		},
	}
	return f
}
func TestCentralProfileRegistrationAndResolution(t *testing.T) {
	f := centralFixture(t)
	t.Setenv("HOME", t.TempDir())
	r, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := r.Selection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if selection.ProfileID != f.request.ProfileID || selection.ClientSelectionPath != filepath.Join(f.directory, "client-selection.json") || selection.Context.Environment == nil || selection.Context.Project != nil {
		t.Fatal("selection changed")
	}
	*selection.Context.Environment = "Changed"
	if *r.record.Environment != "Development" {
		t.Fatal("context was mutable")
	}
	if err = r.ExecClient(context.Background(), "startup"); err != nil {
		t.Fatal(err)
	}
	if f.clients[0].execs != 1 {
		t.Fatal("original client not used")
	}
	raw, err := os.ReadFile(filepath.Join(f.directory, centralProfileRegistrationName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"project"`) {
		t.Fatal("absent metadata persisted")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if f.clients[0].closes != 1 || f.images[0].closes != 1 || f.hostImages[0].closes != 1 || f.hostImages[0].checks == 0 {
		t.Fatal("owner closed more than once")
	}
	if _, err = registerCentralProfile(context.Background(), f.request, f.deps); err == nil {
		t.Fatal("registration replaced")
	}
	after, _ := os.ReadFile(filepath.Join(f.directory, centralProfileRegistrationName))
	if string(raw) != string(after) {
		t.Fatal("existing registration changed")
	}
	r, err = resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.Selection(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(f.directory)
	if len(entries) != 4 {
		t.Fatal("staging file left behind")
	}
}
func TestCentralProfileMetadata(t *testing.T) {
	for _, tc := range []struct {
		name         string
		env, project *string
		valid        bool
	}{
		{"missing", nil, nil, false}, {"environment", centralString("Local"), nil, true}, {"project", nil, centralString("Console"), true}, {"both", centralString("Staging"), centralString("Console"), true}, {"empty", centralString(""), nil, false}, {"space", nil, centralString(" Project"), false}, {"control", centralString("one\ntwo"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := centralFixture(t)
			f.request.Context = CentralProfileContext{tc.env, tc.project}
			r, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if r != nil {
				defer r.Close()
			}
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if !tc.valid {
				if _, err = os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); !os.IsNotExist(err) {
					t.Fatal("invalid context published")
				}
			}
		})
	}
}
func centralString(s string) *string { return &s }
func TestCentralProfileRejectsChangedFiles(t *testing.T) {
	for _, kind := range []string{"replacement", "rewrite-restored-time", "symlink", "hardlink", "permissions", "ancestor"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			r, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			path := filepath.Join(f.directory, "host-policy.json")
			info, _ := os.Stat(path)
			raw, _ := os.ReadFile(path)
			switch kind {
			case "replacement":
				if err = os.Rename(path, path+".old"); err == nil {
					err = os.WriteFile(path, raw, 0600)
				}
			case "rewrite-restored-time":
				time.Sleep(time.Millisecond)
				err = os.WriteFile(path, []byte(`{"fixture":null}`), 0600)
				if err == nil {
					err = os.Chtimes(path, info.ModTime(), info.ModTime())
				}
			case "symlink":
				if err = os.Rename(path, path+".old"); err == nil {
					err = os.Symlink(path+".old", path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			case "permissions":
				err = os.Chmod(path, 0644)
			case "ancestor":
				parent := filepath.Dir(f.directory)
				err = os.Chmod(parent, 0777)
				defer os.Chmod(parent, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Recheck(context.Background()); err == nil {
				t.Fatal("changed admission accepted")
			}
			if err = r.ExecClient(context.Background(), "startup"); err == nil || f.clients[0].execs != 0 {
				t.Fatal("changed admission executed")
			}
			if kind != "replacement" {
				if got, err := resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps); err == nil {
					got.Close()
					t.Fatal("changed registration resolved")
				}
			}
		})
	}
}
func TestCentralProfileRejectsWrongReferenceAndRepository(t *testing.T) {
	f := centralFixture(t)
	r, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	for _, id := range []string{"../" + f.request.ProfileID, "Profile_" + strings.Repeat("a", 32), "", f.request.ProfileID + "/extra"} {
		if r, err = resolveCentralProfile(context.Background(), id, f.repository, f.deps); err == nil {
			r.Close()
			t.Fatal("invalid profile reference accepted")
		}
	}
	other, _ := filepath.EvalSymlinks(t.TempDir())
	if r, err = resolveCentralProfile(context.Background(), f.request.ProfileID, other, f.deps); err == nil {
		r.Close()
		t.Fatal("unregistered repository admitted")
	}
}
func TestCentralProfileFailureRetainsCleanupOwner(t *testing.T) {
	f := centralFixture(t)
	o := &centralTestOwner{closeErr: errors.New("uncertain close")}
	f.deps.client = func(context.Context, string) (centralClientOwner, error) { return o, errors.New("admission failed") }
	r, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err == nil || r == nil || o.closes != 0 {
		t.Fatal("failed owner lost or consumed before explicit close")
	}
	if r.Close() == nil || o.closes != 1 {
		t.Fatal("failed cleanup retried or forgotten")
	}
	if r.Close() == nil || o.closes != 1 {
		t.Fatal("failed cleanup retried on repeated close")
	}
	if _, err = os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); !os.IsNotExist(err) {
		t.Fatal("partial admission published")
	}
}
func TestCentralProfileRegistrationClosedSchema(t *testing.T) {
	f := centralFixture(t)
	r, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	path := filepath.Join(f.directory, centralProfileRegistrationName)
	raw, _ := os.ReadFile(path)
	for _, change := range []func(map[string]any){func(v map[string]any) { v["project"] = nil }, func(v map[string]any) { v["environment"] = "" }, func(v map[string]any) { delete(v, "environment") }, func(v map[string]any) { v["OwnerUid"] = v["ownerUid"]; delete(v, "ownerUid") }, func(v map[string]any) { v["instanceId"] = "instance_" + strings.Repeat("c", 32) }, func(v map[string]any) { v["clientSelectionSha256"] = "sha256:" + strings.Repeat("e", 64) }} {
		var fields map[string]any
		json.Unmarshal(raw, &fields)
		change(fields)
		changed, _ := json.Marshal(fields)
		os.WriteFile(path, changed, 0600)
		if got, err := resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps); err == nil {
			got.Close()
			t.Fatal("changed registration accepted")
		}
	}
}

func TestCentralProfileRegistrationStopsBeforePublication(t *testing.T) {
	for _, kind := range []string{"cancelled", "workspace-mismatch", "client-release-mismatch", "changed-during-admission", "selection-null-application", "selection-missing-client-key", "wrong-profile", "wrong-instance"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			ctx := context.Background()
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "workspace-mismatch":
				other, _ := filepath.EvalSymlinks(t.TempDir())
				f.request.ApprovedWorkspaceRoots = []string{other}
			case "client-release-mismatch":
				f.deps.clientDigest = func(context.Context, string, *CentralProfileResolution) (string, error) {
					return "sha256:" + strings.Repeat("f", 64), nil
				}
			case "changed-during-admission":
				previous := f.deps.image
				f.deps.image = func(ctx context.Context, path, digest string) (centralImageOwner, error) {
					if err := os.WriteFile(filepath.Join(f.directory, "host-policy.json"), []byte(`{"fixture":false}`), 0600); err != nil {
						t.Fatal(err)
					}
					return previous(ctx, path, digest)
				}
			default:
				path := filepath.Join(f.directory, "client-selection.json")
				raw, _ := os.ReadFile(path)
				var fields map[string]any
				json.Unmarshal(raw, &fields)
				switch kind {
				case "selection-null-application":
					fields["application"] = nil
				case "selection-missing-client-key":
					fields["application"] = map[string]any{"connection": filepath.Join(f.directory, "connection.json")}
				case "wrong-profile":
					fields["profileId"] = "profile_" + strings.Repeat("d", 32)
				case "wrong-instance":
					fields["instanceId"] = "instance_" + strings.Repeat("d", 32)
				}
				changed, _ := json.Marshal(fields)
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := registerCentralProfile(ctx, f.request, f.deps)
			if r != nil {
				r.Close()
			}
			if err == nil {
				t.Fatal("invalid registration accepted")
			}
			entries, err := os.ReadDir(f.directory)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 {
				t.Fatal("failed registration changed profile directory")
			}
			for _, o := range append(f.clients, f.images...) {
				if o.closes != 1 {
					t.Fatal("partial admission not closed once")
				}
			}
		})
	}
}
func TestCentralProfileMissingRegistrationDoesNotMigrate(t *testing.T) {
	f := centralFixture(t)
	if r, err := resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps); err == nil {
		r.Close()
		t.Fatal("unregistered profile resolved")
	}
	entries, err := os.ReadDir(f.directory)
	if err != nil || len(entries) != 3 {
		t.Fatal("resolution modified existing profile")
	}
	host, err := f.deps.host(HostPolicySelection{Path: filepath.Join(f.directory, "host-policy.json")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = LoadProfile(host.policy.Profile); err != nil {
		t.Fatal("explicit profile selection no longer works", err)
	}
}

func TestCentralProfileApplicationServicesSelection(t *testing.T) {
	for _, kind := range []string{"valid", "null", "missing-attestor", "missing-field", "stale-host-account", "workspace-selection", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			path := filepath.Join(f.directory, "client-selection.json")
			raw, _ := os.ReadFile(path)
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			fields["applicationAttestor"] = map[string]any{"selection": filepath.Join(f.directory, "attestor.json"), "sha256": "sha256:" + strings.Repeat("a", 64)}
			services := map[string]any{"installationId": strings.Repeat("c", 64), "selection": filepath.Join(f.directory, "services.json"), "sha256": "sha256:" + strings.Repeat("b", 64)}
			fields["applicationServices"] = services
			switch kind {
			case "null":
				fields["applicationServices"] = nil
			case "missing-attestor":
				delete(fields, "applicationAttestor")
			case "missing-field":
				delete(services, "installationId")
			case "stale-host-account":
				services["hostAccountPublicKey"] = "not-an-account-key"
			case "workspace-selection":
				services["selection"] = filepath.Join(f.repository, "services.json")
			case "unknown-field":
				services["unknown"] = true
			}
			changed, _ := json.Marshal(fields)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if r != nil {
				r.Close()
			}
			if (err == nil) != (kind == "valid") {
				t.Fatalf("%s: %v", kind, err)
			}
		})
	}
}

func TestCentralProfileApplicationRepositoryRoutes(t *testing.T) {
	for _, kind := range []string{"absent", "valid", "empty", "duplicate", "uppercase", "hyphen", "too-long", "wrong-type"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			path := filepath.Join(f.directory, "client-selection.json")
			raw, _ := os.ReadFile(path)
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			application := map[string]any{"clientKey": filepath.Join(f.directory, "client-key.json"),
				"connection": filepath.Join(f.directory, "connection.json")}
			if kind != "absent" {
				application["repositories"] = []any{"alpha", "repo_2"}
			}
			switch kind {
			case "empty":
				application["repositories"] = []any{}
			case "duplicate":
				application["repositories"] = []any{"alpha", "alpha"}
			case "uppercase":
				application["repositories"] = []any{"Alpha"}
			case "hyphen":
				application["repositories"] = []any{"alpha-one"}
			case "too-long":
				application["repositories"] = []any{strings.Repeat("a", 33)}
			case "wrong-type":
				application["repositories"] = "alpha"
			}
			fields["application"] = application
			changed, _ := json.Marshal(fields)
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if r != nil {
				r.Close()
			}
			want := kind == "absent" || kind == "valid"
			if (err == nil) != want {
				t.Fatalf("%s: %v", kind, err)
			}
		})
	}
}

func TestCentralProfilePublicationCancellationRetainsOriginalOwner(t *testing.T) {
	f := centralFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	account := f.deps.account
	f.deps.account = func() (string, uint32, error) {
		if _, err := os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); err == nil {
			cancel()
		}
		return account()
	}
	r, err := registerCentralProfile(ctx, f.request, f.deps)
	if err == nil || err.Error() != "central_profile_publication_uncertain" {
		t.Fatalf("expected publication uncertainty, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); statErr != nil {
		t.Fatal("publication did not occur", statErr)
	}
	if r == nil {
		t.Fatal("published registration lost its original owner")
	}
	defer r.Close()
	if f.clients[0].closes != 0 || f.images[0].closes != 0 {
		t.Fatal("uncertain publication consumed recovery owners")
	}
	if r.directoryFile.file.Fd() == ^uintptr(0) || len(r.stages) != 1 || r.stages[0].Fd() == ^uintptr(0) {
		t.Fatal("original publication descriptors were consumed")
	}
	for _, file := range r.files {
		if _, statErr := file.file.Stat(); statErr != nil {
			t.Fatal("original file owner was consumed", statErr)
		}
	}
	if err = r.Recheck(context.Background()); err == nil {
		t.Fatal("uncertain publication passed recheck")
	}
	if _, err = r.Selection(context.Background()); err == nil {
		t.Fatal("uncertain publication disclosed selection")
	}
	if err = r.ExecClient(context.Background(), "startup"); err == nil || f.clients[0].execs != 0 {
		t.Fatal("uncertain publication executed")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if f.clients[0].closes != 1 || f.images[0].closes != 1 {
		t.Fatal("explicit close did not consume owners once")
	}
}

func TestCentralProfileStageCleanupUncertaintyRetainsOriginalOwner(t *testing.T) {
	f := centralFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	account := f.deps.account
	changed := false
	f.deps.account = func() (string, uint32, error) {
		if !changed {
			entries, err := os.ReadDir(f.directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), ".registration-") {
					continue
				}
				stage := filepath.Join(f.directory, entry.Name())
				if err = os.Rename(stage, stage+".held"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(stage, 0700); err != nil {
					t.Fatal(err)
				}
				changed = true
				cancel()
				break
			}
		}
		return account()
	}
	r, err := registerCentralProfile(ctx, f.request, f.deps)
	if err == nil || err.Error() != "central_profile_publication_uncertain" || r == nil {
		t.Fatalf("stage cleanup lost owner: %v", err)
	}
	defer r.Close()
	if !changed || f.clients[0].closes != 0 || f.images[0].closes != 0 {
		t.Fatal("stage cleanup consumed original owners")
	}
	if _, err = r.stages[0].Stat(); err != nil {
		t.Fatal("original stage descriptor closed", err)
	}
	if _, err = os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); !os.IsNotExist(err) {
		t.Fatal("registration was published")
	}
	if err = r.ExecClient(context.Background(), "startup"); err == nil || f.clients[0].execs != 0 {
		t.Fatal("uncertain stage executed")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil || f.clients[0].closes != 1 || f.images[0].closes != 1 {
		t.Fatal("original owners not closed once")
	}
}

func TestCentralProfileStageRegularReplacementPreserved(t *testing.T) {
	f := centralFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	account := f.deps.account
	var replacement string
	f.deps.account = func() (string, uint32, error) {
		if replacement == "" {
			entries, err := os.ReadDir(f.directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), ".registration-") {
					continue
				}
				replacement = filepath.Join(f.directory, entry.Name())
				if err = os.Rename(replacement, replacement+".held"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(replacement, []byte("FOREIGN"), 0600); err != nil {
					t.Fatal(err)
				}
				cancel()
				break
			}
		}
		return account()
	}
	r, err := registerCentralProfile(ctx, f.request, f.deps)
	if r != nil {
		defer r.Close()
	}
	raw, readErr := os.ReadFile(replacement)
	if readErr != nil || string(raw) != "FOREIGN" {
		t.Fatal("replacement file was deleted or changed", readErr)
	}
	if err == nil || err.Error() != "central_profile_publication_uncertain" || r == nil {
		t.Fatalf("replacement lost original recovery owner: %v", err)
	}
	if f.clients[0].closes != 0 || f.images[0].closes != 0 {
		t.Fatal("replacement consumed original owners")
	}
	held, err := os.Stat(replacement + ".held")
	if err != nil {
		t.Fatal(err)
	}
	retained, err := r.stages[0].Stat()
	if err != nil || !os.SameFile(held, retained) {
		t.Fatal("original stage owner was lost")
	}
	if err = r.ExecClient(context.Background(), "startup"); err == nil || f.clients[0].execs != 0 {
		t.Fatal("replaced stage executed")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil || f.clients[0].closes != 1 || f.images[0].closes != 1 {
		t.Fatal("original owners not closed once")
	}
	raw, readErr = os.ReadFile(replacement)
	if readErr != nil || string(raw) != "FOREIGN" {
		t.Fatal("explicit close changed replacement")
	}
}

func TestCentralProfileExecCarriesOriginalRegistration(t *testing.T) {
	for _, kind := range []string{"environment", "project", "both"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			if kind == "project" {
				f.request.Context = CentralProfileContext{Project: centralString("Console")}
			}
			if kind == "both" {
				f.request.Context.Project = centralString("Console")
			}
			admitted, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			if err = admitted.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			var original *centralProfileFile
			for _, file := range r.files {
				if !file.directory && file.path == filepath.Join(f.directory, centralProfileRegistrationName) {
					original = file
				}
			}
			if original == nil {
				t.Fatal("original registration not retained")
			}
			client := f.clients[len(f.clients)-1]
			execFailure := errors.New("exec returned without replacing process")
			client.registeredFailure = execFailure
			if err = r.ExecClient(context.Background(), "startup-json"); !errors.Is(err, execFailure) {
				t.Fatal("registered execution boundary was not used")
			}
			if client.registeredExecs != 1 || client.execs != 1 || client.registeredFile != original.file || client.registeredDigest != original.digest || client.registeredOperation != "startup-json" || client.registeredSelection != filepath.Join(f.directory, "client-selection.json") {
				t.Fatal("registration descriptor or binding changed at execution")
			}
			raw, err := io.ReadAll(io.NewSectionReader(client.registeredFile, 0, 16385))
			if err != nil {
				t.Fatal(err)
			}
			var record centralProfileRegistration
			if decodeCentralRegistration(raw, &record) != nil || centralDigest(raw) != client.registeredDigest {
				t.Fatal("execution did not receive the pinned registration")
			}
			if (record.Environment != nil) != (kind != "project") || (record.Project != nil) != (kind != "environment") {
				t.Fatal("metadata was inferred or dropped")
			}
			if client.closes != 0 {
				t.Fatal("exec failure consumed original client owner")
			}
			if _, err = original.file.Stat(); err != nil {
				t.Fatal("exec failure consumed original registration")
			}
			if err = r.Close(); err != nil || client.closes != 1 {
				t.Fatal("explicit close did not consume original owner once")
			}
		})
	}
}

// An error-only result can be the sole reference to an original cleanup owner.
type centralTestAdmissionFailure struct{ owner *centralTestOwner }

func (*centralTestAdmissionFailure) Error() string { return "private admission details /private/owner" }

func TestCentralProfileAdmissionErrorOnlyRetainsOriginalOwner(t *testing.T) {
	for _, kind := range []string{"client", "client-digest", "image", "host-image", "host"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			original := &centralTestOwner{}
			cause := &centralTestAdmissionFailure{owner: original}
			switch kind {
			case "client":
				f.deps.client = func(context.Context, string) (centralClientOwner, error) { return nil, cause }
			case "client-digest":
				f.deps.clientDigest = func(context.Context, string, *CentralProfileResolution) (string, error) { return "", cause }
			case "image":
				f.deps.image = func(context.Context, string, string) (centralImageOwner, error) { return nil, cause }
			case "host-image":
				f.deps.hostImage = func(context.Context, string, string) (centralImageOwner, error) { return nil, cause }
			case "host":
				f.deps.host = func(HostPolicySelection) (*EnrolledHostPolicy, error) { return nil, cause }
			}
			r, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if r == nil || err == nil {
				t.Fatal("opaque admission failure lost its original resolution")
			}
			defer r.Close()
			var retained *centralTestAdmissionFailure
			if !errors.As(err, &retained) || retained != cause || retained.owner != original {
				t.Fatal("original nested cleanup owner was discarded")
			}
			for _, owned := range append(append(f.clients, f.images...), f.hostImages...) {
				if owned.closes != 0 {
					t.Fatal("admission failure implicitly consumed original owners")
				}
			}
			if _, statErr := os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); !os.IsNotExist(statErr) {
				t.Fatal("failed admission published registration")
			}
			if useErr := r.ExecClient(context.Background(), "startup"); !errors.Is(useErr, cause) {
				t.Fatal("failed admission was not fenced with original cause")
			}
			encoded, _ := json.Marshal(err)
			if strings.Contains(fmt.Sprintf("%+v %s", err, encoded), "private admission") || strings.Contains(fmt.Sprintf("%+v %s", err, encoded), "/private/owner") {
				t.Fatal("admission cause leaked through public formatting")
			}
			closeErr := r.Close()
			if closeErr == nil || !errors.As(closeErr, &retained) || retained != cause || retained.owner != original {
				t.Fatal("explicit close claimed nested recovery complete or lost original owner")
			}
			if r.Close() != closeErr || original.closes != 0 {
				t.Fatal("nested cleanup owner was retried or forgotten")
			}
			for _, owned := range append(append(f.clients, f.images...), f.hostImages...) {
				if owned.closes != 1 {
					t.Fatal("explicit close did not consume known owners once")
				}
			}
		})
	}
}

func TestCentralProfileRecheckRetainsAdmissionErrorOwner(t *testing.T) {
	for _, kind := range []string{"client", "image", "host-image", "host"} {
		t.Run(kind, func(t *testing.T) {
			f := centralFixture(t)
			r, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			original := &centralTestOwner{}
			cause := &centralTestAdmissionFailure{owner: original}
			switch kind {
			case "client":
				f.clients[0].checkErr = cause
			case "image":
				f.images[0].checkErr = cause
			case "host-image":
				f.hostImages[0].checkErr = cause
			case "host":
				r.dependencies.host = func(HostPolicySelection) (*EnrolledHostPolicy, error) { return nil, cause }
			}
			err = r.ExecClient(context.Background(), "startup")
			var actual *centralTestAdmissionFailure
			if !errors.As(err, &actual) || actual != cause || actual.owner != original || f.clients[0].execs != 0 {
				t.Fatal("recheck discarded admission cause or executed")
			}
			if err = r.Close(); !errors.As(err, &actual) || actual != cause {
				t.Fatal("close hid unresolved nested admission owner")
			}
			if f.clients[0].closes != 1 || f.images[0].closes != 1 || f.hostImages[0].closes != 1 || original.closes != 0 {
				t.Fatal("close retried an opaque nested owner")
			}
		})
	}
}

func TestCentralProfileRefusesFrontendAsHostBeforePublicationOrUse(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(fmt.Sprint(registered), func(t *testing.T) {
			f := centralFixture(t)
			if registered {
				r, err := registerCentralProfile(context.Background(), f.request, f.deps)
				if err != nil || r.Close() != nil {
					t.Fatal("valid profile did not register")
				}
			}
			original := f.deps.host
			f.deps.host = func(s HostPolicySelection) (*EnrolledHostPolicy, error) {
				host, err := original(s)
				host.record.RuntimeExecutable.Path = protected.StableFrontendPath
				return host, err
			}
			var result *CentralProfileResolution
			var err error
			if registered {
				result, err = resolveCentralProfile(context.Background(), f.request.ProfileID, f.repository, f.deps)
			} else {
				result, err = registerCentralProfile(context.Background(), f.request, f.deps)
			}
			if result != nil {
				defer result.Close()
			}
			if err == nil {
				t.Fatal("fixed frontend was admitted as a release host")
			}
			if !registered {
				if _, err := os.Stat(filepath.Join(f.directory, centralProfileRegistrationName)); !os.IsNotExist(err) || len(f.clients) != 0 || len(f.images) != 0 || len(f.hostImages) != 0 {
					t.Fatal("incompatible host path reached code admission or publication")
				}
			}
		})
	}
}

func TestCentralProfileHostImageCloseFailureKeepsOriginalOwner(t *testing.T) {
	f := centralFixture(t)
	r, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("controlled_host_close_failure")
	f.hostImages[0].closeErr = cause
	err = r.Close()
	if !errors.Is(err, cause) || r.hostImage != f.hostImages[0] || r.Close() != err || f.hostImages[0].closes != 1 || f.images[0].closes != 1 || f.clients[0].closes != 1 {
		t.Fatal("failed host close lost or retried an original owner")
	}
}
