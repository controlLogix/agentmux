//go:build darwin && arm64

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/controlLogix/agentmux/platform/installer"
)

func localOptions(t *testing.T) options {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	image, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The test executable is a real native Mach-O image. No synthetic header or
	// alternate verifier replaces the product installer's image/signature checks.
	return options{development: true, kernel: image, frontend: image, output: filepath.Join(parent, "package"),
		image: "docker.io/library/nats@sha256:" + strings.Repeat("a", 64)}
}

func localPrepare(t *testing.T) (options, prepared, installer.Selection) {
	t.Helper()
	o := localOptions(t)
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	p, err := prepare(context.Background(), o, root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := installer.ReadSelection(context.Background(), p.Selection, p.SelectionDigest, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	return o, p, s
}

func TestDevelopmentPackageUsesFreshEphemeralKeyAndExistingVerifier(t *testing.T) {
	o, p, s := localPrepare(t)
	_, other, second := localPrepare(t)
	if s.Release.PublicKeyHex == second.Release.PublicKeyHex || p.SelectionDigest == other.SelectionDigest {
		t.Fatal("development builds shared a signing identity")
	}
	if p.Purpose != "local-development-only" || p.Verification.Outcome != "verified" ||
		p.Verification.Enrollment != "not_checked" || p.Verification.Readiness != "not_observed" ||
		s.Release.ReleaseAuthority.ID != "local_development" || s.Release.ReleaseVersion != "0.0.0" {
		t.Fatal("preparation implied installation, enrollment or an official release")
	}
	files := map[string]bool{}
	err := filepath.WalkDir(o.output, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(o.output, path)
		files[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"foundation-selection.json", "payload/release-manifest.json", "payload/protected-assembly.json",
		"payload/release-authorization.json", "payload/release-authorization.sig", "payload/agentmux-runtime",
		"payload/bin/boot", "payload/bin/kernel-lifecycle", "payload/bin/internal-communication", "payload/bin/exported-status"}
	if len(files) != len(want) {
		t.Fatal("unexpected output, possibly including signing material", files)
	}
	for _, name := range want {
		if !files[name] {
			t.Fatal("missing output", name)
		}
	}
	info, err := os.Stat(p.Selection)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("installation selection is not private")
	}
	public, err := hex.DecodeString(s.Release.PublicKeyHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("invalid public verification key")
	}
	approval, _ := os.ReadFile(filepath.Join(s.Release.PackageDirectory, "release-authorization.json"))
	signature, _ := os.ReadFile(filepath.Join(s.Release.PackageDirectory, "release-authorization.sig"))
	if !ed25519.Verify(public, approval, signature) {
		t.Fatal("signature does not bind exact authorization bytes")
	}
	if _, err := installer.Prepare(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	// The serialized selection has public policy only; it remains the product's
	// closed Selection contract, not a new trust-store or key enrollment format.
	raw, _ := os.ReadFile(p.Selection)
	var shape map[string]json.RawMessage
	if json.Unmarshal(raw, &shape) != nil || len(shape) != 3 {
		t.Fatal("selection contract widened")
	}
}

func TestDevelopmentPackageChangedKeyOrBytesAreRefused(t *testing.T) {
	for _, name := range []string{"key", "release-manifest.json", "protected-assembly.json", "release-authorization.json", "release-authorization.sig", "bin/boot", "agentmux-runtime"} {
		t.Run(name, func(t *testing.T) {
			_, _, s := localPrepare(t)
			if name == "key" {
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				clear(private)
				s.Release.PublicKeyHex = hex.EncodeToString(public)
			} else {
				path := filepath.Join(s.Release.PackageDirectory, name)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw[0] ^= 1
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, raw, 0600) != nil {
					t.Fatal("tamper setup failed")
				}
			}
			if pkg, err := installer.Prepare(context.Background(), s); err == nil || pkg != nil {
				t.Fatal("changed package accepted")
			}
		})
	}
}

func TestDevelopmentPackageRefusesUnsafePreparation(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"authorization", "relative-output", "checkout-output", "insecure-parent", "linked-parent", "existing-output", "linked-image", "not-native", "image-tag"} {
		t.Run(name, func(t *testing.T) {
			o := localOptions(t)
			parent := filepath.Dir(o.output)
			switch name {
			case "authorization":
				o.development = false
			case "relative-output":
				o.output = "relative"
			case "checkout-output":
				o.output = filepath.Join(root, "dev-package-test-must-not-exist")
			case "insecure-parent":
				if os.Chmod(parent, 0755) != nil {
					t.Fatal("chmod failed")
				}
			case "linked-parent":
				link := filepath.Join(parent, "link")
				if os.Symlink(parent, link) != nil {
					t.Fatal("symlink failed")
				}
				o.output = filepath.Join(link, "package")
			case "existing-output":
				if os.Mkdir(o.output, 0700) != nil {
					t.Fatal("mkdir failed")
				}
			case "linked-image":
				link := filepath.Join(parent, "kernel-link")
				if os.Symlink(o.kernel, link) != nil {
					t.Fatal("symlink failed")
				}
				o.kernel = link
			case "not-native":
				o.kernel = filepath.Join(parent, "not-native")
				if os.WriteFile(o.kernel, []byte("not an executable"), 0500) != nil {
					t.Fatal("write failed")
				}
			case "image-tag":
				o.image = "docker.io/library/nats:latest"
			}
			if _, err := prepare(context.Background(), o, root); err == nil {
				t.Fatal("unsafe development preparation accepted")
			}
			if name == "checkout-output" {
				if _, err := os.Lstat(o.output); !os.IsNotExist(err) {
					t.Fatal("wrote inside checkout")
				}
			}
		})
	}
}

func TestDevelopmentPackageCancellationAndCommandRefusal(t *testing.T) {
	o := localOptions(t)
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepare(ctx, o, root); err == nil {
		t.Fatal("canceled preparation accepted")
	}
	if _, err := os.Lstat(o.output); !os.IsNotExist(err) {
		t.Fatal("canceled preparation wrote output")
	}
	var output bytes.Buffer
	for _, args := range [][]string{nil, {"--development", "unexpected"}, {"--private-key", "forbidden"}} {
		if err := run(context.Background(), args, &output); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
}
