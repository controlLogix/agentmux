//go:build darwin && arm64

// agentmux-dev-package prepares a local development package without installing it.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/controlLogix/agentmux/platform/installer"
	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/launcher"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

type options struct {
	development                     bool
	kernel, frontend, output, image string
}

type prepared struct {
	Purpose         string           `json:"purpose"`
	Selection       string           `json:"selection"`
	SelectionDigest string           `json:"selectionDigest"`
	Verification    installer.Result `json:"verification"`
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonical(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func repositoryRoot() (string, error) {
	path, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
			if _, err := os.Stat(filepath.Join(path, "platform", "go.mod")); err == nil {
				return path, nil
			}
		}
		next := filepath.Dir(path)
		if next == path {
			return "", errors.New("run from the Agentmux checkout")
		}
		path = next
	}
}

// Retain regular, unchanged local build bytes. Never execute an input image.
func readImage(path string) ([]byte, error) {
	if !canonical(path) {
		return nil, errors.New("select a canonical absolute image path")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("local build image is unavailable")
	}
	file := os.NewFile(uintptr(fd), "local-build-image")
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG ||
		before.Uid != uint32(os.Getuid()) || before.Mode&0022 != 0 || before.Nlink != 1 ||
		before.Size < 1 || before.Size > assembly.MaxMemberBytes {
		return nil, errors.Join(errors.New("local build image type, owner, access or size refused"), file.Close())
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, assembly.MaxMemberBytes+1))
	stable := unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino &&
		before.Size == after.Size && before.Mode == after.Mode && before.Uid == after.Uid &&
		before.Gid == after.Gid && before.Nlink == after.Nlink && before.Mtim == after.Mtim && before.Ctim == after.Ctim
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !stable || int64(len(raw)) != before.Size {
		return nil, errors.New("local build image changed or could not be closed")
	}
	return raw, nil
}

func writeFile(path string, raw []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("new package member could not be created")
	}
	n, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
		return errors.New("package write incomplete; keep the partial output for inspection")
	}
	return nil
}

func prepare(ctx context.Context, o options, repository string) (prepared, error) {
	var result prepared
	if ctx == nil || ctx.Err() != nil || !o.development || os.Getuid() == 0 || os.Getuid() != os.Geteuid() {
		return result, errors.New("explicit --development and an ordinary native macOS ARM64 user are required")
	}
	if !canonical(o.output) || !canonical(repository) || within(repository, o.output) ||
		!regexp.MustCompile(`^docker\.io/library/nats@sha256:[a-f0-9]{64}$`).MatchString(o.image) {
		return result, errors.New("select new output outside the checkout and an approved digest-pinned NATS image")
	}
	parent := filepath.Dir(o.output)
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil || realParent != parent {
		return result, errors.New("output parent must already exist without symbolic links")
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return result, errors.New("private output parent is unavailable")
	}
	file := os.NewFile(uintptr(fd), "development-output-parent")
	var info unix.Stat_t
	valid := unix.Fstat(fd, &info) == nil && info.Uid == uint32(os.Getuid()) && info.Mode&07777 == 0700 &&
		privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil
	closeErr := file.Close()
	if !valid || closeErr != nil {
		return result, errors.New("output parent must be private mode 0700 on supported local storage")
	}
	kernel, err := readImage(o.kernel)
	if err != nil {
		return result, err
	}
	frontend, err := readImage(o.frontend)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := os.Mkdir(o.output, 0700); err != nil {
		return result, errors.New("output must be a new directory")
	}
	// Keep partial output on failure; never replace or remove an existing package.
	payload := filepath.Join(o.output, "payload")
	if err := os.Mkdir(payload, 0700); err != nil {
		return result, err
	}
	if err := os.Mkdir(filepath.Join(payload, "bin"), 0700); err != nil {
		return result, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return result, errors.New("development signing key generation failed")
	}
	defer clear(private) // Ephemeral memory only; never persist a signing key or seed.
	authority := assembly.Authority{ID: "local_development", OwnerHubID: "dev_" + hex.EncodeToString(public[:16]), Revision: 1}
	manifest, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "0.0.0", "kernelApiMajor": 1,
		"releaseAuthorityRef": authority, "broker": launcher.BrokerPins{Image: o.image, NATSVersion: "2.15.0", ComposeVersion: "5.5.1"}})
	if err != nil {
		return result, err
	}
	members := make([]map[string]string, 0, 4)
	for _, role := range protocol.Roles() {
		if err := writeFile(filepath.Join(payload, "bin", role), kernel, 0500); err != nil {
			return result, err
		}
		members = append(members, map[string]string{"id": role, "entrypoint": "bin/" + role, "binaryDigest": digest(kernel)})
	}
	assemblyRaw, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "0.0.0", "kernelApiMajor": 1,
		"releaseAuthorityRef": authority, "releaseManifestDigest": digest(manifest), "plugins": members})
	if err != nil {
		return result, err
	}
	authorization, err := json.Marshal(map[string]any{"schemaVersion": "1.0.0", "releaseVersion": "0.0.0", "kernelApiMajor": 1,
		"releaseAuthorityRef": authority, "releaseManifestDigest": digest(manifest), "assemblyDigest": digest(assemblyRaw)})
	if err != nil {
		return result, err
	}
	for name, raw := range map[string][]byte{"release-manifest.json": manifest, "protected-assembly.json": assemblyRaw,
		"release-authorization.json": authorization, "release-authorization.sig": ed25519.Sign(private, authorization)} {
		if err := writeFile(filepath.Join(payload, name), raw, 0400); err != nil {
			return result, err
		}
	}
	if err := writeFile(filepath.Join(payload, "agentmux-runtime"), frontend, 0500); err != nil {
		return result, err
	}
	selected := installer.Selection{SchemaVersion: "1.0.0", Release: installer.ReleaseSelection{
		PackageDirectory: payload, PublicKeyHex: hex.EncodeToString(public), ReleaseManifestDigest: digest(manifest),
		ReleaseAuthority: authority, ReleaseVersion: "0.0.0", KernelAPIMajor: 1},
		Runtime: installer.RuntimeSelection{Path: filepath.Join(payload, "agentmux-runtime"), Digest: digest(frontend)}}
	raw, err := json.Marshal(selected)
	if err != nil {
		return result, err
	}
	selectionPath := filepath.Join(o.output, "foundation-selection.json")
	if err := writeFile(selectionPath, raw, 0600); err != nil {
		return result, err
	}
	checked, err := installer.ReadSelection(ctx, selectionPath, digest(raw), uint32(os.Getuid()))
	if err != nil {
		return result, errors.New("private development selection was refused")
	}
	pkg, err := installer.Prepare(ctx, checked)
	if err != nil {
		return result, fmt.Errorf("development package verification failed: %s", err)
	}
	return prepared{"local-development-only", selectionPath, digest(raw), pkg.Result("verified")}, nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("agentmux-dev-package", flag.ContinueOnError)
	flags.SetOutput(output)
	var o options
	flags.BoolVar(&o.development, "development", false, "Prepare only a local development package; never install or enroll")
	flags.StringVar(&o.kernel, "kernel", "", "Locally built agentmux-kernel (absolute path)")
	flags.StringVar(&o.frontend, "runtime", "", "Locally built agentmux-runtime (absolute path)")
	flags.StringVar(&o.output, "output", "", "New output directory under an existing private parent, outside the checkout")
	flags.StringVar(&o.image, "broker-image", "", "Approved docker.io/library/nats@sha256:... image")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	result, err := prepare(ctx, o, root)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
