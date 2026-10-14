package launcher

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This dispatch controls only the current test executable's three fixed cp
// operations. Other commands retain the existing owned-broker fixture.
func init() {
	if dir := os.Getenv("AMX_FIXED_ARCHIVE_DIR"); dir != "" && os.Getenv("AMX_BROKER_INSPECT_FIXTURE") == "1" {
		args := os.Args[1:]
		if len(args) == 5 && args[0] == "--context" && args[1] == "instance-fixture" && args[2] == "cp" && args[4] == "-" {
			name := strings.TrimPrefix(args[3], instanceID()+":/etc/nats/")
			if name != "private.conf" && name != "server-cert.pem" && name != "server-key.pem" {
				os.Exit(6)
			}
			fixedArchiveProcess(dir, name)
			os.Exit(0)
		}
	}
}

func fixedArchiveProcess(dir, name string) {
	if os.WriteFile(filepath.Join(dir, "started-"+name), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		os.Exit(6)
	}
	mode := os.Getenv("AMX_FIXED_ARCHIVE_MODE")
	if mode == "overlap" || mode == "cancel" || mode == "deadline" {
		deadline := time.Now().Add(1500 * time.Millisecond)
		for {
			all := true
			for _, file := range []string{"private.conf", "server-cert.pem", "server-key.pem"} {
				if _, err := os.Stat(filepath.Join(dir, "started-"+file)); err != nil {
					all = false
				}
			}
			if all {
				break
			}
			if time.Now().After(deadline) {
				fmt.Fprintln(os.Stderr, "synthetic-private-archive")
				os.Exit(7)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if mode == "cancel" {
		if name != "server-cert.pem" {
			time.Sleep(time.Hour)
			os.Exit(8)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "release-failure")); err == nil {
				break
			}
			time.Sleep(time.Millisecond)
		}
		os.Stdout.Write(fixedTestArchive(name, "digest"))
		return
	}
	if mode == "deadline" {
		time.Sleep(time.Hour)
		os.Exit(8)
	}
	os.Stdout.Write(fixedTestArchive(name, ""))
	if os.WriteFile(filepath.Join(dir, "completed-"+name), []byte("joined"), 0600) != nil {
		os.Exit(6)
	}
}

func fixedTestBody(name string) []byte {
	if name == "private.conf" {
		return instanceConfig()
	}
	return tlsInstanceBody(name)
}
func fixedTestArchive(name, fault string) []byte {
	body := fixedTestBody(name)
	h := tar.Header{Name: name, Mode: 0400, Size: int64(len(body)), Typeflag: tar.TypeReg}
	switch fault {
	case "name":
		h.Name = "../" + name
	case "mode":
		h.Mode = 0444
	case "uid":
		h.Uid = 1
	case "gid":
		h.Gid = 1
	case "symlink":
		h.Typeflag = tar.TypeSymlink
		h.Linkname = "private-target"
		h.Size = 0
		body = nil
	case "hardlink":
		h.Typeflag = tar.TypeLink
		h.Linkname = "private-target"
		h.Size = 0
		body = nil
	case "zero":
		h.Size = 0
		body = nil
	case "size":
		body = bytes.Repeat([]byte{'x'}, 65537)
		h.Size = int64(len(body))
	case "digest":
		body = []byte("synthetic-private-archive")
		h.Size = int64(len(body))
	case "pax":
		h.Format = tar.FormatPAX
		h.PAXRecords = map[string]string{"comment": "private"}
	case "xattr":
		h.Format = tar.FormatPAX
		h.Xattrs = map[string]string{"user.private": "value"}
	}
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	writer.WriteHeader(&h)
	writer.Write(body)
	if fault == "extra" {
		writer.WriteHeader(&tar.Header{Name: "other", Mode: 0400, Size: 1, Typeflag: tar.TypeReg})
		writer.Write([]byte{'x'})
	}
	writer.Close()
	if fault == "tail" {
		output.WriteString("synthetic-private-tail")
	}
	if fault == "truncated" {
		return output.Bytes()[:300]
	}
	return output.Bytes()
}
func fixedArchiveSetup(t *testing.T, mode string) (*Docker, string, string) {
	t.Helper()
	driver, log := instanceSetup(t, "running")
	dir := t.TempDir()
	t.Setenv("AMX_FIXED_ARCHIVE_DIR", dir)
	t.Setenv("AMX_FIXED_ARCHIVE_MODE", mode)
	return driver, log, dir
}
func fixedArchiveDigests() ([32]byte, [32]byte, [32]byte) {
	return sha256.Sum256(instanceConfig()), sha256.Sum256(tlsInstanceBody("server-cert.pem")), sha256.Sum256(tlsInstanceBody("server-key.pem"))
}

func TestFixedTLSArchiveReadsActuallyOverlap(t *testing.T) {
	driver, log, dir := fixedArchiveSetup(t, "overlap")
	a, b, c := fixedArchiveDigests()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	broker, err := driver.InspectOwnedTLSBroker(ctx, instanceOwner(), instanceImage(), 43210, a, b, c)
	if err != nil || broker.ContainerID != instanceID() || broker.State != "running" {
		t.Fatal("overlapping three-file inspection failed", err)
	}
	for _, name := range []string{"private.conf", "server-cert.pem", "server-key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, "completed-"+name)); err != nil {
			t.Fatal("archive child did not complete")
		}
	}
	noMutation(t, log)
	if parallelDockerReadAllowed([]string{"cp", instanceID() + ":/etc/nats/private.conf", "-"}) {
		t.Fatal("general read allowlist widened")
	}
}

func TestFixedTLSArchiveOwnershipFailureStartsNoArchive(t *testing.T) {
	for _, mode := range []string{"multiple", "foreign-profile", "actual-image", "public-port", "extra-mount", "volume-label"} {
		t.Run(mode, func(t *testing.T) {
			driver, log, dir := fixedArchiveSetup(t, "")
			t.Setenv("AMX_BROKER_INSPECT_MODE", mode)
			a, b, c := fixedArchiveDigests()
			broker, err := driver.InspectOwnedTLSBroker(context.Background(), instanceOwner(), instanceImage(), 43210, a, b, c)
			if err == nil || broker != (OwnedBroker{}) {
				t.Fatal("unowned broker accepted")
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 {
				t.Fatal("private archive read preceded complete ownership checks")
			}
			noMutation(t, log)
		})
	}
}

func TestFixedTLSArchiveAllMetadataAndDigestChecks(t *testing.T) {
	for _, name := range []string{"private.conf", "server-cert.pem", "server-key.pem"} {
		limit := int64(65536)
		if name == "server-cert.pem" {
			limit = 16384
		}
		if name == "server-key.pem" {
			limit = 8192
		}
		expected := sha256.Sum256(fixedTestBody(name))
		if verifyPrivateFileArchive(fixedTestArchive(name, ""), expected, name, limit) != nil {
			t.Fatal("positive archive refused")
		}
		for _, fault := range []string{"name", "mode", "uid", "gid", "symlink", "hardlink", "zero", "size", "digest", "pax", "xattr", "extra", "tail", "truncated"} {
			t.Run(name+"/"+fault, func(t *testing.T) {
				err := verifyPrivateFileArchive(fixedTestArchive(name, fault), expected, name, limit)
				if err == nil || strings.Contains(err.Error(), "synthetic-private") || strings.Contains(fmt.Sprintf("%#v", err), "private-target") {
					t.Fatal("malformed private archive accepted or disclosed")
				}
			})
		}
	}
}

func TestFixedTLSArchiveMissingExpectationsNoProcess(t *testing.T) {
	driver, log, dir := fixedArchiveSetup(t, "")
	a, b, c := fixedArchiveDigests()
	for _, missing := range []string{"config", "certificate", "key"} {
		x, y, z := a, b, c
		switch missing {
		case "config":
			x = [32]byte{}
		case "certificate":
			y = [32]byte{}
		case "key":
			z = [32]byte{}
		}
		if err := driver.verifyOwnedTLSArchives(context.Background(), instanceID(), x, y, z); err == nil {
			t.Fatal("missing digest accepted")
		}
	}
	if err := driver.verifyOwnedTLSArchives(nil, instanceID(), a, b, c); err == nil {
		t.Fatal("missing context accepted")
	}
	if err := driver.verifyOwnedTLSArchives(context.Background(), "arbitrary-id", a, b, c); err == nil {
		t.Fatal("invalid container ID accepted")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 || commands(log) != "" {
		t.Fatal("invalid expectation started archive process")
	}
}
