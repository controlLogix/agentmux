//go:build darwin && cgo

package runtime

import (
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These parser controls use the actual native test Mach-O. They do not qualify
// installation ownership, signatures, OS shared-cache protection or spawning.
func TestDarwinMachODependencyPolicy(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	image, err := macho.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if image.Magic != macho.Magic64 {
		t.Fatal("native fixture must be a thin 64-bit executable")
	}
	check := func(data []byte, wantCode string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "policy-fixture")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		hash := sha256.Sum256(data)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = darwinImage(ctx, file, "sha256:"+hex.EncodeToString(hash[:]), int64(len(data)+1))
		if wantCode == "" {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || err.Error() != wantCode {
			t.Fatal("actual Mach-O negative did not fail at its declared boundary")
		}
	}
	check(data, "")
	offset := 32
	found := false
	for _, load := range image.Loads {
		raw := load.Raw()
		command := image.ByteOrder.Uint32(raw[:4])
		if command == 0xc {
			nameOffset := int(image.ByteOrder.Uint32(raw[8:12]))
			name := strings.TrimRight(string(raw[nameOffset:]), "\x00")
			if name == "/usr/lib/libSystem.B.dylib" {
				mutable := append([]byte(nil), data...)
				for i := offset + nameOffset; i < offset+len(raw); i++ {
					mutable[i] = 0
				}
				copy(mutable[offset+nameOffset:offset+len(raw)], "/tmp/untrusted/lib.dylib")
				check(mutable, "protected_macho_dependency_denied")
				weak := append([]byte(nil), data...)
				image.ByteOrder.PutUint32(weak[offset:offset+4], 0x80000018)
				check(weak, "protected_macho_load_denied")
				found = true
			}
		}
		offset += len(raw)
	}
	if !found {
		t.Fatal("actual native binary did not expose the declared system-library control")
	}
	wrongArch := append([]byte(nil), data...)
	cpu := uint32(macho.CpuArm64)
	if image.Cpu == macho.CpuArm64 {
		cpu = uint32(macho.CpuAmd64)
	}
	image.ByteOrder.PutUint32(wrongArch[4:8], cpu)
	check(wrongArch, "protected_macho_architecture_invalid")
}

func TestDarwinEnvironmentRejectsLoaderInjection(t *testing.T) {
	roles := [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
	for _, key := range []string{"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "LD_PRELOAD"} {
		var supplied [4]RoleOptions
		for i, role := range roles {
			supplied[i] = RoleOptions{ID: role}
		}
		supplied[0].Env = map[string]string{key: "/tmp/unapproved"}
		if _, err := options(roles, supplied); err == nil {
			t.Fatal("unapproved loader environment accepted")
		}
	}
}
