//go:build linux && agentmux_bootstrap_docker

package launcher

import (
	"debug/elf"
	"testing"
)

func bootstrapCheckNativeKernel(t *testing.T, path, arch string) {
	t.Helper()
	executable, err := elf.Open(path)
	if err != nil {
		t.Fatal("actual kernel is not an ELF executable")
	}
	defer executable.Close()
	want := elf.EM_X86_64
	if arch == "arm64" {
		want = elf.EM_AARCH64
	}
	if executable.Class != elf.ELFCLASS64 || executable.Type != elf.ET_EXEC || executable.Machine != want {
		t.Fatal("actual kernel ELF target does not match the native host")
	}
	for _, segment := range executable.Progs {
		if segment.Type == elf.PT_INTERP {
			t.Fatal("actual kernel requires a dynamic interpreter")
		}
	}
	needed, err := executable.ImportedLibraries()
	if err != nil || len(needed) != 0 {
		t.Fatal("actual kernel has dynamic library dependencies")
	}
}

func bootstrapPrepareNativeRelease(t *testing.T, release *releaseTestFixture) {
	t.Helper()
	// Linux keeps the private package; the production runtime seals each image.
}
