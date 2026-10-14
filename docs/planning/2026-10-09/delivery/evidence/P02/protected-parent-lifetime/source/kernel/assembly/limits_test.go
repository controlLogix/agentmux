package assembly

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyByteLimits(t *testing.T) {
	root, m, trust := fixture(t)
	raw, trust := encode(t, m, trust)
	var total, max int64
	for _, member := range m.Plugins {
		info, err := os.Stat(filepath.Join(root, member.Entrypoint))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
		if info.Size() > max {
			max = info.Size()
		}
	}
	if _, err := VerifyWithLimits(raw, root, trust, Limits{max, total}); err != nil {
		t.Fatal(err)
	}
	for name, limits := range map[string]Limits{"member": {max - 1, total}, "total": {max, total - 1}, "zero": {}, "expanded": {MaxMemberBytes + 1, MaxAssemblyBytes}} {
		t.Run(name, func(t *testing.T) {
			v, err := VerifyWithLimits(raw, root, trust, limits)
			if err == nil || v.PackageRoot() != "" {
				t.Fatal("oversized or invalid policy accepted")
			}
		})
	}
}

func TestVerifySparseOversizedMember(t *testing.T) {
	root, m, trust := fixture(t)
	file, err := os.OpenFile(filepath.Join(root, m.Plugins[0].Entrypoint), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(MaxMemberBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	raw, trust := encode(t, m, trust)
	refused(t, raw, root, trust)
}
