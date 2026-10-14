//go:build linux || darwin

package runtime

import (
	"debug/macho"
	"encoding/binary"
	"testing"
)

func entryFixture(thread bool) *macho.File {
	text := &macho.Segment{SegmentHeader: macho.SegmentHeader{Name: "__TEXT", Addr: 0x1000000, Offset: 0, Memsz: 4096, Filesz: 4096, Prot: 5}, LoadBytes: make([]byte, 72)}
	binary.LittleEndian.PutUint32(text.LoadBytes[:4], 0x19)
	raw := make([]byte, 24)
	cpu := macho.CpuArm64
	if thread {
		cpu = macho.CpuAmd64
		raw = make([]byte, 184)
		binary.LittleEndian.PutUint32(raw[:4], 0x5)
		binary.LittleEndian.PutUint32(raw[8:12], 4)
		binary.LittleEndian.PutUint32(raw[12:16], 42)
		binary.LittleEndian.PutUint64(raw[144:152], text.Addr+64)
	} else {
		binary.LittleEndian.PutUint32(raw[:4], 0x80000028)
		binary.LittleEndian.PutUint64(raw[8:16], 64)
	}
	binary.LittleEndian.PutUint32(raw[4:8], uint32(len(raw)))
	return &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64, Cpu: cpu}, ByteOrder: binary.LittleEndian, Loads: []macho.Load{text, macho.LoadBytes(raw)}}
}

func TestDarwinEntrypointRequiresOneSupportedFileBackedEntry(t *testing.T) {
	for _, thread := range []bool{false, true} {
		if validateDarwinEntrypoint(entryFixture(thread), 8192) != nil {
			t.Fatal("supported entrypoint refused")
		}
	}
	controls := map[string]func(*macho.File){
		"missing":              func(f *macho.File) { f.Loads = f.Loads[:1] },
		"duplicate":            func(f *macho.File) { f.Loads = append(f.Loads, f.Loads[1]) },
		"wrong-flavor":         func(f *macho.File) { binary.LittleEndian.PutUint32(f.Loads[1].Raw()[8:12], 5) },
		"wrong-count":          func(f *macho.File) { binary.LittleEndian.PutUint32(f.Loads[1].Raw()[12:16], 41) },
		"other-register":       func(f *macho.File) { f.Loads[1].Raw()[16] = 1 },
		"outside-file-text":    func(f *macho.File) { binary.LittleEndian.PutUint64(f.Loads[1].Raw()[144:152], 0x1001000) },
		"writable-text":        func(f *macho.File) { f.Loads[0].(*macho.Segment).Prot = 7 },
		"execute-without-read": func(f *macho.File) { f.Loads[0].(*macho.Segment).Prot = 4 },
		"non-executable-text":  func(f *macho.File) { f.Loads[0].(*macho.Segment).Prot = 1 },
		"overflow-text":        func(f *macho.File) { f.Loads[0].(*macho.Segment).Addr = ^uint64(0) - 1 },
		"declared-beyond-file": func(f *macho.File) {
			f.Loads[0].(*macho.Segment).Filesz = 16384
			f.Loads[0].(*macho.Segment).Memsz = 16384
		},
		"file-offset-outside":    func(f *macho.File) { f.Loads[0].(*macho.Segment).Offset = 8193 },
		"duplicate-text":         func(f *macho.File) { f.Loads = append(f.Loads, f.Loads[0]) },
		"wrong-command-size":     func(f *macho.File) { binary.LittleEndian.PutUint32(f.Loads[1].Raw()[4:8], 176) },
		"unsupported-cpu-thread": func(f *macho.File) { f.Cpu = macho.CpuArm64 },
	}
	for name, mutate := range controls {
		t.Run(name, func(t *testing.T) {
			f := entryFixture(true)
			mutate(f)
			if validateDarwinEntrypoint(f, 8192) == nil {
				t.Fatal("hostile entrypoint accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*macho.File){
		"stacksize":         func(f *macho.File) { f.Loads[1].Raw()[16] = 1 },
		"unaligned-arm64":   func(f *macho.File) { binary.LittleEndian.PutUint64(f.Loads[1].Raw()[8:16], 65) },
		"main-outside-file": func(f *macho.File) { binary.LittleEndian.PutUint64(f.Loads[1].Raw()[8:16], 4096) },
		"conflicting-entry": func(f *macho.File) { f.Loads = append(f.Loads, entryFixture(true).Loads[1]) },
	} {
		t.Run(name, func(t *testing.T) {
			f := entryFixture(false)
			mutate(f)
			if validateDarwinEntrypoint(f, 8192) == nil {
				t.Fatal("hostile main entrypoint accepted")
			}
		})
	}
}
