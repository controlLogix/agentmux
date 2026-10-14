//go:build linux || darwin

package runtime

import (
	"debug/macho"
	"encoding/binary"
	"errors"
)

// Validate only the supported product entrypoint forms. This does not admit
// dependencies or grant a file permission to run; the protected loader owns
// those separate signature, descriptor, platform and library checks.
func validateDarwinEntrypoint(image *macho.File, imageSize uint64) error {
	invalid := errors.New("protected_macho_entrypoint_invalid")
	if imageSize == 0 || image == nil || image.Magic != macho.Magic64 || image.ByteOrder != binary.LittleEndian || (image.Cpu != macho.CpuAmd64 && image.Cpu != macho.CpuArm64) {
		return invalid
	}
	var text *macho.Segment
	for _, load := range image.Loads {
		if segment, ok := load.(*macho.Segment); ok && segment.Name == "__TEXT" {
			if text != nil || segment.Filesz == 0 || segment.Memsz < segment.Filesz || segment.Prot != 5 || segment.Addr > ^uint64(0)-segment.Filesz || segment.Offset > ^uint64(0)-segment.Filesz || segment.Offset > imageSize || segment.Filesz > imageSize-segment.Offset {
				return invalid
			}
			text = segment
		}
	}
	if text == nil {
		return invalid
	}
	entries := 0
	for _, load := range image.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return invalid
		}
		command := image.ByteOrder.Uint32(raw[:4])
		if command != 0x5 && command != 0x80000028 {
			continue
		}
		entries++
		if entries != 1 || image.ByteOrder.Uint32(raw[4:8]) != uint32(len(raw)) {
			return invalid
		}
		var address uint64
		if command == 0x5 {
			// Pinned Go AMD64 binaries use one x86_THREAD_STATE64 frame.
			if image.Cpu != macho.CpuAmd64 || len(raw) != 184 || image.ByteOrder.Uint32(raw[8:12]) != 4 || image.ByteOrder.Uint32(raw[12:16]) != 42 {
				return invalid
			}
			for i, value := range raw[16:] {
				if (i < 128 || i >= 136) && value != 0 {
					return invalid
				}
			}
			address = image.ByteOrder.Uint64(raw[144:152])
		} else {
			if len(raw) != 24 || image.ByteOrder.Uint64(raw[16:24]) != 0 {
				return invalid
			}
			offset := image.ByteOrder.Uint64(raw[8:16])
			if offset < text.Offset || offset-text.Offset >= text.Filesz {
				return invalid
			}
			address = text.Addr + (offset - text.Offset)
		}
		if address < text.Addr || address-text.Addr >= text.Filesz || (image.Cpu == macho.CpuArm64 && address%4 != 0) {
			return invalid
		}
	}
	if entries != 1 {
		return invalid
	}
	return nil
}
