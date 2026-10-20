//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"bytes"
	"encoding/binary"
)

// parseNativeArguments parses only the bounded argv region; trailing environment
// bytes are neither returned nor interpreted. The caller owns buffer wiping.
func parseNativeArguments(raw []byte) ([]string, error) {
	if len(raw) < 4 || len(raw) > 256*1024 {
		return nil, failed("fixture_arguments_buffer_refused", nil)
	}
	count := int(binary.NativeEndian.Uint32(raw[:4]))
	if count < 1 || count > 64 {
		return nil, failed("fixture_arguments_count_refused", nil)
	}
	remaining := raw[4:]
	end := bytes.IndexByte(remaining, 0)
	if end < 1 {
		return nil, failed("fixture_arguments_header_refused", nil)
	}
	remaining = bytes.TrimLeft(remaining[end+1:], "\x00")
	args := make([]string, 0, count)
	for range count {
		end = bytes.IndexByte(remaining, 0)
		if end < 1 || end > 4096 {
			return nil, failed("fixture_arguments_shape_refused", nil)
		}
		args = append(args, string(remaining[:end]))
		remaining = remaining[end+1:]
	}
	return args, nil
}
