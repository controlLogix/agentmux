//go:build darwin && arm64 && cgo

// This cooperative test image is built and installed separately after review.
// It exercises receipt transport only, never Bootstrap or an authenticated status.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

func run() int {
	if len(os.Args) != 8 || os.Args[1] != "host" || os.Args[2] != "--host-policy" ||
		os.Args[4] != "--invocation-id" || os.Args[6] != "--workspace" ||
		!filepath.IsAbs(os.Args[3]) || filepath.Clean(os.Args[3]) != os.Args[3] ||
		!filepath.IsAbs(os.Args[7]) || filepath.Clean(os.Args[7]) != os.Args[7] ||
		filepath.Dir(os.Args[3]) != os.Args[7] {
		return 2
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	defer signal.Stop(signals)
	// A missing cooperative stop must fail, not masquerade as successful cleanup.
	lifetime := time.AfterFunc(15*time.Second, func() { os.Exit(6) })
	defer lifetime.Stop()
	file, err := os.Open(os.Args[3])
	if err != nil {
		return 3
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 64*1024+1))
	closeErr := file.Close()
	var policy struct {
		Binding protected.BootstrapReceiptBinding
		Stay    bool
	}
	if readErr != nil || closeErr != nil || protocol.DecodeClosedJSON(raw, &policy, 64*1024) != nil ||
		policy.Binding.ColdInvocationID != os.Args[5] {
		return 3
	}
	writer, err := protected.OpenBootstrapReceiptWriter(policy.Binding)
	if err != nil {
		return 4
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err = writer.Accepted(ctx)
	cancel()
	if err != nil {
		return 5
	}
	if policy.Stay {
		<-signals
	}
	return 0
}

func main() { os.Exit(run()) }
