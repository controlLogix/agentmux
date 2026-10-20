//go:build linux || darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/controlLogix/agentmux/platform/launcher"
	"golang.org/x/sys/unix"
)

func prepareBrokerImage(ctx context.Context, host *launcher.EnrolledHostPolicy, output io.Writer) error {
	result, failure := host.PrepareBrokerImage(ctx, func(progress launcher.BrokerImagePreparationProgress) error {
		return writePreparationJSON(ctx, output, progress)
	})
	// The launcher has joined its original Docker command before any terminal
	// response. An output failure cannot abandon an active pull or its lease.
	if err := writePreparationJSON(ctx, output, result); err != nil {
		return errors.Join(failure, err)
	}
	return failure
}

// Preparation emits only a few small closed frames. For the actual CLI's
// single output writer, poll before each atomic-sized write rather than leave
// a goroutine blocked on a slow pipe. No descriptor flags or owners change.
// Regular local-file writes have the same supported-filesystem assumption as
// private enrollment reads; a blocked filesystem syscall is not preemptible.
func writePreparationJSON(parent context.Context, output io.Writer, value any) error {
	if parent == nil || output == nil {
		return launcher.ErrBrokerPreparationOutput
	}
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	data, err := json.Marshal(value)
	if err != nil || len(data) > 4095 {
		return launcher.ErrBrokerPreparationOutput
	}
	data = append(data, '\n')
	if err := ctx.Err(); err != nil {
		return err
	}
	file, native := output.(*os.File)
	if !native {
		// In-process callers supply their own prompt writer; production passes
		// only the inherited stdout/stderr files handled below.
		n, err := output.Write(data)
		if err != nil || n != len(data) {
			return launcher.ErrBrokerPreparationOutput
		}
		return ctx.Err()
	}
	if file == nil {
		return launcher.ErrBrokerPreparationOutput
	}
	fd := int(file.Fd())
	defer runtime.KeepAlive(file)
	info, err := file.Stat()
	if err != nil {
		return launcher.ErrBrokerPreparationOutput
	}
	chunkLimit := 1
	if info.Mode().IsRegular() || info.Mode()&os.ModeNamedPipe != 0 {
		chunkLimit = 512
	}
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		deadline, _ := ctx.Deadline()
		wait := min(25, int((time.Until(deadline)+time.Millisecond-1)/time.Millisecond))
		if wait <= 0 {
			return context.DeadlineExceeded
		}
		n, err := unix.Poll(poll, wait)
		if err == unix.EINTR {
			continue
		}
		if err != nil || poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return launcher.ErrBrokerPreparationOutput
		}
		if n == 0 || poll[0].Revents&unix.POLLOUT == 0 {
			continue
		}
		// Pipes accept at most POSIX's minimum atomic write. Other streaming
		// descriptors use one byte because poll may promise only that much room.
		chunk := data
		if len(chunk) > chunkLimit {
			chunk = chunk[:chunkLimit]
		}
		n, err = unix.Write(fd, chunk)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n <= 0 {
			return launcher.ErrBrokerPreparationOutput
		}
		data = data[n:]
	}
	return ctx.Err()
}
