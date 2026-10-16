//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLocalPortPreflightActualOccupiedAndReleased(t *testing.T) {
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("actual selected-port blocker unavailable")
	}
	defer blocker.Close()
	port := blocker.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	failure := preflightLocalPort(ctx, NativeUnix, port)
	if failure == nil || ProjectRequestDiagnostic(failure).Code != "selected_host_port_occupied" {
		t.Fatal("actual selected bind conflict did not produce its trusted diagnostic")
	}
	if err := blocker.Close(); err != nil {
		t.Fatal("exact fixture blocker close failed")
	}
	if err := preflightLocalPort(ctx, NativeUnix, port); err != nil {
		t.Fatal("released selected endpoint did not pass native preflight")
	}
	// A successful preflight must leave no held listener of its own.
	rebound, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal("successful preflight retained the selected endpoint")
	}
	if err := rebound.Close(); err != nil {
		t.Fatal("rebound fixture close failed")
	}
}

func TestLocalPortPreflightCancellationAndLegacyDoNotClaimConflict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if preflightLocalPort(ctx, NativeUnix, 4222) != context.Canceled {
		t.Fatal("preflight masked prior cancellation")
	}
	if err := preflightLocalPort(context.Background(), NativeUnix, 4222); err == nil || ProjectRequestDiagnostic(err).Code == "selected_host_port_occupied" {
		t.Fatal("unbounded preflight admitted or fabricated conflict")
	}
	if err := preflightLocalPort(context.Background(), WindowsInterop, 4222); err != nil {
		t.Fatal("legacy interop acquired a native probe requirement")
	}
	if err := preflightLocalPort(nil, NativeUnix, 4222); err == nil {
		t.Fatal("nil probe context admitted")
	}
}

func TestLocalPortPreflightOnlyConcreteBindAddressInUse(t *testing.T) {
	bind := func(err error) error {
		return &net.OpError{Op: "listen", Net: "tcp4", Err: &os.SyscallError{Syscall: "bind", Err: err}}
	}
	if !localPortAddressInUse(bind(syscall.EADDRINUSE)) {
		t.Fatal("exact native bind errno not recognized")
	}
	for _, failure := range []error{nil, syscall.EADDRINUSE, bind(syscall.EACCES), errors.New("bind: address already in use"), diagnosticHostileError{}, diagnosticHostileUnwrap{}, errors.Join(syscall.EADDRINUSE), &net.OpError{Op: "dial", Net: "tcp4", Err: syscall.EADDRINUSE}} {
		if localPortAddressInUse(failure) {
			t.Fatal("unconfirmed error became exact selected-endpoint evidence")
		}
	}
}

func TestLocalPortPreflightModeledCloseFailureRetainsActualListener(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("actual cleanup fixture listener unavailable")
	}
	defer listener.Close()
	// Model only the Close result at the ownership boundary. This is not a
	// claim that a native TCPListener.Close actually failed on this host.
	closeFailure := errors.New("private fixture close failure")
	failure := finishLocalPortProbe(listener, closeFailure, context.DeadlineExceeded)
	var retained *LocalPortCleanupError
	if !errors.As(failure, &retained) || retained.listener != listener || !errors.Is(failure, closeFailure) || !errors.Is(failure, context.DeadlineExceeded) {
		t.Fatal("failed close lost its exact owner or error causes")
	}
	if ProjectRequestDiagnostic(failure).Code != "owned_cleanup_incomplete" {
		t.Fatal("listener cleanup failure lost priority")
	}
	contender, bindErr := net.ListenTCP("tcp4", listener.Addr().(*net.TCPAddr))
	if bindErr == nil {
		contender.Close()
		t.Fatal("modeled failed close did not retain an actual held listener")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if output := fmt.Sprintf(format, failure); strings.Contains(output, "private") || strings.Contains(output, "0x") {
			t.Fatal("listener cleanup formatting leaked owner or error state")
		}
	}
	raw, err := json.Marshal(failure)
	if err != nil || strings.Contains(string(raw), "private") {
		t.Fatal("listener cleanup JSON leaked error state")
	}
	if err := retained.Close(); err != nil || retained.listener != nil {
		t.Fatal("exact retained listener cleanup did not finish")
	}
	if err := retained.Close(); err != nil {
		t.Fatal("completed retained cleanup was not idempotent")
	}
	if !errors.Is(failure, closeFailure) {
		t.Fatal("successful retry erased the original close failure")
	}
}
