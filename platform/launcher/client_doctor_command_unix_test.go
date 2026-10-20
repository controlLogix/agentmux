//go:build darwin || linux

package launcher

import (
	"context"
	"reflect"
	"testing"
)

func TestClientDoctorCommandUsesStandardCancellationAndFixedArguments(t *testing.T) {
	// An absolute nonexistent path avoids looking up any real client. No Start.
	command := clientDoctorCommand(context.Background(), "/fixture/no-client")
	if command.SysProcAttr != nil || command.Cancel == nil {
		t.Fatal("standard cancellation was replaced or group signaling was enabled")
	}
	if !reflect.DeepEqual(command.Args, []string{"/fixture/no-client", "--version"}) || command.Stdin != nil {
		t.Fatal("unexpected command or stdin")
	}
	if command.Process != nil {
		t.Fatal("process unexpectedly started")
	}
}

func TestClientDoctorAuthCommandArgumentsAreFixed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		client string
		args   []string
	}{{"codex", []string{"codex", "login", "status"}}, {"claude", []string{"claude", "auth", "status"}}} {
		command := clientDoctorProbeCommand(context.Background(), tc.client, true)
		if !reflect.DeepEqual(command.Args, tc.args) || command.Process != nil || command.Stdin != nil {
			t.Fatal("auth command is not a fixed unstarted lookup")
		}
	}
}
