// agentmux-kernel dispatches one fixed protected role per supervised process.
package main

import (
	"context"
	"fmt"
	"github.com/controlLogix/agentmux/platform/kernel/boot"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/lifecycle"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/kernel/status"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "kernel_arguments_not_supported")
		os.Exit(1)
	}
	c, err := protocol.LoadEnvironment()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	wire, err := communication.Subjects(c.Credentials.Scope.HubID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kernel_subjects_invalid")
		os.Exit(1)
	}
	subjects := protocol.SubjectSet{Commands: wire.Commands, Events: wire.Events, Snapshot: wire.Snapshot, Update: wire.Update}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	switch c.Credentials.Role {
	case "boot":
		err = boot.Run(ctx, c, subjects)
	case "kernel-lifecycle":
		err = lifecycle.Run(ctx, c, subjects)
	case "internal-communication":
		err = communication.Run(ctx, c, subjects)
	case "exported-status":
		err = status.Run(ctx, c, subjects)
	default:
		err = fmt.Errorf("kernel_role_invalid")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
