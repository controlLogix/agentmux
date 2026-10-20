package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"runtime"
	"time"

	"github.com/controlLogix/agentmux/platform/plugins"
	"golang.org/x/sys/unix"
)

func prepareGraphComposition(ctx context.Context, input composition, request plugins.ActivationRequest) (preparedComposition, error) {
	invalid := func(code string) (preparedComposition, error) { return preparedComposition{}, fail(code, nil) }
	if input.Roots != nil || input.Instances != nil || input.Configurations != nil || input.InstanceConfigurations == nil || input.Topology == nil || len(input.Topology.Instances) > 64 || len(input.Topology.Children) > 256 || len(input.Topology.Dependencies) > 256 {
		return invalid("activation_binding_set_invalid")
	}
	topology, err := plugins.ResolveInstanceTopology(request.Catalog, input.Selected, *input.Topology)
	if err != nil {
		return preparedComposition{}, err
	}
	if err = validateTopologyDriverShape(input.Driver, topology); err != nil {
		return preparedComposition{}, err
	}
	if len(input.InstanceConfigurations) != len(topology.Instances()) {
		return invalid("activation_binding_set_invalid")
	}
	request.Topology = input.Topology
	seen := map[string]bool{}
	count := 0
	for _, config := range input.InstanceConfigurations {
		if ctx.Err() != nil {
			return invalid("plugin_command_canceled")
		}
		pkg, exists := topology.Package(config.InstanceID)
		node, _ := topology.Instance(config.InstanceID)
		if !exists || seen[config.InstanceID] || config.Pin != pkg.Pin() {
			return invalid("activation_configuration_invalid")
		}
		seen[config.InstanceID] = true
		validateSupport := plugins.ValidateActivationSupport
		if input.NativeContext != nil && input.SchemaVersion == "1.2.0" {
			validateSupport = plugins.ValidateContextActivationSupport
		}
		if err = validateSupport(pkg, node.InstallationMode, input.Platform); err != nil {
			return preparedComposition{}, err
		}
		raw, err := plugins.ReadOwnerPrivateFile(config.ConfigurationFile, compositionLimit)
		if err != nil {
			return preparedComposition{}, err
		}
		if _, err = plugins.PrepareConfiguration(pkg, config.Resources, raw); err != nil {
			return preparedComposition{}, err
		}
		request.InstanceConfigurations = append(request.InstanceConfigurations, plugins.InstanceConfigurationInput{InstanceID: config.InstanceID, Pin: config.Pin, Resources: config.Resources, Raw: raw})
		count += len(pkg.Manifest().Contributions)
	}
	if err = plugins.ValidateInstanceContributionDeclarations(topology, input.Contracts); err != nil {
		return preparedComposition{}, err
	}
	if ctx.Err() != nil {
		return invalid("plugin_command_canceled")
	}
	return preparedComposition{request: request, options: plugins.ManagerOptions{Platform: input.Platform, InstallationMode: "independent", ActivationTimeout: time.Duration(input.ActivationTimeoutMS) * time.Millisecond, CleanupTimeout: time.Duration(input.CleanupTimeoutMS) * time.Millisecond}, driver: input.Driver, plan: topology.Plan(), contributionCount: count, graph: true, instanceUnavailable: len(topology.OptionalUnavailable())}, nil
}

// Owner controls are accepted only on an explicitly enabled inherited input.
// They do not reuse a child lifecycle subject or claim an enrolled human identity.
type ownerControl struct {
	SchemaVersion string                  `json:"schemaVersion"`
	Action        string                  `json:"action"`
	Owner         *plugins.OwnerReference `json:"owner,omitempty"`
}

func decodeOwnerControl(raw []byte) (ownerControl, error) {
	var command ownerControl
	invalid := func() (ownerControl, error) { return ownerControl{}, fail("plugin_owner_control_invalid", nil) }
	if len(raw) == 0 || len(raw) > 8192 || plugins.ValidateJSON(raw) != nil || checkExactFields(raw, reflect.TypeOf(command)) != nil || json.Unmarshal(raw, &command) != nil || command.SchemaVersion != "1.0.0" {
		return invalid()
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	switch command.Action {
	case "snapshot":
		if len(fields) != 2 || command.Owner != nil {
			return invalid()
		}
	case "release-root":
		if len(fields) != 3 || command.Owner == nil {
			return invalid()
		}
	default:
		return invalid()
	}
	return command, nil
}

// One foreground loop owns reads, commands and output. Polling avoids an
// abandoned blocking input goroutine when the owner cancels or a process fails.
func superviseControlled(ctx context.Context, manager *plugins.Manager, prepared preparedComposition, input *os.File, output io.Writer) error {
	var pending, previous []byte
	if input != nil {
		if _, err := input.Stat(); err != nil {
			return fail("plugin_owner_input_unavailable", nil)
		}
		defer runtime.KeepAlive(input)
	}
	emit := func(status, code string, force bool) error {
		snapshot := manager.Snapshot()
		raw, _ := json.Marshal(snapshot)
		if !force && bytes.Equal(previous, raw) {
			return nil
		}
		previous = raw
		result := resultFor(prepared, status)
		result.Code, result.Snapshot = code, &snapshot
		return writeResult(ctx, output, result)
	}
	previous, _ = json.Marshal(manager.Snapshot())
	lastCleanup := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-manager.Done():
			return nil
		default:
		}
		if manager.Snapshot().RetainedCleanup > 0 && time.Since(lastCleanup) >= time.Second {
			cleanup, cancel := context.WithTimeout(ctx, prepared.options.CleanupTimeout)
			_ = manager.RetryCleanup(cleanup)
			cancel()
			lastCleanup = time.Now()
		}
		if err := emit("snapshot", "", false); err != nil {
			return err
		}
		if input == nil {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		poll := []unix.PollFd{{Fd: int32(input.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil || poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return fail("plugin_owner_input_unavailable", nil)
		}
		if ready == 0 || poll[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			continue
		}
		var chunk [512]byte
		n, err := unix.Read(int(input.Fd()), chunk[:])
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return fail("plugin_owner_input_unavailable", nil)
		}
		if n == 0 {
			if len(pending) != 0 {
				return fail("plugin_owner_control_incomplete", nil)
			}
			return nil // Explicit input EOF releases this foreground owner.
		}
		pending = append(pending, chunk[:n]...)
		for {
			newline := bytes.IndexByte(pending, '\n')
			if newline < 0 {
				break
			}
			command, decodeErr := decodeOwnerControl(pending[:newline])
			pending = pending[newline+1:]
			if decodeErr != nil {
				if err = emit("rejected", errorCode(decodeErr), true); err != nil {
					return err
				}
				continue
			}
			if command.Action == "release-root" {
				work, cancel := context.WithTimeout(ctx, prepared.options.CleanupTimeout)
				_, err = manager.ReleaseRoot(work, *command.Owner)
				cancel()
				if err != nil {
					if err = emit("rejected", errorCode(err), true); err != nil {
						return err
					}
					continue
				}
			}
			if err = emit("snapshot", "", true); err != nil {
				return err
			}
		}
		if len(pending) > 8192 {
			return fail("plugin_owner_control_limit", nil)
		}
	}
}
