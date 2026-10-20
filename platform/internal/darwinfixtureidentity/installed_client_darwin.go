//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"

	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type installedClientExpectation struct {
	admission interface {
		Recheck(context.Context) error
		Close() error
	}
	original identity
	frontend expectedImage
	python   expectedImage
}

// StartInstalledClient retains the admitted package and the original command,
// waits for its fixed Python image, then admits a proof that rejects later execs.
// It accepts no caller-selected interpreter or Python arguments.
func (c *Creator) StartInstalledClient(ctx context.Context, launch Launch, installationID, operation, selection string) (*Owned, error) {
	if operation != "mcp" && operation != "startup" {
		return nil, failed("fixture_client_operation_refused", nil)
	}
	a, err := protected.PrepareInstalledClient(ctx, installationID)
	if err != nil {
		return nil, failed("fixture_client_package_refused", err)
	}
	d, err := a.Declaration(ctx, selection)
	if err != nil {
		return nil, errors.Join(failed("fixture_client_declaration_refused", err), safeClose(a, "fixture_client_close_failed"))
	}
	d.Arguments[0] = operation
	if launch.Path != d.Command || !reflect.DeepEqual(launch.Args, d.Arguments) {
		return nil, errors.Join(failed("fixture_client_launch_refused", nil), safeClose(a, "fixture_client_close_failed"))
	}
	root := filepath.Join(protected.InstalledClientBase, installationID)
	interpreter := filepath.Join(root, protected.ClientInterpreter)
	client := &installedClientExpectation{
		admission: a,
		frontend:  expectedImage{Path: launch.Path, Args: append([]string(nil), launch.Args...)},
		python:    expectedImage{Path: interpreter, Args: []string{"-I", "-S", filepath.Join(root, protected.ClientBootstrap), operation, selection}},
	}
	x, err := c.startProtectedClient(ctx, launch, true, client)
	if x == nil {
		err = errors.Join(err, safeClose(a, "fixture_client_close_failed"))
	}
	return x, err
}

// Exec changes the audit-token version. The creation identity stays bound to
// the original unreaped child; only the exact admitted target can receive a new
// version-bound cleanup identity. No existing proof survives this transition.
func sameCreation(a, b identity) bool {
	return a.PID == b.PID && a.Unique != 0 && a.Unique == b.Unique &&
		a.ParentUnique == b.ParentUnique && a.UID == b.UID && a.RealUID == b.RealUID
}

func clientTransitionState(original, now identity, path string, args []string, client *installedClientExpectation) (ready bool, err error) {
	if client == nil || !sameCreation(original, now) || original.ParentPID != now.ParentPID {
		return false, failed("fixture_client_creation_changed", nil)
	}
	if matchesArguments(client.python, path, args) {
		return true, nil
	}
	if sameIdentity(original, now) && matchesArguments(client.frontend, path, args) {
		return false, nil
	}
	return false, failed("fixture_client_exec_refused", nil)
}

// Called before the sole Wait starts, so an exited child cannot be reaped and
// replaced while the helper is deciding whether the direct exec completed.
func (x *Owned) awaitInstalledClient(ctx context.Context) error {
	if x.cleanupIdentity == nil {
		return failed("fixture_client_creation_unavailable", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	original := x.client.original
	for {
		if err := ctx.Err(); err != nil {
			return failed("fixture_client_exec_incomplete", err)
		}
		now, err := observe(int(original.PID))
		if err != nil {
			return failed("fixture_client_observation_failed", err)
		}
		path, pathErr := nativePath(now)
		args, argsErr := nativeArguments(now)
		after, afterErr := observe(int(original.PID))
		if pathErr != nil || argsErr != nil || afterErr != nil || !sameIdentity(now, after) {
			// The expected exec may race the native reads. Retain the original
			// creation identity and retry within the same fixed deadline.
			if afterErr != nil || !sameCreation(original, after) {
				return failed("fixture_client_observation_changed", errors.Join(pathErr, argsErr, afterErr))
			}
		} else {
			ready, err := clientTransitionState(original, now, path, args, x.client)
			if err != nil {
				return err
			}
			if ready {
				return x.retainInstalledClientTarget(ctx, now)
			}
		}
		select {
		case <-ctx.Done():
			return failed("fixture_client_exec_incomplete", ctx.Err())
		case <-ticker.C:
		}
	}
}

// The target already passed creation, image, argv and version-stability checks.
// Preserve cleanup authority before any fallible package recheck. The original
// creation snapshot stays retained, and full proof admission still follows.
func (x *Owned) retainInstalledClientTarget(ctx context.Context, target identity) error {
	x.cleanupIdentity = &target
	if err := x.client.admission.Recheck(ctx); err != nil {
		return failed("fixture_client_package_changed", err)
	}
	x.expected = x.client.python
	return nil
}

// PinDirectClientEnsure admits only the installed adapter's literal ensure
// child. The caller must retain this proof before that child exits. Its creation
// identity can then anchor PinDirectHost even after the child is reaped.
func (p *Proof) PinDirectClientEnsure(ctx context.Context, host ExpectedHost, frontendDigest string) (*Proof, error) {
	if host.PolicyPath == "" || len(host.WorkspaceRoots) == 0 || len(host.WorkspaceRoots) > 16 {
		return nil, failed("fixture_host_expectation_invalid", nil)
	}
	args := []string{"ensure", "--host-policy", host.PolicyPath}
	for _, root := range host.WorkspaceRoots {
		args = append(args, "--workspace", root)
	}
	application, err := applicationArguments(host.Application)
	if err != nil {
		return nil, err
	}
	args = append(args, application...)
	proofs, err := p.pinDirectChildrenWithExec(ctx, []expectedImage{{Path: protected.StableFrontendPath, Digest: frontendDigest, Args: args, stableFrontend: true}}, true)
	return singleChildResult(proofs, err)
}
