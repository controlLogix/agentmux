//go:build linux || darwin

package launcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Count only fixed read-only archive commands in the owned inspector fixture.
// This init runs before the fixture's own dispatch; it changes no production API.
func init() {
	if audit := os.Getenv("AMX_KERNEL_PROOF_AUDIT"); audit != "" && os.Getenv("AMX_OWNER_BRIDGE_DOCKER_FIXTURE") != "" {
		for _, argument := range os.Args[1:] {
			if argument == "cp" {
				file, err := os.OpenFile(audit, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					os.Exit(7)
				}
				_, err = file.WriteString("archive\n")
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					os.Exit(7)
				}
				break
			}
		}
	}
}

func proofAudit(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inspection-count")
	if os.WriteFile(path, nil, 0600) != nil {
		t.Fatal("inspection audit unavailable")
	}
	t.Setenv("AMX_KERNEL_PROOF_AUDIT", path)
	return path
}

func TestKernelOperationProofUsesOneActualInspection(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	audit := proofAudit(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authority, proof, err := inspectLocalBrokerOperation(ctx, f.config)
	if err != nil || authority.broker.State != "running" || proof == nil {
		t.Fatal("actual inspection proof unavailable", err)
	}
	before, err := os.ReadFile(audit)
	if err != nil || string(before) != "archive\narchive\narchive\n" {
		t.Fatal("full three-file inspection not observed")
	}
	frame, err := observeKernelWithProof(ctx, f.config.Kernel, proof)
	if err != nil || frame.KernelReadiness != "ready" {
		t.Fatal("actual pinned TLS snapshot unavailable", err)
	}
	after, err := os.ReadFile(audit)
	if err != nil || string(after) != string(before) {
		t.Fatal("same-operation observer repeated archive inspection")
	}
	if _, err := observeKernelWithProof(ctx, f.config.Kernel, proof); !IsKernelStatusAuthorityError(err) {
		t.Fatal("consumed proof accepted twice", err)
	}
	// The exported API still performs its own full inspection.
	if _, err := ObserveKernel(ctx, f.config.Kernel); err != nil {
		t.Fatal("public fresh observer failed", err)
	}
	final, _ := os.ReadFile(audit)
	if len(final) != 2*len(before) {
		t.Fatal("public observer skipped full inspection")
	}
}

func TestKernelOperationProofBoundaries(t *testing.T) {
	for _, fault := range []string{"binding", "context", "cancelled", "expired", "future", "changed_enrollment"} {
		t.Run(fault, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.controlledDocker(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, proof, err := inspectLocalBrokerOperation(ctx, f.config)
			if err != nil {
				t.Fatal("actual inspection proof unavailable", err)
			}
			binding := f.config.Kernel.authority
			parent := ctx
			switch fault {
			case "binding":
				binding = &localBrokerBinding{config: binding.config}
			case "context":
				other, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				parent = other
			case "cancelled":
				cancel()
			case "expired":
				proof.completed = time.Now().Add(-4*time.Second - time.Millisecond)
			case "future":
				proof.completed = time.Now().Add(time.Second)
			case "changed_enrollment":
				profile := f.profile
				profile.ReleaseFingerprint = "sha256:" + string(make([]byte, 64))
				releaseTestWrite(t, profile.ProfileDirectory, "profile.json", mustStatusJSON(profile))
			}
			_, refresh, err := proof.consume(parent, binding)
			if fault == "expired" || fault == "future" {
				if err != nil || !refresh {
					t.Fatal("invalid age did not require actual refresh", err)
				}
			} else if !IsKernelStatusAuthorityError(err) {
				t.Fatal("operation binding denial missing", err)
			}
			if _, _, err := proof.consume(ctx, f.config.Kernel.authority); !IsKernelStatusAuthorityError(err) {
				t.Fatal("failed consumption reused", err)
			}
		})
	}
}

func TestKernelOperationProofRejectsUnboundedInvocation(t *testing.T) {
	f := newBridgeFixture(t)
	if _, proof, err := inspectLocalBrokerOperation(context.Background(), f.config); err == nil || proof != nil {
		t.Fatal("unbounded invocation minted proof")
	}
}

func TestKernelOperationProofExpiryActuallyReinspects(t *testing.T) {
	f := newBridgeFixture(t)
	f.startBroker(t)
	f.startActors(t)
	audit := proofAudit(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, proof, err := inspectLocalBrokerOperation(ctx, f.config)
	if err != nil {
		t.Fatal("actual proof unavailable", err)
	}
	proof.completed = time.Now().Add(-5 * time.Second)
	frame, err := observeKernelWithProof(ctx, f.config.Kernel, proof)
	if err != nil || frame.KernelReadiness != "ready" {
		t.Fatal("fresh expired-proof observation unavailable", err)
	}
	count, _ := os.ReadFile(audit)
	if string(count) != "archive\narchive\narchive\narchive\narchive\narchive\n" {
		t.Fatal("expiry skipped actual fresh inspection")
	}
}
