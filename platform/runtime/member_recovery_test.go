package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/assembly"
	"golang.org/x/sys/unix"
)

// These primitive tests use ordinary exact-owned OS commands through the private
// image seam. They do not qualify installed protected assembly admission.
type recoveryImage struct {
	exit           bool
	validation     error
	closeFailure   error
	launches       int
	closes         int
	validationHook func(context.Context) error
	commanded      *exec.Cmd
}

func (i *recoveryImage) command([]string) *exec.Cmd {
	i.launches++
	if i.exit {
		i.commanded = exec.Command("/usr/bin/false")
	} else {
		i.commanded = exec.Command("/bin/sleep", "60")
	}
	return i.commanded
}
func (i *recoveryImage) validateForStart(ctx context.Context) error {
	if i.validationHook != nil {
		return i.validationHook(ctx)
	}
	return i.validation
}
func (i *recoveryImage) close() error { i.closes++; return i.closeFailure }

func recoveryPrepared(t *testing.T, exitRole string) (*Prepared, [4]RoleOptions, [4]*recoveryImage) {
	t.Helper()
	p := &Prepared{roles: [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}, release: assembly.Trust{AssemblyDigest: "fixture-assembly"}}
	var supplied [4]RoleOptions
	var images [4]*recoveryImage
	for i, role := range p.roles {
		supplied[i] = RoleOptions{ID: role}
		images[i] = &recoveryImage{exit: role == exitRole}
		p.images[i] = images[i]
	}
	return p, supplied, images
}
func recoveryGroup(t *testing.T, exitRole string) *Group {
	t.Helper()
	p, options, _ := recoveryPrepared(t, exitRole)
	ctx, cancel := context.WithCancel(context.Background())
	g, err := p.StartRecoverable(ctx, options, Deadlines{StartTimeout: time.Second, StopGrace: 20 * time.Millisecond, ReapTimeout: time.Second}, RecoveryPolicy{MaxAttemptsPerRole: 2, Timeout: time.Second})
	if err != nil {
		cancel()
		t.Fatal("primitive group start failed", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer stopCancel()
		if err := g.Stop(stopCtx); err != nil {
			t.Error("owned primitive group cleanup failed", err)
		}
		cancel()
		<-g.Done()
		if err := g.CleanupError(); err != nil {
			t.Error("owned primitive cleanup cause", err)
		}
	})
	return g
}
func waitRecoveryRole(t *testing.T, g *Group, role string) {
	t.Helper()
	for _, child := range g.currentChildren() {
		if child.role == role {
			select {
			case <-child.done:
				return
			case <-time.After(2 * time.Second):
				t.Fatal("owned role did not complete its original wait")
			}
		}
	}
	t.Fatal("owned role absent")
}

func TestMemberRecoveryReplacesOnlyDeadCurrentGeneration(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	before := g.Status()
	p, options, images := recoveryPrepared(t, "")
	generation, err := g.RecoverRole(context.Background(), "boot", 1, p, options[0])
	if err != nil || generation != 2 {
		t.Fatal("dead member recovery failed", err)
	}
	after := g.Status()
	for i, status := range after {
		if status.Role == "boot" {
			if status.Exited || status.Generation != 2 || status.PID == before[i].PID {
				t.Fatal("new member retained retired process observation")
			}
		} else if status != before[i] {
			t.Fatal("recovery changed another member")
		}
	}
	for i, image := range images {
		want := 0
		if i == 0 {
			want = 1
		}
		if image.launches != want || image.closes != 1 {
			t.Fatal("replacement did not dispose all four images exactly once")
		}
	}
	if observed, ok := g.RoleGeneration("boot"); !ok || observed != 2 {
		t.Fatal("role generation missing")
	}
	select {
	case <-g.Done():
		t.Fatal("one member exit closed recovery lifetime")
	default:
	}
}

func TestMemberRecoveryRefusesAliveStaleChangedAndStopped(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	for _, kind := range []string{"alive", "stale", "release", "settings", "stopped"} {
		p, options, images := recoveryPrepared(t, "")
		role, generation, option := "boot", uint64(1), options[0]
		switch kind {
		case "alive":
			role = "kernel-lifecycle"
			option = options[1]
		case "stale":
			generation = 2
		case "release":
			p.release.AssemblyDigest = "another-release"
		case "settings":
			option.Args = []string{"changed"}
		case "stopped":
			if err := g.StopRole(context.Background(), "boot"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := g.RecoverRole(context.Background(), role, generation, p, option); err == nil {
			t.Fatalf("%s recovery admitted", kind)
		}
		for _, image := range images {
			if image.launches != 0 || image.closes != 1 {
				t.Fatal("refusal leaked or launched replacement image")
			}
		}
	}
}

func TestMemberRecoveryBoundedAttemptsAndSpawnRevalidation(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	for attempt := 0; attempt < 3; attempt++ {
		p, options, images := recoveryPrepared(t, "")
		images[0].validation = errors.New("changed protected installation")
		generation, err := g.RecoverRole(context.Background(), "boot", 1, p, options[0])
		if err == nil || generation != 0 {
			t.Fatal("invalid replacement reached a process generation")
		}
		if attempt < 2 && images[0].launches != 1 {
			t.Fatal("spawn validation seam was not reached")
		}
		if attempt == 2 && images[0].launches != 0 {
			t.Fatal("recovery exceeded fixed attempt cap")
		}
	}
	if generation, _ := g.RoleGeneration("boot"); generation != 1 {
		t.Fatal("failed spawn advanced generation")
	}
}

func TestMemberRecoveryCleanupRetainsPreparedAndRefusalCause(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	p, options, images := recoveryPrepared(t, "")
	cause := errors.New("private disposal detail")
	images[2].closeFailure = cause
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := g.RecoverRole(ctx, "boot", 1, p, options[0])
	var cleanup *RecoveryCleanupError
	if !errors.As(err, &cleanup) || cleanup.Prepared != p || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
		t.Fatal("recovery discarded an exact cleanup owner or cause")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if fmt.Sprintf(format, err) != "protected recovery failed; owned image cleanup incomplete" {
			t.Fatal("cleanup formatting exposed private cause")
		}
	}
	raw, _ := json.Marshal(err)
	if string(raw) != `"protected recovery failed; owned image cleanup incomplete"` {
		t.Fatal("cleanup JSON exposed private owner")
	}
	images[2].closeFailure = nil
	if err := cleanup.RetryClose(); !errors.Is(err, cause) || images[2].closes != 1 {
		t.Fatal("consumed image close acquired false retry success")
	}
	for _, image := range images {
		if image.launches != 0 {
			t.Fatal("canceled recovery launched a member")
		}
	}
}

func TestMemberRecoveryConcurrentAdmissionAndStop(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			p, options, _ := recoveryPrepared(t, "")
			_, _ = g.RecoverRole(context.Background(), "boot", 1, p, options[0])
			_ = g.Status()
			_, _ = g.Output("boot")
			_, _ = g.RoleGeneration("boot")
		}()
	}
	workers.Add(1)
	go func() { defer workers.Done(); _ = g.Stop(context.Background()) }()
	workers.Wait()
	select {
	case <-g.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown left replacement admission open")
	}
	p, options, images := recoveryPrepared(t, "")
	if _, err := g.RecoverRole(context.Background(), "boot", 1, p, options[0]); err == nil {
		t.Fatal("shutdown admitted replacement")
	}
	for _, image := range images {
		if image.launches != 0 {
			t.Fatal("shutdown launched another process")
		}
	}
}

func TestMemberRecoveryIntentionalStopAndContextCloseAdmission(t *testing.T) {
	g := recoveryGroup(t, "")
	if err := g.StopRole(context.Background(), "boot"); err != nil {
		t.Fatal("live member stop failed", err)
	}
	waitRecoveryRole(t, g, "boot")
	p, options, images := recoveryPrepared(t, "")
	if _, err := g.RecoverRole(context.Background(), "boot", 1, p, options[0]); err == nil {
		t.Fatal("intentional stop admitted recovery")
	}
	for _, image := range images {
		if image.launches != 0 {
			t.Fatal("intentional stop launched replacement")
		}
	}
	if err := g.Stop(context.Background()); err != nil {
		t.Fatal("whole group stop failed", err)
	}
	select {
	case <-g.Done():
	case <-time.After(time.Second):
		t.Fatal("whole stop did not close recovery lifetime")
	}
}

func TestMemberRecoveryInheritedLeaseReleasesBeforeReplacement(t *testing.T) {
	leasePath := t.TempDir() + "/owned-role-lease"
	lease, err := os.OpenFile(leasePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	p, options, _ := recoveryPrepared(t, "boot")
	options[0].LifetimeLease = lease
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := p.StartRecoverable(ctx, options, Deadlines{StartTimeout: time.Second, StopGrace: 20 * time.Millisecond, ReapTimeout: time.Second}, RecoveryPolicy{MaxAttemptsPerRole: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := g.Stop(context.Background()); err != nil {
			t.Error(err)
		}
		_ = g.CleanupError()
	}()
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	waitRecoveryRole(t, g, "boot")
	next, err := os.OpenFile(leasePath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := unix.Flock(int(next.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("old reaped child retained role lease")
	}
	replacement, fresh, _ := recoveryPrepared(t, "")
	fresh[0].LifetimeLease = next
	if generation, err := g.RecoverRole(context.Background(), "boot", 1, replacement, fresh[0]); err != nil || generation != 2 {
		t.Fatal("fresh role lease recovery failed", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	contender, err := os.OpenFile(leasePath, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer contender.Close()
	if err := unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("live replacement lost child-held role lease")
	}
	if err := g.StopRole(context.Background(), "boot"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(contender.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("replacement wait did not release exact role lease")
	}
}

func TestMemberRecoveryPriorCleanupRefusesReplacement(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	previous := g.currentChildren()[0]
	cause := errors.New("owned previous writer cleanup failed")
	previous.mu.Lock()
	previous.cleanupError = cause
	previous.mu.Unlock()
	p, options, images := recoveryPrepared(t, "")
	_, err := g.RecoverRole(context.Background(), "boot", 1, p, options[0])
	if !errors.Is(err, cause) {
		t.Fatal("prior cleanup cause was discarded")
	}
	for _, image := range images {
		if image.launches != 0 {
			t.Fatal("replacement began before previous cleanup")
		}
	}
	previous.mu.Lock()
	previous.cleanupError = nil
	previous.mu.Unlock()
}

func TestMemberRecoveryLifetimeCancellationReapsAndClosesAdmission(t *testing.T) {
	p, options, _ := recoveryPrepared(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := p.StartRecoverable(ctx, options, Deadlines{StartTimeout: time.Second, StopGrace: 20 * time.Millisecond, ReapTimeout: time.Second}, RecoveryPolicy{MaxAttemptsPerRole: 2, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-g.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("canceled group retained recovery lifetime")
	}
	if err := g.CleanupError(); err != nil {
		t.Fatal("canceled group cleanup failed", err)
	}
	for _, status := range g.Status() {
		if !status.Exited || status.RecoveryEnabled {
			t.Fatal("canceled group retained a live or recoverable member")
		}
	}
}

func TestMemberRecoveryPostSpawnCleanupKeepsCurrentOwnedChild(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	p, options, images := recoveryPrepared(t, "")
	cause := errors.New("unused replacement disposal failed")
	images[2].closeFailure = cause
	generation, err := g.RecoverRole(context.Background(), "boot", 1, p, options[0])
	var cleanup *RecoveryCleanupError
	if generation != 2 || !errors.As(err, &cleanup) || cleanup.Prepared != p || !errors.Is(err, cause) {
		t.Fatal("post-spawn cleanup lost ownership or generation")
	}
	for _, status := range g.Status() {
		if status.Role == "boot" && (status.Exited || status.Generation != 2) {
			t.Fatal("post-spawn failure discarded live replacement child")
		}
	}
	images[2].closeFailure = nil
	if err := cleanup.RetryClose(); !errors.Is(err, cause) || images[2].closes != 1 {
		t.Fatal("unused consumed image close acquired false retry success")
	}
}

func TestMemberRecoveryConsumedNativeCloseCannotBecomeRetrySuccess(t *testing.T) {
	g := recoveryGroup(t, "boot")
	waitRecoveryRole(t, g, "boot")
	p, options, _ := recoveryPrepared(t, "")
	file, err := os.CreateTemp(t.TempDir(), "consumed-close-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	consumed := &preparedCleanupImage{file: file}
	p.images[2] = consumed
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, failure := g.RecoverRole(ctx, "boot", 1, p, options[0])
	var cleanup *RecoveryCleanupError
	if !errors.As(failure, &cleanup) || cleanup.Prepared != p || !errors.Is(failure, os.ErrClosed) || consumed.calls != 1 {
		t.Fatal("actual consumed close lost its owner or cause")
	}
	if !errors.Is(cleanup.RetryClose(), os.ErrClosed) || consumed.calls != 1 {
		t.Fatal("second native close manufactured success")
	}
	if !errors.Is(p.Close(), os.ErrClosed) || consumed.calls != 1 {
		t.Fatal("prepared Close discarded historical native close failure")
	}
}

func TestMemberRecoveryExpiryDuringRevalidationDoesNotSpawn(t *testing.T) {
	for _, closeFault := range []bool{false, true} {
		t.Run(fmt.Sprintf("closeFault_%t", closeFault), func(t *testing.T) {
			g := recoveryGroup(t, "boot")
			waitRecoveryRole(t, g, "boot")
			p, options, images := recoveryPrepared(t, "")
			images[0].validationHook = func(ctx context.Context) error { <-ctx.Done(); return nil }
			cause := errors.New("expiry cleanup failure")
			if closeFault {
				images[2].closeFailure = cause
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			generation, failure := g.RecoverRole(ctx, "boot", 1, p, options[0])
			if generation != 0 || !errors.Is(failure, context.DeadlineExceeded) || images[0].commanded == nil || images[0].commanded.Process != nil {
				t.Fatal("expired replacement spawned or lost its deadline")
			}
			if current, _ := g.RoleGeneration("boot"); current != 1 {
				t.Fatal("expired revalidation advanced generation")
			}
			for _, image := range images {
				if image.closes != 1 {
					t.Fatal("expired replacement lost an image cleanup owner")
				}
			}
			if closeFault {
				var cleanup *RecoveryCleanupError
				if !errors.As(failure, &cleanup) || cleanup.Prepared != p || !errors.Is(failure, cause) {
					t.Fatal("expiry cleanup lost its concrete owner")
				}
			}
		})
	}
}

type orderedRecoveryImage struct{ role, path, mode, binary string }

func (i *orderedRecoveryImage) command([]string) *exec.Cmd {
	return exec.Command("/usr/bin/env", "GORACE=atexit_sleep_ms=0", i.binary, "-test.run=^TestMemberRecoveryOrderedShutdownChild$", "--", "ordered-child", i.role, i.path, i.mode)
}
func (*orderedRecoveryImage) close() error { return nil }

func TestMemberRecoveryOrderedShutdownChild(t *testing.T) {
	if len(os.Args) < 5 || os.Args[len(os.Args)-4] != "ordered-child" {
		return
	}
	role, path, mode := os.Args[len(os.Args)-3], os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	fmt.Println("ready")
	for range signals {
		if mode == "ignore" {
			continue
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(2)
		}
		_, writeErr := fmt.Fprintln(file, role)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
}

func TestMemberRecoveryReverseShutdownUsesOneSharedBudget(t *testing.T) {
	for _, mode := range []string{"graceful", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			p, options, _ := recoveryPrepared(t, "")
			path := t.TempDir() + "/shutdown-order"
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			for i, role := range p.roles {
				p.images[i] = &orderedRecoveryImage{role: role, path: path, mode: mode, binary: binary}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deadlines := Deadlines{StartTimeout: time.Second, StopGrace: 240 * time.Millisecond, ReapTimeout: 200 * time.Millisecond}
			g, err := p.StartRecoverable(ctx, options, deadlines, RecoveryPolicy{MaxAttemptsPerRole: 2, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := g.Stop(context.Background()); err != nil {
					t.Error(err)
				}
				_ = g.CleanupError()
			}()
			readyUntil := time.Now().Add(3 * time.Second)
			for {
				all := true
				for _, role := range p.roles {
					output, _ := g.Output(role)
					all = all && strings.Contains(string(output), "ready")
				}
				if all {
					break
				}
				if time.Now().After(readyUntil) {
					t.Fatal("owned shutdown helpers did not initialize")
				}
				time.Sleep(time.Millisecond)
			}
			started := time.Now()
			if err := g.Stop(context.Background()); err != nil {
				t.Fatal("ordered shutdown failed", err)
			}
			if time.Since(started) > 600*time.Millisecond {
				t.Fatal("ordered shutdown reset its per-role budget")
			}
			for _, status := range g.Status() {
				if !status.Exited || status.RecoveryEnabled {
					t.Fatal("ordered shutdown retained live recovery admission")
				}
			}
			if mode == "graceful" {
				order, err := os.ReadFile(path)
				if err != nil || string(order) != "exported-status\ninternal-communication\nkernel-lifecycle\nboot\n" {
					t.Fatal("shutdown did not join each role in reverse fixed assembly order")
				}
			}
		})
	}
}
