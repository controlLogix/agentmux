package launcher

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func doctorFixture(t *testing.T) (DoctorConfig, string) {
	t.Helper()
	driver, _, log := setupDocker(t)
	return DoctorConfig{Docker: driver.config, ProfileValidated: true}, log
}

func doctorCheck(t *testing.T, report DoctorReport, name string) DoctorCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("missing check %s", name)
	return DoctorCheck{}
}

func doctorNoDisclosure(t *testing.T, report DoctorReport, config DoctorConfig) {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{config.Docker.Executable, config.Docker.Endpoint,
		"synthetic-private-value", "private invalid output", "--format", "Endpoints.docker.Host"} {
		if secret != "" && strings.Contains(string(body), secret) {
			t.Fatal("report disclosed a private path or raw subprocess data")
		}
	}
}

func TestDoctorReadOnlyAndMissingProbesUnknown(t *testing.T) {
	config, log := doctorFixture(t)
	report := RunDoctor(context.Background(), config)
	if report.DiagnosticsPassed || report.Observation == nil || report.Observation.EngineID != "fixture-engine" ||
		report.Observation.Versions != config.Docker.Versions {
		t.Fatal("missing validated observations or invented complete diagnostic pass")
	}
	for _, name := range []string{"broker", "persistence", "protected-roles"} {
		check := doctorCheck(t, report, name)
		if check.Status != DoctorUnknown || check.Code != DoctorNotProbed {
			t.Fatal("unimplemented service was reported available")
		}
	}
	lines := strings.Split(strings.TrimSpace(commands(log)), "\n")
	if len(lines) != 4 || lines[0] != "context inspect fixture --format {{json .Endpoints.docker.Host}}" {
		t.Fatal("doctor did not use the literal read-only driver allowlist")
	}
	// The endpoint must be verified first. The remaining independent reads may
	// finish in any order, but each exact permitted command must occur once.
	sort.Strings(lines[1:])
	want := []string{"compose version --short", "info --format " + dockerInfoReadFormat, "version --format " + dockerVersionReadFormat}
	if strings.Join(lines[1:], "\n") != strings.Join(want, "\n") {
		t.Fatal("doctor did not use each literal read-only command exactly once")
	}
	noMutation(t, log)
	doctorNoDisclosure(t, report, config)
}

func TestDoctorRefusesBeforeAnySubprocessOrProbe(t *testing.T) {
	for _, kind := range []string{"profile", "context", "endpoint", "engine", "versions", "timeout", "environment", "missing-client", "directory-client", "non-executable"} {
		t.Run(kind, func(t *testing.T) {
			config, log := doctorFixture(t)
			called := false
			config.Probes.Broker = func(context.Context) DoctorProbeResult {
				called = true
				return DoctorProbeResult{DoctorPassed, DoctorProbeVerified}
			}
			switch kind {
			case "profile":
				config.ProfileValidated = false
			case "context":
				config.Docker.Context = "fixture; unsafe"
			case "endpoint":
				config.Docker.Endpoint = "tcp://remote:2375"
			case "engine":
				config.Docker.EngineID = "private\nunsafe"
			case "versions":
				config.Docker.Versions.Client = "unknown"
			case "timeout":
				config.Timeout = 6 * time.Second
			case "environment":
				t.Setenv("DOCKER_CONTEXT", "unselected")
			case "missing-client":
				config.Docker.Executable = filepath.Join(t.TempDir(), "absent")
			case "directory-client":
				config.Docker.Executable = t.TempDir()
			case "non-executable":
				config.Docker.Executable = filepath.Join(t.TempDir(), "not-executable")
				if err := os.WriteFile(config.Docker.Executable, []byte("not a program"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report := RunDoctor(context.Background(), config)
			if report.DiagnosticsPassed || report.Observation != nil || called || commands(log) != "" {
				t.Fatal("refusal still executed a subprocess or integration probe")
			}
			if kind == "missing-client" && doctorCheck(t, report, "client").Code != DoctorClientMissing {
				t.Fatal("missing executable did not retain its observed reason")
			}
			doctorNoDisclosure(t, report, config)
		})
	}
}

func TestDoctorInspectionFailuresStaySafeAndSpecificOnlyWhenProven(t *testing.T) {
	for _, fixture := range []struct {
		mode string
		code DoctorCode
	}{
		{"error", DoctorInspectionUnknown}, {"endpoint", DoctorEndpointConflict},
		{"engine", DoctorBackendConflict}, {"version", DoctorBackendConflict},
		{"server-version", DoctorBackendConflict}, {"compose-version", DoctorBackendConflict},
		{"os", DoctorBackendConflict}, {"malformed", DoctorInvalidObservation},
	} {
		t.Run(fixture.mode, func(t *testing.T) {
			config, log := doctorFixture(t)
			t.Setenv("AMX_DOCKER_MODE", fixture.mode)
			report := RunDoctor(context.Background(), config)
			if report.Observation != nil || report.DiagnosticsPassed || doctorCheck(t, report, "docker").Code != fixture.code {
				t.Fatal("inspection failure disclosed unvalidated observations or wrong reason")
			}
			noMutation(t, log)
			doctorNoDisclosure(t, report, config)
		})
	}
}

func TestDoctorOneTotalBudgetAndCallerCancellation(t *testing.T) {
	t.Run("insufficient driver cleanup budget", func(t *testing.T) {
		config, log := doctorFixture(t)
		config.Timeout = 100 * time.Millisecond
		report := RunDoctor(context.Background(), config)
		if commands(log) != "" || doctorCheck(t, report, "docker").Code != DoctorDeadline {
			t.Fatal("driver launched without its total cleanup budget")
		}
	})
	t.Run("first read timeout stops remaining reads", func(t *testing.T) {
		config, log := doctorFixture(t)
		config.Timeout = 1500 * time.Millisecond
		t.Setenv("AMX_DOCKER_MODE", "timeout")
		begin := time.Now()
		report := RunDoctor(context.Background(), config)
		if time.Since(begin) > 1700*time.Millisecond || doctorCheck(t, report, "docker").Code != DoctorDeadline {
			t.Fatal("selected daemon inspection exceeded the shared total budget")
		}
		if strings.Count(commands(log), "\n") != 1 {
			t.Fatal("inspection continued after its first timed-out observation")
		}
		noMutation(t, log)
	})
	t.Run("already canceled", func(t *testing.T) {
		config, log := doctorFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report := RunDoctor(ctx, config)
		if commands(log) != "" || doctorCheck(t, report, "profile").Code != DoctorCancelled {
			t.Fatal("canceled doctor still launched a process")
		}
	})
	t.Run("cooperative probes use the same remaining context", func(t *testing.T) {
		config, _ := doctorFixture(t)
		config.Timeout = 1500 * time.Millisecond
		var first context.Context
		config.Probes.Broker = func(ctx context.Context) DoctorProbeResult {
			first = ctx
			return DoctorProbeResult{DoctorPassed, DoctorProbeVerified}
		}
		config.Probes.Persistence = func(ctx context.Context) DoctorProbeResult {
			if ctx != first {
				t.Fatal("probe received a fresh independent budget")
			}
			<-ctx.Done()
			return DoctorProbeResult{DoctorPassed, DoctorProbeVerified}
		}
		called := false
		config.Probes.ProtectedRoles = func(context.Context) DoctorProbeResult {
			called = true
			return DoctorProbeResult{DoctorPassed, DoctorProbeVerified}
		}
		report := RunDoctor(context.Background(), config)
		if called || report.DiagnosticsPassed || doctorCheck(t, report, "persistence").Code != DoctorDeadline {
			t.Fatal("a late probe result overrode the common deadline")
		}
	})
}

func TestDoctorProbeCodesAreClosedAndDiagnosticsAreNotReadiness(t *testing.T) {
	config, _ := doctorFixture(t)
	verified := func(context.Context) DoctorProbeResult { return DoctorProbeResult{DoctorPassed, DoctorProbeVerified} }
	config.Probes = DoctorProbes{verified, verified, verified}
	report := RunDoctor(context.Background(), config)
	if !report.DiagnosticsPassed || !strings.Contains(report.Scope, "not application readiness") {
		t.Fatal("diagnostic results were confused with product readiness")
	}
	config.Probes.Broker = func(context.Context) DoctorProbeResult {
		return DoctorProbeResult{DoctorPassed, DoctorCode("synthetic-private-value")}
	}
	report = RunDoctor(context.Background(), config)
	if report.DiagnosticsPassed || doctorCheck(t, report, "broker").Code != DoctorInvalidObservation {
		t.Fatal("untrusted callback text became a diagnostic code")
	}
	doctorNoDisclosure(t, report, config)
	var external DoctorConfig
	if err := json.Unmarshal([]byte(`{"ProfileValidated":true}`), &external); err != nil || external.ProfileValidated {
		t.Fatal("external JSON supplied the internal validation assertion")
	}
}

// This disposable helper owns only bounded synthetic children. The pipe holder
// exits on its own and writes a completion marker before test cleanup. It is not
// a Docker daemon, and its behavior grants no application readiness evidence.
const doctorTimingHelper = `package main
import (
 "fmt"
 "os"
 "os/exec"
 "strings"
 "time"
)
func main() {
 if len(os.Args)>1 && os.Args[1]=="pipe-holder" {
  time.Sleep(2500*time.Millisecond)
  _=os.WriteFile(os.Args[2],[]byte("finished"),0600)
  return
 }
 args:=os.Args[1:]
 if len(args)<3 || args[0]!="--context" || args[1]!="fixture" { os.Exit(9) }
 args=args[2:]
 log,err:=os.OpenFile(os.Getenv("AMX_DOCTOR_TIMING_LOG"),os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600)
 if err!=nil { os.Exit(8) }
 _,_=fmt.Fprintln(log,strings.Join(args," "))
 _=log.Close()
 mode:=os.Getenv("AMX_DOCTOR_TIMING_MODE")
 if mode=="late" { time.Sleep(150*time.Millisecond) }
 switch args[0] {
 case "context": fmt.Println("\"unix:///tmp/docker.sock\"")
 case "version": fmt.Println("{\"Client\":\"29.8.0\",\"Server\":\"29.8.0\"}")
 case "info": fmt.Println("{\"ID\":\"fixture-engine\",\"OS\":\"linux\"}")
 case "compose":
  if len(args)!=3 || args[1]!="version" || args[2]!="--short" { os.Exit(7) }
  if mode=="pipe" {
   child:=exec.Command(os.Args[0],"pipe-holder",os.Getenv("AMX_DOCTOR_TIMING_DONE"))
   child.Stdout=os.Stdout
   if child.Start()!=nil { os.Exit(6) }
   time.Sleep(4*time.Second)
   _=child.Wait()
  } else { time.Sleep(3*time.Second) }
  fmt.Println("5.5.1")
 default: os.Exit(5)
 }
}
`

func TestDoctorLaterReadAndInheritedPipeCleanupShareTotalBudget(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "helper.go")
	if err := os.WriteFile(source, []byte(doctorTimingHelper), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "doctor-helper")
	buildCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	build := exec.CommandContext(buildCtx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", helper, source)
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GO111MODULE=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("controlled helper build failed: %v (%s)", err, output)
	}
	for _, mode := range []string{"late", "pipe"} {
		t.Run(mode, func(t *testing.T) {
			config, _ := doctorFixture(t)
			config.Docker.Executable = helper
			config.Timeout = 2 * time.Second
			log := filepath.Join(t.TempDir(), "commands")
			done := filepath.Join(t.TempDir(), "holder-finished")
			if mode == "pipe" {
				// Register before the doctor call so even a failed assertion waits
				// for the bounded holder before temporary directories are removed.
				t.Cleanup(func() {
					until := time.Now().Add(3 * time.Second)
					for {
						if _, err := os.Stat(done); err == nil {
							return
						}
						if time.Now().After(until) {
							t.Error("bounded fixture pipe holder did not finish")
							return
						}
						time.Sleep(10 * time.Millisecond)
					}
				})
			}
			t.Setenv("AMX_DOCTOR_TIMING_LOG", log)
			t.Setenv("AMX_DOCTOR_TIMING_DONE", done)
			t.Setenv("AMX_DOCTOR_TIMING_MODE", mode)
			begin := time.Now()
			report := RunDoctor(context.Background(), config)
			elapsed := time.Since(begin)
			t.Logf("Doctor call elapsed %s; any bounded fixture teardown follows this measurement.", elapsed)
			if elapsed > 2200*time.Millisecond || doctorCheck(t, report, "docker").Code != DoctorDeadline ||
				report.Observation != nil || report.DiagnosticsPassed {
				t.Fatal("later observation or inherited pipe exceeded the total diagnostic budget")
			}
			if strings.Count(commands(log), "\n") != 4 {
				t.Fatal("fixture did not reach the fourth literal read after three valid observations")
			}
			if mode == "pipe" {
				if elapsed < 1800*time.Millisecond {
					t.Fatal("inherited pipe fixture did not exercise WaitDelay cleanup")
				}
				// Registered fixture teardown is separate from the doctor call.
				// Pipe cleanup never kills or adopts an unknown descendant.
			}
			noMutation(t, log)
			doctorNoDisclosure(t, report, config)
		})
	}
}
