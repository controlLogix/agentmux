//go:build darwin

// This cooperative fixture exercises internal test authority. It is not the
// installed Agentmux CLI, a broker, a role implementation or a product daemon.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type policy struct {
	Scenario         string `json:"scenario"`
	DeadlineUnixNano int64  `json:"deadlineUnixNano"`
}

var roles = [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}

func main()                   { os.Exit(run()) }
func refuse(label string) int { fmt.Fprintln(os.Stderr, label); return 70 }
func lifetime(deadline int64) bool {
	remaining := time.Until(time.Unix(0, deadline))
	if remaining <= 0 || remaining > 15*time.Second {
		return false
	}
	go func() { timer := time.NewTimer(remaining); defer timer.Stop(); <-timer.C; os.Exit(124) }()
	return true
}
func loadPolicy(path string) (result policy, resultErr error) {
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	raw, readErr := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if readErr != nil {
		return result, readErr
	}
	if len(raw) > 64*1024 {
		return result, fmt.Errorf("fixture_policy_size_refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return result, fmt.Errorf("fixture_policy_trailing_data")
	}
	switch result.Scenario {
	case "four", "missing", "extra", "ambiguous":
	default:
		return result, fmt.Errorf("fixture_policy_scenario_invalid")
	}
	return result, nil
}
func eof(file *os.File) bool {
	if file == nil {
		return false
	}
	var b [1]byte
	n, err := file.Read(b[:])
	return n == 0 && err == io.EOF
}
func run() int {
	if len(os.Args) < 2 {
		return refuse("fixture_mode_required")
	}
	switch os.Args[1] {
	case "fast-exit":
		if len(os.Args) != 2 {
			return refuse("fixture_arguments_invalid")
		}
		fmt.Fprintln(os.Stdout, "fixture_complete")
		return 0
	case "frontend":
		return frontend()
	case "host":
		return host()
	case "role":
		return role()
	default:
		return refuse("fixture_mode_invalid")
	}
}
func frontend() int {
	if len(os.Args) != 4 || !literalPath(os.Args[2]) || !literalPath(os.Args[3]) {
		return refuse("fixture_frontend_arguments_invalid")
	}
	p, err := loadPolicy(os.Args[2])
	if err != nil || !lifetime(p.DeadlineUnixNano) {
		return refuse("fixture_policy_refused")
	}
	frontGate := os.NewFile(3, "fixture-frontend-gate")
	familyGate := os.NewFile(4, "fixture-family-gate")
	cleanupWriter := os.NewFile(5, "fixture-host-cleanup")
	if frontGate == nil || familyGate == nil || cleanupWriter == nil {
		return refuse("fixture_gate_missing")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return refuse("fixture_attempt_unavailable")
	}
	readyRead, readyWrite, pipeErr := os.Pipe()
	if pipeErr != nil {
		return refuse("fixture_ready_pipe_failed")
	}
	cmd := exec.Command(os.Args[0], "host", "--host-policy", os.Args[2], "--invocation-id", "attempt_"+hex.EncodeToString(nonce[:]), "--workspace", os.Args[3])
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.ExtraFiles = []*os.File{familyGate, readyWrite, cleanupWriter}
	// The host has a separate lifetime gate. Frontend exit deliberately hands
	// it to the OS reaper; the test retains native lineage and exact watches.
	// No Wait is started for the live host, and frontend exit never claims it
	// joined that host. The host independently joins its own role children.
	if err := cmd.Start(); err != nil {
		closeErr := errors.Join(readyRead.Close(), readyWrite.Close())
		if closeErr != nil {
			return refuse("fixture_host_start_and_ready_cleanup_failed")
		}
		return refuse("fixture_host_start_failed")
	}
	if err := cleanupWriter.Close(); err != nil {
		return refuse("fixture_cleanup_writer_handoff_failed")
	}
	if err := readyWrite.Close(); err != nil {
		return refuse("fixture_ready_writer_close_failed")
	}
	var ready [1]byte
	n, readyErr := io.ReadFull(readyRead, ready[:])
	readyClose := readyRead.Close()
	if readyErr != nil || readyClose != nil || n != 1 || ready[0] != 1 {
		return refuse("fixture_host_readiness_failed")
	}
	fmt.Fprintln(os.Stdout, "fixture_ready")
	okay := eof(frontGate)
	closeFront := frontGate.Close()
	closeFamily := familyGate.Close()
	if !okay || closeFront != nil || closeFamily != nil {
		return refuse("fixture_frontend_gate_failed")
	}
	return 0
}
func host() int {
	if len(os.Args) != 8 || os.Args[2] != "--host-policy" || os.Args[4] != "--invocation-id" || os.Args[6] != "--workspace" || !literalPath(os.Args[3]) || !literalPath(os.Args[7]) || !validAttempt(os.Args[5]) {
		return refuse("fixture_host_arguments_invalid")
	}
	p, err := loadPolicy(os.Args[3])
	if err != nil || !lifetime(p.DeadlineUnixNano) {
		return refuse("fixture_policy_refused")
	}
	familyGate := os.NewFile(3, "fixture-family-gate")
	cleanupWriter := os.NewFile(5, "fixture-host-cleanup")
	if familyGate == nil || cleanupWriter == nil {
		return refuse("fixture_gate_missing")
	}
	roster := append([]string(nil), roles[:]...)
	switch p.Scenario {
	case "missing":
		roster = roster[:3]
	case "extra":
		roster = append(roster, "boot")
	case "ambiguous":
		roster[1] = "boot"
	}
	// Each successful start has exactly one Wait owned by this host. EOF is
	// shared by all family readers; no command data competes between readers.
	completions := make([]<-chan error, 0, len(roster))
	failedStart := false
	for _, id := range roster {
		cmd := exec.Command(filepath.Join(filepath.Dir(os.Args[0]), "bin", id), "role", id, strconv.FormatInt(p.DeadlineUnixNano, 10))
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
		cmd.ExtraFiles = []*os.File{familyGate}
		if err := cmd.Start(); err != nil {
			failedStart = true
			break
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		completions = append(completions, done)
	}
	ready := os.NewFile(4, "fixture-host-ready")
	if ready == nil {
		return refuse("fixture_ready_missing")
	}
	status := byte(1)
	if failedStart {
		status = 0
	}
	written, readyErr := ready.Write([]byte{status})
	readyClose := ready.Close()
	okay := eof(familyGate)
	closeErr := familyGate.Close()
	failedWait := false
	for _, done := range completions {
		if err := <-done; err != nil {
			failedWait = true
		}
	}
	if failedStart || failedWait || !okay || closeErr != nil || readyErr != nil || readyClose != nil || written != 1 {
		if err := cleanupWriter.Close(); err != nil {
			return refuse("fixture_family_cleanup_and_receipt_close_failed")
		}
		return refuse("fixture_family_cleanup_failed")
	}
	// A forced deadline exits without this receipt. Successful role Wait outcomes
	// and owned family/ready closes must precede the single fixed success byte.
	written, receiptErr := cleanupWriter.Write([]byte{1})
	receiptClose := cleanupWriter.Close()
	if receiptErr != nil || receiptClose != nil || written != 1 {
		return refuse("fixture_cleanup_receipt_failed")
	}
	return 0
}
func role() int {
	if len(os.Args) != 4 {
		return refuse("fixture_role_arguments_invalid")
	}
	deadline, err := strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil || !lifetime(deadline) {
		return refuse("fixture_deadline_refused")
	}
	known := false
	for _, id := range roles {
		if os.Args[2] == id {
			known = true
		}
	}
	if !known || filepath.Base(os.Args[0]) != os.Args[2] {
		return refuse("fixture_role_identity_refused")
	}
	gate := os.NewFile(3, "fixture-role-gate")
	if gate == nil {
		return refuse("fixture_gate_missing")
	}
	okay := eof(gate)
	err = gate.Close()
	if !okay || err != nil {
		return refuse("fixture_role_gate_failed")
	}
	return 0
}

func literalPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && strings.IndexFunc(path, func(r rune) bool { return r < 32 || r == 127 }) < 0
}
func validAttempt(value string) bool {
	if len(value) != 40 || !strings.HasPrefix(value, "attempt_") {
		return false
	}
	for _, b := range []byte(value[8:]) {
		if !(b >= '0' && b <= '9') && !(b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
