//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"golang.org/x/sys/unix"
)

// Recovery admits the complete credential set. Earlier interruptions cannot be
// completed by inventing keys that may have existed in the original process.
// Stages and unknown files remain untouched and require inspection.
func (r *OwnerProfilePreparation) openRecoveryDirectory(ctx context.Context) (*ownerProfilePreparationDirectory, map[string][]byte, error) {
	store, err := r.files.openDirectory(ctx, r.files.store, true)
	if err != nil {
		return nil, nil, err
	}
	if unix.Flock(int(store.file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, nil, centralProfileError("preparation_busy")
	}
	dir, err := r.files.openDirectory(ctx, r.files.directory, true)
	if err != nil {
		return nil, nil, err
	}
	r.files.directoryFile = dir
	names := []string{localServerTrustFile, localServerCertificateFile, localServerKeyFile, "broker.json", "runtime.json", "status-owner.json", "owner-host.json", "owner-client.json", "host-policy.json", "client-selection.json"}
	for _, role := range protocol.Roles() {
		names = append(names, role+".json")
	}
	allowed := map[string]bool{"profile.json": true, centralProfileRegistrationName: true}
	for _, name := range names {
		allowed[name] = true
	}
	fd, err := openOwnerProfileChild(int(dir.file.Fd()), ".")
	if err != nil {
		return nil, nil, centralProfileError("directory_unavailable")
	}
	listing := os.NewFile(uintptr(fd), "owner-profile-recovery-list")
	// Retain the inventory descriptor even when reading or closing fails.
	r.files.stages = append(r.files.stages, listing)
	entries, err := listing.ReadDir(len(allowed) + 1)
	if err != nil && err != io.EOF || len(entries) > len(allowed) {
		return nil, nil, centralProfileError("recovery_ambiguous")
	}
	present := map[string]bool{}
	for _, entry := range entries {
		if !allowed[entry.Name()] || present[entry.Name()] {
			return nil, nil, centralProfileError("recovery_ambiguous")
		}
		present[entry.Name()] = true
	}
	for _, name := range names {
		if !present[name] {
			return nil, nil, centralProfileError("recovery_credentials_incomplete")
		}
	}
	if present[centralProfileRegistrationName] && !present["profile.json"] {
		return nil, nil, centralProfileError("recovery_registration_mismatch")
	}
	retained := map[string][]byte{}
	for name := range present {
		raw, err := r.files.readFile(ctx, dir, name, r.account.uid, 0600, deployment.MaxPrivateConfigBytes)
		if err != nil {
			return nil, nil, err
		}
		retained[name] = raw
	}
	if err := r.recheckInputs(ctx); err != nil {
		return nil, nil, err
	}
	return &ownerProfilePreparationDirectory{dir}, retained, nil
}

// This extracts no authority from broker contents. The shared preparation
// factory rebuilds every artifact from the approved request and these secrets;
// recovery compares all retained bytes before permitting publication.
func ownerProfileRetainedSecrets(profile string, retained map[string][]byte) (*deployment.LocalTLSMaterial, map[string]string, error) {
	fail := func() (*deployment.LocalTLSMaterial, map[string]string, error) {
		return nil, nil, centralProfileError("recovery_credentials_invalid")
	}
	var trust protocol.ServerTrustRecord
	if json.Unmarshal(retained[localServerTrustFile], &trust) != nil {
		return fail()
	}
	material, err := deployment.NewLocalTLSMaterial(profile, []byte(trust.RootsPEM), retained[localServerCertificateFile], retained[localServerKeyFile])
	if err != nil {
		return fail()
	}
	var broker struct {
		Accounts map[string]struct {
			Users []struct {
				Name     string `json:"user"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"accounts"`
	}
	if !uniqueComposeJSON(retained["broker.json"]) || json.Unmarshal(retained["broker.json"], &broker) != nil {
		return fail()
	}
	secrets := map[string]string{}
	for _, account := range broker.Accounts {
		for _, user := range account.Users {
			if _, exists := secrets[user.Name]; exists || !kernelStatusPassword.MatchString(user.Password) {
				return fail()
			}
			secrets[user.Name] = user.Password
		}
	}
	return material, secrets, nil
}
