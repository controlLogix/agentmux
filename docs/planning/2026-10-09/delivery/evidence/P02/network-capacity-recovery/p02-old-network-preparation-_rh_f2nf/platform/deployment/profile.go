// Package deployment configures infrastructure outside the protected assembly.
package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
)

const HealthAccount = "HEALTH"
const HealthUser = "infrastructure-health"

type StorageProfile struct {
	HubID          string
	ServerName     string
	Domain         string
	StoreDirectory string
	MaxMemoryBytes int64
	MaxFileBytes   int64
	Listener       communication.Listener
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var secret = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

// BuildLocalConfig preserves the protected account boundary and adds an isolated
// infrastructure health account. Returned bytes contain secrets; never log them.
// This does not provision business accounts, migrate stores or claim R3 storage.
func BuildLocalConfig(p StorageProfile, credentials communication.Credentials, healthPassword string) ([]byte, error) {
	if !identifier.MatchString(p.HubID) || !identifier.MatchString(p.ServerName) || !identifier.MatchString(p.Domain) {
		return nil, errors.New("storage_identity_invalid")
	}
	if !filepath.IsAbs(p.StoreDirectory) || filepath.Clean(p.StoreDirectory) != p.StoreDirectory || strings.IndexFunc(p.StoreDirectory, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || p.StoreDirectory == string(filepath.Separator) || p.MaxMemoryBytes < 1024*1024 || p.MaxFileBytes < 1024*1024 {
		return nil, errors.New("storage_limits_or_path_invalid")
	}
	if !secret.MatchString(healthPassword) {
		return nil, errors.New("health_credential_invalid")
	}
	for _, password := range credentials {
		if password == healthPassword {
			return nil, errors.New("health_credential_not_distinct")
		}
	}
	raw, err := communication.BuildConfigWithListener(p.HubID, p.Listener, credentials)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		return nil, errors.New("storage_config_invalid")
	}
	config["server_name"] = p.ServerName
	config["jetstream"] = map[string]any{"store_dir": p.StoreDirectory, "domain": p.Domain, "max_memory_store": p.MaxMemoryBytes, "max_file_store": p.MaxFileBytes, "sync_interval": "always"}
	stream := HealthStream(p.HubID)
	api := "$JS." + p.Domain + ".API.STREAM."
	// NATS maps domain-qualified API subjects to its local API before checking
	// permissions. Permit both exact spellings only inside the health account.
	allow := []string{HealthSubject(p.HubID), "$JS." + p.Domain + ".API.INFO", "$JS.API.INFO"}
	for _, operation := range []string{"CREATE.", "INFO.", "MSG.GET."} {
		allow = append(allow, api+operation+stream, "$JS.API.STREAM."+operation+stream)
	}
	config["accounts"].(map[string]any)[HealthAccount] = map[string]any{
		"jetstream": "enabled",
		"users": []any{map[string]any{"user": HealthUser, "password": healthPassword,
			"permissions": map[string]any{
				"publish":   map[string]any{"allow": allow},
				"subscribe": map[string]any{"allow": []string{"_INBOX.>"}},
			}}},
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil {
		return nil, errors.New("storage_config_encode_failed")
	}
	return output.Bytes(), nil
}

// These names refer only to disposable infrastructure probes, never task records.
func HealthStream(hubID string) string  { return "AMX_HEALTH_" + hubID }
func HealthSubject(hubID string) string { return "amx.v1.h." + hubID + ".health.probe" }
