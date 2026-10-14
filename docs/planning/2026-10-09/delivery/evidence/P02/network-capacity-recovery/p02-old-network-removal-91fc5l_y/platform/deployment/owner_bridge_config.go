package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/controlLogix/agentmux/platform/kernel/communication"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

const OwnerBridgeAccount = "HOST"
const OwnerBridgeServerUser = "runtime-host"
const OwnerBridgeClientUser = "runtime-client"

// OwnerBridgeSettings grants only local owner-status transport. It supplies no
// protected commands, account management, storage or business permissions.
// Passwords and generated broker bytes belong in the private host store.
type OwnerBridgeSettings struct {
	Scope                          protocol.Scope
	ServerPassword, ClientPassword string
}

func (OwnerBridgeSettings) String() string   { return "[private owner bridge settings]" }
func (OwnerBridgeSettings) GoString() string { return "[private owner bridge settings]" }

type OwnerBridgeSubjectSet struct{ Request, ReplyPrefix string }

func OwnerBridgeSubjects(scope protocol.Scope) (OwnerBridgeSubjectSet, error) {
	digest := regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	version := regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	if !identifier.MatchString(scope.HubID) || !identifier.MatchString(scope.InstanceID) || !identifier.MatchString(scope.ProfileID) || !digest.MatchString(scope.AssemblyDigest) || !digest.MatchString(scope.ReleaseManifestDigest) || !version.MatchString(scope.ReleaseVersion) {
		return OwnerBridgeSubjectSet{}, errors.New("owner_bridge_scope_invalid")
	}
	base := "amx.v1.h." + scope.HubID + ".host.owner." + scope.InstanceID
	return OwnerBridgeSubjectSet{Request: base + ".request", ReplyPrefix: base + ".reply."}, nil
}

// BuildLocalConfigWithOwnerBridge is an explicit additive factory. The original
// factory stays unchanged; a host cannot admit this account through arbitrary
// broker JSON or ordinary plugin configuration.
func BuildLocalConfigWithOwnerBridge(p StorageProfile, credentials communication.Credentials, healthPassword string, settings OwnerBridgeSettings) ([]byte, error) {
	subjects, err := OwnerBridgeSubjects(settings.Scope)
	if err != nil || settings.Scope.HubID != p.HubID {
		return nil, errors.New("owner_bridge_scope_invalid")
	}
	if !secret.MatchString(settings.ServerPassword) || !secret.MatchString(settings.ClientPassword) || settings.ServerPassword == settings.ClientPassword || settings.ServerPassword == healthPassword || settings.ClientPassword == healthPassword {
		return nil, errors.New("owner_bridge_credentials_invalid")
	}
	for _, password := range credentials {
		if password == settings.ServerPassword || password == settings.ClientPassword {
			return nil, errors.New("owner_bridge_credentials_invalid")
		}
	}
	raw, err := BuildLocalConfig(p, credentials, healthPassword)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&config) != nil {
		return nil, errors.New("owner_bridge_config_invalid")
	}
	user := func(name, password string, publish, subscribe string) any {
		return map[string]any{"user": name, "password": password, "permissions": map[string]any{"publish": map[string]any{"allow": []string{publish}}, "subscribe": map[string]any{"allow": []string{subscribe}}}}
	}
	config["accounts"].(map[string]any)[OwnerBridgeAccount] = map[string]any{"users": []any{
		user(OwnerBridgeServerUser, settings.ServerPassword, subjects.ReplyPrefix+">", subjects.Request),
		user(OwnerBridgeClientUser, settings.ClientPassword, subjects.Request, subjects.ReplyPrefix+">"),
	}}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil {
		return nil, errors.New("owner_bridge_config_encode_failed")
	}
	return output.Bytes(), nil
}
