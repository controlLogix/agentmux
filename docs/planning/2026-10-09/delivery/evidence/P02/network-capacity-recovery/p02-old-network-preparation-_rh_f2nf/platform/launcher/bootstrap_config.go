//go:build linux || darwin

package launcher

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/controlLogix/agentmux/platform/deployment"
	"github.com/controlLogix/agentmux/platform/kernel/communication"
)

// Check the private broker bytes against the fixed account factory before Docker
// can start. Resource labels cannot substitute for these account permissions.
func bootstrapBrokerCredentials(raw []byte, c BootstrapConfig) (communication.Credentials, error) {
	if len(raw) == 0 || len(raw) > deployment.MaxPrivateConfigBytes || !uniqueComposeJSON(raw) {
		return nil, bootstrapError("broker_policy_invalid")
	}
	var config struct {
		ServerName string `json:"server_name"`
		JetStream  struct {
			StoreDirectory string `json:"store_dir"`
			Domain         string `json:"domain"`
			Memory         int64  `json:"max_memory_store"`
			File           int64  `json:"max_file_store"`
		} `json:"jetstream"`
		Accounts map[string]struct {
			Users []struct {
				Username string `json:"user"`
				Password string `json:"password"`
			} `json:"users"`
		} `json:"accounts"`
	}
	if json.Unmarshal(raw, &config) != nil || config.ServerName != c.Health.ServerName || config.JetStream.Domain != c.Health.Domain || !strings.HasPrefix(config.JetStream.StoreDirectory, "/data/") || c.Health.ServerVersion != "2.15.0" {
		return nil, bootstrapError("broker_policy_invalid")
	}
	credentials := communication.Credentials{}
	seen := map[string]bool{}
	for _, account := range config.Accounts {
		for _, user := range account.Users {
			if user.Username == "" || seen[user.Username] {
				return nil, bootstrapError("broker_policy_invalid")
			}
			seen[user.Username] = true
			if user.Username == deployment.HealthUser {
				if user.Password != c.Health.Password {
					return nil, bootstrapError("health_credential_binding_invalid")
				}
			} else if user.Username == deployment.OwnerBridgeServerUser || user.Username == deployment.OwnerBridgeClientUser {
				if c.OwnerBridge == nil || c.OwnerBridge.Scope != c.Kernel.Scope || user.Username == deployment.OwnerBridgeServerUser && user.Password != c.OwnerBridge.ServerPassword || user.Username == deployment.OwnerBridgeClientUser && user.Password != c.OwnerBridge.ClientPassword {
					return nil, bootstrapError("owner_bridge_credential_binding_invalid")
				}
			} else {
				credentials[user.Username] = user.Password
			}
		}
	}
	if !seen[deployment.HealthUser] || credentials[communication.OrdinaryPlugin] != c.Kernel.Password {
		return nil, bootstrapError("observer_credential_binding_invalid")
	}
	storage := deployment.StorageProfile{HubID: c.Health.HubID, ServerName: c.Health.ServerName, Domain: c.Health.Domain, StoreDirectory: config.JetStream.StoreDirectory, MaxMemoryBytes: config.JetStream.Memory, MaxFileBytes: config.JetStream.File, Listener: communication.Listener{Mode: communication.ContainerInternal, Port: 4222}}
	var expected []byte
	var err error
	if c.OwnerBridge != nil {
		if c.OwnerBridge.Scope != c.Kernel.Scope || !seen[deployment.OwnerBridgeServerUser] || !seen[deployment.OwnerBridgeClientUser] {
			return nil, bootstrapError("owner_bridge_credential_binding_invalid")
		}
		if c.LocalTLS != nil {
			expected, err = deployment.BuildSecureLocalConfigWithOwnerBridge(storage, credentials, c.Health.Password, *c.OwnerBridge, c.LocalTLS)
		} else {
			expected, err = deployment.BuildLocalConfigWithOwnerBridge(storage, credentials, c.Health.Password, *c.OwnerBridge)
		}
	} else {
		if c.LocalTLS != nil {
			expected, err = deployment.BuildSecureLocalConfig(storage, credentials, c.Health.Password, c.LocalTLS)
		} else {
			expected, err = deployment.BuildLocalConfig(storage, credentials, c.Health.Password)
		}
	}
	if err != nil {
		return nil, bootstrapError("broker_policy_invalid")
	}
	decode := func(data []byte) (any, error) {
		var v any
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		err := d.Decode(&v)
		return v, err
	}
	actual, actualErr := decode(raw)
	wanted, wantedErr := decode(expected)
	if actualErr != nil || wantedErr != nil || !reflect.DeepEqual(actual, wanted) {
		return nil, bootstrapError("broker_policy_invalid")
	}
	return credentials, nil
}
