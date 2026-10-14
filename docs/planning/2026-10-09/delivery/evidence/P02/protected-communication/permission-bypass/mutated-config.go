// Package communication builds the initial protected broker boundary.
package communication

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
)

const SystemAccount = "SYS"
const ProtectedAccount = "KERNEL"
const ApplicationAccount = "APPLICATION"
const Administrator = "deployment-admin"
const OrdinaryPlugin = "ordinary-plugin"

var roles = [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
var secretToken = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
var token = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)

// Credentials are distinct local secrets supplied by deployment, never inherited by plugins.
// Config bytes contain these secrets and must remain in a private deployment store.
type Credentials map[string]string

// ListenerMode is explicit deployment selection, never inferred from ambient state.
type ListenerMode string

const NativeLoopback ListenerMode = "native-loopback"
const ContainerInternal ListenerMode = "container-internal"

type Listener struct {
	Mode ListenerMode
	Port int
}

type SubjectSet struct {
	Commands map[string]string
	Events   map[string]string
	Snapshot string
	Update   string
}

func Subjects(hubID string) (SubjectSet, error) {
	if !token.MatchString(hubID) {
		return SubjectSet{}, errors.New("broker_hub_id_invalid")
	}
	prefix := "amx.v1.h." + hubID + ".kernel."
	s := SubjectSet{Commands: map[string]string{}, Events: map[string]string{}, Snapshot: prefix + "status.snapshot", Update: prefix + "status.update"}
	for _, role := range roles {
		s.Commands[role] = prefix + "internal." + role + ".command"
		s.Events[role] = prefix + "internal." + role + ".event"
	}
	return s, nil
}

type permission struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny,omitempty"`
}
type userPermissions struct {
	Publish   permission `json:"publish"`
	Subscribe permission `json:"subscribe"`
}
type user struct {
	User        string          `json:"user"`
	Password    string          `json:"password"`
	Permissions userPermissions `json:"permissions"`
}
type streamExport struct {
	Stream   string   `json:"stream"`
	Accounts []string `json:"accounts"`
}
type importedStream struct {
	Account string `json:"account"`
	Subject string `json:"subject"`
}
type streamImport struct {
	Stream importedStream `json:"stream"`
}
type account struct {
	Users   []user         `json:"users"`
	Exports []streamExport `json:"exports,omitempty"`
	Imports []streamImport `json:"imports,omitempty"`
}
type configuration struct {
	Listen        string             `json:"listen"`
	SystemAccount string             `json:"system_account"`
	Accounts      map[string]account `json:"accounts"`
}

// BuildConfig creates Core NATS account isolation for an explicitly enrolled local bootstrap.
// It does not implement JWT enrollment, project authority, business persistence or a general auth service.
func BuildConfig(hubID string, port int, credentials Credentials) ([]byte, error) {
	return BuildConfigWithListener(hubID, Listener{Mode: NativeLoopback, Port: port}, credentials)
}

// BuildConfigWithListener permits container binding only through explicit deployment selection.
// A container deployment must separately enforce the private host port binding.
func BuildConfigWithListener(hubID string, listener Listener, credentials Credentials) ([]byte, error) {
	host := "127.0.0.1"
	switch listener.Mode {
	case NativeLoopback:
	case ContainerInternal:
		host = "0.0.0.0"
	default:
		return nil, errors.New("broker_listener_mode_invalid")
	}
	port := listener.Port
	s, err := Subjects(hubID)
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("broker_port_invalid")
	}
	names := append([]string{Administrator, OrdinaryPlugin}, roles[:]...)
	if len(credentials) != len(names) {
		return nil, errors.New("broker_credentials_membership_invalid")
	}
	seen := map[string]bool{}
	for _, name := range names {
		secret, ok := credentials[name]
		if !ok || !secretToken.MatchString(secret) || seen[secret] {
			return nil, errors.New("broker_credentials_invalid")
		}
		seen[secret] = true
	}
	events := []string{}
	commands := []string{}
	for _, role := range roles {
		events = append(events, s.Events[role])
		commands = append(commands, s.Commands[role])
	}
	denied := []string{"$SYS.>", "$JS.>"}
	protected := account{Users: []user{}}
	for _, role := range roles {
		pub := []string{s.Events[role]}
		if role == "boot" || role == "kernel-lifecycle" {
			pub = append(pub, commands...)
		}
		if role == "exported-status" {
			pub = append(pub, s.Snapshot, s.Update)
		}
		sub := append(append([]string{}, events...), s.Commands[role])
		protected.Users = append(protected.Users, user{role, credentials[role], userPermissions{permission{pub, denied}, permission{sub, denied}}})
	}
	for _, subject := range []string{s.Snapshot, s.Update} {
		protected.Exports = append(protected.Exports, streamExport{subject, []string{ApplicationAccount}})
	}
	application := account{Users: []user{{OrdinaryPlugin, credentials[OrdinaryPlugin], userPermissions{permission{[]string{s.Snapshot, s.Update}, nil}, permission{[]string{s.Snapshot, s.Update}, denied}}}}}
	for _, subject := range []string{s.Snapshot, s.Update} {
		application.Imports = append(application.Imports, streamImport{importedStream{ProtectedAccount, subject}})
	}
	system := account{Users: []user{{Administrator, credentials[Administrator], userPermissions{permission{[]string{"$SYS.>", "_INBOX.>"}, nil}, permission{[]string{"$SYS.>", "_INBOX.>"}, nil}}}}}
	cfg := configuration{Listen: host + ":" + strconv.Itoa(port), SystemAccount: SystemAccount, Accounts: map[string]account{SystemAccount: system, ProtectedAccount: protected, ApplicationAccount: application}}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	// NATS config accepts UTF-8 JSON syntax but not JSON Unicode escape sequences.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(cfg); err != nil {
		return nil, errors.New("broker_config_encode_failed")
	}
	return buf.Bytes(), nil
}
