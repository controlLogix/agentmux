package plugins

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/controlLogix/agentmux/platform/internal/natscredential"
)

type lifecycleCredential struct {
	raw    []byte
	jwt    string
	seed   string
	public string
}

func (lifecycleCredential) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private ordinary lifecycle credential]")
}
func (lifecycleCredential) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-lifecycle-credential"}`), nil
}

func readOwnerPrivate(path string, limit int64) ([]byte, error) {
	return ReadOwnerPrivateFile(path, limit)
}

// Read private bytes before applying the shared enrolled credential policy.
func readLifecycleCredential(path, account string, publish, subscribe []string) (lifecycleCredential, error) {
	return readLifecycleCredentialPolicy(path, account, publish, subscribe, false)
}
func readLifecycleCredentialPolicy(path, account string, publish, subscribe []string, privateInbox bool) (lifecycleCredential, error) {
	raw, err := readOwnerPrivate(path, natscredential.MaxBytes)
	if err != nil {
		return lifecycleCredential{}, err
	}
	admitted, err := natscredential.Validate(raw, natscredential.Policy{AccountPublicKey: account, PublishSubjects: publish, SubscribeSubjects: subscribe, PrivateInbox: privateInbox})
	if err != nil {
		return lifecycleCredential{}, pluginError("lifecycle_credential_invalid")
	}
	return lifecycleCredential{bytes.Clone(raw), admitted.JWT(), string(admitted.Seed()), admitted.PublicKey()}, nil
}

func validateLifecycleURL(raw string) (bool, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return false, pluginError("lifecycle_endpoint_invalid")
	}
	port, portErr := strconv.ParseUint(u.Port(), 10, 16)
	if portErr != nil || port == 0 || strconv.FormatUint(port, 10) != u.Port() {
		return false, pluginError("lifecycle_endpoint_invalid")
	}
	if u.Scheme == "tls" {
		return true, nil
	}

	return false, pluginError("lifecycle_endpoint_invalid")
}

func lifecycleSubject(value string) bool {
	if value == "" || strings.ContainsAny(value, "*> \t\r\n\x00") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if token == "" {
			return false
		}
	}
	return true
}

// Extraction alone does not validate the account or subject permissions.
func parseLifecycleDecorated(raw []byte) (string, []byte, error) {
	jwt, seed, err := natscredential.ParseDecorated(raw)
	if err != nil {
		return "", nil, pluginError("lifecycle_credential_invalid")
	}
	return jwt, seed, nil
}
