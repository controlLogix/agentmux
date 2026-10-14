package protocol

import (
	"errors"
	"github.com/controlLogix/agentmux/platform/localtls"
)

// ServerTrustRecord binds public server trust to the full enrolled role scope.
// The private artifact is separate from role credentials and wire observations.
type ServerTrustRecord struct {
	SchemaVersion         string `json:"schemaVersion"`
	Endpoint              string `json:"endpoint"`
	ServerName            string `json:"serverName"`
	RootsPEM              string `json:"rootsPem"`
	LeafCertificateSHA256 string `json:"leafCertificateSha256"`
	Scope                 Scope  `json:"scope"`
}

func ValidateServerTrustRecord(record ServerTrustRecord, expectedScope Scope, expectedEndpoint string) (*localtls.ClientTrust, error) {
	if record.SchemaVersion != Version || !expectedScope.valid() || record.Scope != expectedScope || record.Endpoint != expectedEndpoint {
		return nil, errors.New("kernel_server_trust_binding_invalid")
	}
	trust, err := localtls.NewClientTrust(localtls.Policy{Endpoint: record.Endpoint, ServerName: record.ServerName,
		RootsPEM: []byte(record.RootsPEM), LeafCertificateSHA256: record.LeafCertificateSHA256})
	if err != nil {
		return nil, errors.New("kernel_server_trust_policy_invalid")
	}
	return trust, nil
}

func LoadServerTrustFile(path string, expectedScope Scope, expectedEndpoint string) (*localtls.ClientTrust, error) {
	raw, err := readServerTrustFile(path)
	if err != nil {
		return nil, errors.New("kernel_server_trust_file_invalid")
	}
	var record ServerTrustRecord
	if DecodeClosedJSON(raw, &record, MaxPayload) != nil {
		return nil, errors.New("kernel_server_trust_record_invalid")
	}
	return ValidateServerTrustRecord(record, expectedScope, expectedEndpoint)
}
