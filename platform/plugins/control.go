package plugins

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// LifecycleControl is the ordinary process protocol, not a kernel command or a
// business-operation grant. Trusted deployment supplies its transport identity.
type LifecycleControl struct {
	SchemaVersion         string          `json:"schemaVersion"`
	Kind                  string          `json:"kind"`
	Action                string          `json:"action"`
	CommandID             string          `json:"commandId"`
	Owner                 OwnerReference  `json:"owner"`
	ConfigurationChecksum string          `json:"configurationChecksum"`
	ContributionsChecksum string          `json:"contributionsChecksum"`
	Deadline              string          `json:"deadline"`
	ParentOwner           *OwnerReference `json:"parentOwner,omitempty"`
	ContextChecksum       string          `json:"contextChecksum,omitempty"`
}

type LifecycleReport struct {
	SchemaVersion         string          `json:"schemaVersion"`
	Kind                  string          `json:"kind"`
	CommandID             string          `json:"commandId"`
	Owner                 OwnerReference  `json:"owner"`
	ConfigurationChecksum string          `json:"configurationChecksum"`
	ContributionsChecksum string          `json:"contributionsChecksum"`
	Status                string          `json:"status"`
	ObservedAt            string          `json:"observedAt"`
	ParentOwner           *OwnerReference `json:"parentOwner,omitempty"`
	ContextChecksum       string          `json:"contextChecksum,omitempty"`
}

// NativeBootstrap is a private startup file. It exposes only this process's
// credentials and configuration; it is never a status response or log record.
type NativeBootstrap struct {
	ServerName            string                  `json:"serverName,omitempty"`
	LeafCertificateSHA256 string                  `json:"leafCertificateSha256,omitempty"`
	SchemaVersion         string                  `json:"schemaVersion"`
	ServerURL             string                  `json:"serverURL"`
	CAFile                string                  `json:"caFile,omitempty"`
	CredentialsFile       string                  `json:"credentialsFile"`
	ConfigurationFile     string                  `json:"configurationFile"`
	ControlSubject        string                  `json:"controlSubject"`
	EventSubject          string                  `json:"eventSubject"`
	Prepare               LifecycleControl        `json:"prepare"`
	Context               *NativeContextBootstrap `json:"context,omitempty"`
}

// Context files belong to the original native owner and are removed only after
// its context workers and process have joined. They are not public diagnostics.
type NativeContextBootstrap struct {
	ContextFile     string           `json:"contextFile"`
	CredentialsFile string           `json:"credentialsFile"`
	CAFile          string           `json:"caFile"`
	Transport       ContextTransport `json:"transport"`
}

func lifecycleSubjects(hub, instance string) (string, string, error) {
	if !registryIdentifier.MatchString(hub) || !registryIdentifier.MatchString(instance) {
		return "", "", pluginError("lifecycle_identity_invalid")
	}
	prefix := "amx.v1.h." + hub + ".plugins." + instance + ".lifecycle."
	return prefix + "control", prefix + "event", nil
}

func randomControlID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", pluginError("lifecycle_random_unavailable")
	}
	return hex.EncodeToString(raw[:]), nil
}

func decodeLifecycleReport(raw []byte, expected LifecycleControl) (LifecycleReport, error) {
	if len(raw) > 8192 || strictDocument(raw) != nil {
		return LifecycleReport{}, pluginError("lifecycle_report_invalid")
	}
	names := []string{"schemaVersion", "kind", "commandId", "owner", "configurationChecksum", "contributionsChecksum", "status", "observedAt"}
	switch expected.SchemaVersion {
	case "1.0.0":
		if expected.ParentOwner != nil || expected.ContextChecksum != "" {
			return LifecycleReport{}, pluginError("lifecycle_report_invalid")
		}
	case "1.1.0":
		if expected.ParentOwner == nil || expected.ContextChecksum != "" {
			return LifecycleReport{}, pluginError("lifecycle_report_invalid")
		}
	case "1.2.0":
		if !configurationDigest.MatchString(expected.ContextChecksum) {
			return LifecycleReport{}, pluginError("lifecycle_report_invalid")
		}
		names = append(names, "contextChecksum")
	default:
		return LifecycleReport{}, pluginError("lifecycle_report_invalid")
	}
	if expected.ParentOwner != nil {
		names = append(names, "parentOwner")
	}
	fields, ok := exactControlObject(raw, names...)
	if !ok || !exactControlOwner(fields["owner"]) || (expected.ParentOwner != nil && !exactControlOwner(fields["parentOwner"])) {
		return LifecycleReport{}, pluginError("lifecycle_report_invalid")
	}
	var report LifecycleReport
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return LifecycleReport{}, pluginError("lifecycle_report_invalid")
	}
	normalized, err := json.Marshal(normalizeManifestNumbers(value))
	if err != nil || json.Unmarshal(normalized, &report) != nil || report.SchemaVersion != expected.SchemaVersion || report.Kind != "ordinary-plugin-report" ||
		report.CommandID != expected.CommandID || report.Owner != expected.Owner ||
		!sameParentOwner(report.ParentOwner, expected.ParentOwner) ||
		report.ContextChecksum != expected.ContextChecksum ||
		report.ConfigurationChecksum != expected.ConfigurationChecksum || report.ContributionsChecksum != expected.ContributionsChecksum {
		return LifecycleReport{}, pluginError("lifecycle_report_invalid")
	}
	observed, err := time.Parse(time.RFC3339Nano, report.ObservedAt)
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, expected.Deadline)
	if err != nil || deadlineErr != nil || observed.After(deadline) || observed.After(time.Now().Add(time.Second)) || time.Since(observed) > 3*time.Minute {
		return LifecycleReport{}, pluginError("lifecycle_report_stale")
	}
	switch report.Status {
	case "registered", "ready", "failed", "stopped":
	default:
		return LifecycleReport{}, pluginError("lifecycle_report_invalid")
	}
	return report, nil
}

// A private instance acknowledges the exact parent lifetime. Independent v1.0
// frames retain their original closed shape and omit this field entirely.
func sameParentOwner(a, b *OwnerReference) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Go's JSON decoder accepts case aliases. Public messages use exact contract
// field names, including the nested owner and all five package-pin fields.
func exactControlObject(raw []byte, names ...string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return nil, false
	}
	for _, name := range names {
		value, found := fields[name]
		if !found || string(value) == "null" {
			return nil, false
		}
	}
	return fields, true
}
func exactControlOwner(raw []byte) bool {
	fields, ok := exactControlObject(raw, "pin", "instanceId", "epoch", "generation")
	if !ok {
		return false
	}
	_, ok = exactControlObject(fields["pin"], "packageId", "version", "manifestChecksum", "packageChecksum", "provenanceChecksum")
	return ok
}
