package installer

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
)

type ClientSelection struct {
	SchemaVersion    string `json:"schemaVersion"`
	PackageDirectory string `json:"packageDirectory"`
	ManifestDigest   string `json:"manifestDigest"`
}

type ClientResult struct {
	SchemaVersion            string `json:"schemaVersion"`
	Kind                     string `json:"kind"`
	Outcome                  string `json:"outcome"`
	InstallationID           string `json:"installationId"`
	FoundationInstallationID string `json:"foundationInstallationId"`
	PythonVersion            string `json:"pythonVersion"`
	Enrollment               string `json:"enrollment"`
	Readiness                string `json:"readiness"`
}

type ClientPackage struct {
	id       string
	manifest protected.ClientManifest
	files    []payload
}

func (p *ClientPackage) Result(outcome string) ClientResult {
	if p == nil {
		return ClientResult{}
	}
	return ClientResult{"1.0.0", "client-installation-result", outcome, p.id, p.manifest.FoundationInstallationID, p.manifest.PythonVersion, "not_checked", "not_observed"}
}

func ReadClientSelection(ctx context.Context, path, expectedDigest string, ownerUID uint32) (ClientSelection, error) {
	var selected ClientSelection
	if ctx == nil || !digestPattern.MatchString(expectedDigest) || !canonical(path) || ownerUID == 0 {
		return selected, refusal("selection_invalid", nil)
	}
	raw, err := readSelection(ctx, path, ownerUID)
	if err != nil {
		return selected, err
	}
	var fields map[string]json.RawMessage
	if hash(raw) != expectedDigest || protocol.DecodeClosedJSON(raw, &selected, metadataLimit) != nil || json.Unmarshal(raw, &fields) != nil || !exactFields(fields, "schemaVersion", "packageDirectory", "manifestDigest") || selected.SchemaVersion != "1.0.0" || !canonical(selected.PackageDirectory) || !digestPattern.MatchString(selected.ManifestDigest) {
		return ClientSelection{}, refusal("selection_invalid", nil)
	}
	return selected, nil
}

func PrepareClient(parent context.Context, selected ClientSelection) (*ClientPackage, error) {
	return prepareClient(parent, selected, nil)
}

func prepareClient(parent context.Context, selected ClientSelection, checkNative func(string, []byte, map[string]protected.ClientFile) error) (*ClientPackage, error) {
	if parent == nil || selected.SchemaVersion != "1.0.0" || !canonical(selected.PackageDirectory) || !digestPattern.MatchString(selected.ManifestDigest) {
		return nil, refusal("selection_invalid", nil)
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	root, err := openSourceDirectory(ctx, selected.PackageDirectory)
	if err != nil {
		return nil, err
	}
	p, failure := snapshotClient(ctx, root, selected.ManifestDigest, checkNative)
	failure = closeOwned(root, failure)
	if failure != nil {
		return nil, failure
	}
	return p, nil
}

func snapshotClient(ctx context.Context, root *os.File, expected string, checkNative func(string, []byte, map[string]protected.ClientFile) error) (*ClientPackage, error) {
	raw, err := readBelow(ctx, root, "client-manifest.json", protected.ClientManifestLimit)
	if err != nil || hash(raw) != expected {
		return nil, refusal("client_manifest_rejected", err)
	}
	m, err := protected.DecodeClientManifest(raw)
	if err != nil {
		return nil, refusal("client_manifest_rejected", err)
	}
	p := &ClientPackage{id: strings.TrimPrefix(expected, "sha256:"), manifest: m}
	roster := make(map[string]protected.ClientFile, len(m.Files))
	nativeFiles := map[string][]byte{}
	for _, file := range m.Files {
		roster[file.Path] = file
	}
	for _, file := range m.Files {
		data, err := readClientBelow(ctx, root, file.Path, file.Size)
		if err != nil || hash(data) != file.Digest {
			return nil, refusal("client_file_rejected", err)
		}
		if checkNative != nil {
			if err := checkNative(file.Path, data, roster); err != nil {
				return nil, refusal("client_native_rejected", err)
			}
		} else if protected.ClientNativeCandidate(file.Path, data) {
			nativeFiles[file.Path] = data
		}
		p.files = append(p.files, payload{file.Path, data, os.FileMode(file.Mode)})
	}
	if checkNative == nil {
		if err := protected.CheckClientNativePayload(nativeFiles, roster); err != nil {
			return nil, refusal("client_native_rejected", err)
		}
	}
	// Publish metadata last. Partial new directories are never usable packages.
	p.files = append(p.files, payload{"client-manifest.json", raw, 0444})
	if err := verifyClientTree(ctx, root, p, nil); err != nil {
		return nil, err
	}
	return p, nil
}

func validClientPackage(p *ClientPackage) bool {
	if p == nil || !protected.ValidClientInstallationID(p.id) || len(p.files) != len(p.manifest.Files)+1 {
		return false
	}
	last := p.files[len(p.files)-1]
	if last.name != "client-manifest.json" || hash(last.data) != "sha256:"+p.id || last.mode != 0444 {
		return false
	}
	if _, err := protected.DecodeClientManifest(last.data); err != nil {
		return false
	}
	for i, file := range p.manifest.Files {
		copy := p.files[i]
		if copy.name != file.Path || copy.mode != os.FileMode(file.Mode) || int64(len(copy.data)) != file.Size || hash(copy.data) != file.Digest {
			return false
		}
	}
	return true
}
