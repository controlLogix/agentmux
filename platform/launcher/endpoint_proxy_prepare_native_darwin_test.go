//go:build darwin && arm64 && cgo && agentmux_bootstrap_docker

package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

// This preparation copies admitted local tool bytes and creates private input
// files only. It runs no Docker command, binds no socket and starts no process.
func TestPrepareInstalledCLIDarwinPrivateEndpointInputs(t *testing.T) {
	endpointProxyRequire(t, os.Getuid() == 501 && os.Geteuid() == 501 && os.Getenv("HOME") == "/Users/ryan" &&
		os.Getenv("DOCKER_CONFIG") == "" && os.Getenv("AMX_BOOTSTRAP_DOCKER_AUTHORIZED") == "1", "endpoint_private_preparation_authorization")
	base, _ := loadBootstrapFixtureSelection(t)
	endpointProxyRequire(t, base.Target == "native-darwin" && base.GOARCH == "arm64" && base.Docker.Executable == missingDockerGenuinePath,
		"endpoint_private_preparation_genuine_selection")
	for _, name := range []string{"permission", "unavailable", "readiness"} {
		t.Run(name, func(t *testing.T) {
			slot, upstream := missingComposePrepare(t, base)
			contextName := "amx-ep-" + bootstrapFixtureRandom(t, 8)
			path := filepath.Join("/private/tmp", contextName)
			endpointProxyRequire(t, os.Mkdir(path, 0700) == nil, "endpoint_private_fresh_root")
			root, err := openPrivateHostRoot(path, 501, []string{base.WorkspaceRoot})
			endpointProxyRequire(t, err == nil, "endpoint_private_root_admission")
			t.Cleanup(func() {
				if root.Close() != nil {
					t.Error("endpoint_private_root_close")
				}
			})
			endpointProxyRequire(t, root.Mkdir("gate", 0700) == nil, "endpoint_private_fresh_gate")
			rootFD, err := root.Open(".")
			endpointProxyRequire(t, err == nil, "endpoint_private_root_descriptor")
			t.Cleanup(func() {
				if rootFD.Close() != nil {
					t.Error("endpoint_private_root_descriptor_close")
				}
			})
			gateFD, err := root.Open("gate")
			endpointProxyRequire(t, err == nil, "endpoint_private_gate_descriptor")
			t.Cleanup(func() {
				if gateFD.Close() != nil {
					t.Error("endpoint_private_gate_descriptor_close")
				}
			})
			stat := func(file *os.File) *syscall.Stat_t {
				info, err := file.Stat()
				endpointProxyRequire(t, err == nil && info.IsDir() && info.Mode().Perm() == 0700 && privatefs.CheckDescriptor(file, privatefs.PrivateObject) == nil,
					"endpoint_private_directory_admission")
				value, ok := info.Sys().(*syscall.Stat_t)
				endpointProxyRequire(t, ok && value.Uid == 501 && value.Flags == 0, "endpoint_private_directory_owner")
				return value
			}
			rootStat, gateStat := stat(rootFD), stat(gateFD)
			entries, err := gateFD.ReadDir(-1)
			endpointProxyRequire(t, err == nil && len(entries) == 0, "endpoint_private_gate_not_empty")
			selected := upstream
			selected.Docker.Context, selected.Docker.Endpoint = contextName, "unix://"+filepath.Join(path, "gate", "docker.sock")
			contextID := sha256.Sum256([]byte(contextName))
			contextPath := filepath.Join("config", "contexts", "meta", hex.EncodeToString(contextID[:]))
			endpointProxyRequire(t, slot.root.Mkdir(contextPath, 0700) == nil, "endpoint_private_context_directory")
			metadata, err := json.Marshal(map[string]any{
				"Name": contextName, "Metadata": map[string]string{"Description": "Disposable endpoint proxy"},
				"Endpoints": map[string]any{"docker": map[string]any{"Host": selected.Docker.Endpoint, "SkipTLSVerify": false}},
			})
			endpointProxyRequire(t, err == nil && missingComposeContext(metadata, selected.Docker), "endpoint_private_context_binding")
			missingComposeWrite(t, slot.root, filepath.Join(contextPath, "meta.json"), metadata, 0600)
			write := func(name string, value any) (string, string) {
				raw, err := json.Marshal(value)
				endpointProxyRequire(t, err == nil, "endpoint_private_input_encoding")
				missingComposeWrite(t, slot.root, name, raw, 0600)
				digest := sha256.Sum256(raw)
				return filepath.Join(filepath.Dir(slot.docker.path), name), hex.EncodeToString(digest[:])
			}
			upstreamPath, upstreamPin := write("endpoint-upstream-selection.json", upstream)
			selectedPath, selectedPin := write("endpoint-selection.json", selected)
			prep := endpointProxyPreparation{SchemaVersion: "1.0.0", Root: path, RootDev: uint64(rootStat.Dev), RootInode: rootStat.Ino,
				GateDev: uint64(gateStat.Dev), GateInode: gateStat.Ino, OwnerUID: 501,
				UpstreamSelectionSHA256: upstreamPin, SelectedSelectionSHA256: selectedPin}
			prepPath, prepPin := write("endpoint-preparation.json", prep)
			slot.check(t, false)
			// This is the existing fixture's input contract, not a new status or
			// acceptance record. The caller reviews pins before a separate run.
			input, err := json.Marshal(map[string]string{
				"case":                         name,
				"AMX_BOOTSTRAP_SELECTION_FILE": selectedPath, "AMX_BOOTSTRAP_SELECTION_SHA256": selectedPin,
				"AMX_DARWIN_ENDPOINT_UPSTREAM_SELECTION_FILE": upstreamPath, "AMX_DARWIN_ENDPOINT_UPSTREAM_SELECTION_SHA256": upstreamPin,
				"AMX_DARWIN_ENDPOINT_PREPARATION": prepPath, "AMX_DARWIN_ENDPOINT_PREPARATION_SHA256": "sha256:" + prepPin,
			})
			endpointProxyRequire(t, err == nil, "endpoint_private_input_presentation")
			t.Log(string(input))
		})
	}
}
