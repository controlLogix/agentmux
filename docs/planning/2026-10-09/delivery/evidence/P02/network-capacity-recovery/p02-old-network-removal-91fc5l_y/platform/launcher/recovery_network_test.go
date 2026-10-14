package launcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var recoverySafeCode = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func recoveryCode(e error) string {
	if e == nil {
		return ""
	}
	s := e.Error()
	if recoverySafeCode.MatchString(s) {
		return s
	}
	return "closed_diagnostic_failure"
}
func TestRecoveryNetworkPreparation(t *testing.T) {
	var approved map[string]map[string]any
	if json.Unmarshal([]byte(`{"p02-bootstrap-private-445772231":{"broker":{"ContainerID":"389c32a884dd6999a8a098ad1a8babe1387d0fe07a34963ae4a44caea25e508a","State":"stopped"},"certificateDigest":"sha256:adc748ca4028ec22e69b7fd2c38a4dc6e1bd2d760633940ef9c1e239829d21cb","composeDigest":"sha256:6a85f9055a6f69d84d69b4342457aff4ee27ee0aa7adff8e09026dbd40b67b70","configDigest":"sha256:51c37ef2a66745143af3eaff35fb73ba89e8b3ecaefed4839ee9e67ffa119cfa","container":{"Created":"2026-10-14T08:34:43.528313699Z","Id":"389c32a884dd6999a8a098ad1a8babe1387d0fe07a34963ae4a44caea25e508a","Name":"/amx-p02-bootstrap-202ca056edb1502a-nats-1","Networks":{"amx-p02-bootstrap-202ca056edb1502a_default":{"Aliases":["amx-p02-bootstrap-202ca056edb1502a-nats-1","nats"],"DNSNames":["amx-p02-bootstrap-202ca056edb1502a-nats-1","nats","389c32a884dd"],"DriverOpts":null,"EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"GwPriority":0,"IPAMConfig":null,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","Links":null,"MacAddress":"","NetworkID":"7321bac5c2e346e5cb0eb98a76aab58b0f7a43261a4fe22bd9c423284e4b7ae4"}},"State":{"FinishedAt":"2026-10-14T08:35:17.933398203Z","Paused":false,"Restarting":false,"Running":false,"Status":"exited"}},"containerId":"389c32a884dd6999a8a098ad1a8babe1387d0fe07a34963ae4a44caea25e508a","directory":"p02-bootstrap-private-445772231","engine":{"Backend":"windows-interop","Endpoint":"npipe:////./pipe/dockerDesktopLinuxEngine","EngineID":"e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c","Versions":{"Client":"29.8.0","Server":"29.8.0","Compose":"5.5.1"}},"errorCode":"","finishedAt":"2026-10-14T09:19:24.716605019Z","instanceId":"instance_8f2ed383829cbe6049f23987c1644dad","keyDigest":"sha256:07d1226742b0a626e4fb6763968e5f30abf3729ea21a48bdeafc34a13619fdc0","leaseCloseErrors":null,"leaseCountHeldDuringChecks":6,"leasesReleased":6,"mutationExecuted":false,"authorization":"Root exact two-network fixture recovery","network":{"Attachable":false,"ConfigOnly":false,"Containers":{},"Created":"2026-10-14T08:34:43.471378311Z","Driver":"bridge","IPAM":{"Config":[{"Gateway":"192.168.176.1","Subnet":"192.168.176.0/20"}],"Driver":"default","Options":null},"Id":"7321bac5c2e346e5cb0eb98a76aab58b0f7a43261a4fe22bd9c423284e4b7ae4","Ingress":false,"Internal":false,"Labels":{"agentmux.instance.id":"instance_8f2ed383829cbe6049f23987c1644dad","agentmux.profile.id":"profile_4dd998b1c902cb61d5048af5b3d5a12f","agentmux.release.digest":"sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248","com.docker.compose.config-hash":"0e34383e74ea9a5c2c0778482226b6eb505536ae1b0550043656f1c894844933","com.docker.compose.network":"default","com.docker.compose.project":"amx-p02-bootstrap-202ca056edb1502a","com.docker.compose.version":"5.5.1"},"Name":"amx-p02-bootstrap-202ca056edb1502a_default","Options":{"com.docker.network.enable_ipv4":"true","com.docker.network.enable_ipv6":"false"},"Scope":"local"},"networkId":"7321bac5c2e346e5cb0eb98a76aab58b0f7a43261a4fe22bd9c423284e4b7ae4","profileId":"profile_4dd998b1c902cb61d5048af5b3d5a12f","project":"amx-p02-bootstrap-202ca056edb1502a","releaseDigest":"sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248","stage":"all_admission_and_read_checks_completed","startedAt":"2026-10-14T09:19:20.411190471Z","volume":{"CreatedAt":"2026-10-14T08:34:43Z","Driver":"local","Labels":{"agentmux.instance.id":"instance_8f2ed383829cbe6049f23987c1644dad","agentmux.profile.id":"profile_4dd998b1c902cb61d5048af5b3d5a12f","agentmux.release.digest":"sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248","com.docker.compose.config-hash":"febef4d3512739075366579a0e09fb98eafb13b9a3284167e7dca4dcb5103219","com.docker.compose.project":"amx-p02-bootstrap-202ca056edb1502a","com.docker.compose.version":"5.5.1","com.docker.compose.volume":"data"},"Name":"amx-p02-bootstrap-202ca056edb1502a_data","Options":null}},"p02-bootstrap-private-2557942521":{"broker":{"ContainerID":"d4a83e1a6f24320889051f64c323a5d40d6fdcecb415f236d1964eedcf336695","State":"stopped"},"certificateDigest":"sha256:86c3cc483e288405580e52dd17d03b362344a924a6fadb46e09edc69b0ff7703","composeDigest":"sha256:524cf6d307ebd9134a1cea7585f6e5fbc193a0c609811d8bf8ca252c397865e5","configDigest":"sha256:b0b61d3d4c6e6778a68ef211182c751b8406710b19428dcebb5a5561d6d07ee1","container":{"Created":"2026-10-14T08:35:40.981949605Z","Id":"d4a83e1a6f24320889051f64c323a5d40d6fdcecb415f236d1964eedcf336695","Name":"/amx-p02-bootstrap-29d849b00cc31852-nats-1","Networks":{"amx-p02-bootstrap-29d849b00cc31852_default":{"Aliases":["amx-p02-bootstrap-29d849b00cc31852-nats-1","nats"],"DNSNames":["amx-p02-bootstrap-29d849b00cc31852-nats-1","nats","d4a83e1a6f24"],"DriverOpts":null,"EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"GwPriority":0,"IPAMConfig":null,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","Links":null,"MacAddress":"","NetworkID":"119efa115928b9ccca3ade12d02d829f192f4e0bd3fc2318da2a4288d448ab36"}},"State":{"FinishedAt":"2026-10-14T08:36:04.039344996Z","Paused":false,"Restarting":false,"Running":false,"Status":"exited"}},"containerId":"d4a83e1a6f24320889051f64c323a5d40d6fdcecb415f236d1964eedcf336695","directory":"p02-bootstrap-private-2557942521","engine":{"Backend":"windows-interop","Endpoint":"npipe:////./pipe/dockerDesktopLinuxEngine","EngineID":"e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c","Versions":{"Client":"29.8.0","Server":"29.8.0","Compose":"5.5.1"}},"errorCode":"","finishedAt":"2026-10-14T09:19:28.687594181Z","instanceId":"instance_52488a303d6c831edea712692844a18d","keyDigest":"sha256:e3445ea07769c61bf5fb922c05e54c5fc12c20173c26138ff84f51c9c932bc6a","leaseCloseErrors":null,"leaseCountHeldDuringChecks":6,"leasesReleased":6,"mutationExecuted":false,"authorization":"Root exact two-network fixture recovery","network":{"Attachable":false,"ConfigOnly":false,"Containers":{},"Created":"2026-10-14T08:35:40.9017013Z","Driver":"bridge","IPAM":{"Config":[{"Gateway":"192.168.192.1","Subnet":"192.168.192.0/20"}],"Driver":"default","Options":null},"Id":"119efa115928b9ccca3ade12d02d829f192f4e0bd3fc2318da2a4288d448ab36","Ingress":false,"Internal":false,"Labels":{"agentmux.instance.id":"instance_52488a303d6c831edea712692844a18d","agentmux.profile.id":"profile_d9c85f327feb02b2330a02dce4fef2d7","agentmux.release.digest":"sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248","com.docker.compose.config-hash":"0c2b83a303b6426d1a90f042f801145ff17634e4bc5ec400dda5b42f2bc63814","com.docker.compose.network":"default","com.docker.compose.project":"amx-p02-bootstrap-29d849b00cc31852","com.docker.compose.version":"5.5.1"},"Name":"amx-p02-bootstrap-29d849b00cc31852_default","Options":{"com.docker.network.enable_ipv4":"true","com.docker.network.enable_ipv6":"false"},"Scope":"local"},"networkId":"119efa115928b9ccca3ade12d02d829f192f4e0bd3fc2318da2a4288d448ab36","profileId":"profile_d9c85f327feb02b2330a02dce4fef2d7","project":"amx-p02-bootstrap-29d849b00cc31852","releaseDigest":"sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248","stage":"all_admission_and_read_checks_completed","startedAt":"2026-10-14T09:19:24.716897119Z","volume":{"CreatedAt":"2026-10-14T08:35:40Z","Driver":"local","Labels":{"agentmux.instance.id":"instance_52488a303d6c831edea712692844a18d","agentmux.profile.id":"profile_d9c85f327feb02b2330a02dce4fef2d7","agentmux.release.digest":"sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248","com.docker.compose.config-hash":"4f7638930397b81eca1df48bd18122f28b22d932392e4562c36c08f75da15e85","com.docker.compose.project":"amx-p02-bootstrap-29d849b00cc31852","com.docker.compose.version":"5.5.1","com.docker.compose.volume":"data"},"Name":"amx-p02-bootstrap-29d849b00cc31852_data","Options":null}}}`), &approved) != nil {
		t.Fatal("approved observations invalid")
	}
	out := os.Getenv("RECOVERY_OUTPUT")
	if out == "" {
		t.Fatal("diagnostic output missing")
	}
	candidates := []struct{ directory, network, container string }{{"p02-bootstrap-private-445772231", "7321bac5c2e346e5cb0eb98a76aab58b0f7a43261a4fe22bd9c423284e4b7ae4", "389c32a884dd6999a8a098ad1a8babe1387d0fe07a34963ae4a44caea25e508a"}, {"p02-bootstrap-private-2557942521", "119efa115928b9ccca3ade12d02d829f192f4e0bd3fc2318da2a4288d448ab36", "d4a83e1a6f24320889051f64c323a5d40d6fdcecb415f236d1964eedcf336695"}}
	for _, x := range candidates {
		func() {
			r := map[string]any{"directory": x.directory, "networkId": x.network, "containerId": x.container, "mutationExecuted": false, "authorization": "Root exact two-network fixture recovery", "startedAt": time.Now().UTC()}
			var locks []*BootstrapLock
			defer func() {
				var failures []string
				for _, l := range locks {
					if e := l.Close(); e != nil {
						failures = append(failures, recoveryCode(e))
					}
				}
				r["leasesReleased"] = len(locks)
				r["leaseCloseErrors"] = failures
				r["finishedAt"] = time.Now().UTC()
				raw, _ := json.MarshalIndent(r, "", "  ")
				if os.WriteFile(filepath.Join(out, x.directory+".json"), append(raw, '\n'), 0600) != nil {
					t.Error("report write failed")
				}
				fmt.Println(x.directory, r["stage"], r["errorCode"])
			}()
			guard := func(s string, e error) bool { r["stage"] = s; r["errorCode"] = recoveryCode(e); return e == nil }
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			root := filepath.Join("/home/ryan/.cache/agentmux-governance", x.directory)
			h, e := LoadEnrolledHostPolicy(HostPolicySelection{Path: filepath.Join(root, "installed", "host-policy.json"), OwnerUID: uint32(os.Geteuid()), WorkspaceRoots: []string{"/mnt/c/Users/RyanHelms/GitHub/agentmux"}})
			if !guard("host_policy_admission", e) {
				return
			}
			c, owner, e := h.Load()
			if !guard("private_admission", e) {
				return
			}
			if owner == nil {
				guard("owner_admission", fmt.Errorf("owner_missing"))
				return
			}
			p, e := LoadProfile(c.ProfilePolicy)
			if !guard("profile_admission", e) {
				return
			}
			decl := p.Declaration()
			sel, local := p.LocalDocker()
			if !local {
				guard("local_selection", fmt.Errorf("local_missing"))
				return
			}
			r["profileId"] = decl.ProfileID
			r["instanceId"] = decl.InstanceID
			r["project"] = decl.ComposeProject
			r["releaseDigest"] = decl.ReleaseFingerprint
			r["composeDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256(c.Compose))
			r["configDigest"] = fmt.Sprintf("sha256:%x", c.BrokerConfigDigest)
			r["certificateDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256(c.LocalTLS.ServerCertificatePEM()))
			r["keyDigest"] = fmt.Sprintf("sha256:%x", sha256.Sum256(c.LocalTLS.ServerKeyPEM()))
			ids := []string{sel.EngineID}
			for _, role := range protocol.Roles() {
				ids = append(ids, sel.EngineID+":runtime:"+role)
			}
			ids = append(ids, "owner-status-service")
			for _, id := range ids {
				l, e := AcquireBootstrapLock(ctx, decl.ProfileDirectory, decl.InstanceID, id)
				if !guard("actual_lease_acquisition", e) {
					return
				}
				locks = append(locks, l)
			}
			r["leaseCountHeldDuringChecks"] = len(locks)
			d, e := NewDocker(DockerConfig{Executable: sel.Executable, Context: sel.Context, Endpoint: sel.Endpoint, EngineID: sel.EngineID, Versions: DockerVersions{sel.ClientVersion, sel.ServerVersion, sel.ComposeVersion}, Timeout: 10 * time.Second, Backend: sel.Backend})
			if !guard("selected_driver", e) {
				return
			}
			engine, e := d.Inspect(ctx)
			if !guard("selected_engine", e) {
				return
			}
			r["engine"] = engine
			var network any
			e = d.read(ctx, &network, "network", "inspect", x.network, "--format", `{"Id":{{json .Id}},"Name":{{json .Name}},"Created":{{json .Created}},"Driver":{{json .Driver}},"Scope":{{json .Scope}},"Internal":{{json .Internal}},"Attachable":{{json .Attachable}},"Ingress":{{json .Ingress}},"ConfigOnly":{{json .ConfigOnly}},"Containers":{{json .Containers}},"Labels":{{json .Labels}},"Options":{{json .Options}},"IPAM":{{json .IPAM}}}`)
			if !guard("exact_network_read", e) {
				return
			}
			r["network"] = network
			var container any
			e = d.read(ctx, &container, "container", "inspect", x.container, "--format", `{"Id":{{json .Id}},"Created":{{json .Created}},"Name":{{json .Name}},"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}},"FinishedAt":{{json .State.FinishedAt}}},"Networks":{{json .NetworkSettings.Networks}}}`)
			if !guard("exact_container_relation_read", e) {
				return
			}
			r["container"] = container
			var volume any
			e = d.read(ctx, &volume, "volume", "inspect", decl.ComposeProject+"_data", "--format", `{"Name":{{json .Name}},"CreatedAt":{{json .CreatedAt}},"Driver":{{json .Driver}},"Labels":{{json .Labels}},"Options":{{json .Options}}}`)
			if !guard("exact_volume_read", e) {
				return
			}
			r["volume"] = volume
			u, e := url.Parse(decl.NATSEndpoint)
			if !guard("selected_endpoint", e) {
				return
			}
			port, e := strconv.Atoi(u.Port())
			if !guard("selected_port", e) {
				return
			}
			broker, e := d.InspectOwnedTLSBroker(ctx, OwnershipPreflight{Project: decl.ComposeProject, InstanceID: decl.InstanceID, ProfileID: decl.ProfileID, ReleaseDigest: decl.ReleaseFingerprint, ConfigDigest: sha256.Sum256(c.Compose)}, c.BrokerImage, port, c.BrokerConfigDigest, sha256.Sum256(c.LocalTLS.ServerCertificatePEM()), sha256.Sum256(c.LocalTLS.ServerKeyPEM()))
			if !guard("full_owned_tls_broker", e) {
				return
			}
			r["broker"] = broker
			if broker.ContainerID != x.container || broker.State != "stopped" {
				guard("exact_stopped_guard", fmt.Errorf("exact_stopped_mismatch"))
				return
			}
			r["brokerImage"] = c.BrokerImage
			r["hostPort"] = port
			expected := map[string]map[string]string{
				"p02-bootstrap-private-445772231":  {"profileId": "profile_4dd998b1c902cb61d5048af5b3d5a12f", "instanceId": "instance_8f2ed383829cbe6049f23987c1644dad", "project": "amx-p02-bootstrap-202ca056edb1502a", "composeDigest": "sha256:6a85f9055a6f69d84d69b4342457aff4ee27ee0aa7adff8e09026dbd40b67b70", "configDigest": "sha256:51c37ef2a66745143af3eaff35fb73ba89e8b3ecaefed4839ee9e67ffa119cfa", "certificateDigest": "sha256:adc748ca4028ec22e69b7fd2c38a4dc6e1bd2d760633940ef9c1e239829d21cb", "keyDigest": "sha256:07d1226742b0a626e4fb6763968e5f30abf3729ea21a48bdeafc34a13619fdc0"},
				"p02-bootstrap-private-2557942521": {"profileId": "profile_d9c85f327feb02b2330a02dce4fef2d7", "instanceId": "instance_52488a303d6c831edea712692844a18d", "project": "amx-p02-bootstrap-29d849b00cc31852", "composeDigest": "sha256:524cf6d307ebd9134a1cea7585f6e5fbc193a0c609811d8bf8ca252c397865e5", "configDigest": "sha256:b0b61d3d4c6e6778a68ef211182c751b8406710b19428dcebb5a5561d6d07ee1", "certificateDigest": "sha256:86c3cc483e288405580e52dd17d03b362344a924a6fadb46e09edc69b0ff7703", "keyDigest": "sha256:e3445ea07769c61bf5fb922c05e54c5fc12c20173c26138ff84f51c9c932bc6a"},
			}
			for key, value := range expected[x.directory] {
				if r[key] != value {
					guard("approved_binding_guard", fmt.Errorf("approved_binding_changed"))
					return
				}
			}
			if c.BrokerImage != "docker.io/library/nats@sha256:fdae708d900cb150ce13f203359719bdd9cefd3dbbbc32a4c6224b23ea3e0b2c" || decl.ReleaseFingerprint != "sha256:831ca8755a801de341668c3ad5704ecd60e69faec0993bf72c5cd8421b926248" || (x.directory == "p02-bootstrap-private-445772231" && port != 29913) || (x.directory == "p02-bootstrap-private-2557942521" && port != 29987) {
				guard("approved_release_image_port_guard", fmt.Errorf("approved_binding_changed"))
				return
			}
			beforeNetworks, e := recoveryRoster(ctx, d, "network")
			if !guard("pre_all_network_roster", e) {
				return
			}
			beforeContainers, e := recoveryRoster(ctx, d, "container")
			if !guard("pre_all_container_roster", e) {
				return
			}
			r["beforeNetworks"] = beforeNetworks
			r["beforeContainers"] = beforeContainers
			if !reflect.DeepEqual(network, approved[x.directory]["network"]) || !reflect.DeepEqual(container, approved[x.directory]["container"]) || !reflect.DeepEqual(volume, approved[x.directory]["volume"]) {
				guard("approved_actual_object_guard", fmt.Errorf("approved_object_changed"))
				return
			}
			n, ok := network.(map[string]any)
			if !ok || !recoveryEmptyNetwork(n, x.network, decl.ComposeProject) {
				guard("empty_owned_network_guard", fmt.Errorf("network_changed_or_nonempty"))
				return
			}
			cr, ok := container.(map[string]any)
			if !ok || !recoveryStoppedRelation(cr, x.container, x.network, decl.ComposeProject) {
				guard("stopped_relation_guard", fmt.Errorf("stopped_relation_changed"))
				return
			}
			start, end := "2026-10-14T08:34:26.897798Z", "2026-10-14T08:35:24.340798649Z"
			if x.directory == "p02-bootstrap-private-2557942521" {
				start, end = "2026-10-14T08:35:24.340829Z", "2026-10-14T08:36:11.771957642Z"
			}
			nt, e1 := time.Parse(time.RFC3339Nano, n["Created"].(string))
			ct, e2 := time.Parse(time.RFC3339Nano, cr["Created"].(string))
			st, _ := time.Parse(time.RFC3339Nano, start)
			et, _ := time.Parse(time.RFC3339Nano, end)
			if e1 != nil || e2 != nil || !nt.After(st) || !ct.After(nt) || !ct.Before(et) {
				guard("original_creation_window_guard", fmt.Errorf("creation_relation_changed"))
				return
			}
			// No network disconnect, force, container stop or storage operation occurs.
			r["rmArgv"] = []string{sel.Executable, "--context", sel.Context, "network", "rm", x.network}
			r["sixLeasesHeldAtMutation"] = len(locks)
			removed, e := d.run(ctx, nil, "network", "rm", x.network)
			r["mutationExecuted"] = true
			r["rmReturnedTargetId"] = strings.TrimSpace(string(removed)) == x.network
			if !guard("exact_network_rm", e) {
				return
			}
			if strings.TrimSpace(string(removed)) != x.network {
				guard("exact_rm_reply_guard", fmt.Errorf("network_removal_outcome_unknown"))
				return
			}
			afterNetworks, e := recoveryRoster(ctx, d, "network")
			if !guard("post_all_network_roster", e) {
				return
			}
			afterContainers, e := recoveryRoster(ctx, d, "container")
			if !guard("post_all_container_roster", e) {
				return
			}
			r["afterNetworks"] = afterNetworks
			r["afterContainers"] = afterContainers
			_, exists := afterNetworks[x.network]
			if exists || len(afterNetworks) != len(beforeNetworks)-1 {
				guard("exact_network_absence_guard", fmt.Errorf("network_roster_changed"))
				return
			}
			expectedNetworks := map[string]any{}
			for id, value := range beforeNetworks {
				if id != x.network {
					expectedNetworks[id] = value
				}
			}
			if !reflect.DeepEqual(expectedNetworks, afterNetworks) || !reflect.DeepEqual(beforeContainers, afterContainers) {
				guard("unrelated_projection_guard", fmt.Errorf("unrelated_roster_changed"))
				return
			}
			var postContainer any
			e = d.read(ctx, &postContainer, "container", "inspect", x.container, "--format", `{"Id":{{json .Id}},"Created":{{json .Created}},"Name":{{json .Name}},"State":{"Status":{{json .State.Status}},"Running":{{json .State.Running}},"Paused":{{json .State.Paused}},"Restarting":{{json .State.Restarting}},"FinishedAt":{{json .State.FinishedAt}}},"Networks":{{json .NetworkSettings.Networks}}}`)
			if !guard("post_exact_container", e) {
				return
			}
			r["postContainer"] = postContainer
			var postVolume any
			e = d.read(ctx, &postVolume, "volume", "inspect", decl.ComposeProject+"_data", "--format", `{"Name":{{json .Name}},"CreatedAt":{{json .CreatedAt}},"Driver":{{json .Driver}},"Labels":{{json .Labels}},"Options":{{json .Options}}}`)
			if !guard("post_exact_volume", e) {
				return
			}
			r["postVolume"] = postVolume
			if !reflect.DeepEqual(container, postContainer) || !reflect.DeepEqual(volume, postVolume) {
				guard("retained_container_volume_guard", fmt.Errorf("retained_fixture_changed"))
				return
			}
			postBroker, e := d.InspectOwnedTLSBroker(ctx, oForRecovery(decl, c), c.BrokerImage, port, c.BrokerConfigDigest, sha256.Sum256(c.LocalTLS.ServerCertificatePEM()), sha256.Sum256(c.LocalTLS.ServerKeyPEM()))
			if !guard("post_full_owned_tls_broker", e) {
				return
			}
			r["postBroker"] = postBroker
			if postBroker != broker {
				guard("retained_broker_guard", fmt.Errorf("retained_broker_changed"))
				return
			}
			r["retainedDanglingNetworkReference"] = true
			r["recordRetentionScope"] = "No broker start/data writes or volume/container deletion; old record evidence and exact retained volume preserved, no fresh record checksum claimed."
			guard("exact_removal_and_all_preservation_checks_completed", nil)

		}()
	}
}

func oForRecovery(p Profile, c BootstrapConfig) OwnershipPreflight {
	return OwnershipPreflight{Project: p.ComposeProject, InstanceID: p.InstanceID, ProfileID: p.ProfileID, ReleaseDigest: p.ReleaseFingerprint, ConfigDigest: sha256.Sum256(c.Compose)}
}
func recoveryEmptyNetwork(n map[string]any, id, project string) bool {
	members, ok := n["Containers"].(map[string]any)
	return ok && len(members) == 0 && n["Id"] == id && n["Name"] == project+"_default" && n["Driver"] == "bridge" && n["Scope"] == "local" && n["Internal"] == false && n["Ingress"] == false && n["ConfigOnly"] == false
}
func recoveryStoppedRelation(c map[string]any, id, network, project string) bool {
	state, ok := c["State"].(map[string]any)
	if !ok || c["Id"] != id || state["Status"] != "exited" || state["Running"] != false || state["Paused"] != false || state["Restarting"] != false {
		return false
	}
	ns, ok := c["Networks"].(map[string]any)
	if !ok || len(ns) != 1 {
		return false
	}
	n, ok := ns[project+"_default"].(map[string]any)
	return ok && n["NetworkID"] == network && n["EndpointID"] == "" && n["IPAddress"] == ""
}
func recoveryRoster(ctx context.Context, d *Docker, kind string) (map[string]any, error) {
	args := []string{"network", "ls", "--quiet", "--no-trunc"}
	if kind == "container" {
		args = []string{"ps", "--all", "--quiet", "--no-trunc"}
	}
	ids, e := d.run(ctx, nil, args...)
	if e != nil {
		return nil, e
	}
	fields := bytes.Fields(ids)
	roster := map[string]any{}
	if len(fields) == 0 {
		return roster, nil
	}
	inspect := []string{kind, "inspect"}
	for _, id := range fields {
		if !fullID.Match(id) {
			return nil, fmt.Errorf("roster_id_invalid")
		}
		inspect = append(inspect, string(id))
		roster[string(id)] = nil
	}
	format := `{"Id":{{json .Id}},"Name":{{json .Name}},"Driver":{{json .Driver}},"Created":{{json .Created}},"Containers":{{json .Containers}},"IPAM":{{json .IPAM}}}`
	if kind == "container" {
		format = `{"Id":{{json .Id}},"State":{{json .State.Status}},"DeclaredPorts":{{json .HostConfig.PortBindings}},"ActivePorts":{{json .NetworkSettings.Ports}}}`
	}
	inspect = append(inspect, "--format", format)
	raw, e := d.run(ctx, nil, inspect...)
	if e != nil {
		return nil, e
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	count := 0
	for {
		var item map[string]any
		if e = dec.Decode(&item); e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("roster_invalid")
		}
		id, ok := item["Id"].(string)
		if !ok {
			return nil, fmt.Errorf("roster_invalid")
		}
		prior, present := roster[id]
		if !present || prior != nil {
			return nil, fmt.Errorf("roster_mismatch")
		}
		roster[id] = item
		count++
	}
	if count != len(fields) {
		return nil, fmt.Errorf("roster_incomplete")
	}
	return roster, nil
}
