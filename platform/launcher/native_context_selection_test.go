//go:build linux || darwin

package launcher

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	"github.com/controlLogix/agentmux/platform/plugins"
)

// Reuse the identity owner's existing signed-credential fixtures. This is an
// offline file-admission check; it opens no broker or native child.
func nativeContextSelectionFixture(t *testing.T, r *CentralProfileResolution) ([]byte, protocol.Scope) {
	return nativeContextCapabilitySelectionFixture(t, r, "")
}
func nativeContextCapabilitySelectionFixture(t *testing.T, r *CentralProfileResolution, change string) ([]byte, protocol.Scope) {
	t.Helper()
	python := os.Getenv("AGENTMUX_NATIVE_AUTHORITY_PYTHON")
	if python == "" {
		t.Skip("prepared identity Python is not selected")
	}
	root := filepath.Join(r.directory, "native-material")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	scope := protocol.Scope{HubID: r.selected.HubID, ProfileID: r.record.ProfileID, InstanceID: r.record.InstanceID, AssemblyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseManifestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseVersion: "1.0.0"}
	header, _ := json.Marshal(map[string]any{"root": root, "hostPolicy": filepath.Join(r.directory, "host-policy.json"), "ownerUid": r.uid, "workspaces": r.selected.Workspaces, "kernelScope": scope, "change": change})
	script := `import sys,json,copy,os
from pathlib import Path
from identity.test_native_transport_selection import NativeTransportSelectionTests,credentials
from identity.native_host_selection import NativeHostSelection
from identity.test_authority import ref
from agentmux_contracts import canonical_bytes
f=NativeTransportSelectionTests();f.setUp();f.subscription()
h=json.loads(sys.argv[1]);old=str(f.root);new=h['root']
def convert(v):
 if isinstance(v,dict):return {k:convert(x) for k,x in v.items()}
 if isinstance(v,list):return [convert(x) for x in v]
 if isinstance(v,str):return v.replace(old,new).replace('hub-one',h['kernelScope']['hubId']).replace('profile-one',h['kernelScope']['profileId'])
 return v
v=convert(f.value)
for p in f.root.iterdir():
 if p.is_file():
  target=Path(new)/p.name;target.write_bytes(p.read_bytes());target.chmod(0o600)
f.root=Path(new);f.value=v
v.update({k:h[k] for k in ('hostPolicy','ownerUid','workspaces','kernelScope')})
v['configurationRoutes']['plugin-one']['scope']=copy.deepcopy(v['activationDeclarations']['plugin-one']['facts']['grant']['scope'])
v['capabilityRoutes']=[{'bindingId':'storage','requestContractId':'capability-storage-read','replyContractId':'capability-content-reply','scope':copy.deepcopy(v['configurationRoutes']['plugin-one']['scope']),'service':{'profileId':h['kernelScope']['profileId'],'hubId':h['kernelScope']['hubId'],'serviceId':'storage-owner','serviceInstanceId':'storage-one','serviceIdentityRef':convert(ref('storage-service')),'signingKeyRef':convert(ref('storage-issuer'))}}]
route=v['capabilityRoutes'][0]
change=h['change']
if change=='organization':route['scope']['organizationId']='other-organization'
elif change=='workspace-project':route['scope'].update(projectId=None,workspaceId='workspace-one')
elif change=='duplicate-binding':v['capabilityRoutes'].append(copy.deepcopy(route))
elif change=='contract':route['requestContractId']='task-inspect'
elif change=='service':route['service']['serviceId']='secret-owner'
elif change=='reply':route['replyContractId']='capability-storage-write-reply'
elif change=='profile':route['service']['profileId']='other-profile'
elif change=='hub':route['service']['hubId']='other-hub'
elif change=='identity-hub':route['service']['serviceIdentityRef']['ownerHubId']='other-hub'
elif change=='signer-hub':route['service']['signingKeyRef']['ownerHubId']='other-hub'
prefix='amx.v1.h.'+h['kernelScope']['hubId']+'.plugins.plugin-one.'
for role,index,server in (('lifecycle',10,'controllerCredentials'),('contextTransport',12,'serverCredentials')):
 outgoing,incoming=([prefix+'lifecycle.control'],[prefix+'lifecycle.event']) if role=='lifecycle' else ([prefix+'context.reply',prefix+'operation.invoke',prefix+'operation.cancel'],[prefix+'context.request',prefix+'operation.result'])
 raw,account,user=credentials(index,outgoing,incoming)
 v[role][server]=dict(f.pin(role+'-server.creds',raw),userPublicKey=user)
 raw,_,user=credentials(index+1,incoming,outgoing)
 v[role]['bindings'][0]['credentials']=dict(f.pin(role+'-client.creds',raw),userPublicKey=user)
Path(v['lifecycle']['stateDirectory']).mkdir(mode=0o700)
raw,account,user=credentials(2,list(NativeHostSelection(canonical_bytes(v)).publish_subjects()),[v['credentials']['replyPrefix']+'.>'])
v['credentials'].update(f.pin('authority.creds',raw),accountPublicKey=account,userPublicKey=user)
sys.stdout.buffer.write(canonical_bytes(v))
f.doCleanups()
`
	cmd := exec.Command(python, "-c", script, string(header))
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Dir = repository
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH="+filepath.Join(repository, "sdk/python")+":"+repository)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("existing identity fixture failed: %T", err)
	}
	return raw, scope
}

func TestCentralProfileNativeContextSelectionAdmitsExplicitRoutes(t *testing.T) {
	f := centralFixture(t)
	owner, err := registerCentralProfile(context.Background(), f.request, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	raw, scope := nativeContextSelectionFixture(t, owner)
	options, err := prepareNativeContextSelection(context.Background(), owner, raw, scope, "tls://127.0.0.1:4999")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(options.Authority.RequestSigningSeed)
	if len(options.Subscriptions) != 1 || options.Subscriptions[0].Source.ConfigurationRef.ID != "subscription-configuration" || options.Subscriptions[0].Source.ConfigurationRef.ID == options.Configurations["plugin-one"].Binding.ConfigurationRef.ID || options.Subscriptions[0].Transport.Subject != "amx.v1.h."+scope.HubID+".o.org-one.p._.w._.configuration.subscription-configuration.command" || len(options.Driver.Bindings) != 1 || options.Driver.ProfileContext != nil || options.Driver.LifecycleTrust != nil {
		t.Fatal("protected routes or driver binding changed")
	}
	if len(options.Subscriptions[0].Source.SchemaRef) != 4096 {
		t.Fatal("source schema reference was truncated")
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("selection decode failed")
	}
	changes := map[string]func(map[string]any){
		"omitted-subscription": func(v map[string]any) { delete(v, "subscriptionRoutes") },
		"changed-source": func(v map[string]any) {
			v["subscriptionRoutes"].([]any)[0].(map[string]any)["source"].(map[string]any)["sourceDigest"] = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"changed-scope": func(v map[string]any) {
			v["subscriptionRoutes"].([]any)[0].(map[string]any)["scope"].(map[string]any)["projectId"] = "other"
		},
		"unadmitted-workspace": func(v map[string]any) {
			v["lifecycle"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["workspace"] = "/unadmitted"
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			json.Unmarshal(raw, &v)
			change(v)
			changed, _ := json.Marshal(v)
			if _, err := prepareNativeContextSelection(context.Background(), owner, changed, scope, "tls://127.0.0.1:4999"); err == nil {
				t.Fatal("changed selection admitted")
			}
		})
	}
	pin := value["requestSigner"].(map[string]any)["keyFile"].(map[string]any)["path"].(string)
	content, err := os.ReadFile(pin)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(pin, pin+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(pin, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareNativeContextSelection(context.Background(), owner, raw, scope, "tls://127.0.0.1:4999"); err == nil {
		t.Fatal("replacement original material admitted")
	}
}

func TestNativeHostSelectionEmbeddedSchemaMatchesCanonical(t *testing.T) {
	for _, name := range []string{"native-authority-host-selection", "identity-native-instance"} {
		canonical, err := os.ReadFile(filepath.Join("..", "..", "contracts", "v1", "schemas", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := os.ReadFile(filepath.Join("..", "plugins", "schemas", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != string(embedded) {
			t.Fatal("embedded host schema differs from canonical")
		}
	}
	if plugins.ValidateNativeHostSelection([]byte(`{}`)) == nil {
		t.Fatal("incomplete host selection admitted")
	}
}

func TestCentralProfileNativeContextRejectsInvalidCapabilitySelection(t *testing.T) {
	for _, change := range []string{"organization", "workspace-project", "duplicate-binding", "contract", "service", "reply", "profile", "hub", "identity-hub", "signer-hub"} {
		t.Run(change, func(t *testing.T) {
			f := centralFixture(t)
			owner, err := registerCentralProfile(context.Background(), f.request, f.deps)
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			// The signed host credentials include the changed route's exact subject.
			// Refusal must come from route admission rather than a JWT mismatch.
			raw, scope := nativeContextCapabilitySelectionFixture(t, owner, change)
			var selected nativeHostSelectionDocument
			if json.Unmarshal(raw, &selected) != nil || nativeCapabilitySelectionValid(selected.CapabilityRoutes, selected.Keys) {
				t.Fatal("invalid capability mapping passed selection validation")
			}
			if _, err := prepareNativeContextSelection(context.Background(), owner, raw, scope, "tls://127.0.0.1:4999"); err == nil {
				t.Fatal("invalid capability route admitted")
			}
		})
	}
}
