package plugins

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativePythonPeer struct {
	ctx       context.Context
	binding   ContextBinding
	parent    *ContextBinding
	authority *NativeContextAuthority
	original  []byte
	public    ed25519.PublicKey
	hello     map[string]json.RawMessage
	exchange  func(context.Context, any) map[string]json.RawMessage
}

// One process per offline test; production Go never starts Python. Only the
// broker and local trust pins are fixtures. Provider, enrollment and ledger code
// execute unchanged, including the receiver and signer in capability mode.
func startNativePythonPeer(t *testing.T, capability bool, privateMode ...bool) *nativePythonPeer {
	private := len(privateMode) > 0 && privateMode[0]
	t.Helper()
	python := os.Getenv("AGENTMUX_NATIVE_AUTHORITY_PYTHON")
	if python == "" {
		t.Skip("prepared Python SDK and NATS dependencies required for offline integration")
	}
	manifest := fixtureManifest("native_provider_test")
	manifest.RequestedCapabilities = []Capability{{Action: "inspect", ResourceClass: "task", Required: true}}
	destination := "task-owner"
	if capability {
		manifest.RequestedCapabilities = []Capability{{Action: "read", ResourceClass: "storage", Required: true}}
		destination = "storage-owner"
	}
	if private {
		manifest.InstallationModes = []string{"private-child"}
	}
	pkg := fixturePackage(t, manifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
	configuration, err := PrepareConfiguration(pkg, nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	lifetime := make(chan struct{})
	t.Cleanup(func() { close(lifetime) })
	p := &nativePythonPeer{binding: ContextBinding{Owner: OwnerReference{Pin: pkg.Pin(), InstanceID: "plugin-one", Epoch: strings.Repeat("b", 64), Generation: 1}, Package: pkg, Configuration: configuration, LifetimeDone: lifetime}}
	if private {
		parentManifest := fixtureManifest("native_provider_parent")
		parentManifest.RequestedCapabilities = append([]Capability{}, manifest.RequestedCapabilities...)
		parentPackage := fixturePackage(t, parentManifest, map[string][]byte{"schemas/config.json": []byte(`{"type":"object"}`)})
		parentConfiguration, err := PrepareConfiguration(parentPackage, nil, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		parentLifetime := make(chan struct{})
		t.Cleanup(func() { close(parentLifetime) })
		p.parent = &ContextBinding{Owner: OwnerReference{Pin: parentPackage.Pin(), InstanceID: "parent-one", Epoch: strings.Repeat("c", 64), Generation: 1}, Package: parentPackage, Configuration: parentConfiguration, LifetimeDone: parentLifetime}
		p.binding.Parent = copyParent(&p.parent.Owner)
		p.binding.ParentLifetime = parentLifetime
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	p.ctx = ctx
	command := exec.CommandContext(ctx, python, filepath.Join(root, "platform/plugins/testdata/native_authority_provider.py"))
	command.Dir = root
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(root, "sdk/python")+string(os.PathListSeparator)+root, "PYTHONDONTWRITEBYTECODE=1")
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if command.Start() != nil {
		cancel()
		t.Fatal("Python provider did not start")
	}
	joined := make(chan error, 1)
	go func() { joined <- command.Wait() }()
	t.Cleanup(func() {
		defer cancel()
		_ = input.Close()
		select {
		case err := <-joined:
			if err != nil {
				t.Error("Python provider cleanup failed")
			}
		case <-time.After(2 * time.Second):
			_ = command.Process.Kill()
			<-joined
			t.Error("Python provider required forced cleanup")
		}
	})
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 4*nativeCapabilityRequestLimit)
	p.exchange = func(ctx context.Context, value any) map[string]json.RawMessage {
		t.Helper()
		deadline, _ := ctx.Deadline()
		if pipe, ok := input.(*os.File); ok {
			_ = pipe.SetWriteDeadline(deadline)
		}
		if pipe, ok := output.(*os.File); ok {
			_ = pipe.SetReadDeadline(deadline)
		}
		raw, _ := json.Marshal(value)
		if _, err := input.Write(append(raw, '\n')); err != nil {
			t.Fatal("Python provider input failed")
		}
		if !scanner.Scan() {
			t.Fatal("Python provider did not return a protocol frame")
		}
		var result map[string]json.RawMessage
		if json.Unmarshal(scanner.Bytes(), &result) != nil {
			t.Fatal("Python provider returned invalid frame")
		}
		return result
	}
	setup := map[string]any{"owner": p.binding.Owner, "manifestDigest": pkg.manifest.Checksum(), "configurationChecksum": configuration.Checksum(), "capability": capability}
	if p.parent != nil {
		setup["parent"] = map[string]any{"owner": p.parent.Owner, "manifestDigest": p.parent.Package.manifest.Checksum(), "configurationChecksum": p.parent.Configuration.Checksum()}
	}
	p.hello = p.exchange(ctx, setup)
	var envelope64, key64 string
	_ = json.Unmarshal(p.hello["envelope"], &envelope64)
	_ = json.Unmarshal(p.hello["publicKey"], &key64)
	p.original, err = base64.StdEncoding.Strict().DecodeString(envelope64)
	if err != nil {
		t.Fatal("Python original envelope invalid")
	}
	p.public, err = base64.RawURLEncoding.Strict().DecodeString(key64)
	if err != nil {
		t.Fatal("Python public fixture key invalid")
	}
	seed := bytes.Repeat([]byte{7}, 32)
	keys := &nativeAuthorityTestKeys{request: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), response: p.public}
	transport := nativeAuthorityTestExchange(func(ctx context.Context, _ string, request []byte) ([]byte, error) {
		return nativePythonResponse(p.exchange(ctx, map[string]string{"request": base64.StdEncoding.EncodeToString(request)}))
	})
	destinations := map[string]string{p.binding.Owner.InstanceID: destination}
	if p.parent != nil {
		destinations[p.parent.Owner.InstanceID] = destination
	}
	p.authority, err = NewNativeContextAuthority(NativeAuthorityClientOptions{ProfileID: "profile-one", HubID: "hub-one", AuthorityID: "authority-one", RequestSigningRef: ContextReference{"host-transport", "hub-one", 1}, ResponseSigningRef: ContextReference{"issuer", "hub-one", 1}, RequestSigningSeed: seed, Keys: keys, Exchange: transport}, destinations)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func nativePythonResponse(result map[string]json.RawMessage) ([]byte, error) {
	if _, denied := result["error"]; denied {
		return nil, pluginError("context_authority_unavailable")
	}
	var encoded string
	if json.Unmarshal(result["response"], &encoded) != nil {
		return nil, pluginError("context_authority_wire_invalid")
	}
	return base64.StdEncoding.Strict().DecodeString(encoded)
}
func TestNativeAuthorityPythonProviderIntegration(t *testing.T) {
	p := startNativePythonPeer(t, false)
	admitted, err := p.authority.BindInstance(p.ctx, p.binding)
	if err != nil {
		t.Fatal("real provider instance admission failed")
	}
	operation, err := p.authority.AdmitOperation(p.ctx, p.binding.Owner, p.original)
	if err != nil {
		t.Fatal("real provider operation admission failed")
	}
	if p.authority.Recheck(p.ctx, p.binding.Owner, admitted, &operation) != nil {
		t.Fatal("real provider fresh recheck failed")
	}
	if _, err := p.authority.PrepareDomainCall(p.ctx, p.binding.Owner, operation, ContextDomainCall{RequestID: "request_" + strings.Repeat("d", 64), BindingID: "inspect-binding", ContractID: "task-inspect", Payload: []byte(`{"taskId":"task-one"}`)}); err == nil {
		t.Fatal("unsupported domain contract became success")
	}
	result := p.exchange(p.ctx, map[string]bool{"revoke": true})
	if string(result["revoked"]) != "true" {
		t.Fatal("real enrollment revocation failed")
	}
	if p.authority.Recheck(p.ctx, p.binding.Owner, admitted, &operation) == nil {
		t.Fatal("revoked persisted native instance remained authorized")
	}
}
func TestNativeCapabilityPythonServiceIntegration(t *testing.T) {
	nativeCapabilityPythonServiceIntegration(t, false)
}
func TestNativeCapabilityPythonPrivateServiceIntegration(t *testing.T) {
	nativeCapabilityPythonServiceIntegration(t, true)
}
func nativeCapabilityPythonServiceIntegration(t *testing.T, private bool) {
	p := startNativePythonPeer(t, true, private)
	if p.parent != nil {
		if _, err := p.authority.BindInstance(p.ctx, *p.parent); err != nil {
			t.Fatal("real provider parent admission failed")
		}
	}
	var requestUntil, responseUntil time.Time
	if _, err := p.authority.BindInstance(p.ctx, p.binding); err != nil {
		t.Fatal("real provider instance admission failed")
	}
	operation, err := p.authority.AdmitOperation(p.ctx, p.binding.Owner, p.original)
	if err != nil {
		t.Fatal("real provider capability operation admission failed")
	}
	approved, err := p.authority.PrepareDomainCall(p.ctx, p.binding.Owner, operation, ContextDomainCall{RequestID: "request_" + strings.Repeat("c", 64), BindingID: "storage-read", ContractID: "capability-storage-read", Payload: []byte(`{"resourceRef":{"id":"task-one","ownerHubId":"hub-one","revision":1},"input":{}}`)})
	if err != nil {
		t.Fatal("real provider capability preparation failed")
	}
	service := NativeCapabilityServiceBinding{ProfileID: "profile-one", HubID: "hub-one", ServiceID: "storage-owner", ServiceInstanceID: "ingress-one", ServiceIdentityRef: ContextReference{"service", "hub-one", 1}, SigningKeyRef: ContextReference{"issuer", "hub-one", 1}}
	route := NativeCapabilityRoute{BindingID: "storage-read", RequestContractID: "capability-storage-read", ReplyContractID: "capability-content-reply", Service: service,
		Keys: nativeCapabilityTestKeys(func(_ context.Context, binding NativeCapabilityServiceBinding) (NativeAuthorityKey, error) {
			if binding != service {
				t.Fatal("enrolled service fixture changed")
			}
			return NativeAuthorityKey{PublicKey: p.public, NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}, nil
		}),
		Exchange: nativeCapabilityTestExchange(func(ctx context.Context, reply string, request []byte) ([]byte, error) {
			if private {
				var value string
				_ = json.Unmarshal(fieldsForClaim(fieldsForClaim(request, "claims"), "validUntil"), &value)
				requestUntil, _ = nativeAuthorityTime(value)
			}
			response, err := nativePythonResponse(p.exchange(ctx, map[string]string{"capabilityRequest": base64.StdEncoding.EncodeToString(request), "replySubject": reply}))
			if err == nil && private {
				var value string
				_ = json.Unmarshal(fieldsForClaim(fieldsForClaim(response, "claims"), "validUntil"), &value)
				responseUntil, _ = nativeAuthorityTime(value)
			}
			return response, err
		})}
	gateway, err := NewNativeCapabilityGateway(p.authority, []NativeCapabilityRoute{route})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if gateway.Close(ctx) != nil {
			t.Error("Python capability gateway did not join")
		}
	}()
	reply, err := gateway.Domain(p.ctx, approved.Clone())
	if err != nil {
		t.Fatal("real signed receiver delivery failed")
	}
	var content struct {
		Data []byte `json:"data"`
	}
	var expectedDigest string
	_ = json.Unmarshal(p.hello["recordDigest"], &expectedDigest)
	if json.Unmarshal(reply, &content) != nil || nativeAuthorityDigest(content.Data) != expectedDigest {
		t.Fatal("complete retained owner record changed in delivery")
	}
	if private {
		var text string
		_ = json.Unmarshal(p.hello["parentPolicyExpiresAt"], &text)
		parentUntil, err := nativeAuthorityTime(text)
		if err != nil || requestUntil.IsZero() || responseUntil.IsZero() || requestUntil.After(parentUntil) || responseUntil.After(parentUntil) {
			t.Fatal("private delivery extended the current parent policy deadline")
		}
	}
	command := "revoke"
	if private {
		command = "revokeParent"
	}
	result := p.exchange(p.ctx, map[string]bool{command: true})
	if string(result["revoked"]) != "true" {
		t.Fatal("real enrollment revocation failed")
	}
	if private {
		if !time.Now().Add(100 * time.Millisecond).Before(requestUntil) {
			t.Fatal("parent revocation reached the receiver after delivery expiry")
		}
		rejected := p.exchange(p.ctx, map[string]string{"capabilityRequest": base64.StdEncoding.EncodeToString(approved.delivery.serviceRequest), "replySubject": approved.delivery.replySubject})
		if len(rejected["error"]) == 0 {
			t.Fatal("Python receiver accepted retained content after parent revocation")
		}
	}
	if raw, err := gateway.Domain(p.ctx, approved.Clone()); err == nil || raw != nil {
		t.Fatal("revoked owner disclosed retained content")
	}
}
