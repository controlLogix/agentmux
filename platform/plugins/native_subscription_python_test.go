package plugins

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeSubscriptionGoControlPythonAuthorityCompatibility(t *testing.T) {
	python := os.Getenv("AGENTMUX_NATIVE_AUTHORITY_PYTHON")
	if python == "" {
		t.Skip("prepared Python required for offline authority compatibility")
	}
	const script = `import asyncio,base64,json,sys
from datetime import datetime,timedelta
from agentmux_contracts import ContractError,strict_loads
from identity.test_configuration_subscription_control import SubscriptionControlTests
from identity.test_authority import NOW
from identity.configuration_subscription_control import evaluate_control
async def main():
    fixture=SubscriptionControlTests('test_open_and_next_need_current_original_subscription_authority')
    fixture.setUp()
    try:
        await fixture.prepare()
        envelope=base64.b64decode(fixture.inp['subscriptionEnvelopeBytes'])
        subscription=strict_loads(envelope)
        snapshot=await fixture.service.reader.current()
        print(json.dumps({'envelopeBytes':fixture.inp['subscriptionEnvelopeBytes'],'operation':fixture.inp['operation'],'owner':fixture.row['owner'],'now':NOW.isoformat().replace('+00:00','Z')}),flush=True)
        allocation=None
        for _ in range(4):
            raw=sys.stdin.buffer.readline().strip()
            claims=strict_loads(raw)['claims']
            now=datetime.fromisoformat(claims['issuedAt']) if claims['action']=='close' else NOW
            try:
                admitted=evaluate_control(snapshot,raw,now=now,reply_subject=claims['replySubject'],
                    allocation=None if claims['action']=='open' else allocation,
                    expected_cursor=subscription['payload']['cursor'],expected_lease_id='lease_one')
                if claims['action']=='open':allocation=admitted.allocation
                print(json.dumps({'allowed':True,'canRead':admitted.can_read}),flush=True)
            except ContractError:
                print(json.dumps({'allowed':False,'canRead':False}),flush=True)
    finally:
        await fixture.service.close()
        fixture.doCleanups()
asyncio.run(main())
`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-c", script)
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "sdk", "python")+string(os.PathListSeparator)+repo, "PYTHONDONTWRITEBYTECODE=1")
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	reader := bufio.NewReader(io.LimitReader(stdout, 65536))
	defer func() {
		stdin.Close()
		if !joined {
			cmd.Process.Kill()
			io.Copy(io.Discard, reader)
			cmd.Wait()
		}
	}()
	read := func(out any) {
		t.Helper()
		line, err := reader.ReadBytes('\n')
		if err != nil || json.Unmarshal(line, out) != nil {
			t.Fatal("Python authority exchange did not return bounded JSON")
		}
	}
	var hello struct {
		EnvelopeBytes string          `json:"envelopeBytes"`
		Operation     json.RawMessage `json:"operation"`
		Owner         OwnerReference  `json:"owner"`
		Now           string          `json:"now"`
	}
	read(&hello)
	envelope, err := base64.StdEncoding.Strict().DecodeString(hello.EnvelopeBytes)
	if err != nil {
		t.Fatal(err)
	}
	var filter nativeConfigurationSubscription
	if json.Unmarshal(fieldsForClaim(envelope, "payload"), &filter) != nil {
		t.Fatal("Python prepared filter missing")
	}
	now, err := nativeAuthorityTime(hello.Now)
	if err != nil {
		t.Fatal(err)
	}
	client := &nativeAuthorityClient{options: NativeAuthorityClientOptions{ProfileID: "profile-one", HubID: "hub-one", AuthorityID: "authority-one", RequestSigningRef: ContextReference{"host-transport", "hub-one", 1}, ReplyPrefix: "_INBOX.abcdefghijklmnop"}, private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))}
	l := &nativeRemoteSubscription{host: &NativeConfigurationSubscriptions{authority: &NativeContextAuthority{client: client}}, openID: "request_" + strings.Repeat("b", 64), approved: ContextApprovedEnvelope{Envelope: envelope, subscription: &nativeSubscriptionApproval{owner: hello.Owner, filter: filter, operation: ContextOperationAdmission{Operation: hello.Operation}}}}
	send := func(action string, leaseID *string, oldOperation bool, stamp time.Time, wantRead, wantAllowed bool) {
		t.Helper()
		claims, err := l.controlClaims(action, strings.Repeat("c", 64), leaseID, filter.Cursor, stamp, stamp.Add(4*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if oldOperation {
			json.Unmarshal(fieldsForClaim(hello.Operation, "operationId"), &claims.OperationID)
		}
		raw, err := nativeAuthoritySign(contextJSON(claims), client.private)
		if err != nil || nativeAuthoritySchema("configuration-subscription-control", raw) != nil {
			t.Fatal("Go frame construction failed", err)
		}
		if _, err := stdin.Write(append(raw, '\n')); err != nil {
			t.Fatal("Python authority input unavailable")
		}
		var result struct {
			Allowed bool `json:"allowed"`
			CanRead bool `json:"canRead"`
		}
		read(&result)
		if result.Allowed != wantAllowed || result.CanRead != wantRead {
			t.Fatal("actual Go/Python control binding differs", action, oldOperation)
		}
	}
	send("open", nil, false, now, true, true)
	send("open", nil, true, now, false, false)
	leaseID := "lease_one"
	send("next", &leaseID, false, now, true, true)
	send("close", nil, false, now.Add(20*time.Second), false, true)
	stdin.Close()
	io.Copy(io.Discard, reader)
	err = cmd.Wait()
	joined = true
	if err != nil {
		t.Fatal("Python authority process failed after exchange")
	}
}
