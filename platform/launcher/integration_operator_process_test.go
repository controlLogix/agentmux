//go:build darwin && arm64

package launcher

import (
	"bytes"
	"strings"
	"testing"
)

func TestIntegrationOperatorReceiptIsClosedAndNonSecret(t *testing.T) {
	receipt := []byte(`{"schemaVersion":"1.0.0","kind":"integration-effect-provisioned","effectId":"effect_one","stream":"AMX_INTEGRATION_ONE","routeGeneration":2,"routeStreams":["AMX_INTEGRATION_ONE"],"routerCredentialDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`)
	if err := validateIntegrationOperatorReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{
		bytes.Replace(receipt, []byte(`"routeGeneration":2`), []byte(`"routeGeneration":0`), 1),
		bytes.Replace(receipt, []byte(`"stream":"AMX_INTEGRATION_ONE"`), []byte(`"stream":"*"`), 1),
		bytes.Replace(receipt, []byte(`}`), []byte(`,"secret":"private"}`), 1),
	} {
		if validateIntegrationOperatorReceipt(changed) == nil {
			t.Fatal("invalid operator output was accepted")
		}
	}
}

func TestIntegrationOperatorOutputIsBounded(t *testing.T) {
	writer := &boundedOperatorOutput{}
	raw := []byte(strings.Repeat("x", integrationOperatorOutputLimit+4096))
	count, err := writer.Write(raw)
	if err != nil || count != len(raw) || writer.buffer.Len() != integrationOperatorOutputLimit || !writer.overflow {
		t.Fatal("operator output bound was not retained")
	}
}
