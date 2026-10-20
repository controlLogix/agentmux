package plugins

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nats.go"
)

func TestNativeChildTLSUsesExactDisclosedPins(t *testing.T) {
	policy := compositionTestTrust(t).Policy()
	ca := filepath.Join(privateTestDirectory(t), "child-ca.pem")
	if os.WriteFile(ca, policy.RootsPEM, 0600) != nil {
		t.Fatal("child CA fixture unavailable")
	}
	for _, test := range []struct {
		name, endpoint, serverName, leaf string
		pinned, allowed                  bool
	}{
		{"pinned", policy.Endpoint, policy.ServerName, policy.LeafCertificateSHA256, true, true},
		{"legacy", policy.Endpoint, "", "", false, true},
		{"missing-name", policy.Endpoint, "", policy.LeafCertificateSHA256, false, false},
		{"missing-leaf", policy.Endpoint, policy.ServerName, "", false, false},
		{"plaintext", "nats://127.0.0.1:4222", policy.ServerName, policy.LeafCertificateSHA256, false, false},
		{"remote", "tls://remote.example:4222", policy.ServerName, policy.LeafCertificateSHA256, false, false},
		{"IP-name", policy.Endpoint, "127.0.0.1", policy.LeafCertificateSHA256, false, false},
		{"invalid-leaf", policy.Endpoint, policy.ServerName, "sha256:invalid", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			options, dialer, err := nativeChildTLSOptions(test.endpoint, ca, test.serverName, test.leaf)
			if (err == nil) != test.allowed {
				t.Fatal("child TLS enrollment policy changed", err)
			}
			if !test.allowed {
				if dialer != nil || options != nil {
					t.Fatal("refused child TLS policy retained an owner")
				}
				return
			}
			if dialer != nil {
				defer func() {
					if dialer.Close() != nil {
						t.Fatal("original child dialer did not join")
					}
				}()
			}
			actual := nats.GetDefaultOptions()
			for _, option := range options {
				if option(&actual) != nil {
					t.Fatal("child TLS option refused")
				}
			}
			if actual.TLSHandshakeFirst != test.pinned || (actual.CustomDialer != nil) != test.pinned || test.pinned && actual.CustomDialer != dialer {
				t.Fatal("explicit child pins did not select original TLS-first dialer")
			}
			if test.pinned {
				if _, err := dialer.Dial("tcp", "127.0.0.1:4333"); err == nil {
					t.Fatal("child dialer accepted an unselected endpoint")
				}
			}
		})
	}
	if os.Chmod(ca, 0644) != nil {
		t.Fatal("child CA mode fixture unavailable")
	}
	if options, dialer, err := nativeChildTLSOptions(policy.Endpoint, ca, policy.ServerName, policy.LeafCertificateSHA256); err == nil || options != nil || dialer != nil {
		t.Fatal("public child CA accepted")
	}
}
