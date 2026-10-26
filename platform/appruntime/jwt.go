//go:build darwin

// Package appruntime owns one installation's local application NATS runtime:
// its operator and account identities, TLS material, JetStream storage and the
// native nats-server process. It never shares private seeds with another
// installation and never reuses the protected infrastructure broker.
package appruntime

import (
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

var errJWT = errors.New("application_runtime_jwt_invalid")

// Claims are the closed NATS v2 claim fields this package issues.
type claims struct {
	JTI      string         `json:"jti"`
	IssuedAt int64          `json:"iat"`
	Expires  int64          `json:"exp,omitempty"`
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	Name     string         `json:"name"`
	NATS     map[string]any `json:"nats"`
}

func encodeSegment(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", errJWT
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// issueJWT signs subject claims with the issuer key. The ID binds the claims
// without the ID itself, matching the NATS JWT v2 convention.
func issueJWT(issuer nkeys.KeyPair, subject, name string, nats map[string]any, now time.Time, expires time.Time) (string, error) {
	issuerKey, err := issuer.PublicKey()
	if err != nil || subject == "" || name == "" || nats == nil {
		return "", errJWT
	}
	c := claims{IssuedAt: now.Unix(), Issuer: issuerKey, Subject: subject, Name: name, NATS: nats}
	if !expires.IsZero() {
		c.Expires = expires.Unix()
	}
	unsigned, err := json.Marshal(c)
	if err != nil {
		return "", errJWT
	}
	sum := sha512.Sum512_256(unsigned)
	c.JTI = strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:]), "=")
	header, err := encodeSegment(map[string]string{"typ": "JWT", "alg": "ed25519-nkey"})
	if err != nil {
		return "", err
	}
	body, err := encodeSegment(c)
	if err != nil {
		return "", err
	}
	signature, err := issuer.Sign([]byte(header + "." + body))
	if err != nil {
		return "", errJWT
	}
	return header + "." + body + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// verifyJWT checks the signature against the expected issuer and returns the
// decoded claims. It is used to re-admit retained JWTs, never to grant trust.
func verifyJWT(token, issuer, subject string) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16384 {
		return claims{}, errJWT
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims{}, errJWT
	}
	verifier, err := nkeys.FromPublicKey(issuer)
	if err != nil || verifier.Verify([]byte(parts[0]+"."+parts[1]), signature) != nil {
		return claims{}, errJWT
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, errJWT
	}
	var c claims
	if json.Unmarshal(raw, &c) != nil || c.Issuer != issuer || c.Subject != subject {
		return claims{}, errJWT
	}
	return c, nil
}

func operatorClaims(systemAccount string) map[string]any {
	return map[string]any{"type": "operator", "version": 2, "system_account": systemAccount}
}

func accountClaims(jetstream bool, diskBytes int64) map[string]any {
	limits := map[string]any{"subs": -1, "data": -1, "payload": -1, "imports": -1, "exports": -1,
		"wildcards": true, "conn": -1, "leaf": -1}
	if jetstream {
		limits["mem_storage"] = 0
		limits["disk_storage"] = diskBytes
		limits["streams"] = -1
		limits["consumer"] = -1
	}
	return map[string]any{"type": "account", "version": 2, "limits": limits,
		"default_permissions": map[string]any{"pub": map[string]any{}, "sub": map[string]any{}}}
}

func userClaims(publish, subscribe []string) map[string]any {
	return map[string]any{"type": "user", "version": 2, "subs": -1, "data": -1, "payload": -1,
		"pub": map[string]any{"allow": publish}, "sub": map[string]any{"allow": subscribe}}
}

// userCredentials encodes the standard .creds layout for one user.
func userCredentials(token string, seed []byte) []byte {
	return []byte("-----BEGIN NATS USER JWT-----\n" + token + "\n------END NATS USER JWT------\n\n" +
		"-----BEGIN USER NKEY SEED-----\n" + string(seed) + "\n------END USER NKEY SEED------\n")
}
