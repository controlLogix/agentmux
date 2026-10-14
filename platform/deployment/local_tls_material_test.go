package deployment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

const localTLSFixtureProfile = "profile_0123456789abcdef0123456789abcdef"

func TestLocalTLSMaterialEnrollmentCopiesAndRedaction(t *testing.T) {
	m, err := EnrollLocalTLS(context.Background(), localTLSFixtureProfile)
	if err != nil {
		t.Fatal("valid offline enrollment failed")
	}
	if m.ServerName() != "profile-0123456789abcdef0123456789abcdef.agentmux.invalid" {
		t.Fatal("profile DNS mismatch")
	}
	leaf, _ := pem.Decode(m.ServerCertificatePEM())
	if leaf == nil {
		t.Fatal("server certificate missing")
	}
	sum := sha256.Sum256(leaf.Bytes)
	if m.LeafCertificateSHA256() != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("leaf DER pin mismatch")
	}
	roots, certificate, key := m.RootsPEM(), m.ServerCertificatePEM(), m.ServerKeyPEM()
	copy, err := NewLocalTLSMaterial(localTLSFixtureProfile, roots, certificate, key)
	if err != nil {
		t.Fatal("generated material was not re-admitted")
	}
	roots[0], certificate[0], key[0] = 0, 0, 0
	if _, err := NewLocalTLSMaterial(localTLSFixtureProfile, copy.RootsPEM(), copy.ServerCertificatePEM(), copy.ServerKeyPEM()); err != nil {
		t.Fatal("caller mutated retained material")
	}
	encoded, err := json.Marshal(m)
	if err != nil || string(encoded) != "{}" {
		t.Fatal("JSON disclosed private material")
	}
	for _, output := range []string{fmt.Sprintf("%v", m), fmt.Sprintf("%#v", m), fmt.Sprintf("%v", *m), fmt.Sprintf("%#v", *m), fmt.Sprintf("%+v", *m), fmt.Sprintf("%d", *m), fmt.Sprintf("%x", *m)} {
		if output != "[private local TLS material]" {
			t.Fatal("formatting disclosed private material")
		}
	}
	if bytes.Contains(m.ServerKeyPEM(), []byte("CERTIFICATE")) {
		t.Fatal("key getter returned certificate data")
	}
	var absent *LocalTLSMaterial
	if absent.ServerName() != "" || absent.LeafCertificateSHA256() != "" || absent.RootsPEM() != nil || absent.ServerCertificatePEM() != nil || absent.ServerKeyPEM() != nil {
		t.Fatal("nil material invented enrollment")
	}
}

func localTLSFixturePEM(t *testing.T, changeCA, changeLeaf func(*x509.Certificate)) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic CA generation failed")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic server key generation failed")
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now, NotAfter: now.Add(localTLSCALifetime), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	name, _ := LocalTLSServerName(localTLSFixtureProfile)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now, NotAfter: now.Add(localTLSLeafLifetime), DNSNames: []string{name}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if changeCA != nil {
		changeCA(ca)
	}
	if changeLeaf != nil {
		changeLeaf(leaf)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("synthetic CA encoding failed")
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("synthetic leaf encoding failed")
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal("synthetic key encoding failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestLocalTLSMaterialRejectsInvalidIdentityAndCertificatePolicy(t *testing.T) {
	cases := []struct {
		name     string
		ca, leaf func(*x509.Certificate)
	}{
		{"expired-leaf", nil, func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-24 * time.Hour)
		}},
		{"future-leaf", nil, func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = c.NotBefore.Add(time.Hour)
		}},
		{"wrong-dns", nil, func(c *x509.Certificate) { c.DNSNames = []string{"other.agentmux.invalid"} }},
		{"extra-dns", nil, func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.agentmux.invalid") }},
		{"client-only-eku", nil, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"excessive-leaf-lifetime", nil, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(localTLSLeafLifetime + time.Second) }},
		{"leaf-ca", nil, func(c *x509.Certificate) { c.IsCA = true }},
		{"missing-leaf-usage", nil, func(c *x509.Certificate) { c.KeyUsage = 0 }},
		{"expired-ca", func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-24 * time.Hour)
		}, nil},
		{"ca-not-ca", func(c *x509.Certificate) { c.IsCA = false }, nil},
		{"ca-missing-signing-usage", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roots, leaf, key := localTLSFixturePEM(t, tc.ca, tc.leaf)
			if material, err := NewLocalTLSMaterial(localTLSFixtureProfile, roots, leaf, key); err == nil || material != nil {
				t.Fatal("invalid certificate policy was admitted")
			}
		})
	}
	roots, leaf, key := localTLSFixturePEM(t, nil, nil)
	otherRoots, _, otherKey := localTLSFixturePEM(t, nil, nil)
	for _, position := range []int{0, 1, 2} {
		inputs := [3][]byte{roots, leaf, key}
		kind := "CERTIFICATE"
		if position == 2 {
			kind = "EC PRIVATE KEY"
		}
		badPrefix := []byte("-----BEGIN " + kind + "-----\nnot-valid-base64!\n-----END " + kind + "-----\n")
		inputs[position] = append(badPrefix, inputs[position]...)
		if material, err := NewLocalTLSMaterial(localTLSFixtureProfile, inputs[0], inputs[1], inputs[2]); err == nil || material != nil {
			t.Fatal("malformed leading PEM was skipped")
		}
	}
	for _, inputs := range [][3][]byte{{otherRoots, leaf, key}, {roots, leaf, otherKey}, {append(bytes.Clone(roots), roots...), leaf, key}, {roots, append(bytes.Clone(leaf), leaf...), key}, {roots, leaf, append(bytes.Clone(key), key...)}, {[]byte(strings.Repeat("x", maxLocalTLSCertificatePEM+1)), leaf, key}, {roots, leaf, []byte("not a key")}} {
		if material, err := NewLocalTLSMaterial(localTLSFixtureProfile, inputs[0], inputs[1], inputs[2]); err == nil || material != nil {
			t.Fatal("mismatched or malformed enrollment was admitted")
		}
	}
	for _, profile := range []string{"", "profile_short", "profile_" + strings.Repeat("A", 32)} {
		if material, err := EnrollLocalTLS(context.Background(), profile); err == nil || material != nil {
			t.Fatal("invalid profile enrolled")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if material, err := EnrollLocalTLS(ctx, localTLSFixtureProfile); err == nil || material != nil {
			t.Fatal("missing or canceled context enrolled")
		}
	}
}
