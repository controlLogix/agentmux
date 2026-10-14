package deployment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

const localTLSLeafLifetime = 90 * 24 * time.Hour
const localTLSCALifetime = 730 * 24 * time.Hour
const maxLocalTLSCertificatePEM = 16 * 1024
const maxLocalTLSKeyPEM = 8 * 1024

// LocalTLSMaterial contains a single profile's enrolled server identity. It
// retains no CA signing key. Its copied private-key getter is for private
// enrollment and contained Compose injection, never logs or review evidence.
type LocalTLSMaterial struct {
	profileID, serverName, leafPin string
	roots, certificate, key        []byte
}

func (LocalTLSMaterial) String() string               { return "[private local TLS material]" }
func (LocalTLSMaterial) GoString() string             { return "[private local TLS material]" }
func (LocalTLSMaterial) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// A Formatter also protects accidental non-string verbs from reflecting the
// private fields. Explicit copied getters remain the only material export.
func (LocalTLSMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[private local TLS material]")
}

func localTLSMaterialError() error { return errors.New("local_tls_material_invalid") }

func LocalTLSServerName(profileID string) (string, error) {
	if !composeProfile.MatchString(profileID) {
		return "", localTLSMaterialError()
	}
	return "profile-" + profileID[len("profile_"):] + ".agentmux.invalid", nil
}

func (m *LocalTLSMaterial) ServerName() string {
	if m == nil {
		return ""
	}
	return m.serverName
}
func (m *LocalTLSMaterial) LeafCertificateSHA256() string {
	if m == nil {
		return ""
	}
	return m.leafPin
}
func (m *LocalTLSMaterial) RootsPEM() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.roots)
}
func (m *LocalTLSMaterial) ServerCertificatePEM() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.certificate)
}
func (m *LocalTLSMaterial) ServerKeyPEM() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.key)
}

func localTLSSinglePEM(raw []byte, kind string, limit int) ([]byte, error) {
	if len(raw) == 0 || len(raw) > limit || !bytes.HasPrefix(raw, []byte("-----BEGIN "+kind+"-----")) ||
		bytes.Count(raw, []byte("-----BEGIN ")) != 1 || bytes.Count(raw, []byte("-----END ")) != 1 {
		return nil, localTLSMaterialError()
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, localTLSMaterialError()
	}
	return block.Bytes, nil
}

// NewLocalTLSMaterial admits the exact generated shape, including current-time
// chain verification. It does not enroll trust from a network peer or renew an
// expired identity. Rotation requires explicit enrollment of a new leaf pin.
func NewLocalTLSMaterial(profileID string, rootsPEM, certificatePEM, keyPEM []byte) (*LocalTLSMaterial, error) {
	name, err := LocalTLSServerName(profileID)
	if err != nil {
		return nil, err
	}
	if len(rootsPEM) == 0 || len(rootsPEM) > maxLocalTLSCertificatePEM || len(certificatePEM) == 0 || len(certificatePEM) > maxLocalTLSCertificatePEM || len(keyPEM) == 0 || len(keyPEM) > maxLocalTLSKeyPEM {
		return nil, localTLSMaterialError()
	}
	roots, cert, key := bytes.Clone(rootsPEM), bytes.Clone(certificatePEM), bytes.Clone(keyPEM)
	rootDER, err := localTLSSinglePEM(roots, "CERTIFICATE", maxLocalTLSCertificatePEM)
	if err != nil {
		return nil, err
	}
	leafDER, err := localTLSSinglePEM(cert, "CERTIFICATE", maxLocalTLSCertificatePEM)
	if err != nil {
		return nil, err
	}
	keyDER, err := localTLSSinglePEM(key, "EC PRIVATE KEY", maxLocalTLSKeyPEM)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, localTLSMaterialError()
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, localTLSMaterialError()
	}
	private, err := x509.ParseECPrivateKey(keyDER)
	if err != nil || private.Curve != elliptic.P256() {
		return nil, localTLSMaterialError()
	}
	rootPublic, rootOK := root.PublicKey.(*ecdsa.PublicKey)
	leafPublic, leafOK := leaf.PublicKey.(*ecdsa.PublicKey)
	if !rootOK || !leafOK || rootPublic.Curve != elliptic.P256() || leafPublic.Curve != elliptic.P256() ||
		!leafPublic.Equal(&private.PublicKey) || !root.IsCA || !root.BasicConstraintsValid ||
		root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || root.CheckSignatureFrom(root) != nil ||
		root.NotAfter.Sub(root.NotBefore) <= 0 || root.NotAfter.Sub(root.NotBefore) > localTLSCALifetime ||
		leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != name || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 ||
		leaf.NotAfter.Sub(leaf.NotBefore) <= 0 || leaf.NotAfter.Sub(leaf.NotBefore) > localTLSLeafLifetime {
		return nil, localTLSMaterialError()
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, localTLSMaterialError()
	}
	sum := sha256.Sum256(leaf.Raw)
	return &LocalTLSMaterial{profileID: profileID, serverName: name, leafPin: "sha256:" + hex.EncodeToString(sum[:]), roots: roots, certificate: cert, key: key}, nil
}

func localTLSSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, localTLSMaterialError()
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

// EnrollLocalTLS issues one server leaf from an offline per-profile CA. It does
// not write files or install/rotate trust. Only the CA certificate survives;
// the signing key is never encoded or returned. Go memory erasure is not an
// assurance against a privileged process-memory observer.
func EnrollLocalTLS(ctx context.Context, profileID string) (*LocalTLSMaterial, error) {
	name, err := LocalTLSServerName(profileID)
	if err != nil || ctx == nil || ctx.Err() != nil {
		return nil, localTLSMaterialError()
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, localTLSMaterialError()
	}
	defer caKey.D.SetInt64(0)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, localTLSMaterialError()
	}
	caSerial, err := localTLSSerial()
	if err != nil {
		return nil, err
	}
	leafSerial, err := localTLSSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "Agentmux offline " + profileID}, NotBefore: now, NotAfter: now.Add(localTLSCALifetime), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, localTLSMaterialError()
	}
	leaf := &x509.Certificate{SerialNumber: leafSerial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now, NotAfter: now.Add(localTLSLeafLifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	caKey.D.SetInt64(0)
	if err != nil || ctx.Err() != nil {
		return nil, localTLSMaterialError()
	}
	privateDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, localTLSMaterialError()
	}
	m, err := NewLocalTLSMaterial(profileID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}))
	if err != nil || ctx.Err() != nil {
		return nil, localTLSMaterialError()
	}
	return m, nil
}
