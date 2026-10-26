//go:build darwin

package appruntime

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"

	"github.com/controlLogix/agentmux/platform/privatefs"
)

const (
	SchemaVersion   = "1.0.0"
	NATSVersion     = "v2.15.0"
	maxPrivateBytes = 1 << 20
	diskStoreBytes  = 1 << 30
	tlsLifetime     = 397 * 24 * time.Hour
)

// Fixed artifact order. Every file is create-only and later files derive only
// from earlier ones, so an interrupted initialization resumes after the last
// complete file and never regenerates a retained identity.
var artifacts = []string{
	"inputs.json",
	"operator.nk", "system-account.nk", "account.nk",
	"tls.json", "tls-server-key.pem", "tls-server-cert.pem",
	"operator.jwt", "system-account.jwt", "account.jwt",
	"readiness.creds", "server.conf", "runtime.json",
}

// Entries the lifecycle owner may add after initialization.
var lifecycleEntries = map[string]bool{".lock": true, "jetstream": true, "runtime-process.json": true, "nats-server.log": true}

var (
	ErrBusy       = errors.New("application_runtime_busy")
	ErrAmbiguous  = errors.New("application_runtime_recovery_ambiguous")
	ErrConflict   = errors.New("application_runtime_material_conflict")
	ErrInputs     = errors.New("application_runtime_inputs_invalid")
	ErrUnsafePath = errors.New("application_runtime_path_unsafe")
	ErrServer     = errors.New("application_runtime_server_unadmitted")
)

// Inputs are fixed at first initialization and retained in inputs.json.
type Inputs struct {
	SchemaVersion string `json:"schemaVersion"`
	NATSServer    string `json:"natsServer"`
	NATSSHA256    string `json:"natsServerSha256"`
	Port          int    `json:"port"`
}

// Manifest is the public runtime description consumed by the provisioning
// ceremony. It contains no private seed or key material.
type Manifest struct {
	SchemaVersion          string `json:"schemaVersion"`
	RuntimeID              string `json:"runtimeId"`
	Endpoint               string `json:"endpoint"`
	ServerName             string `json:"serverName"`
	Domain                 string `json:"domain"`
	RootsPEM               string `json:"rootsPEM"`
	LeafCertificateSHA256  string `json:"leafCertificateSHA256"`
	OperatorPublicKey      string `json:"operatorPublicKey"`
	SystemAccountPublicKey string `json:"systemAccountPublicKey"`
	AccountPublicKey       string `json:"accountPublicKey"`
	AccountSeedFile        string `json:"accountSeedFile"`
	ReadinessCredentials   string `json:"readinessCredentialsFile"`
	StoreDirectory         string `json:"storeDirectory"`
	NATSServer             string `json:"natsServer"`
	NATSServerSHA256       string `json:"natsServerSha256"`
	NATSVersion            string `json:"natsVersion"`
}

type tlsBundle struct {
	RootsPEM string `json:"rootsPEM"`
	CertPEM  string `json:"certPEM"`
	KeyPEM   string `json:"keyPEM"`
}

// DefaultDirectory is the single per-user application runtime location.
func DefaultDirectory() (string, error) {
	current, err := user.Current()
	if err != nil || !filepath.IsAbs(current.HomeDir) {
		return "", ErrUnsafePath
	}
	return filepath.Join(current.HomeDir, "Library", "Application Support", "Agentmux", "application-runtime"), nil
}

// Runtime holds the locked runtime directory for one operation.
type Runtime struct {
	path string
	dir  *os.File
	lock *os.File
}

func (r *Runtime) Close() error {
	var failure error
	if r.lock != nil {
		if err := unix.Flock(int(r.lock.Fd()), unix.LOCK_UN); err != nil {
			failure = err
		}
		if err := r.lock.Close(); err != nil && failure == nil {
			failure = err
		}
	}
	if r.dir != nil {
		if err := r.dir.Close(); err != nil && failure == nil {
			failure = err
		}
	}
	return failure
}

func (r *Runtime) Path(name string) string { return filepath.Join(r.path, name) }

// Open creates (when allowed) and locks the private runtime directory.
func Open(path string, create bool) (*Runtime, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafePath
	}
	if create {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, ErrUnsafePath
		}
		if err := unix.Mkdir(path, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, ErrUnsafePath
		}
	}
	if resolved, err := filepath.EvalSymlinks(path); err != nil || resolved != path {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	dir := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || int(st.Uid) != os.Geteuid() || st.Mode&0o777 != 0o700 || privatefs.CheckDescriptor(dir, privatefs.PrivateObject) != nil {
		dir.Close()
		return nil, ErrUnsafePath
	}
	lockFD, err := unix.Openat(fd, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		dir.Close()
		return nil, ErrUnsafePath
	}
	lock := os.NewFile(uintptr(lockFD), ".lock")
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		dir.Close()
		return nil, ErrBusy
	}
	return &Runtime{path: path, dir: dir, lock: lock}, nil
}

func (r *Runtime) read(name string) ([]byte, bool, error) {
	fd, err := unix.Openat(int(r.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, ErrUnsafePath
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() ||
		st.Mode&0o777 != 0o600 || st.Nlink != 1 || st.Size > maxPrivateBytes {
		return nil, false, ErrUnsafePath
	}
	raw := make([]byte, st.Size+1)
	n, err := file.Read(raw)
	if err != nil && n == 0 && st.Size > 0 {
		return nil, false, ErrUnsafePath
	}
	if int64(n) != st.Size {
		return nil, false, ErrUnsafePath
	}
	return raw[:n], true, nil
}

// publish writes a private file through a stage and links it without ever
// replacing an existing name.
func (r *Runtime) publish(name string, data []byte) error {
	dirFD := int(r.dir.Fd())
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return ErrConflict
	}
	stage := ".stage-" + hex.EncodeToString(suffix)
	fd, err := unix.Openat(dirFD, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrConflict
	}
	file := os.NewFile(uintptr(fd), stage)
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return ErrConflict
	}
	if err := unix.Linkat(dirFD, stage, dirFD, name, 0); err != nil {
		return ErrConflict
	}
	if err := unix.Unlinkat(dirFD, stage, 0); err != nil {
		return ErrConflict
	}
	return unix.Fsync(dirFD)
}

func (r *Runtime) entries() ([]string, error) {
	names, err := r.dir.Readdirnames(-1)
	if err != nil {
		return nil, ErrUnsafePath
	}
	if _, err := r.dir.Seek(0, 0); err != nil {
		return nil, ErrUnsafePath
	}
	return names, nil
}

// AdmitNATSServer checks the pinned native server by version and returns its digest.
func AdmitNATSServer(ctx context.Context, path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrServer
	}
	if resolved, err := filepath.EvalSymlinks(path); err != nil || resolved != path {
		return "", ErrServer
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return "", ErrServer
	}
	sum := sha256.Sum256(raw)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil || strings.TrimSpace(string(out)) != "nats-server: "+NATSVersion {
		return "", ErrServer
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, ErrInputs
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func newSeed(prefix nkeys.PrefixByte) ([]byte, error) {
	key, err := nkeys.CreatePair(prefix)
	if err != nil {
		return nil, ErrConflict
	}
	defer key.Wipe()
	seed, err := key.Seed()
	if err != nil {
		return nil, ErrConflict
	}
	// Wipe zeroes the key's own buffer, so return an independent copy.
	return append([]byte(nil), seed...), nil
}

func loadSeed(raw []byte, prefix nkeys.PrefixByte) (nkeys.KeyPair, error) {
	key, err := nkeys.FromSeed(bytes.TrimSpace(raw))
	if err != nil {
		return nil, ErrConflict
	}
	public, err := key.PublicKey()
	if err != nil || !nkeys.IsValidPublicKey(public) || nkeys.Prefix(public) != prefix {
		key.Wipe()
		return nil, ErrConflict
	}
	return key, nil
}

var serverNamePattern = regexp.MustCompile(`^app-[0-9a-f]{16}\.agentmux\.invalid$`)

func identityFor(operatorPublic string) (runtimeID, serverName, domain string) {
	sum := sha256.Sum256([]byte(operatorPublic))
	short := hex.EncodeToString(sum[:8])
	return "appruntime_" + short, "app-" + short + ".agentmux.invalid", "app_" + short
}

func issueTLS(serverName string) (tlsBundle, error) {
	if !serverNamePattern.MatchString(serverName) {
		return tlsBundle{}, ErrConflict
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsBundle{}, ErrConflict
	}
	defer caKey.D.SetInt64(0)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsBundle{}, ErrConflict
	}
	serial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		return n.Add(n, big.NewInt(1))
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Agentmux application runtime " + serverName},
		NotBefore: now, NotAfter: now.Add(tlsLifetime), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tlsBundle{}, ErrConflict
	}
	leaf := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: now, NotAfter: now.Add(tlsLifetime), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	caKey.D.SetInt64(0)
	if err != nil {
		return tlsBundle{}, ErrConflict
	}
	privateDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return tlsBundle{}, ErrConflict
	}
	return tlsBundle{RootsPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}))}, nil
}

func leafPin(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", ErrConflict
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func serverConfig(r *Runtime, m Manifest, inputs Inputs, operatorJWT, systemJWT, accountJWT string) []byte {
	quote := func(s string) string { raw, _ := json.Marshal(s); return string(raw) }
	return []byte(fmt.Sprintf(`server_name: %s
listen: "127.0.0.1:%d"
operator: %s
system_account: %s
resolver: MEMORY
resolver_preload: {
  %s: %s
  %s: %s
}
jetstream: {
  store_dir: %s
  domain: %s
  max_memory_store: 0
  max_file_store: %d
}
tls: {
  cert_file: %s
  key_file: %s
  min_version: "1.3"
  handshake_first: true
}
`, quote(m.RuntimeID), inputs.Port, quote(operatorJWT), quote(m.SystemAccountPublicKey),
		m.SystemAccountPublicKey, quote(systemJWT), m.AccountPublicKey, quote(accountJWT),
		quote(r.Path("jetstream")), quote(m.Domain), int64(diskStoreBytes),
		quote(r.Path("tls-server-cert.pem")), quote(r.Path("tls-server-key.pem"))))
}

// Result reports one initialization without private material.
type Result struct {
	Outcome   string   `json:"outcome"`
	Manifest  Manifest `json:"manifest"`
	Published []string `json:"published"`
}

// Initialize creates or resumes this installation's runtime material. inputs
// is only used for the very first file; afterwards the retained inputs win and
// a conflicting request is refused.
func Initialize(ctx context.Context, path string, requested Inputs) (Result, error) {
	r, err := Open(path, true)
	if err != nil {
		return Result{}, err
	}
	defer r.Close()
	names, err := r.entries()
	if err != nil {
		return Result{}, err
	}
	known := map[string]int{}
	for i, name := range artifacts {
		known[name] = i
	}
	present := make([]bool, len(artifacts))
	for _, name := range names {
		if i, ok := known[name]; ok {
			present[i] = true
		} else if !lifecycleEntries[name] {
			return Result{}, ErrAmbiguous
		}
	}
	first := len(artifacts)
	for i, ok := range present {
		if !ok {
			first = i
			break
		}
	}
	for i := first; i < len(artifacts); i++ {
		if present[i] {
			return Result{}, ErrAmbiguous
		}
	}
	var published []string
	write := func(name string, data []byte) error {
		if present[known[name]] {
			existing, ok, err := r.read(name)
			if err != nil || !ok {
				return ErrUnsafePath
			}
			if !bytes.Equal(existing, data) {
				return ErrConflict
			}
			return nil
		}
		if err := r.publish(name, data); err != nil {
			return err
		}
		published = append(published, name)
		return nil
	}
	readOr := func(name string, make func() ([]byte, error)) ([]byte, error) {
		if present[known[name]] {
			raw, ok, err := r.read(name)
			if err != nil || !ok {
				return nil, ErrUnsafePath
			}
			return raw, nil
		}
		raw, err := make()
		if err != nil {
			return nil, err
		}
		if err := r.publish(name, raw); err != nil {
			return nil, err
		}
		published = append(published, name)
		return raw, nil
	}

	// 0. Inputs.
	rawInputs, err := readOr("inputs.json", func() ([]byte, error) {
		digest, err := AdmitNATSServer(ctx, requested.NATSServer)
		if err != nil {
			return nil, err
		}
		port := requested.Port
		if port == 0 {
			if port, err = freePort(); err != nil {
				return nil, err
			}
		}
		if port < 1024 || port > 65535 {
			return nil, ErrInputs
		}
		raw, _ := json.Marshal(Inputs{SchemaVersion: SchemaVersion, NATSServer: requested.NATSServer, NATSSHA256: digest, Port: port})
		return append(raw, '\n'), nil
	})
	if err != nil {
		return Result{}, err
	}
	var inputs Inputs
	if json.Unmarshal(rawInputs, &inputs) != nil || inputs.SchemaVersion != SchemaVersion || inputs.Port < 1024 || inputs.Port > 65535 {
		return Result{}, ErrConflict
	}
	if (requested.NATSServer != "" && requested.NATSServer != inputs.NATSServer) || (requested.Port != 0 && requested.Port != inputs.Port) {
		return Result{}, ErrInputs
	}

	// 1-3. Identity seeds.
	keys := map[string]nkeys.KeyPair{}
	defer func() {
		for _, key := range keys {
			key.Wipe()
		}
	}()
	for _, item := range []struct {
		name   string
		prefix nkeys.PrefixByte
	}{{"operator.nk", nkeys.PrefixByteOperator}, {"system-account.nk", nkeys.PrefixByteAccount}, {"account.nk", nkeys.PrefixByteAccount}} {
		raw, err := readOr(item.name, func() ([]byte, error) {
			seed, err := newSeed(item.prefix)
			return append(seed, '\n'), err
		})
		if err != nil {
			return Result{}, err
		}
		key, err := loadSeed(raw, item.prefix)
		if err != nil {
			return Result{}, err
		}
		keys[item.name] = key
	}
	operatorPublic, _ := keys["operator.nk"].PublicKey()
	systemPublic, _ := keys["system-account.nk"].PublicKey()
	accountPublic, _ := keys["account.nk"].PublicKey()
	if systemPublic == accountPublic {
		return Result{}, ErrConflict
	}
	runtimeID, serverName, domain := identityFor(operatorPublic)

	// 4-6. TLS, published atomically then copied for nats-server.
	rawTLS, err := readOr("tls.json", func() ([]byte, error) {
		bundle, err := issueTLS(serverName)
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(bundle)
		return append(raw, '\n'), nil
	})
	if err != nil {
		return Result{}, err
	}
	var bundle tlsBundle
	if json.Unmarshal(rawTLS, &bundle) != nil {
		return Result{}, ErrConflict
	}
	pin, err := leafPin(bundle.CertPEM)
	if err != nil {
		return Result{}, err
	}
	if err := write("tls-server-key.pem", []byte(bundle.KeyPEM)); err != nil {
		return Result{}, err
	}
	if err := write("tls-server-cert.pem", []byte(bundle.CertPEM)); err != nil {
		return Result{}, err
	}

	// 7-9. Operator and account JWTs.
	now := time.Now().UTC()
	jwts := map[string]string{}
	for _, item := range []struct {
		name, subject, label string
		issuer               nkeys.KeyPair
		nats                 map[string]any
	}{
		{"operator.jwt", operatorPublic, "agentmux-application-operator", keys["operator.nk"], operatorClaims(systemPublic)},
		{"system-account.jwt", systemPublic, "SYS", keys["operator.nk"], accountClaims(false, 0)},
		{"account.jwt", accountPublic, "agentmux-application", keys["operator.nk"], accountClaims(true, diskStoreBytes)},
	} {
		raw, err := readOr(item.name, func() ([]byte, error) {
			token, err := issueJWT(item.issuer, item.subject, item.label, item.nats, now, time.Time{})
			return []byte(token + "\n"), err
		})
		if err != nil {
			return Result{}, err
		}
		token := strings.TrimSpace(string(raw))
		if _, err := verifyJWT(token, operatorPublic, item.subject); err != nil {
			return Result{}, ErrConflict
		}
		jwts[item.name] = token
	}

	// 10. Readiness user: JetStream account info only, private inbox replies.
	readinessInbox := "_INBOX.readiness"
	if _, err := readOr("readiness.creds", func() ([]byte, error) {
		user, err := nkeys.CreateUser()
		if err != nil {
			return nil, ErrConflict
		}
		defer user.Wipe()
		public, _ := user.PublicKey()
		seed, _ := user.Seed()
		token, err := issueJWT(keys["account.nk"], public, "agentmux-application-readiness",
			userClaims([]string{"$JS.API.INFO"}, []string{readinessInbox + ".>"}), now, time.Time{})
		if err != nil {
			return nil, err
		}
		return userCredentials(token, seed), nil
	}); err != nil {
		return Result{}, err
	}

	manifest := Manifest{SchemaVersion: SchemaVersion, RuntimeID: runtimeID, Endpoint: fmt.Sprintf("tls://127.0.0.1:%d", inputs.Port),
		ServerName: serverName, Domain: domain, RootsPEM: bundle.RootsPEM, LeafCertificateSHA256: pin,
		OperatorPublicKey: operatorPublic, SystemAccountPublicKey: systemPublic, AccountPublicKey: accountPublic,
		AccountSeedFile: r.Path("account.nk"), ReadinessCredentials: r.Path("readiness.creds"), StoreDirectory: r.Path("jetstream"),
		NATSServer: inputs.NATSServer, NATSServerSHA256: inputs.NATSSHA256, NATSVersion: NATSVersion}

	// 11-12. Server configuration and public manifest.
	if err := write("server.conf", serverConfig(r, manifest, inputs, jwts["operator.jwt"], jwts["system-account.jwt"], jwts["account.jwt"])); err != nil {
		return Result{}, err
	}
	rawManifest, _ := json.MarshalIndent(manifest, "", "  ")
	if err := write("runtime.json", append(rawManifest, '\n')); err != nil {
		return Result{}, err
	}
	if err := unix.Mkdirat(int(r.dir.Fd()), "jetstream", 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return Result{}, ErrUnsafePath
	}
	outcome := "initialized"
	if len(published) == 0 {
		outcome = "unchanged"
	} else if first > 0 {
		outcome = "recovered"
	}
	return Result{Outcome: outcome, Manifest: manifest, Published: published}, nil
}

// LoadManifest re-admits the complete retained material for lifecycle use.
func LoadManifest(r *Runtime) (Manifest, Inputs, error) {
	for _, name := range artifacts {
		if _, ok, err := r.read(name); err != nil || !ok {
			return Manifest{}, Inputs{}, ErrAmbiguous
		}
	}
	rawInputs, _, _ := r.read("inputs.json")
	rawManifest, _, _ := r.read("runtime.json")
	var inputs Inputs
	var manifest Manifest
	if json.Unmarshal(rawInputs, &inputs) != nil || json.Unmarshal(rawManifest, &manifest) != nil ||
		manifest.SchemaVersion != SchemaVersion || inputs.NATSServer != manifest.NATSServer || inputs.NATSSHA256 != manifest.NATSServerSHA256 {
		return Manifest{}, Inputs{}, ErrConflict
	}
	return manifest, inputs, nil
}
