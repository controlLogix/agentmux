// Package natscredential validates enrolled NATS user credential bytes.
// Callers retain responsibility for private file custody and connection ownership.
package natscredential

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/nats-io/nkeys"
)

const MaxBytes = 64 * 1024

var ErrInvalid = errors.New("nats_credential_invalid")
var privateReplyPrefix = regexp.MustCompile(`^_INBOX\.[A-Za-z0-9_-]{16,64}$`)

// Policy comes from protected enrollment, not claims within the credential.
// PrivateInbox allows exactly one _INBOX.<principal>.> subscription. With it
// disabled, every subscription and publication must be a literal subject.
// Response permissions and bearer credentials are refused in either mode.
type Policy struct {
	AccountPublicKey                   string
	PublishSubjects, SubscribeSubjects []string
	PrivateInbox                       bool
}

// Credential hides validated private material from formatting and JSON output.
// Its accessors expose material only for explicit connection setup.
type Credential struct {
	jwt    string
	seed   []byte
	public string
}

func (Credential) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private enrolled NATS credential]")
}
func (Credential) MarshalJSON() ([]byte, error) {
	return []byte(`{"kind":"private-enrolled-nats-credential"}`), nil
}
func (c Credential) JWT() string       { return c.jwt }
func (c Credential) Seed() []byte      { return bytes.Clone(c.seed) }
func (c Credential) PublicKey() string { return c.public }

func exactPermission(actual, expected []string) bool {
	if len(actual) != len(expected) || len(actual) == 0 {
		return false
	}
	a, e := append([]string(nil), actual...), append([]string(nil), expected...)
	sort.Strings(a)
	sort.Strings(e)
	for i := range a {
		if a[i] != e[i] || !literalSubject(a[i]) {
			return false
		}
	}
	return true
}

// Validate verifies bounded decorated bytes against an explicitly enrolled
// account and exact subject permissions. It does not open files or connect.
func Validate(raw []byte, policy Policy) (Credential, error) {
	account, publish, subscribe, privateInbox := policy.AccountPublicKey, policy.PublishSubjects, policy.SubscribeSubjects, policy.PrivateInbox
	if len(raw) == 0 || len(raw) > MaxBytes {
		return Credential{}, ErrInvalid
	}
	fail := func() (Credential, error) {
		return Credential{}, ErrInvalid
	}
	jwt, seedRaw, err := ParseDecorated(raw)
	if err != nil {
		return fail()
	}
	key, err := nkeys.FromSeed(seedRaw)
	if err != nil {
		return fail()
	}
	defer key.Wipe()
	pub, err := key.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(pub) {
		return fail()
	}
	seed, err := key.Seed()
	if err != nil {
		return fail()
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fail()
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	header, ok := allowedFields(headerRaw, []string{"typ", "alg"}, nil)
	var headerType, headerAlgorithm string
	if err != nil || wirejson.Validate(headerRaw, MaxBytes) != nil || !ok || json.Unmarshal(header["typ"], &headerType) != nil || json.Unmarshal(header["alg"], &headerAlgorithm) != nil || headerType != "JWT" || headerAlgorithm != "ed25519-nkey" {
		return fail()
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || wirejson.Validate(claimsRaw, MaxBytes) != nil {
		return fail()
	}
	if !claimsShape(claimsRaw) {
		return fail()
	}
	var claims struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Expires   int64  `json:"exp"`
		NotBefore int64  `json:"nbf"`
		IssuedAt  int64  `json:"iat"`
		Nats      struct {
			Type          string `json:"type"`
			Version       int    `json:"version"`
			IssuerAccount string `json:"issuer_account"`
			Publish       struct {
				Allow []string `json:"allow"`
			} `json:"pub"`
			Subscribe struct {
				Allow []string `json:"allow"`
			} `json:"sub"`
			Response json.RawMessage `json:"resp"`
		} `json:"nats"`
	}
	if json.Unmarshal(claimsRaw, &claims) != nil || !nkeys.IsValidPublicAccountKey(account) || claims.Issuer != account || claims.Subject != pub || claims.Nats.Type != "user" || claims.Nats.Version != 2 ||
		(claims.Nats.IssuerAccount != "" && claims.Nats.IssuerAccount != account) ||
		(claims.Expires != 0 && claims.Expires <= time.Now().Unix()) || claims.NotBefore > time.Now().Unix() || claims.NotBefore < 0 || claims.Expires < 0 || claims.IssuedAt < 0 || claims.IssuedAt > time.Now().Add(time.Second).Unix() ||
		!exactPermission(claims.Nats.Publish.Allow, publish) || !subscribePermission(claims.Nats.Subscribe.Allow, subscribe, privateInbox) ||
		(len(claims.Nats.Response) != 0 && !bytes.Equal(claims.Nats.Response, []byte("null"))) {
		return fail()
	}
	issuer, err := nkeys.FromPublicKey(account)
	if err != nil {
		return fail()
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || issuer.Verify([]byte(parts[0]+"."+parts[1]), signature) != nil {
		return fail()
	}
	// Recheck time after signature verification, before releasing the material.
	now := time.Now()
	if (claims.Expires != 0 && claims.Expires <= now.Unix()) || claims.NotBefore > now.Unix() {
		return fail()
	}
	return Credential{jwt: jwt, seed: bytes.Clone(seed), public: pub}, nil
}

func literalSubject(value string) bool {
	if value == "" || strings.ContainsAny(value, "*> \t\r\n\x00") {
		return false
	}
	for _, token := range strings.Split(value, ".") {
		if token == "" {
			return false
		}
	}
	return true
}

var jwtBlock = regexp.MustCompile(`(?m)^-{3,}BEGIN NATS USER JWT-{3,}\r?\n([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\r?\n-{3,}END NATS USER JWT-{3,}\r?$`)
var seedBlock = regexp.MustCompile(`(?m)^-{3,}BEGIN USER NKEY SEED-{3,}\r?\n(SU[A-Z2-7]+)\r?\n-{3,}END USER NKEY SEED-{3,}\r?$`)

// ParseDecorated extracts the single JWT and user seed from bounded decorated
// bytes. Extraction alone does not verify the signature or grant permission.
func ParseDecorated(raw []byte) (string, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return "", nil, ErrInvalid
	}
	tokens := jwtBlock.FindAllSubmatch(raw, -1)
	seeds := seedBlock.FindAllSubmatch(raw, -1)
	if len(tokens) != 1 || len(seeds) != 1 {
		return "", nil, ErrInvalid
	}
	markers := 0
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "---") {
			switch strings.Trim(line, "-") {
			case "BEGIN NATS USER JWT", "END NATS USER JWT", "BEGIN USER NKEY SEED", "END USER NKEY SEED":
				markers++
			default:
				return "", nil, ErrInvalid
			}
		}
	}
	if markers != 4 {
		return "", nil, ErrInvalid
	}
	return string(tokens[0][1]), bytes.Clone(seeds[0][1]), nil
}
func allowedFields(raw []byte, required, optional []string) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	allowed := map[string]bool{}
	for _, name := range append(append([]string(nil), required...), optional...) {
		allowed[name] = true
	}
	for key, value := range fields {
		if !allowed[key] || (key != "resp" && bytes.Equal(bytes.TrimSpace(value), []byte("null"))) {
			return nil, false
		}
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return nil, false
		}
	}
	return fields, true
}
func claimsShape(raw []byte) bool {
	top, ok := allowedFields(raw, []string{"iss", "sub", "nats"}, []string{"exp", "nbf", "iat", "jti", "name"})
	if !ok {
		return false
	}
	for _, name := range []string{"jti", "name"} {
		if value, found := top[name]; found {
			var text string
			if json.Unmarshal(value, &text) != nil {
				return false
			}
		}
	}
	nats, ok := allowedFields(top["nats"], []string{"type", "version", "pub", "sub"}, []string{"issuer_account", "resp", "subs", "data", "payload", "bearer_token"})
	if !ok {
		return false
	}
	for _, name := range []string{"pub", "sub"} {
		permissions, ok := allowedFields(nats[name], []string{"allow"}, []string{"deny"})
		if !ok {
			return false
		}
		if deny, found := permissions["deny"]; found {
			var values []string
			if json.Unmarshal(deny, &values) != nil || len(values) != 0 {
				return false
			}
		}
	}
	if value, found := nats["resp"]; found && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return false
	}
	if value, found := nats["bearer_token"]; found && !bytes.Equal(bytes.TrimSpace(value), []byte("false")) {
		return false
	}
	for _, name := range []string{"subs", "data", "payload"} {
		if value, found := nats[name]; found {
			var limit int64
			if json.Unmarshal(value, &limit) != nil || limit < -1 || limit > 9007199254740991 {
				return false
			}
		}
	}
	return true
}

func subscribePermission(actual, expected []string, privateInbox bool) bool {
	if !privateInbox {
		return exactPermission(actual, expected)
	}
	return len(actual) == 1 && len(expected) == 1 && actual[0] == expected[0] && strings.HasSuffix(expected[0], ".>") && privateReplyPrefix.MatchString(strings.TrimSuffix(expected[0], ".>"))
}
