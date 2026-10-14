package protocol

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

type Credentials struct {
	SchemaVersion string `json:"schemaVersion"`
	Role          string `json:"role"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	NATSURL       string `json:"natsUrl"`
	Scope         Scope  `json:"scope"`
}

type Clock interface{ Now() time.Time }
type Logger interface{ Code(string) }
type localClock struct{}

func (localClock) Now() time.Time { return time.Now() }

type silentLogger struct{}

func (silentLogger) Code(string) {}

// Services are local context-owned references, never serialized or inherited from a root client.
type Services struct {
	Clock  Clock
	Logger Logger
}
type Config struct {
	Credentials Credentials
	Interval    time.Duration
	StaleAfter  time.Duration
	Services    Services
}

func (c Credentials) valid() bool {
	secret := regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
	u, err := url.Parse(c.NATSURL)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "nats" && u.Scheme != "tls") {
		return false
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && c.SchemaVersion == Version && validRole(c.Role) && c.Username == c.Role && secret.MatchString(c.Password) && c.Scope.valid()
}
func (c Config) prepared(role string) (Config, error) {
	if !c.Credentials.valid() || c.Credentials.Role != role {
		return Config{}, errors.New("kernel_credentials_invalid")
	}
	if c.Interval == 0 {
		c.Interval = time.Second
	}
	if c.StaleAfter == 0 {
		c.StaleAfter = 3 * time.Second
	}
	if c.Interval < 10*time.Millisecond || c.Interval > time.Second || c.StaleAfter < 2*c.Interval || c.StaleAfter > 3*time.Second {
		return Config{}, errors.New("kernel_timing_invalid")
	}
	if c.Services.Clock == nil {
		c.Services.Clock = localClock{}
	}
	if c.Services.Logger == nil {
		c.Services.Logger = silentLogger{}
	}
	return c, nil
}

// LoadEnvironment reads only the fixed supervisor contract, not a whole host profile.
func LoadEnvironment() (Config, error) {
	role := os.Getenv("AGENTMUX_KERNEL_ROLE")
	if !validRole(role) || os.Getenv("AGENTMUX_KERNEL_API_MAJOR") != "1" {
		return Config{}, errors.New("kernel_supervisor_identity_invalid")
	}
	path := os.Getenv("AGENTMUX_NATS_CREDS_FILE")
	if path == "" || !filepath.IsAbs(path) {
		return Config{}, errors.New("kernel_credential_reference_invalid")
	}
	data, err := readPrivateFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Credentials
	if err := StrictJSON(data, &c); err != nil {
		return Config{}, errors.New("kernel_credentials_invalid")
	}
	if c.Role != role || c.Scope.InstanceID != os.Getenv("AGENTMUX_INSTANCE_ID") || c.Scope.ProfileID != os.Getenv("AGENTMUX_PROFILE_ID") || c.NATSURL != os.Getenv("AGENTMUX_NATS_URL") {
		return Config{}, errors.New("kernel_supervisor_context_mismatch")
	}
	return (Config{Credentials: c}).prepared(role)
}
