//go:build linux || darwin

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/controlLogix/agentmux/platform/internal/wirejson"
	"github.com/controlLogix/agentmux/platform/privatefs"
	"golang.org/x/sys/unix"
)

const clientRegistrationLimit = 16 * 1024

var clientRegistrationProfile = regexp.MustCompile(`^profile_[0-9a-f]{32}$`)
var clientRegistrationInstance = regexp.MustCompile(`^instance_[0-9a-f]{32}$`)

type clientRegistration struct {
	SchemaVersion         string  `json:"schemaVersion"`
	OwnerUID              uint32  `json:"ownerUid"`
	ProfileID             string  `json:"profileId"`
	InstanceID            string  `json:"instanceId"`
	ClientInstallationID  string  `json:"clientInstallationId"`
	ProfileSHA256         string  `json:"profileSha256"`
	HostPolicySHA256      string  `json:"hostPolicySha256"`
	ClientSelectionSHA256 string  `json:"clientSelectionSha256"`
	Environment           *string `json:"environment,omitempty"`
	Project               *string `json:"project,omitempty"`
}

func validClientRegistration(raw []byte, id string) bool {
	if wirejson.Validate(raw, clientRegistrationLimit) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	required := []string{"schemaVersion", "ownerUid", "profileId", "instanceId", "clientInstallationId", "profileSha256", "hostPolicySha256", "clientSelectionSha256"}
	allowed := map[string]bool{"environment": true, "project": true}
	for _, key := range required {
		allowed[key] = true
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	for key, value := range fields {
		if !allowed[key] || string(value) == "null" {
			return false
		}
	}
	var record clientRegistration
	if json.Unmarshal(raw, &record) != nil || record.SchemaVersion != "1.0.0" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || record.OwnerUID != uint32(os.Getuid()) || record.ClientInstallationID != id || !ValidClientInstallationID(id) || !clientRegistrationProfile.MatchString(record.ProfileID) || !clientRegistrationInstance.MatchString(record.InstanceID) {
		return false
	}
	for _, digest := range []string{record.ProfileSHA256, record.HostPolicySHA256, record.ClientSelectionSHA256} {
		if !clientDigestPattern.MatchString(digest) {
			return false
		}
	}
	if record.Environment == nil && record.Project == nil {
		return false
	}
	for _, value := range []*string{record.Environment, record.Project} {
		if value == nil {
			continue
		}
		if *value == "" || strings.TrimSpace(*value) != *value || len(*value) > 128 || !utf8.ValidString(*value) {
			return false
		}
		for _, character := range *value {
			if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
				return false
			}
		}
	}
	return true
}

func duplicateClientRegistration(original *os.File) (*os.File, error) {
	if original == nil {
		return nil, &clientFailure{code: "registration_invalid"}
	}
	raw, err := original.SyscallConn()
	if err != nil {
		return nil, &clientFailure{code: "registration_invalid", cause: err}
	}
	fd := -1
	var duplicateErr error
	err = raw.Control(func(owned uintptr) {
		flags, flagErr := unix.FcntlInt(owned, unix.F_GETFD, 0)
		access, accessErr := unix.FcntlInt(owned, unix.F_GETFL, 0)
		if owned < 3 || flagErr != nil || accessErr != nil || flags&unix.FD_CLOEXEC == 0 || access&unix.O_ACCMODE != unix.O_RDONLY {
			duplicateErr = &clientFailure{code: "registration_invalid"}
			return
		}
		fd, duplicateErr = unix.FcntlInt(owned, unix.F_DUPFD_CLOEXEC, 3)
	})
	var duplicate *os.File
	if fd >= 0 {
		duplicate = os.NewFile(uintptr(fd), "installed-client-registration")
	}
	if err != nil || duplicateErr != nil || duplicate == nil {
		return duplicate, &clientFailure{code: "registration_invalid", cause: errors.Join(err, duplicateErr)}
	}
	return duplicate, nil
}

func withClientRegistration(ctx context.Context, original *os.File, id, digest string, run func(*os.File) error) (failure error) {
	if ctx == nil || ctx.Err() != nil || !ValidClientInstallationID(id) || !clientDigestPattern.MatchString(digest) || run == nil {
		return &clientFailure{code: "registration_invalid"}
	}
	duplicate, err := duplicateClientRegistration(original)
	forkLocked := false
	if duplicate != nil {
		defer func() {
			if closeErr := duplicate.Close(); closeErr != nil {
				failure = &clientFailure{code: "registration_cleanup_failed", cause: errors.Join(failure, closeErr), owner: duplicate}
			}
			if forkLocked {
				syscall.ForkLock.RUnlock()
			}
		}()
	}
	if err != nil {
		return err
	}
	before, err := clientStat(duplicate, uint32(os.Getuid()), 0600, false, privatefs.CheckDescriptor)
	if err != nil || before.Size <= 0 || before.Size > clientRegistrationLimit {
		return &clientFailure{code: "registration_invalid", cause: err}
	}
	// ReadAt keeps the borrowed original's shared file offset unchanged.
	raw, err := io.ReadAll(io.NewSectionReader(duplicate, 0, before.Size))
	after, statErr := clientStat(duplicate, uint32(os.Getuid()), 0600, false, privatefs.CheckDescriptor)
	if err != nil || statErr != nil || !reflect.DeepEqual(before, after) || int64(len(raw)) != before.Size || ClientDigest(raw) != digest || !validClientRegistration(raw, id) || ctx.Err() != nil {
		return &clientFailure{code: "registration_invalid", cause: errors.Join(err, statErr)}
	}
	// No concurrent Go child may inherit the temporary non-CLOEXEC duplicate.
	// On exec failure the defer closes it before allowing another fork.
	syscall.ForkLock.RLock()
	forkLocked = true
	return run(duplicate)
}

// withClientRegistration holds ForkLock and owns the duplicate through return.
func execInstalledRegisteredClient(path string, args, environment []string, registration *os.File) error {
	if registration == nil {
		return &clientFailure{code: "registration_invalid"}
	}
	flags, err := unix.FcntlInt(registration.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return &clientFailure{code: "registration_invalid", cause: err}
	}
	if _, err := unix.FcntlInt(registration.Fd(), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		return &clientFailure{code: "registration_invalid", cause: err}
	}
	return execInstalledClient(path, args, environment)
}
