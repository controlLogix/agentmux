// Package protocol contains shared wire parsing and local transport helpers, not a plugin bus.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const Version = "1.0.0"
const MaxPayload = 8192

var roles = [4]string{"boot", "kernel-lifecycle", "internal-communication", "exported-status"}
var opaque = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,95}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var incarnation = regexp.MustCompile(`^[a-f0-9]{32}$`)
var releaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

const MaxRevision = 9007199254740991

func Roles() [4]string { return roles }
func validRole(role string) bool {
	for _, r := range roles {
		if role == r {
			return true
		}
	}
	return false
}

type Scope struct {
	HubID                 string `json:"hubId"`
	InstanceID            string `json:"instanceId"`
	ProfileID             string `json:"profileId"`
	AssemblyDigest        string `json:"assemblyDigest"`
	ReleaseManifestDigest string `json:"releaseManifestDigest"`
	ReleaseVersion        string `json:"releaseVersion"`
}

func (s Scope) valid() bool {
	return opaque.MatchString(s.HubID) && opaque.MatchString(s.InstanceID) && opaque.MatchString(s.ProfileID) && digest.MatchString(s.AssemblyDigest) && digest.MatchString(s.ReleaseManifestDigest) && releaseVersion.MatchString(s.ReleaseVersion)
}

type Member struct {
	Role        string `json:"role"`
	State       string `json:"state"`
	Incarnation string `json:"incarnation"`
	Revision    uint64 `json:"revision"`
	ObservedAt  string `json:"observedAt"`
}

type Event struct {
	SchemaVersion string   `json:"schemaVersion"`
	Kind          string   `json:"kind"`
	Scope         Scope    `json:"scope"`
	Role          string   `json:"role"`
	Incarnation   string   `json:"incarnation"`
	Revision      uint64   `json:"revision"`
	ObservedAt    string   `json:"observedAt"`
	State         string   `json:"state"`
	ErrorCodes    []string `json:"errorCodes"`
	Members       []Member `json:"members"`
}

type Command struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Scope         Scope  `json:"scope"`
	Destination   string `json:"destination"`
	Action        string `json:"action"`
}

type Snapshot struct {
	SchemaVersion   string   `json:"schemaVersion"`
	Kind            string   `json:"kind"`
	Scope           Scope    `json:"scope"`
	Role            string   `json:"role"`
	Incarnation     string   `json:"incarnation"`
	Revision        uint64   `json:"revision"`
	ObservedAt      string   `json:"observedAt"`
	ValidUntil      string   `json:"validUntil"`
	KernelReadiness string   `json:"kernelReadiness"`
	Members         []Member `json:"members"`
}

// StrictJSON applies the fixed kernel wire limit and exact field names.
func StrictJSON(data []byte, out any) error {
	return DecodeClosedJSON(data, out, MaxPayload)
}

// DecodeClosedJSON checks exact struct field names before typed decoding. Map
// keys remain open where the destination type declares a map. This helper does
// not validate required fields, authorization or the values of decoded fields.
func DecodeClosedJSON(data []byte, out any, maxBytes int) error {
	target := reflect.TypeOf(out)
	if maxBytes <= 0 || maxBytes > 64*1024 || len(data) == 0 || len(data) > maxBytes || !utf8.Valid(data) || target == nil || target.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return errors.New("kernel_payload_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int, reflect.Type) error
	walk = func(depth int, destination reflect.Type) error {
		for destination != nil && destination.Kind() == reflect.Pointer {
			destination = destination.Elem()
		}
		if depth > 16 {
			return errors.New("kernel_payload_depth")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := t.(json.Delim); ok {
			switch delimiter {
			case '{':
				fields := map[string]reflect.Type{}
				var valueType reflect.Type
				if destination != nil {
					switch destination.Kind() {
					case reflect.Struct:
						for i := 0; i < destination.NumField(); i++ {
							f := destination.Field(i)
							if !f.IsExported() {
								continue
							}
							name := strings.Split(f.Tag.Get("json"), ",")[0]
							if name == "-" {
								continue
							}
							if f.Anonymous {
								return errors.New("kernel_payload_invalid")
							}
							if name == "" {
								name = f.Name
							}
							if _, duplicate := fields[name]; duplicate {
								return errors.New("kernel_payload_invalid")
							}
							fields[name] = f.Type
						}
					case reflect.Map:
						valueType = destination.Elem()
					case reflect.Interface:
					default:
						return errors.New("kernel_payload_invalid")
					}
				}
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return err
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return errors.New("kernel_duplicate_key")
					}
					seen[key] = true
					childType := valueType
					if destination != nil && destination.Kind() == reflect.Struct {
						var exists bool
						childType, exists = fields[key]
						if !exists {
							return errors.New("kernel_payload_invalid")
						}
					}
					if err := walk(depth+1, childType); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("kernel_payload_invalid")
				}
			case '[':
				var element reflect.Type
				if destination != nil {
					switch destination.Kind() {
					case reflect.Array, reflect.Slice:
						element = destination.Elem()
					case reflect.Interface:
					default:
						return errors.New("kernel_payload_invalid")
					}
				}
				for d.More() {
					if err := walk(depth+1, element); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("kernel_payload_invalid")
				}
			default:
				return errors.New("kernel_payload_invalid")
			}
		}
		return nil
	}
	if err := walk(0, target.Elem()); err != nil {
		return errors.New("kernel_payload_invalid")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("kernel_payload_invalid")
	}
	typed := json.NewDecoder(bytes.NewReader(data))
	typed.DisallowUnknownFields()
	if err := typed.Decode(out); err != nil {
		return errors.New("kernel_payload_invalid")
	}
	return nil
}

func fresh(observed string, now time.Time, stale time.Duration) bool {
	at, err := time.Parse(time.RFC3339Nano, observed)
	return err == nil && !at.After(now.Add(2*time.Second)) && now.Sub(at) <= stale
}
func state(value string) bool {
	return value == "starting" || value == "ready" || value == "degraded" || value == "stopping"
}
func errorsValid(codes []string) bool {
	if codes == nil || len(codes) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if seen[code] {
			return false
		}
		seen[code] = true
		if code != "peer_unavailable" && code != "broker_disconnected" && code != "starting" && code != "protocol_rejected" {
			return false
		}
	}
	return true
}
func membersValid(members []Member) bool {
	if members == nil || len(members) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, m := range members {
		if !validRole(m.Role) || seen[m.Role] {
			return false
		}
		seen[m.Role] = true
		if m.State == "unknown" {
			if m.Incarnation != "" || m.Revision != 0 || m.ObservedAt != "" {
				return false
			}
			continue
		}
		if !state(m.State) && m.State != "stale" {
			return false
		}
		if !incarnation.MatchString(m.Incarnation) || m.Revision == 0 || m.Revision > MaxRevision {
			return false
		}
		if _, err := time.Parse(time.RFC3339Nano, m.ObservedAt); err != nil {
			return false
		}
	}
	return true
}

func DecodeEvent(data []byte, scope Scope, role string, now time.Time, stale time.Duration) (Event, error) {
	var e Event
	if err := StrictJSON(data, &e); err != nil {
		return e, err
	}
	if e.SchemaVersion != Version || e.Kind != "kernel-role-observation" || e.Scope != scope || !scope.valid() || e.Role != role || !validRole(role) || !incarnation.MatchString(e.Incarnation) || e.Revision == 0 || e.Revision > MaxRevision || !fresh(e.ObservedAt, now, stale) || !state(e.State) || !errorsValid(e.ErrorCodes) || !membersValid(e.Members) {
		return Event{}, errors.New("kernel_event_invalid")
	}
	if (role == "kernel-lifecycle" && len(e.Members) != 4) || (role != "kernel-lifecycle" && len(e.Members) != 0) {
		return Event{}, errors.New("kernel_event_invalid")
	}
	return e, nil
}
func DecodeCommand(data []byte, scope Scope, role string) (Command, error) {
	var c Command
	if err := StrictJSON(data, &c); err != nil {
		return c, err
	}
	if c.SchemaVersion != Version || c.Kind != "kernel-observation-command" || c.Scope != scope || !scope.valid() || c.Destination != role || !validRole(role) || c.Action != "announce" {
		return Command{}, errors.New("kernel_command_invalid")
	}
	return c, nil
}
func DecodeSnapshot(data []byte, scope Scope, now time.Time, stale time.Duration) (Snapshot, error) {
	var s Snapshot
	if err := StrictJSON(data, &s); err != nil {
		return s, err
	}
	until, err := time.Parse(time.RFC3339Nano, s.ValidUntil)
	at, atErr := time.Parse(time.RFC3339Nano, s.ObservedAt)
	if s.SchemaVersion != Version || s.Kind != "kernel-info" || s.Scope != scope || !scope.valid() || s.Role != "exported-status" || !incarnation.MatchString(s.Incarnation) || s.Revision == 0 || s.Revision > MaxRevision || !fresh(s.ObservedAt, now, stale) || err != nil || atErr != nil || !until.After(now) || until.Sub(at) != stale || len(s.Members) != 4 || !membersValid(s.Members) || (s.KernelReadiness != "ready" && s.KernelReadiness != "not_ready" && s.KernelReadiness != "degraded") {
		return Snapshot{}, errors.New("kernel_snapshot_invalid")
	}
	for _, m := range s.Members {
		if m.State != "unknown" && m.State != "stale" && !fresh(m.ObservedAt, now, stale) {
			return Snapshot{}, errors.New("kernel_snapshot_invalid")
		}
		if m.Role == "exported-status" && m.State != "unknown" && (m.Incarnation != s.Incarnation || m.Revision > s.Revision) {
			return Snapshot{}, errors.New("kernel_snapshot_invalid")
		}
	}
	if s.KernelReadiness == "ready" {
		for _, m := range s.Members {
			if m.State != "ready" || !fresh(m.ObservedAt, now, stale) {
				return Snapshot{}, errors.New("kernel_snapshot_invalid")
			}
		}
	}
	return s, nil
}

// SnapshotCursor flags missed revisions while every accepted frame remains a full snapshot.
// It never treats an old incarnation or stale frame as a current observation.
type SnapshotCursor struct {
	incarnation string
	revision    uint64
	retired     map[string]bool
}

func (c *SnapshotCursor) Accept(data []byte, scope Scope, now time.Time, stale time.Duration) (Snapshot, bool, error) {
	s, err := DecodeSnapshot(data, scope, now, stale)
	if err != nil {
		return Snapshot{}, false, err
	}
	if c.retired == nil {
		c.retired = map[string]bool{}
	}
	gap := false
	if c.incarnation == s.Incarnation {
		if s.Revision <= c.revision {
			return Snapshot{}, false, errors.New("kernel_snapshot_replayed")
		}
		gap = s.Revision != c.revision+1
	} else if c.incarnation != "" {
		if c.retired[s.Incarnation] || len(c.retired) >= 32 {
			return Snapshot{}, false, errors.New("kernel_snapshot_incarnation_invalid")
		}
		c.retired[c.incarnation] = true
		gap = true
	}
	c.incarnation = s.Incarnation
	c.revision = s.Revision
	return s, gap, nil
}
