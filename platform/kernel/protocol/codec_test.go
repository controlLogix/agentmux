package protocol

import (
	"encoding/json"
	"github.com/nats-io/nats.go"
	"strings"
	"testing"
	"time"
)

func testScope() Scope {
	return Scope{"fixture_hub", "fixture_instance", "fixture_profile", "sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("b", 64), "1.0.0"}
}
func testEvent(now time.Time) Event {
	return Event{Version, "kernel-role-observation", testScope(), "boot", strings.Repeat("a", 32), 1, now.UTC().Format(time.RFC3339Nano), "ready", []string{}, []Member{}}
}
func TestClosedEventAndCommandBoundaries(t *testing.T) {
	now := time.Now()
	original := testEvent(now)
	if _, err := DecodeEvent(mustJSON(original), testScope(), "boot", now, time.Second); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"role", "context", "release", "revision", "future", "stale", "unknown", "duplicate", "depth", "invalid-utf8", "unknown-error"} {
		t.Run(change, func(t *testing.T) {
			e := original
			switch change {
			case "role":
				e.Role = "kernel-lifecycle"
			case "context":
				e.Scope.InstanceID = "another"
			case "release":
				e.Scope.AssemblyDigest = "sha256:" + strings.Repeat("c", 64)
			case "revision":
				e.Revision = MaxRevision + 1
			case "future":
				e.ObservedAt = now.Add(3 * time.Second).Format(time.RFC3339Nano)
			case "stale":
				e.ObservedAt = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
			case "unknown-error":
				e.ErrorCodes = []string{"private-value"}
			}
			data := mustJSON(e)
			switch change {
			case "unknown":
				data = append(data[:len(data)-1], []byte(`,"senderAuthority":"invented"}`)...)
			case "duplicate":
				data = append(data[:len(data)-1], []byte(`,"role":"boot"}`)...)
			case "depth":
				data = []byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18))
			case "invalid-utf8":
				data = []byte{0xff}
			}
			if _, err := DecodeEvent(data, testScope(), "boot", now, time.Second); err == nil {
				t.Fatal("malformed event accepted")
			}
		})
	}
	command := Command{Version, "kernel-observation-command", testScope(), "boot", "announce"}
	if _, err := DecodeCommand(mustJSON(command), testScope(), "boot"); err != nil {
		t.Fatal(err)
	}
	command.Action = "stop"
	if _, err := DecodeCommand(mustJSON(command), testScope(), "boot"); err == nil {
		t.Fatal("unimplemented mutation command accepted")
	}
	data := []byte(`{"schemaVersion":"1.0.0","schema\u0056ersion":"1.0.0"}`)
	var c Command
	if StrictJSON(data, &c) == nil {
		t.Fatal("escaped duplicate key accepted")
	}
}
func TestPeerReplayIncarnationAndReceiptFreshness(t *testing.T) {
	now := time.Now()
	e := testEvent(now)
	prefix := "amx.v1.h.fixture_hub.kernel."
	a := &Actor{config: Config{Credentials: Credentials{Scope: testScope()}, StaleAfter: time.Second}, subjects: SubjectSet{Events: map[string]string{"boot": prefix + "internal.boot.event"}}, peers: map[string]*peer{}}
	a.connected.Store(true)
	msg := &nats.Msg{Subject: a.subjects.Events["boot"], Data: mustJSON(e)}
	if !a.accept(msg, now) || a.accept(msg, now) {
		t.Fatal("first observation/replay handling failed")
	}
	e.Incarnation = strings.Repeat("b", 32)
	msg.Data = mustJSON(e)
	if !a.accept(msg, now) {
		t.Fatal("new incarnation rejected")
	}
	e.Incarnation = strings.Repeat("a", 32)
	e.Revision = 2
	msg.Data = mustJSON(e)
	if a.accept(msg, now) {
		t.Fatal("retired incarnation resurrected")
	}
	if a.view(now.Add(2 * time.Second)).Members[0].State != "stale" {
		t.Fatal("expired receipt stayed healthy")
	}
	msg.Reply = "_INBOX.forged"
	e.Incarnation = strings.Repeat("b", 32)
	e.Revision = 3
	msg.Data = mustJSON(e)
	if a.accept(msg, now) {
		t.Fatal("request-shaped event accepted")
	}
}
func TestSnapshotCursorGapReplayAndExpiry(t *testing.T) {
	now := time.Now()
	members := []Member{}
	for _, role := range Roles() {
		members = append(members, Member{role, "ready", strings.Repeat("a", 32), 1, now.UTC().Format(time.RFC3339Nano)})
	}
	s := Snapshot{Version, "kernel-info", testScope(), "exported-status", strings.Repeat("a", 32), 1, now.UTC().Format(time.RFC3339Nano), now.Add(time.Second).UTC().Format(time.RFC3339Nano), "ready", members}
	cursor := SnapshotCursor{}
	if _, gap, err := cursor.Accept(mustJSON(s), testScope(), now, time.Second); err != nil || gap {
		t.Fatal("valid initial snapshot rejected")
	}
	if _, _, err := cursor.Accept(mustJSON(s), testScope(), now, time.Second); err == nil {
		t.Fatal("snapshot replay accepted")
	}
	s.Revision = 3
	if _, gap, err := cursor.Accept(mustJSON(s), testScope(), now, time.Second); err != nil || !gap {
		t.Fatal("missing revision not visible")
	}
	s.Incarnation = strings.Repeat("b", 32)
	s.Members[3].Incarnation = s.Incarnation
	s.Revision = 1
	if _, gap, err := cursor.Accept(mustJSON(s), testScope(), now, time.Second); err != nil || !gap {
		t.Fatal("restart incarnation not visible")
	}
	s.Incarnation = strings.Repeat("a", 32)
	s.Members[3].Incarnation = s.Incarnation
	s.Revision = 4
	if _, _, err := cursor.Accept(mustJSON(s), testScope(), now, time.Second); err == nil {
		t.Fatal("retired snapshot incarnation accepted")
	}
	if _, err := DecodeSnapshot(mustJSON(s), testScope(), now.Add(2*time.Second), time.Second); err == nil {
		t.Fatal("expired snapshot accepted")
	}
	s.Incarnation = strings.Repeat("b", 32)
	s.Members[3].Incarnation = s.Incarnation
	s.Members[0].State = "stale"
	if _, err := DecodeSnapshot(mustJSON(s), testScope(), now, time.Second); err == nil {
		t.Fatal("ready snapshot carried stale member")
	}
	var ignored map[string]any
	if json.Unmarshal(mustJSON(s), &ignored) != nil {
		t.Fatal("fixture JSON invalid")
	}
}

func TestSnapshotSelfIncarnationAndPartialFreshness(t *testing.T) {
	now := time.Now()
	members := []Member{}
	for _, role := range Roles() {
		members = append(members, Member{role, "ready", strings.Repeat("a", 32), 1, now.UTC().Format(time.RFC3339Nano)})
	}
	s := Snapshot{Version, "kernel-info", testScope(), "exported-status", strings.Repeat("a", 32), 2, now.UTC().Format(time.RFC3339Nano), now.Add(time.Second).UTC().Format(time.RFC3339Nano), "degraded", members}
	s.Members[3].Incarnation = strings.Repeat("b", 32)
	if _, err := DecodeSnapshot(mustJSON(s), testScope(), now, time.Second); err == nil {
		t.Fatal("conflicting status incarnation accepted")
	}
	s.Members[3].Incarnation = s.Incarnation
	s.Members[0].ObservedAt = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
	if _, err := DecodeSnapshot(mustJSON(s), testScope(), now, time.Second); err == nil {
		t.Fatal("partial snapshot advertised expired peer as ready")
	}
	s.Members[0].State = "stale"
	if _, err := DecodeSnapshot(mustJSON(s), testScope(), now, time.Second); err != nil {
		t.Fatal("honest stale peer observation rejected")
	}
}

func TestUnknownPeerFieldsRemainRequiredAndTyped(t *testing.T) {
	now := time.Now().UTC()
	members := []Member{}
	for _, role := range Roles() {
		members = append(members, Member{Role: role, State: "unknown"})
	}
	event := testEvent(now)
	event.Role, event.Members = "kernel-lifecycle", members
	snapshot := Snapshot{Version, "kernel-info", testScope(), "exported-status", strings.Repeat("a", 32), 1, now.Format(time.RFC3339Nano), now.Add(time.Second).Format(time.RFC3339Nano), "not_ready", members}
	for _, frame := range []struct {
		name   string
		value  any
		decode func([]byte) error
	}{
		{"event", event, func(raw []byte) error {
			_, err := DecodeEvent(raw, testScope(), "kernel-lifecycle", now, time.Second)
			return err
		}},
		{"snapshot", snapshot, func(raw []byte) error { _, err := DecodeSnapshot(raw, testScope(), now, time.Second); return err }},
	} {
		t.Run(frame.name, func(t *testing.T) {
			raw := mustJSON(frame.value)
			if frame.decode(raw) != nil {
				t.Fatal("complete unknown peer rejected")
			}
			for _, field := range []string{"incarnation", "revision", "observedAt"} {
				for _, missing := range []bool{false, true} {
					var object map[string]any
					if json.Unmarshal(raw, &object) != nil {
						t.Fatal("frame fixture decode failed")
					}
					member := object["members"].([]any)[0].(map[string]any)
					if missing {
						delete(member, field)
					} else {
						member[field] = nil
					}
					if frame.decode(mustJSON(object)) == nil {
						t.Fatalf("missing=%t or null peer field %s accepted", missing, field)
					}
				}
			}
		})
	}
}
