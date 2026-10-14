package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func readOnlyObservationFixture(t *testing.T, record bool) *healthFixture {
	t.Helper()
	f := newHealthFixture(t, false)
	if record {
		if _, err := ProvisionAndProbe(context.Background(), f.options); err != nil {
			t.Fatal("controlled writer could not seed observation fixture")
		}
	}
	f.stop(t)
	raw, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal("controlled config unavailable")
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("controlled config invalid")
	}
	permissions := config["accounts"].(map[string]any)[HealthAccount].(map[string]any)["users"].([]any)[0].(map[string]any)["permissions"].(map[string]any)
	stream := HealthStream(f.options.HubID)
	allow := []any{"$JS." + f.options.Domain + ".API.INFO", "$JS.API.INFO"}
	for _, operation := range []string{"INFO.", "MSG.GET."} {
		allow = append(allow, "$JS."+f.options.Domain+".API.STREAM."+operation+stream,
			"$JS.API.STREAM."+operation+stream)
	}
	permissions["publish"] = map[string]any{"allow": allow}
	if os.WriteFile(f.config, fixtureConfigJSON(t, config), 0600) != nil {
		t.Fatal("controlled config could not select read-only principal")
	}
	f.start(t)
	return f
}

func noObservationDisclosure(t *testing.T, result Observation, err error, options ProbeOptions) {
	t.Helper()
	raw, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	text := string(raw)
	if err != nil {
		text += err.Error()
	}
	for _, private := range []string{options.Password, options.Endpoint, "private-record-payload"} {
		if strings.Contains(text, private) {
			t.Fatal("observer exposed a credential, endpoint or raw record")
		}
	}
}

func TestObserveExistingRecordIsReadOnlyAndClosesOwnedConnection(t *testing.T) {
	f := readOnlyObservationFixture(t, true)
	nc, js := f.connect(t)
	before, err := js.StreamInfo(HealthStream(f.options.HubID))
	if err != nil {
		t.Fatal("seeded fixture stream unavailable")
	}
	stored, err := js.GetMsg(before.Config.Name, before.State.LastSeq)
	if err != nil {
		t.Fatal("seeded fixture record unavailable")
	}
	nc.Close()
	for i := 0; i < 3; i++ {
		result, err := Observe(context.Background(), ObserveOptions{f.options, true})
		if err != nil || !result.BrokerVerified || result.ServerName != f.options.ServerName ||
			result.ServerVersion != f.options.ServerVersion || result.Domain != f.options.Domain ||
			result.PersistenceEvidence != PersistenceRecordSeen || result.RecordSequence != stored.Sequence ||
			result.RecordObservedAt != stored.Time.UTC().Format(time.RFC3339Nano) || result.RecordDigest == "" {
			t.Fatal("existing authenticated record was not observed")
		}
		noObservationDisclosure(t, result, err, f.options)
		f.assertConnections(t, 0)
	}
	_, js = f.connect(t)
	after, err := js.StreamInfo(before.Config.Name)
	if err != nil || !reflect.DeepEqual(before.Config, after.Config) || !reflect.DeepEqual(before.State, after.State) ||
		!before.Created.Equal(after.Created) {
		t.Fatal("read-only observation mutated the stream, sequence or records")
	}
}

func TestObserveAbsentStreamNeverProvisions(t *testing.T) {
	f := readOnlyObservationFixture(t, false)
	for _, read := range []bool{false, true} {
		result, err := Observe(context.Background(), ObserveOptions{f.options, read})
		if err != nil || !result.BrokerVerified || result.PersistenceEvidence != PersistenceUnknown ||
			result.Code != "health_stream_absent" || result.RecordSequence != 0 {
			t.Fatal("absent persistence was reported ready or observer tried to provision it")
		}
		noObservationDisclosure(t, result, err, f.options)
		f.assertConnections(t, 0)
	}
	_, js := f.connect(t)
	if _, err := js.StreamInfo(HealthStream(f.options.HubID)); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal("observer provisioned an absent stream")
	}
}

func TestObserveEmptyStreamAndConfigurationAreNotWriteEvidence(t *testing.T) {
	f := newHealthFixture(t, false)
	nc, js := f.connect(t)
	config := HealthConfig(f.options.HubID)
	before, err := js.AddStream(&config)
	if err != nil {
		t.Fatal("controlled empty stream unavailable")
	}
	nc.Close()
	for _, read := range []bool{false, true} {
		result, err := Observe(context.Background(), ObserveOptions{f.options, read})
		want := PersistenceConfigSeen
		if read {
			want = PersistenceUnknown
		}
		if err != nil || result.PersistenceEvidence != want || result.RecordSequence != 0 || result.RecordDigest != "" {
			t.Fatal("configuration or absence became an invented persistence record")
		}
		f.assertConnections(t, 0)
	}
	_, js = f.connect(t)
	after, err := js.StreamInfo(config.Name)
	if err != nil || !reflect.DeepEqual(before.Config, after.Config) || after.State.Msgs != 0 || after.State.LastSeq != 0 {
		t.Fatal("observation changed the empty stream")
	}
}

func TestObserveWrongAuthDomainIdentityAndUnavailableEndpoint(t *testing.T) {
	f := readOnlyObservationFixture(t, false)
	for _, kind := range []string{"auth", "domain", "server", "version", "endpoint"} {
		t.Run(kind, func(t *testing.T) {
			o := f.options
			o.Timeout = 150 * time.Millisecond
			switch kind {
			case "auth":
				o.Password = strings.Repeat("a", 48)
			case "domain":
				o.Domain = "other_domain"
			case "server":
				o.ServerName = "other_server"
			case "version":
				o.ServerVersion = "2.14.0"
			case "endpoint":
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal("controlled port unavailable")
				}
				o.Endpoint = "nats://" + listener.Addr().String()
				listener.Close()
			}
			begin := time.Now()
			result, err := Observe(context.Background(), ObserveOptions{o, true})
			if err == nil || result.BrokerVerified || result.RecordSequence != 0 || result.ServerName != "" ||
				result.ServerVersion != "" || result.Domain != "" || time.Since(begin) > 500*time.Millisecond {
				t.Fatal("failed selection leaked observations or escaped its total deadline")
			}
			noObservationDisclosure(t, result, err, o)
			f.assertConnections(t, 0)
		})
	}
	_, js := f.connect(t)
	if _, err := js.StreamInfo(HealthStream(f.options.HubID)); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatal("failed selection changed persistence")
	}
}

func TestObserveReadOnlyPrincipalCannotWriteOrCreate(t *testing.T) {
	f := readOnlyObservationFixture(t, false)
	violations := make(chan error, 4)
	nc, err := nats.Connect(f.options.Endpoint, nats.UserInfo(HealthUser, f.options.Password), nats.NoReconnect(),
		nats.Timeout(time.Second), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case violations <- err:
			default:
			}
		}))
	if err != nil {
		t.Fatal("read-only negative-control connection unavailable")
	}
	defer nc.Close()
	for _, subject := range []string{HealthSubject(f.options.HubID),
		"$JS." + f.options.Domain + ".API.STREAM.CREATE." + HealthStream(f.options.HubID)} {
		if _, err := nc.Request(subject, []byte("{}"), 50*time.Millisecond); err == nil {
			t.Fatal("read-only principal accepted a write or provisioning request")
		}
		select {
		case err := <-violations:
			if !errors.Is(err, nats.ErrPermissionViolation) {
				t.Fatal("negative control did not observe actual permission denial")
			}
		case <-time.After(time.Second):
			t.Fatal("negative control did not receive actual permission denial")
		}
	}
	nc.Close()
	f.assertConnections(t, 0)
	result, err := Observe(context.Background(), ObserveOptions{f.options, true})
	if err != nil || result.PersistenceEvidence != PersistenceUnknown || result.Code != "health_stream_absent" {
		t.Fatal("read-only positive observation failed after real denial controls")
	}
	f.assertConnections(t, 0)
}

func TestObserveInvalidRecordAndConfigurationAreNotRepaired(t *testing.T) {
	for _, mode := range []string{"record", "configuration"} {
		t.Run(mode, func(t *testing.T) {
			f := newHealthFixture(t, false)
			nc, js := f.connect(t)
			config := HealthConfig(f.options.HubID)
			if mode == "configuration" {
				config.MaxMsgs++
			}
			if _, err := js.AddStream(&config); err != nil {
				t.Fatal("controlled incompatible fixture unavailable")
			}
			if _, err := js.Publish(HealthSubject(f.options.HubID), []byte("private-record-payload")); err != nil {
				t.Fatal("controlled invalid record unavailable")
			}
			before, err := js.StreamInfo(config.Name)
			if err != nil {
				t.Fatal("controlled stream info unavailable")
			}
			result, err := Observe(context.Background(), ObserveOptions{f.options, true})
			if err == nil || result.PersistenceEvidence != PersistenceUnknown || result.RecordSequence != 0 {
				t.Fatal("invalid configuration or record accepted")
			}
			noObservationDisclosure(t, result, err, f.options)
			after, err := js.StreamInfo(config.Name)
			if err != nil || !reflect.DeepEqual(before.Config, after.Config) || !reflect.DeepEqual(before.State, after.State) {
				t.Fatal("observer tried to repair invalid persistence")
			}
			nc.Close()
			f.assertConnections(t, 0)
		})
	}
}

func TestObserveEarlierDeadlineAndValidationNeverCreateConnections(t *testing.T) {
	f := readOnlyObservationFixture(t, false)
	for _, mode := range []string{"nil-context", "cancelled", "expired", "invalid-timeout", "credential-endpoint"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			o := f.options
			switch mode {
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			case "invalid-timeout":
				o.Timeout = 6 * time.Second
			case "credential-endpoint":
				o.Endpoint = "nats://name:private-record-payload@127.0.0.1:4222"
			}
			result, err := Observe(ctx, ObserveOptions{o, true})
			if err == nil || result.BrokerVerified || result.PersistenceEvidence != PersistenceUnknown {
				t.Fatal("invalid or canceled input supplied observations")
			}
			noObservationDisclosure(t, result, err, o)
			f.assertConnections(t, 0)
		})
	}
	// A real TCP peer that withholds the NATS greeting proves connection work uses
	// the earlier overall deadline, not a new independent options timeout.
	endpoint, accepted, _ := stalledObservationPeer(t)
	o := f.options
	o.Endpoint = endpoint
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	begin := time.Now()
	result, err := Observe(ctx, ObserveOptions{o, true})
	if err == nil || result.BrokerVerified || time.Since(begin) > 500*time.Millisecond {
		t.Fatal("withheld greeting escaped the earlier total deadline")
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("stalled peer was not actually contacted")
	}
}

func stalledObservationPeer(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("controlled stalled peer unavailable")
	}
	accepted := make(chan struct{})
	finished := make(chan struct{})
	var connection net.Conn
	var mu sync.Mutex
	go func() {
		defer close(finished)
		client, err := listener.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		connection = client
		mu.Unlock()
		close(accepted)
	}()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			listener.Close()
			<-finished
			mu.Lock()
			if connection != nil {
				connection.Close()
			}
			mu.Unlock()
		})
	}
	t.Cleanup(cleanup)
	return "nats://" + listener.Addr().String(), accepted, cleanup
}

func TestObserveCancellationInterruptsAcceptedConnectionSetup(t *testing.T) {
	f := readOnlyObservationFixture(t, false)
	endpoint, accepted, cleanupPeer := stalledObservationPeer(t)
	o := f.options
	o.Endpoint = endpoint
	o.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	var result Observation
	var err error
	go func() {
		defer close(finished)
		result, err = Observe(ctx, ObserveOptions{o, true})
	}()
	t.Cleanup(func() {
		cancel()
		cleanupPeer()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("owned observation goroutine did not finish after socket cleanup")
		}
	})
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("stalled connection was not actually accepted")
	}
	begin := time.Now()
	cancel()
	select {
	case <-finished:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("caller cancellation waited for the much longer connection timeout")
	}
	if err == nil || result.BrokerVerified || time.Since(begin) > 500*time.Millisecond {
		t.Fatal("canceled setup returned observations or ignored cancellation")
	}
	noObservationDisclosure(t, result, err, o)
	f.assertConnections(t, 0)
}

func TestObserveDialerRefusesUnselectedOrReleasedSocketOwnership(t *testing.T) {
	endpoint, accepted, _ := stalledObservationPeer(t)
	unselectedEndpoint, unselectedAccepted, _ := stalledObservationPeer(t)
	selected, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("controlled selection unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialer := &observeDialer{ctx: ctx, address: selected.Host}
	defer dialer.close()
	unselected, err := url.Parse(unselectedEndpoint)
	if err != nil {
		t.Fatal("controlled unselected listener unavailable")
	}
	if connection, err := dialer.Dial("tcp", unselected.Host); err == nil ||
		err.Error() != "observe_endpoint_selection_mismatch" || connection != nil {
		t.Fatal("unselected endpoint was contacted")
	}
	select {
	case <-unselectedAccepted:
		t.Fatal("selection refusal contacted the live unselected listener")
	default:
	}
	dialer.close()
	if connection, err := dialer.Dial("tcp", selected.Host); err == nil || connection != nil {
		t.Fatal("released observation owner opened a new socket")
	}
	select {
	case <-accepted:
		t.Fatal("selection or closed-owner refusal still created a TCP connection")
	default:
	}
}
