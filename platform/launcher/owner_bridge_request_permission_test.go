//go:build linux || darwin

package launcher

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestOwnerBridgeDefaultRequestPermissionFailureStaysHard(t *testing.T) {
	for _, denial := range []string{"publish", "reply_subscribe"} {
		t.Run(denial, func(t *testing.T) {
			f := newBridgeFixture(t)
			f.startBroker(t)
			client, err := LoadOwnerBridgeClient(f.config, f.enrollment)
			if err != nil {
				t.Fatal("actual enrolled default client refused")
			}
			// These private negative mutations exercise real broker permissions. No
			// installed API exposes caller-selected subjects or reply routing.
			if denial == "publish" {
				client.subjects.Request = "$SYS.REQ.SERVER.PING"
			} else {
				client.subjects.ReplyPrefix = "$SYS.denied.reply."
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			observation, err := client.Request(ctx, "status", "attempt_"+strings.Repeat("a", 32))
			if err == nil || !IsOwnerBridgeAuthorityError(err) || err.Error() != "owner_bridge_authority_rejected" || observation.Disposition != "" || ProjectRequestDiagnostic(err).Code != "runtime_authority_rejected" {
				t.Fatal("actual permission denial became unavailable status or a historical/progress fallback")
			}
		})
	}
}
