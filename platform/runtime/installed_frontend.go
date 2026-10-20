package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

const StableFrontendPath = "/Library/Application Support/Agentmux/Protected/agentmux-runtime"

// InstalledFrontendImage retains admission descriptors only. It cannot start a
// host, expose descriptors or authorize an application command. The creator
// remains responsible for exact process creation, pinning and joined cleanup.
type InstalledFrontendImage struct {
	mu           sync.Mutex
	image        interface{ close() error }
	closeFailure error
}

type installedFrontendFailure struct {
	code  string
	cause error
}

func (e *installedFrontendFailure) Error() string                { return "installed_frontend_" + e.code }
func (e *installedFrontendFailure) Unwrap() error                { return e.cause }
func (e *installedFrontendFailure) Format(s fmt.State, _ rune)   { fmt.Fprint(s, e.Error()) }
func (e *installedFrontendFailure) MarshalJSON() ([]byte, error) { return json.Marshal(e.Error()) }

// Recheck requires the admitted file and its protected parents to retain their
// identities. It does not authorize process creation or host startup.
func (image *InstalledFrontendImage) Recheck(ctx context.Context) error {
	if image == nil || ctx == nil || ctx.Err() != nil {
		return &installedFrontendFailure{code: "recheck_invalid"}
	}
	image.mu.Lock()
	defer image.mu.Unlock()
	backend, ok := image.image.(interface{ validateForStart(context.Context) error })
	if !ok {
		return &installedFrontendFailure{code: "recheck_invalid"}
	}
	if err := backend.validateForStart(ctx); err != nil {
		return &installedFrontendFailure{"recheck_failed", err}
	}
	return nil
}

func (image *InstalledFrontendImage) Close() error {
	if image == nil {
		return nil
	}
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.image != nil {
		err := image.image.close()
		image.image = nil
		if err != nil {
			image.closeFailure = &installedFrontendFailure{"close_failed", errors.Join(err, ErrStartupCleanup)}
		}
	}
	return image.closeFailure
}
