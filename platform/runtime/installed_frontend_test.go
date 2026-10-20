package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

type frontendTestFile struct {
	file  *os.File
	calls int
}

func (f *frontendTestFile) close() error { f.calls++; return f.file.Close() }

func TestInstalledFrontendCloseConsumesOwnerAndKeepsPrivateFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "private-close-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	owner := &frontendTestFile{file: file}
	image := &InstalledFrontendImage{image: owner}
	first := image.Close()
	if first == nil || !errors.Is(first, ErrStartupCleanup) || !errors.Is(first, os.ErrClosed) {
		t.Fatal("concrete consumed close failure lost", first)
	}
	if second := image.Close(); second != first || owner.calls != 1 || image.image != nil {
		t.Fatal("consumed close was retried or failure changed")
	}
	raw, err := json.Marshal(first)
	if err != nil || string(raw) != `"installed_frontend_close_failed"` {
		t.Fatal("close failure JSON was not closed", err)
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		text := fmt.Sprintf(format, first)
		if strings.Contains(text, file.Name()) || text != "installed_frontend_close_failed" {
			t.Fatal("private close detail exposed")
		}
	}
}

func TestInstalledFrontendOnlyExposesAdmissionAndClose(t *testing.T) {
	typ := reflect.TypeOf((*InstalledFrontendImage)(nil))
	if typ.NumMethod() != 2 || typ.Method(0).Name != "Close" || typ.Method(1).Name != "Recheck" {
		t.Fatal("frontend admission exposed execution capability")
	}
	var empty *InstalledFrontendImage
	if empty.Close() != nil || (&InstalledFrontendImage{}).Close() != nil {
		t.Fatal("empty frontend close failed")
	}
}

type frontendTestValidation struct {
	context       context.Context
	calls, closes int
	failure       error
}

func (f *frontendTestValidation) close() error { f.closes++; return nil }
func (f *frontendTestValidation) validateForStart(ctx context.Context) error {
	f.context = ctx
	f.calls++
	return f.failure
}

func TestInstalledFrontendRecheckUsesRetainedValidatorAndOriginalContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &frontendTestValidation{}
	image := &InstalledFrontendImage{image: owner}
	if err := image.Recheck(ctx); err != nil || owner.calls != 1 || owner.context != ctx || owner.closes != 0 {
		t.Fatal("recheck did not use original retained validation", err)
	}
	private := errors.New("private frontend admission details")
	owner.failure = private
	err := image.Recheck(ctx)
	if err == nil || !errors.Is(err, private) || owner.calls != 2 {
		t.Fatal("validation cause lost", err)
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, err), private.Error()) {
			t.Fatal("private validation detail exposed")
		}
	}
	raw, encodeErr := json.Marshal(err)
	if encodeErr != nil || strings.Contains(string(raw), private.Error()) {
		t.Fatal("private validation JSON exposed", encodeErr)
	}
	if image.Close() != nil || owner.closes != 1 {
		t.Fatal("retained validation owner was not closed")
	}
	if err := image.Recheck(ctx); err == nil || owner.calls != 2 {
		t.Fatal("closed owner was validated")
	}
}

func TestInstalledFrontendRecheckRejectsIncompleteAdmission(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	owner := &frontendTestValidation{}
	image := &InstalledFrontendImage{image: owner}
	for _, invalid := range []context.Context{nil, ctx} {
		if image.Recheck(invalid) == nil || owner.calls != 0 {
			t.Fatal("invalid context reached validation")
		}
	}
	var absent *InstalledFrontendImage
	if absent.Recheck(context.Background()) == nil || (&InstalledFrontendImage{}).Recheck(context.Background()) == nil {
		t.Fatal("missing admission rechecked")
	}
	// A closer alone does not establish an admitted executable.
	plain := &InstalledFrontendImage{image: &frontendTestFile{}}
	if plain.Recheck(context.Background()) == nil {
		t.Fatal("nonvalidating owner admitted")
	}
}
