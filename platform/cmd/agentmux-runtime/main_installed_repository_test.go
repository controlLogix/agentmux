//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type repositoryClientFixture struct {
	calls             []string
	execErr, closeErr error
}

func (o *repositoryClientFixture) Exec(_ context.Context, operation, path string) error {
	o.calls = append(o.calls, "selection:"+operation+":"+path)
	return o.execErr
}
func (o *repositoryClientFixture) ExecRepository(_ context.Context, operation, path string) error {
	o.calls = append(o.calls, "repository:"+operation+":"+path)
	return o.execErr
}
func (o *repositoryClientFixture) Close() error {
	o.calls = append(o.calls, "close")
	return o.closeErr
}
func TestInstalledRepositorySixOperationsAndSelectionPriority(t *testing.T) {
	for _, row := range []struct {
		command   string
		flags     []string
		operation string
	}{
		{"startup", nil, "startup"}, {"startup", []string{"--output", "json"}, "startup-json"},
		{"startup", []string{"--managed-worker"}, "startup-worker"}, {"startup", []string{"--managed-worker", "--output", "json"}, "startup-worker-json"},
		{"mcp", nil, "mcp"}, {"mcp", []string{"--managed-worker"}, "mcp-worker"},
	} {
		args := append([]string{row.command, "--client-installation", strings.Repeat("a", 64), "--repository-root", "/approved/répo with spaces"}, row.flags...)
		for _, explicit := range []bool{false, true} {
			selected := append([]string{}, args...)
			kind, path := "repository", "/approved/répo with spaces"
			if explicit {
				selected[4] = "relative-unused"
				selected = append(selected, "--selection", "/private/selected.json")
				kind, path = "selection", "/private/selected.json"
			}
			owner := &repositoryClientFixture{}
			err := runInstalledClientRequest(context.Background(), selected, func(_ context.Context, id string) (installedClientSession, error) {
				if id != strings.Repeat("a", 64) {
					t.Fatal("installation changed")
				}
				return owner, nil
			})
			if err != nil || !reflect.DeepEqual(owner.calls, []string{kind + ":" + row.operation + ":" + path, "close"}) {
				t.Fatal("literal handoff or owner order changed", err, owner.calls)
			}
		}
	}
}
func TestInstalledRepositoryRefusesBeforeAdmissionAndRetainsPartialOwner(t *testing.T) {
	base := []string{"startup", "--client-installation", strings.Repeat("a", 64), "--repository-root", "/approved/repo"}
	for _, root := range []string{"/", "//root", "relative", "/root/../repo", "/root/\u0080repo", "/" + strings.Repeat("a/", 127) + "a"} {
		args := append([]string{}, base...)
		args[4] = root
		if err := runInstalledClientRequest(context.Background(), args, func(context.Context, string) (installedClientSession, error) {
			t.Fatal("invalid root reached admission")
			return nil, nil
		}); err == nil {
			t.Fatal("invalid root accepted")
		}
	}
	for _, tail := range [][]string{{"--output", "yaml"}, {"--managed-worker=false"}, {"--selection", "/private/a", "--selection", "/private/b"}, {"--unexpected", "x"}} {
		if _, err := parseInstalledClientRequest(append(append([]string{}, base...), tail...)); err == nil {
			t.Fatal("unknown or repeated option accepted")
		}
	}
	for _, partial := range []bool{false, true} {
		owner := &repositoryClientFixture{execErr: errors.New("PRIVATE exec"), closeErr: errors.New("PRIVATE close")}
		err := runInstalledClientRequest(context.Background(), base, func(context.Context, string) (installedClientSession, error) {
			if partial {
				return owner, errors.New("PRIVATE admission")
			}
			return owner, nil
		})
		retained, ok := err.(*installedClientRequestFailure)
		if !ok || retained.owner != owner || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("failed cleanup lost original owner or exposed cause")
		}
		expected := []string{"repository:startup:/approved/repo", "close"}
		if partial {
			expected = []string{"close"}
		}
		if !reflect.DeepEqual(owner.calls, expected) {
			t.Fatal("partial owner reused or closed again", owner.calls)
		}
	}
}
