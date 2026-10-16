//go:build darwin && cgo && agentmux_bootstrap_docker

package darwinfixtureidentity

import (
	"github.com/controlLogix/agentmux/platform/kernel/protocol"
	protected "github.com/controlLogix/agentmux/platform/runtime"
	"testing"
)

func TestRoleArgumentsRequireExactRosterAndCopy(t *testing.T) {
	args := make(map[string][]string)
	for _, role := range protocol.Roles() {
		args[role] = []string{"literal"}
	}
	copied, err := snapshotRoleArguments(args)
	if err != nil {
		t.Fatal(err)
	}
	for role := range args {
		args[role][0] = "changed"
		if copied[role][0] != "literal" {
			t.Fatal("caller mutation changed admitted arguments")
		}
		break
	}
	args["extra"] = nil
	if _, err := snapshotRoleArguments(args); err == nil {
		t.Fatal("extra role admitted")
	}
	delete(args, "extra")
	for role := range args {
		delete(args, role)
		break
	}
	args["wrong-role"] = nil
	if _, err := snapshotRoleArguments(args); err == nil {
		t.Fatal("substituted role admitted")
	}
}
func TestAssemblyOwnerKeepsImagesUntilLastReference(t *testing.T) {
	owner := &assemblyOwner{prepared: &protected.Prepared{}, refs: 1}
	owner.retain()
	owner.retain()
	if err := owner.release(); err != nil || owner.consumed {
		t.Fatal("images consumed before proofs close")
	}
	if err := owner.release(); err != nil || owner.consumed {
		t.Fatal("images consumed with remaining proof")
	}
	if err := owner.release(); err != nil || !owner.consumed {
		t.Fatal("last proof did not consume owner")
	}
	refs := owner.refs
	if err := owner.release(); err != nil || owner.refs != refs {
		t.Fatal("consumed owner released twice")
	}
}

func TestRuntimeRoleArgumentsKeepImageAndLiteralAliasSeparate(t *testing.T) {
	for _, role := range protocol.Roles() {
		item := expectedImage{Path: "/protected/bin/" + role, Digest: "fixed", argv0: "agentmux-" + role, Args: []string{"literal"}}
		want := []string{"agentmux-" + role, "literal"}
		if !matchesArguments(item, item.Path, want) {
			t.Fatal("exact runtime role invocation refused")
		}
		for _, wrong := range [][]string{{item.Path, "literal"}, {"agentmux-foreign", "literal"}, {"agentmux-" + role}, {"agentmux-" + role, "changed"}, {"agentmux-" + role, "literal", "extra"}} {
			if matchesArguments(item, item.Path, wrong) {
				t.Fatal("wrong role alias or argument tail admitted")
			}
		}
		if matchesArguments(item, "/other/image", want) {
			t.Fatal("role alias bypassed native executable path")
		}
		proof := &Proof{proofState: &proofState{valid: true, expected: item}}
		got := proof.LiteralArgs()
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatal("proof changed admitted literal arguments")
		}
		got[0] = "mutated"
		if proof.LiteralArgs()[0] != want[0] {
			t.Fatal("proof arguments escaped by reference")
		}
		fixture := expectedImage{Path: item.Path, Args: item.Args}
		if !matchesArguments(fixture, fixture.Path, []string{fixture.Path, "literal"}) || matchesArguments(fixture, fixture.Path, want) {
			t.Fatal("private cooperative invocation mode widened")
		}
	}
}
