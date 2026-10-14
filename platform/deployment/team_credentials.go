package deployment

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/controlLogix/agentmux/platform/kernel/protocol"
)

// This host-selected policy identifies dedicated team credentials, not provider
// authentication. Reference/scope equality is a binding check, not a permission.
type TeamPrivateCredentialPolicy struct {
	Directory      string
	OwnerUID       uint32
	WorkspaceRoots []string
	Reference      TeamCredentialReference
	Scope          TeamScope
}
type PrivateTeamCredentialResolver struct{ policy TeamPrivateCredentialPolicy }
type teamCredentialDocument struct {
	SchemaVersion        string                  `json:"schemaVersion"`
	Reference            TeamCredentialReference `json:"reference"`
	Scope                TeamScope               `json:"scope"`
	DecoratedCredentials string                  `json:"decoratedCredentials,omitempty"`
	Username             string                  `json:"username,omitempty"`
	Password             string                  `json:"password,omitempty"`
}

func NewPrivateTeamCredentialResolver(policy TeamPrivateCredentialPolicy) (*PrivateTeamCredentialResolver, error) {
	if !filepath.IsAbs(policy.Directory) || filepath.Clean(policy.Directory) != policy.Directory || strings.ContainsAny(policy.Directory, "\x00\r\n") || int64(os.Geteuid()) != int64(policy.OwnerUID) || !identifier.MatchString(policy.Reference.ID) || (policy.Reference.AuthKind != TeamJWT && policy.Reference.AuthKind != TeamBasic) || len(policy.WorkspaceRoots) == 0 {
		return nil, teamError("private_policy_invalid")
	}
	resolved, err := filepath.EvalSymlinks(policy.Directory)
	if err != nil || resolved != policy.Directory {
		return nil, teamError("private_directory_invalid")
	}
	for _, workspace := range policy.WorkspaceRoots {
		if !filepath.IsAbs(workspace) {
			return nil, teamError("private_policy_invalid")
		}
		root, err := filepath.EvalSymlinks(workspace)
		if err != nil {
			return nil, teamError("private_policy_invalid")
		}
		rel, err := filepath.Rel(root, policy.Directory)
		if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return nil, teamError("private_directory_inside_workspace")
		}
	}
	policy.WorkspaceRoots = append([]string(nil), policy.WorkspaceRoots...)
	return &PrivateTeamCredentialResolver{policy: policy}, nil
}

func (resolver *PrivateTeamCredentialResolver) Resolve(ctx context.Context, reference TeamCredentialReference) (TeamCredential, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil {
		return TeamCredential{}, teamError("deadline")
	}
	p := resolver.policy
	if reference != p.Reference {
		return TeamCredential{}, teamError("credential_binding_invalid")
	}
	raw, err := teamReadPrivate(p.Directory, reference.ID+".json", p.OwnerUID)
	if err != nil {
		return TeamCredential{}, teamError("credential_unavailable")
	}
	if ctx.Err() != nil {
		return TeamCredential{}, teamError("deadline")
	}
	var document teamCredentialDocument
	if protocol.DecodeClosedJSON(raw, &document, 64*1024) != nil || document.SchemaVersion != "1.0.0" || document.Reference != reference || document.Scope != p.Scope {
		return TeamCredential{}, teamError("credential_binding_invalid")
	}
	if reference.AuthKind == TeamJWT {
		if document.Username != "" || document.Password != "" {
			return TeamCredential{}, teamError("credential_invalid")
		}
		return NewTeamJWTCredential(reference, p.Scope, []byte(document.DecoratedCredentials))
	}
	if document.DecoratedCredentials != "" {
		return TeamCredential{}, teamError("credential_invalid")
	}
	return NewTeamBasicCredential(reference, p.Scope, document.Username, document.Password)
}
func (*PrivateTeamCredentialResolver) String() string   { return "[private team credential resolver]" }
func (*PrivateTeamCredentialResolver) GoString() string { return "[private team credential resolver]" }
