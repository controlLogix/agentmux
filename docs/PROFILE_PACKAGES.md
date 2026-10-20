# Project profile examples

This profile adoption boundary belongs to
[AMUX-43](https://adag-csai.atlassian.net/browse/AMUX-43). It follows the actual
ADAG Design Patterns 0.5.3
[assessment](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/assess/SKILL.md),
[guidance](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/guide/SKILL.md)
and [refactoring](https://github.com/csai-bms/marketplace/blob/main/plugins/design-patterns/skills/refactor/SKILL.md)
skills. The domain adapter reuses the parser and scoped writer. The
`ProfilePackagePreview` organism owns presentation; its feature owns HTTP reads.
The local command establishes OS-owner admission separately from team approval
and the future authenticated human request boundary. Jira holds review findings;
no separate pattern registry, generated diagram or evidence gate is required.

The 14 Markdown profiles under `.agentmux/agents` are examples, not default project
membership. The catalogue groups the survey profiles, Agora profiles, orchestration
profile and network reviewer into four descriptive packages. These labels do not
register runnable plugins or grant access. Opening a repository, enrolling a local
runtime or recruiting a team does not adopt these examples globally.

The Agents page has a read-only package preview. It shows the project directory,
source revision, example project, historical task aliases, requested permissions,
client requirements and machine-specific path references. Historical aliases remain
references; this feature imports no tasks, claims or live work. Profile prose is
data to review, never instructions for the preview or adoption command.

## Explicit local-owner adoption

Use the prepared native macOS ARM64 Python runtime to run
`taskmgmt/profilecli.py`. This command checks equal real/effective OS user IDs,
the canonical project and its held directory ancestry, native ACLs, local mount
ownership policy and private record permissions. It establishes operating-system
ownership only. It does not authenticate an enrolled human, organization or team.
The HTTP endpoint has no adoption mutation and cannot construct this authority
from an actor label or submitted user/project fields.

1. Run `python3 taskmgmt/profilecli.py catalog --project /absolute/project`.
2. Create a private request file in an owner-only 0700 directory. Its mode must be
   0600, with one link and no ACL access grants. Use the observed source checksum.
3. Run `python3 taskmgmt/profilecli.py preview --project /absolute/project --request /absolute/private/request.json`.
   Review the output, including path warnings, permissions and client limitations.
4. Run the same request with `adopt` and pass the exact observed
   `--approval-checksum` and `--record-checksum`. Any intervening source, selected
   executable, request or record revision change refuses the mutation.

For example, a request selecting one survey worker has this shape:

```json
{
  "schemaVersion": "1.0.0",
  "clients": {"codex": "/absolute/canonical/client-executable"},
  "selections": [{
    "packageId": "example.survey",
    "name": "scan-dev",
    "relationship": "independent",
    "parentPackage": null,
    "sourceChecksum": "sha256:THE_OBSERVED_SOURCE_CHECKSUM",
    "overrides": {
      "paths": {},
      "execution": {"posture": "read-only", "worktree": "none", "maxInstances": 1}
    }
  }]
}
```

`clients` contains explicitly selected canonical executable paths. Preview checks
their bounded regular-file bytes and records their checksum; it does not execute
them or establish provider compatibility. The actual spawn path still checks
supported posture and client options. Named tool restrictions unsupported by a
client remain visible intent, not enforcement. No permission grant is created.

The execution override requires a bounded existing posture (`read-only` or
`workspace-write`), existing worktree policy and an instance limit from 1 through 8.
This adds no CPU, memory, time or network sandbox. Unsupported execution fields
are rejected. An administrator can map an exact original path reference to an
explicit replacement in `paths`; only the derived description/persona changes.
Path replacement does not grant filesystem or network access. The original
source bytes, parsed fields and source checksum remain unchanged. A separate
derived checksum identifies effective overrides.

`parent-owned` requires an explicit different `parentPackage` label. It describes
profile package ownership; it is not proof that a process parent is running or
authorized. Runtime parent/child supervision belongs to the ordinary plugin
manager, which verifies its own instance topology and owner references. An
independent adoption has no parent. Neither form borrows another package's
credentials or permissions.

## Storage, changes and recovery

The same definition service owns the private project record at
`.agentmux/profile-adoptions/record.json`. Its directory is 0700 and the record is
0600 with one link. It retains original and derived snapshots, exact source
revisions, explicit ownership declarations and OS-owner provenance. It contains
personas: do not publish it. Public lists and preview responses contain no persona
or source bytes. Filesystem/network scanners require this explicit adoption too.

Adoption replaces the selected membership set; an empty selection explicitly
removes membership. It never follows later source edits automatically. Changing
or removing adoption does not edit existing proposed, approved or hired team
snapshots, approvals, processes, worktrees or work. Existing team approval and
hiring checks still apply. To use a changed revision for future team work, make an
explicit new proposal and approval through those existing entry points.

The writer uses a directory lock shared by independent command processes, a
checked record revision and an atomic replacement. Concurrent requests with the
same prior revision have one winner. Preview alone cancels without writing.
Invalid, stale or conflicting candidates preserve the original record. Source
profiles are read-only through the product writer; arbitrary user definitions in
other repositories keep their existing discovery and collision behavior.

Descriptor, ACL, source and record identities are rechecked before trust or
mutation. This local file compatibility store is not isolation from malicious
code already running as the same OS user. A failure after atomic replacement or
during descriptor/directory cleanup leaves the outcome uncertain; reread the
checked record before retrying. Do not delete unrelated files or retry a consumed
numeric descriptor. Unsupported platforms fail admission; these checks do not
qualify Linux, Windows, macOS AMD64 or every provider client.

The separate authenticated human-edit requirement remains with AMUX-41 and its
identity prerequisites. Local-owner adoption does not complete that requirement.
