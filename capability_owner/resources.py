"""Host-enrolled references to existing owners; never caller-selected subjects."""
from dataclasses import dataclass, field

from agentmux_contracts import ContractError
from state_owner.artifacts import OwnerArtifacts
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject
from .workspace import WorkspaceRoot


@dataclass(frozen=True, repr=False)
class RetainedResource:
    binding: OwnerBinding = field(repr=False)
    ledger: OwnerLedger = field(repr=False)
    artifacts: OwnerArtifacts | None = field(default=None, repr=False)

    workspace: WorkspaceRoot | None = field(default=None, repr=False)

    def __post_init__(self):
        # Construction is host-private. The factory below binds both values to
        # the same existing stream without creating a second storage authority.
        if (not isinstance(self.binding, OwnerBinding) or not isinstance(self.ledger, OwnerLedger)
                or (self.artifacts is not None and not isinstance(self.artifacts, OwnerArtifacts))
                or (self.workspace is not None and not isinstance(self.workspace, WorkspaceRoot))):
            raise ContractError('capability_owner_configuration')

    @classmethod
    def open_existing(cls, jetstream, *, binding, stream, stream_identity, retention,
                      artifacts=None, workspace=None):
        if not isinstance(binding, OwnerBinding):
            raise ContractError('capability_owner_configuration')
        ledger = OwnerLedger(jetstream, stream=stream, subject=owner_subject(binding),
                             binding=binding, stream_identity=stream_identity,
                             retention=retention)
        return cls(binding, ledger, artifacts, workspace)

    def __repr__(self):
        return '<RetainedResource private>'

    def check_current(self):
        """Recheck borrowed owner custody at admission and disclosure."""
        if self.workspace is not None:
            self.workspace.check_files()
