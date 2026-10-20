"""Identity checkpoint receipt; writer ownership belongs to the shared owner API."""
from dataclasses import dataclass
from state_owner.checkpoints import export_checkpoint_async


@dataclass(frozen=True, repr=False)
class CheckpointReceipt:
    manifest_path: str
    digest: str
    cursor: int


async def export_verified_prefix(path, history, binding, stream_identity, cursor):
    return await export_checkpoint_async(path, history, binding, stream_identity, through=cursor)
