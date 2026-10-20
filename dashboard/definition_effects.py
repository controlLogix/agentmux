"""Private file-effect preconditions retained through owner-controlled artifacts.

These are recovery data, not credentials or a second command schema. The effect
in the owner record remains the registered, signed definition-save/drop payload.
"""
import hashlib
import os
import re
import stat

from agentmux_contracts import ContractError, canonical_bytes
from definition_service import _WRITE_LOCK

INTENT_MEDIA_TYPE = 'application/vnd.agentmux.definition-file-intent+json'
INTENT_KEYS = frozenset(('format', 'operationId', 'payloadDigest', 'definitionId', 'version',
                         'target', 'parents', 'sourceIdentity', 'sourceRef', 'targetRef'))


def _identity(info):
    # Creating/removing our own temporary file changes directory timestamps and
    # size. Only stable directory identity belongs in this recovery anchor.
    return [str(info.st_dev), str(info.st_ino)]


def target_anchor(service, prepared):
    root = service.scope.project_root if prepared.scope == 'repo' else service.scope.global_root
    if not root.is_dir():
        raise ContractError('definition_root_unavailable')
    relative = prepared.path.relative_to(root)
    parent = root
    parents = []
    for part in (None, *relative.parts[:-1]):
        if part is not None:
            parent = parent / part
        try:
            info = parent.stat() if part is None else parent.lstat()
        except FileNotFoundError:
            parents.append(None)
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise ContractError('definition_target_redirected')
        parents.append(_identity(info))
    target = 'sha256:' + hashlib.sha256(os.fsencode(root.resolve() / relative)).hexdigest()
    return target, parents


def capture_source(service, prepared):
    """Recheck the preflight under the same lock as every local file writer."""
    with _WRITE_LOCK:
        service._assert_revision(prepared.path, prepared.source.identity)
        target, parents = target_anchor(service, prepared)
        source = None if prepared.source.identity is None else [str(x) for x in prepared.source.identity]
        return target, parents, source


def validate_intent(intent, record, effect, entry):
    if (not isinstance(intent, dict) or set(intent) != INTENT_KEYS
            or intent['format'] != 'amx-definition-file-intent-v1'
            or intent['operationId'] != record['operation']['operationId']
            or intent['payloadDigest'] != record['operation']['payloadDigest']
            or intent['definitionId'] != entry['definitionId'] or type(intent['version']) is not int
            or intent['version'] != entry['version']
            or not isinstance(intent['target'], str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', intent['target'])
            or not isinstance(intent['parents'], list) or not intent['parents']
            or (intent['sourceIdentity'] is None) != (effect['payload']['expectedChecksum'] is None)):
        raise ContractError('definition_intent_invalid')
    source_identity = intent['sourceIdentity']
    if source_identity is not None and (not isinstance(source_identity, list) or len(source_identity) != 5
            or any(not isinstance(x, str) or not x.isdigit() for x in source_identity)):
        raise ContractError('definition_intent_invalid')
    for identity in intent['parents']:
        # Earlier v1 intents retained five directory stat fields. Read their
        # stable device/inode pair; never weaken the separate source-file check.
        if identity is not None and (not isinstance(identity, list) or len(identity) not in (2, 5)
                or any(not isinstance(x, str) or not x.isdigit() for x in identity)):
            raise ContractError('definition_intent_invalid')
    if intent['targetRef'] != entry['contentRef']:
        raise ContractError('definition_intent_invalid')
    source = intent['sourceRef']
    if ((source is None) != (intent['sourceIdentity'] is None)
            or (source is not None and (not isinstance(source, dict)
                or source.get('digest') != effect['payload']['expectedChecksum']))):
        raise ContractError('definition_intent_invalid')
    refs = record['artifacts']
    if any(ref is not None and ref not in refs for ref in (source, intent['targetRef'])):
        raise ContractError('definition_intent_invalid')
    # Also bounds every nested representation before the filesystem is touched.
    if len(canonical_bytes(intent)) > 65536:
        raise ContractError('definition_intent_invalid')


def apply_exact_source(service, prepared, intent, before_commit, writer):
    """Caller holds _WRITE_LOCK and has just rechecked retained/current authority.

    A changed parent or source requires reconciliation, even if bytes happen to
    match the desired result. Matching bytes cannot prove who performed an effect.
    """
    target, parents = target_anchor(service, prepared)
    source = None if prepared.source.identity is None else [str(x) for x in prepared.source.identity]
    retained_parents = [None if parent is None else parent[:2] for parent in intent['parents']]
    if (target != intent['target'] or parents != retained_parents or source != intent['sourceIdentity']):
        raise ContractError('definition_file_reconciliation_required')
    service._assert_revision(prepared.path, prepared.source.identity)
    service._mutate_locked(prepared, before_commit=before_commit, writer=writer)
    root = service.scope.project_root if prepared.scope == 'repo' else service.scope.global_root
    parent = prepared.path.parent
    while True:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | (0 if parent == root else os.O_NOFOLLOW))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if parent == root:
            break
        parent = parent.parent
