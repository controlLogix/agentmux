"""Explicit local key custody and durable trusted receipts for one backup owner.

The host administrator chooses and protects three separate private directories.
This is filesystem key custody, not Keychain or off-volume qualification. No key
is generated implicitly, overwritten, rotated or deleted. Receipts carry no key
material. A receipt establishes a source watermark, not permission to run work.
"""
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from nacl.secret import SecretBox
from native_security.descriptor_admission import check_descriptor, DescriptorPurpose
from .backup import BackupReceipt, MAX_MANIFEST, OVERHEAD
from .checkpoints import _directory, _publish, _read, _digest
from .ledger import OwnerBinding, StreamIdentity
from .recovery import _binding

_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_MANIFEST = re.compile(r'backup-[a-f0-9]{32}\.box\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
_INVENTORY = re.compile(r'inventory-[a-f0-9]{32}\.json\Z')
MAX_ENTRIES = 100_000
MAX_ENTRY_BYTES = 65_536


def _native_guard(fd, *, directory=False, ancestor=False):
    # Shared native policy stays below hub and identity service dependencies.
    purpose = (DescriptorPurpose.PRIVATE_ANCESTOR if ancestor else
               DescriptorPurpose.PRIVATE_DIRECTORY if directory else DescriptorPurpose.PRIVATE_FILE)
    check_descriptor(fd, purpose=purpose, deadline=time.monotonic() + 1)


def _read_private(directory, name, limit):
    return _read(directory, name, limit, admit=_native_guard)


@dataclass(frozen=True, repr=False)
class InventoryEntry:
    receipt: BackupReceipt
    key_id: str
    completed_at: float
    source_identity: StreamIdentity

    def __repr__(self):
        return '<InventoryEntry private>'


class BackupHost:
    def __init__(self, backup_directory, inventory_directory, key_directory, *,
                 destination_id, binding, stream_identity):
        try:
            if (not isinstance(destination_id, str) or not _ID.fullmatch(destination_id)
                    or not isinstance(binding, OwnerBinding) or not isinstance(stream_identity, StreamIdentity)):
                raise ValueError()
            roots = tuple(Path(path) for path in (backup_directory, inventory_directory, key_directory))
            if any(not path.is_absolute() or '..' in path.parts for path in roots):
                raise ValueError()
            if any(first.is_relative_to(second) for i, first in enumerate(roots)
                   for j, second in enumerate(roots) if i != j):
                raise ValueError()
            self._roots, self._identities = roots, []
            ancestor_chains = []
            for root in roots:
                fd, _ = _directory(root / 'probe')
                try:
                    info = os.fstat(fd)
                    if stat.S_IMODE(info.st_mode) != 0o700:
                        raise ValueError()
                    self._identities.append((info.st_dev, info.st_ino))
                    ancestor_chains.append(self._ancestor_identities(fd))
                finally:
                    os.close(fd)
            if any(identity in ancestor_chains[j] for i, identity in enumerate(self._identities)
                   for j in range(len(roots)) if i != j):
                raise ValueError()
            self._destination_id, self._binding, self._stream_identity = destination_id, binding, stream_identity
        except Exception:
            raise ContractError('backup_host_configuration') from None

    @staticmethod
    def _ancestor_identities(directory):
        """Compare real ancestors, including case aliases, without following links."""
        current = os.dup(directory)
        identities = set()
        try:
            for index in range(1024):
                info = os.fstat(current)
                identity = (info.st_dev, info.st_ino)
                if identity in identities:
                    return identities
                _native_guard(current, directory=index == 0, ancestor=index != 0)
                identities.add(identity)
                parent = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                os.close(current)
                current = parent
            raise ValueError()
        finally:
            os.close(current)

    def __repr__(self):
        return '<BackupHost private>'

    @property
    def binding(self):
        return self._binding

    @property
    def stream_identity(self):
        return self._stream_identity

    @property
    def backup_directory(self):
        return self._roots[0]

    def _open(self, index):
        fd, _ = _directory(self._roots[index] / 'probe')
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._identities[index] or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError()
            self._ancestor_identities(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _key_name(key_id):
        if not isinstance(key_id, str) or not _ID.fullmatch(key_id):
            raise ValueError()
        return 'key-' + key_id + '.key'

    def enroll_key(self, key_id):
        """Explicit administrator action; uncertain publication never replaces a key."""
        directory = None
        try:
            name = self._key_name(key_id)
            directory = self._open(2)
            key = os.urandom(SecretBox.KEY_SIZE)
            _publish(directory, name, key, admit=_native_guard)
            if _read_private(directory, name, SecretBox.KEY_SIZE) != key:
                raise ValueError()
        except Exception:
            raise ContractError('backup_key_enrollment_uncertain') from None
        finally:
            if directory is not None:
                os.close(directory)

    def load_key(self, key_id):
        """Read only a previously enrolled private key; never create a missing one."""
        directory = None
        try:
            directory = self._open(2)
            key = _read_private(directory, self._key_name(key_id), SecretBox.KEY_SIZE)
            if len(key) != SecretBox.KEY_SIZE:
                raise ValueError()
            return key
        except Exception:
            raise ContractError('backup_key_unavailable') from None
        finally:
            if directory is not None:
                os.close(directory)

    def _receipt(self, receipt):
        if (not isinstance(receipt, BackupReceipt) or not isinstance(receipt.manifest_name, str)
                or not _MANIFEST.fullmatch(receipt.manifest_name)
                or not isinstance(receipt.digest, str) or not _DIGEST.fullmatch(receipt.digest)
                or type(receipt.cursor) is not int or not 1 <= receipt.cursor <= 9_007_199_254_740_991):
            raise ValueError()

    def _bundle(self, receipt, key_id):
        """Bind the receipt to authenticated top metadata; parts need restore sampling."""
        directory = None
        try:
            key = self.load_key(key_id)
            directory = self._open(0)
            ciphertext = _read_private(directory, receipt.manifest_name, MAX_MANIFEST + OVERHEAD)
            if _digest(ciphertext) != receipt.digest:
                raise ValueError()
            raw = SecretBox(key).decrypt(ciphertext)
            value = strict_loads(raw)
            if (canonical_bytes(value) != raw or type(value) is not dict
                    or set(value) != {'format', 'binding', 'source', 'cursor', 'checkpointDigest', 'components'}
                    or value['format'] != 'amx-owner-encrypted-backup-v1'
                    or value['binding'] != _binding(self._binding)
                    or type(value['source']) is not dict
                    or set(value['source']) != {'created', 'minimumSequence'}
                    or value['source']['created'] != self._stream_identity.created.isoformat()
                    or type(value['cursor']) is not int or value['cursor'] != receipt.cursor
                    or type(value['source']['minimumSequence']) is not int
                    or not 0 <= value['source']['minimumSequence'] <= receipt.cursor
                    or not isinstance(value['checkpointDigest'], str) or not _DIGEST.fullmatch(value['checkpointDigest'])
                    or type(value['components']) is not list or not 2 <= len(value['components']) <= 8192):
                raise ValueError()
            names = {receipt.manifest_name}
            for component in value['components']:
                if (type(component) is not dict
                        or set(component) != {'name', 'kind', 'plainBytes', 'plainDigest', 'cipherBytes', 'cipherDigest', 'logical', 'reference'}
                        or not isinstance(component['name'], str) or not _MANIFEST.fullmatch(component['name'])
                        or component['name'] in names or component['kind'] not in ('checkpoint', 'artifact')
                        or type(component['plainBytes']) is not int or not 0 <= component['plainBytes'] <= 67_108_864
                        or type(component['cipherBytes']) is not int
                        or component['cipherBytes'] != component['plainBytes'] + OVERHEAD
                        or not isinstance(component['plainDigest'], str) or not _DIGEST.fullmatch(component['plainDigest'])
                        or not isinstance(component['cipherDigest'], str) or not _DIGEST.fullmatch(component['cipherDigest'])):
                    raise ValueError()
                names.add(component['name'])
        finally:
            if directory is not None:
                os.close(directory)

    def _decode(self, raw):
        value = strict_loads(raw)
        if (canonical_bytes(value) != raw or type(value) is not dict
                or set(value) != {'format', 'binding', 'source', 'destinationId', 'completedAt', 'keyId', 'receipt'}
                or value['format'] != 'amx-owner-backup-inventory-v1'
                or value['binding'] != _binding(self._binding) or value['destinationId'] != self._destination_id
                or type(value['source']) is not dict or set(value['source']) != {'created', 'minimumSequence'}
                or value['source']['created'] != self._stream_identity.created.isoformat()
                or type(value['receipt']) is not dict or set(value['receipt']) != {'manifestName', 'digest', 'cursor'}
                or type(value['completedAt']) not in (int, float)
                or not math.isfinite(value['completedAt']) or value['completedAt'] < 0):
            raise ValueError()
        self._key_name(value['keyId'])
        receipt = BackupReceipt(value['receipt']['manifestName'], value['receipt']['digest'], value['receipt']['cursor'])
        self._receipt(receipt)
        if type(value['source']['minimumSequence']) is not int or value['source']['minimumSequence'] != receipt.cursor:
            raise ValueError()
        return InventoryEntry(receipt, value['keyId'], value['completedAt'],
                              StreamIdentity(self._stream_identity.created, receipt.cursor))

    def commit(self, receipt, *, key_id, completed_at):
        """Publish and read back a trusted receipt after checking its ciphertext."""
        inventory = backup = None
        try:
            self._receipt(receipt)
            self._key_name(key_id)
            if (receipt.cursor < self._stream_identity.minimum_sequence
                    or type(completed_at) not in (int, float) or not math.isfinite(completed_at) or completed_at < 0):
                raise ValueError()
            self._bundle(receipt, key_id)
            raw = canonical_bytes({'format': 'amx-owner-backup-inventory-v1', 'binding': _binding(self._binding),
                'source': {'created': self._stream_identity.created.isoformat(), 'minimumSequence': receipt.cursor},
                'destinationId': self._destination_id, 'completedAt': completed_at, 'keyId': key_id,
                'receipt': {'manifestName': receipt.manifest_name, 'digest': receipt.digest, 'cursor': receipt.cursor}})
            if len(raw) > MAX_ENTRY_BYTES:
                raise ValueError()
            inventory = self._open(1)
            name = 'inventory-' + secrets.token_hex(16) + '.json'
            _publish(inventory, name, raw, admit=_native_guard)
            reread = _read_private(inventory, name, MAX_ENTRY_BYTES)
            if reread != raw:
                raise ValueError()
            entry = self._decode(reread)
            os.fsync(inventory)
            return entry
        except Exception:
            raise ContractError('backup_inventory_commit_uncertain') from None
        finally:
            for directory in (inventory, backup):
                if directory is not None:
                    os.close(directory)

    def latest(self):
        """Return the greatest retained cursor; malformed owned entries fail closed.

        Lower-cursor entries remain historic even if published later. Completion
        time and filename break ties only within one cursor. The lifecycle must
        compare the selected cursor with the current trusted floor and
        create a fresh backup when this historic receipt is older.
        """
        directory = backup = None
        try:
            directory = self._open(1)
            selected = selected_key = None
            count = 0
            with os.scandir(directory) as entries:
                for item in entries:
                    if not item.name.startswith('inventory-'):
                        continue
                    count += 1
                    if count > MAX_ENTRIES or not _INVENTORY.fullmatch(item.name):
                        raise ValueError()
                    entry = self._decode(_read_private(directory, item.name, MAX_ENTRY_BYTES))
                    order = (entry.receipt.cursor, entry.completed_at, item.name)
                    if selected_key is None or order > selected_key:
                        selected, selected_key = entry, order
            if selected is not None:
                self._bundle(selected.receipt, selected.key_id)
                # Reconcile a prior uncertain link publication before offering it.
                os.fsync(directory)
            return selected
        except Exception:
            raise ContractError('backup_inventory_unavailable') from None
        finally:
            for descriptor in (directory, backup):
                if descriptor is not None:
                    os.close(descriptor)
