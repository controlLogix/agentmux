"""Private immutable bytes for authority-owned secret references.

The identity owner decides which reference generation is current. This module
stores only immutable private bytes and their integrity binding. It stores no
active pointer, revocation state, grant, or independently mutable public record.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import time

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from native_security.descriptor_admission import (AdmissionError, DescriptorPurpose,
                                                   check_descriptor)


_ID = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KINDS = frozenset(("nats-administrator-credential", "nats-account-issuer"))
_FILE_LIMIT = 131_072
SECRET_LIMIT = 65_536


def _fail(code="secret_custody_invalid"):
    raise ContractError(code)


def _admit(fd, purpose):
    try:
        check_descriptor(fd, purpose=purpose, deadline=time.monotonic() + 1)
    except AdmissionError:
        _fail("secret_custody_native_refused")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _binding(value):
    """Validate private binding input supplied from current owner authority."""
    try:
        value = strict_loads(canonical_bytes(value))
        required = {"ref", "kind", "scope", "profileId", "ownerIdentityRef",
                    "accountRef", "administratorTransportRef", "accountPublicKey",
                    "issuedAt", "expiresAt", "accountIssuedAt", "accountExpiresAt"}
        ref, owner, scope = value["ref"], value["ownerIdentityRef"], value["scope"]
        account, transport = value["accountRef"], value["administratorTransportRef"]
        start, end, account_start, account_end = (datetime.fromisoformat(value[name])
            for name in ("issuedAt", "expiresAt", "accountIssuedAt", "accountExpiresAt"))
        if (set(value) != required or set(ref) != {"id", "ownerHubId", "revision"}
                or set(owner) != {"id", "ownerHubId", "revision"}
                or set(account) != {"id", "ownerHubId", "revision"}
                or set(transport) != {"id", "ownerHubId", "revision"}
                or set(scope) != {"organizationId", "projectId", "workspaceId"}
                or value["kind"] not in _KINDS
                or any(type(v) is not str or not _ID.fullmatch(v)
                       for v in (ref["id"], ref["ownerHubId"], value["profileId"],
                                 owner["id"], owner["ownerHubId"],
                                 account["id"], account["ownerHubId"],
                                 transport["id"], transport["ownerHubId"],
                                 scope["organizationId"], scope["projectId"]))
                or len({ref["ownerHubId"], owner["ownerHubId"], account["ownerHubId"],
                        transport["ownerHubId"]}) != 1
                or type(ref["revision"]) is not int or not 1 <= ref["revision"] <= 9_007_199_254_740_991
                or type(owner["revision"]) is not int or not 1 <= owner["revision"] <= 9_007_199_254_740_991
                or type(account["revision"]) is not int or not 1 <= account["revision"] <= 9_007_199_254_740_991
                or type(transport["revision"]) is not int or not 1 <= transport["revision"] <= 9_007_199_254_740_991
                or scope["workspaceId"] is not None
                or type(value["accountPublicKey"]) is not str
                or not re.fullmatch(r"A[A-Z2-7]{55}", value["accountPublicKey"])
                or start.tzinfo is None or end.tzinfo is None
                or start.utcoffset() != timezone.utc.utcoffset(start)
                or end.utcoffset() != timezone.utc.utcoffset(end) or start >= end):
            raise ValueError
        for first, last in ((start, end), (account_start, account_end)):
            if (first.tzinfo is None or last.tzinfo is None
                    or first.utcoffset() != timezone.utc.utcoffset(first)
                    or last.utcoffset() != timezone.utc.utcoffset(last) or first >= last):
                raise ValueError
        return value, canonical_bytes(value)
    except Exception:
        _fail()


def _open_root(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        _fail()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        _admit(fd, DescriptorPurpose.PRIVATE_ANCESTOR)
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            _admit(fd, DescriptorPurpose.PRIVATE_ANCESTOR)
        _admit(fd, DescriptorPurpose.PRIVATE_DIRECTORY)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_namespace(root, name, *, create):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, 0o700, dir_fd=root)
            os.fsync(root)
        except FileExistsError:
            pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
    try:
        _admit(fd, DescriptorPurpose.PRIVATE_DIRECTORY)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_file(directory, name):
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= _FILE_LIMIT):
            _fail("secret_custody_changed")
        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
        raw = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
        if len(raw) != before.st_size or _identity(before) != _identity(after):
            _fail("secret_custody_changed")
        return raw
    except FileNotFoundError:
        raise
    except ContractError:
        raise
    except Exception:
        _fail("secret_custody_unavailable")
    finally:
        if fd is not None:
            os.close(fd)


def _envelope(binding, binding_bytes, secret):
    if type(secret) is not bytes or not 0 < len(secret) <= SECRET_LIMIT:
        _fail()
    raw = canonical_bytes({"format": "agentmux-secret-custody-v1", "binding": binding,
        "bindingSha256": "sha256:" + hashlib.sha256(binding_bytes).hexdigest(),
        "secretBase64": base64.b64encode(secret).decode("ascii")})
    if len(raw) > _FILE_LIMIT:
        _fail()
    return raw


def _decode(raw, expected_binding, expected_bytes):
    try:
        value = strict_loads(raw)
        if (set(value) != {"format", "binding", "bindingSha256", "secretBase64"}
                or value["format"] != "agentmux-secret-custody-v1"
                or canonical_bytes(value["binding"]) != expected_bytes
                or not _DIGEST.fullmatch(value["bindingSha256"])
                or value["bindingSha256"] != "sha256:" + hashlib.sha256(expected_bytes).hexdigest()):
            raise ValueError
        secret = base64.b64decode(value["secretBase64"], validate=True)
        if not 0 < len(secret) <= SECRET_LIMIT or value["binding"] != expected_binding:
            raise ValueError
        return secret
    except Exception:
        _fail("secret_custody_changed")


class PrivateSecret:
    """Secret bytes that cannot be serialized or displayed accidentally."""
    __slots__ = ("_value",)

    def __init__(self, value):
        if type(value) is not bytes:
            _fail()
        object.__setattr__(self, "_value", value)

    def __setattr__(self, name, value):
        raise AttributeError("PrivateSecret is immutable.")

    def __repr__(self):
        return "<PrivateSecret private>"

    def __reduce__(self):
        raise TypeError("PrivateSecret cannot be serialized.")

    def private_copy(self):
        return memoryview(self._value).tobytes()


class _ImmutableSecretStore:
    """Descriptor-safe storage for immutable, generation-bound secret bytes.

    Callers must obtain ``binding`` from current identity-owner authority. This
    primitive deliberately cannot decide whether a generation is active.
    """
    def __init__(self, root):
        root = Path(root)
        fd = _open_root(root)
        os.close(fd)
        self._root = root

    def __repr__(self):
        return "<_ImmutableSecretStore private>"

    def provision(self, binding, secret):
        try:
            return self._provision(binding, secret)
        except ContractError:
            raise
        except BaseException:
            _fail("secret_custody_unavailable")

    def _provision(self, binding, secret):
        binding, binding_bytes = _binding(binding)
        expected = _envelope(binding, binding_bytes, secret)
        root = _open_root(self._root)
        namespace = None
        try:
            try:
                fcntl.flock(root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("secret_custody_busy")
            owner = _open_namespace(root, binding["ref"]["ownerHubId"], create=True)
            try:
                namespace = _open_namespace(owner, binding["ref"]["id"], create=True)
            finally:
                os.close(owner)
            name = str(binding["ref"]["revision"]) + ".secret"
            try:
                existing = _read_file(namespace, name)
            except FileNotFoundError:
                fd = None
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW, 0o600, dir_fd=namespace)
                    _admit(fd, DescriptorPurpose.PRIVATE_FILE)
                    offset = 0
                    while offset < len(expected):
                        count = os.write(fd, expected[offset:])
                        if count <= 0:
                            _fail("secret_custody_write_uncertain")
                        offset += count
                    os.fsync(fd)
                except FileExistsError:
                    pass
                except ContractError:
                    raise
                except Exception:
                    _fail("secret_custody_write_uncertain")
                finally:
                    if fd is not None:
                        os.close(fd)
                os.fsync(namespace)
                existing = _read_file(namespace, name)
            if existing != expected:
                _fail("secret_custody_recovery_required")
            _decode(existing, binding, binding_bytes)
            return strict_loads(canonical_bytes(binding["ref"]))
        finally:
            if namespace is not None:
                os.close(namespace)
            try:
                fcntl.flock(root, fcntl.LOCK_UN)
            finally:
                os.close(root)

    def resolve(self, binding):
        try:
            return self._resolve(binding)
        except ContractError:
            raise
        except BaseException:
            _fail("secret_custody_unavailable")

    def _resolve(self, binding):
        binding, binding_bytes = _binding(binding)
        root = _open_root(self._root)
        namespace = None
        try:
            try:
                fcntl.flock(root, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("secret_custody_busy")
            owner = _open_namespace(root, binding["ref"]["ownerHubId"], create=False)
            try:
                namespace = _open_namespace(owner, binding["ref"]["id"], create=False)
            finally:
                os.close(owner)
            raw = _read_file(namespace, str(binding["ref"]["revision"]) + ".secret")
            return PrivateSecret(_decode(raw, binding, binding_bytes))
        except FileNotFoundError:
            _fail("secret_custody_unavailable")
        finally:
            if namespace is not None:
                os.close(namespace)
            try:
                fcntl.flock(root, fcntl.LOCK_UN)
            finally:
                os.close(root)

    def recover(self, binding):
        """Confirm one complete immutable generation without returning its bytes."""
        self.resolve(binding)
        value, _ = _binding(binding)
        return strict_loads(canonical_bytes(value["ref"]))


def _resolved_binding(snapshot, request_bytes, kind, now):
    """Resolve one exact current binding through the identity-owner contract."""
    try:
        from identity.application_account import resolve_snapshot
        from identity.authority import _active, _indexes, _key
        resolution = resolve_snapshot(snapshot, request_bytes,
            audience={"hubId": strict_loads(snapshot.record)["ownerHubId"],
                      "serviceId": "identity-owner"}, now=now)
        state = strict_loads(snapshot.record)["state"]
        index = _indexes(state, resolution.account_ref["ownerHubId"])
        account = index["applicationAccounts"][_key(resolution.account_ref)]
        reference = (resolution.administrator_credential_ref
                     if kind == "nats-administrator-credential"
                     else resolution.account_issuer_ref)
        secret = index["secretReferences"][_key(reference)]
        if kind not in _KINDS or secret["kind"] != kind or not _active(account, now) or not _active(secret, now):
            raise ValueError
        return {
            "ref": secret["ref"], "kind": secret["kind"], "scope": resolution.scope,
            "profileId": resolution.profile_id,
            "ownerIdentityRef": resolution.administrator_identity_ref,
            "accountRef": resolution.account_ref,
            "administratorTransportRef": resolution.administrator_transport_ref,
            "accountPublicKey": resolution.account_public_key,
            "issuedAt": secret["issuedAt"], "expiresAt": secret["expiresAt"],
            "accountIssuedAt": account["issuedAt"], "accountExpiresAt": account["expiresAt"],
        }
    except ContractError:
        raise
    except Exception:
        _fail("secret_custody_not_authorized")


def _proposed_binding(snapshot, request_bytes, kind, now):
    """Authorize and validate one proposed account generation before commit."""
    try:
        from agentmux_contracts import validate
        from identity.authority import evaluate_snapshot, _active
        from identity.transitions import transition
        request = strict_loads(request_bytes)
        validate("message-envelope", request)
        if request["contractId"] != "identity-application-account-set" or kind not in _KINDS:
            raise ValueError
        record = strict_loads(snapshot.record)
        if request["operation"]["expectedVersion"] != record["entityVersion"]:
            _fail("secret_custody_not_authorized")
        decision = evaluate_snapshot(snapshot, request_bytes,
            audience={"hubId": record["ownerHubId"], "serviceId": "identity-owner"}, now=now)
        if decision.outcome != "allowed" or decision.operation is None or decision.valid_until is None:
            _fail("secret_custody_not_authorized")
        payload = request["payload"]
        # Exercise the same pure transition that the identity owner will commit.
        transition(record["state"], request["contractId"], payload,
                   hub_id=record["ownerHubId"])
        account = payload["record"]
        name = ("administratorCredential" if kind == "nats-administrator-credential"
                else "accountIssuer")
        secret = payload[name]["record"]
        if (secret["kind"] != kind or not _active(account, now) or not _active(secret, now)
                or now >= decision.valid_until):
            _fail("secret_custody_not_authorized")
        return {
            "ref": secret["ref"], "kind": secret["kind"], "scope": account["scope"],
            "profileId": account["profileId"], "ownerIdentityRef": secret["ownerIdentityRef"],
            "accountRef": account["ref"],
            "administratorTransportRef": account["administratorTransportRef"],
            "accountPublicKey": account["accountPublicKey"],
            "issuedAt": secret["issuedAt"], "expiresAt": secret["expiresAt"],
            "accountIssuedAt": account["issuedAt"], "accountExpiresAt": account["expiresAt"],
        }
    except ContractError:
        raise
    except Exception:
        _fail("secret_custody_not_authorized")


class ScopedSecretCustody:
    """Use immutable local bytes only under current identity-owner authority."""
    def __init__(self, root, authority):
        from identity.authority import LedgerAuthorityReader
        if type(authority) is not LedgerAuthorityReader:
            _fail("secret_custody_authority_required")
        self._authority = authority
        self._store = _ImmutableSecretStore(root)

    def __repr__(self):
        return "<ScopedSecretCustody private>"

    @staticmethod
    def _now(now):
        value = datetime.now(timezone.utc) if now is None else now
        if (not isinstance(value, datetime) or value.tzinfo is None
                or value.utcoffset() != timezone.utc.utcoffset(value)):
            _fail("secret_custody_invalid_clock")
        return value

    async def provision(self, request_bytes, *, kind, secret, now=None):
        first = await self._authority.current()
        binding = _proposed_binding(first, request_bytes, kind, self._now(now))
        result = self._store.provision(binding, secret)
        second = await self._authority.current()
        current = _proposed_binding(second, request_bytes, kind, self._now(now))
        if canonical_bytes(current) != canonical_bytes(binding):
            _fail("secret_custody_not_authorized")
        return result

    async def resolve(self, request_bytes, *, kind, now=None):
        first = await self._authority.current()
        binding = _resolved_binding(first, request_bytes, kind, self._now(now))
        private = self._store.resolve(binding)
        second = await self._authority.current()
        current = _resolved_binding(second, request_bytes, kind, self._now(now))
        if canonical_bytes(current) != canonical_bytes(binding):
            _fail("secret_custody_not_authorized")
        return private

    async def recover(self, request_bytes, *, kind, now=None):
        first = await self._authority.current()
        binding = _resolved_binding(first, request_bytes, kind, self._now(now))
        result = self._store.recover(binding)
        second = await self._authority.current()
        current = _resolved_binding(second, request_bytes, kind, self._now(now))
        if canonical_bytes(current) != canonical_bytes(binding):
            _fail("secret_custody_not_authorized")
        return result
