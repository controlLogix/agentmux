"""Owner-private, fixed Atlassian account check for ordinary Secret.Use.

The caller retains custody of PrivateSecret. This consumer holds its own reference
until the original I/O and readers have joined; release never mutates that shared
object. The enclosing owner journals intent and claim before calling start. A new
consumer cannot reconstruct or retry a claim from this process's private state.
"""
import asyncio
import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
import re
import ssl
import tempfile
import time

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from identity.ordinary_secret import OrdinarySecretAuthority
from native_security.secret_custody import PrivateSecret, SECRET_LIMIT
from taskmgmt.atlassian import whoami

_BODY_LIMIT = 65536
_MARKER = b'\nagentmux-secret-check:'
_ID = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
_CERTIFICATES = re.compile(rb'(?:-----BEGIN CERTIFICATE-----\r?\n'
    rb'[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+\Z')


def _refuse():
    raise ContractError('secret_consumer_refused') from None


def _now():
    return datetime.now(timezone.utc)


def _text(value, limit=512):
    return (type(value) is str and 0 < len(value) <= limit
            and all(ord(c) >= 32 and ord(c) != 127 for c in value))


@dataclass(frozen=True, slots=True, repr=False)
class AtlassianAccountCheckEnrollment:
    """Immutable host selection, never supplied by an operation or plugin."""
    record: bytes
    base_url: str
    deployment: str
    email: str | None
    expected_account: str
    trust_pem: bytes
    _url: str = field(init=False)

    def __post_init__(self):
        try:
            if (type(self.record) is not bytes or len(self.record) > 65536
                    or not _text(self.base_url, 2048)
                    or self.deployment not in ('cloud', 'server')
                    or not _text(self.expected_account)
                    or self.email is not None and not _text(self.email)
                    or type(self.trust_pem) is not bytes or not 0 < len(self.trust_pem) <= 65536
                    or not _CERTIFICATES.fullmatch(self.trust_pem)):
                _refuse()
            record = strict_loads(self.record)
            validate('identity-ordinary-secret-reference', record)
            if record['status'] != 'active' or record['scope']['projectId'] is None:
                _refuse()
            target = whoami({'deployment': self.deployment, 'base_url': self.base_url,
                'email': self.email, 'api_token': 'validation-only'}, dry_run=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=self.trust_pem.decode('ascii'))
            object.__setattr__(self, 'record', canonical_bytes(record))
            object.__setattr__(self, 'base_url', self.base_url.rstrip('/'))
            object.__setattr__(self, '_url', target['url'])
        except Exception:
            _refuse()

    def __repr__(self):
        return '<AtlassianAccountCheckEnrollment private selection>'

    def __reduce__(self):
        raise TypeError('Private consumer selection cannot be serialized.')


@dataclass(frozen=True, slots=True)
class SecretConsumerObservation:
    """Sanitized physical result. It is not permission for public disclosure."""
    status: str
    reason: str

    def __post_init__(self):
        if self.status not in ('accepted', 'rejected', 'uncertain') or self.reason not in (
                'account_matched', 'account_mismatch', 'authority_refused', 'http_refused',
                'response_refused', 'transport_uncertain', 'deadline_uncertain'):
            _refuse()


class _Use:
    __slots__ = ()

    def __repr__(self):
        return '<SecretConsumerUse private>'

    def __reduce__(self):
        raise TypeError('Private consumer use cannot be serialized.')


@dataclass(slots=True, repr=False)
class _Entry:
    envelope: bytes
    operation_id: str
    payload_digest: str
    claim_ref: str
    material: PrivateSecret | None
    material_digest: bytes
    deadline: float
    native_proof: object = None
    task: asyncio.Task | None = None
    result: SecretConsumerObservation | None = None
    released: bool = False
    prepared: bool = False


class AtlassianAccountCheckConsumer:
    """One fixed request per retained claim, with no injected transport/resolver."""
    def __init__(self, reader, enrollment):
        if type(enrollment) is not AtlassianAccountCheckEnrollment:
            _refuse()
        self._authority = OrdinarySecretAuthority(reader)
        self._enrollment = enrollment
        self._entries, self._operations = {}, {}
        self._closed = False

    def __repr__(self):
        return '<AtlassianAccountCheckConsumer private>'

    def __reduce__(self):
        raise TypeError('Private consumer cannot be serialized.')

    def _entry(self, handle):
        if type(handle) is not _Use or handle not in self._entries:
            _refuse()
        return self._entries[handle]

    async def _check(self, entry):
        remaining = entry.deadline - time.monotonic()
        if remaining <= 0:
            _refuse()
        try:
            resolution = await asyncio.wait_for(self._authority.resolve(entry.envelope, native_proof=entry.native_proof), remaining)
            operation = strict_loads(resolution.original_operation)
            if (resolution.record != self._enrollment.record
                    or operation['operationId'] != entry.operation_id
                    or operation['payloadDigest'] != entry.payload_digest
                    or time.monotonic() >= entry.deadline):
                _refuse()
            return resolution
        except asyncio.CancelledError:
            raise
        except Exception:
            _refuse()

    async def prepare(self, resolve_envelope, material, *, operation_id, payload_digest, claim_ref, native_proof=None):
        """Retain a private reference; the outer owner must journal before start."""
        import hashlib
        if (self._closed or type(resolve_envelope) is not bytes or len(resolve_envelope) > 65536
                or type(material) is not PrivateSecret
                or type(operation_id) is not str or not _ID.fullmatch(operation_id)
                or type(payload_digest) is not str or not _DIGEST.fullmatch(payload_digest)
                or type(claim_ref) is not str or not _ID.fullmatch(claim_ref)):
            _refuse()
        try:
            raw = material.private_copy()
            if not 0 < len(raw) <= SECRET_LIMIT:
                _refuse()
            token = raw.decode('utf-8')
            if not _text(token, SECRET_LIMIT):
                _refuse()
            digest = hashlib.sha256(raw).digest()
        except Exception:
            _refuse()
        # No await occurs while checking or reserving an existing original claim.
        existing = self._operations.get(operation_id)
        if existing is not None:
            entry = self._entry(existing)
            if (not entry.prepared or entry.released
                    or entry.envelope != resolve_envelope or entry.payload_digest != payload_digest
                    or entry.claim_ref != claim_ref or entry.material_digest != digest
                    or entry.native_proof != native_proof):
                _refuse()
            await self._check(entry)
            return existing
        if len(self._entries) >= 1024 or any(e.claim_ref == claim_ref for e in self._entries.values()):
            _refuse()
        # Reserve before the current read so concurrent prepares cannot create two jobs.
        handle = _Use()
        entry = _Entry(resolve_envelope, operation_id, payload_digest, claim_ref, material,
                       digest, time.monotonic() + 5, native_proof)
        self._entries[handle], self._operations[operation_id] = entry, handle
        try:
            resolution = await self._check(entry)
            remaining = (resolution.valid_until - _now()).total_seconds()
            entry.deadline = min(entry.deadline, time.monotonic() + remaining)
            if entry.deadline <= time.monotonic():
                _refuse()
            entry.prepared = True
            return handle
        except BaseException:
            # A refused or interrupted preparation remains a tombstone, never a retry.
            entry.released, entry.material = True, None
            raise

    def start(self, handle):
        entry = self._entry(handle)
        if self._closed or entry.released or not entry.prepared:
            _refuse()
        if entry.task is None:
            entry.task = asyncio.create_task(self._execute(entry), name='ordinary-secret-account-check')
        return handle

    async def wait(self, handle):
        entry = self._entry(handle)
        if entry.task is None or entry.released:
            _refuse()
        await asyncio.shield(entry.task)
        return await self.observation(handle)

    async def observation(self, handle):
        entry = self._entry(handle)
        if entry.released or entry.task is None or not entry.task.done() or entry.result is None:
            _refuse()
        await self._check(entry)
        return entry.result

    def private_observation(self, handle):
        """626-only reconciliation data; does not authorize a public receipt."""
        entry = self._entry(handle)
        return entry.result if entry.task is not None and entry.task.done() else None

    async def release(self, handle):
        entry = self._entry(handle)
        if entry.task is not None:
            await asyncio.shield(entry.task)
        entry.material, entry.released = None, True

    async def close(self):
        self._closed = True
        # Cancellation leaves all entries and material owned for a later joined close.
        await asyncio.shield(asyncio.gather(*(e.task for e in self._entries.values() if e.task is not None)))
        for entry in self._entries.values():
            entry.material, entry.released = None, True

    async def _execute(self, entry):
        try:
            await self._check(entry)
        except Exception:
            entry.result = SecretConsumerObservation('rejected', 'authority_refused')
            return
        entry.result = await self._request(entry)
        # Keep the actual physical result even if current authority now refuses it.
        try:
            await self._check(entry)
        except Exception:
            pass

    async def _request(self, entry):
        process, output_task, input_task, wait_task, roots = None, None, None, None, None
        result = SecretConsumerObservation('uncertain', 'transport_uncertain')
        try:
            remaining = entry.deadline - time.monotonic()
            if remaining <= 0:
                return SecretConsumerObservation('uncertain', 'deadline_uncertain')
            # Only public CA certificates go to disk. Authorization goes through stdin.
            fd, roots = tempfile.mkstemp(prefix='agentmux-account-check-ca-', suffix='.pem')
            with os.fdopen(fd, 'wb') as target:
                target.write(self._enrollment.trust_pem)
            token = entry.material.private_copy().decode('utf-8')
            if self._enrollment.deployment == 'cloud':
                credential = (self._enrollment.email + ':' + token).encode('utf-8')
                authorization = 'Basic ' + base64.b64encode(credential).decode('ascii')
            else:
                authorization = 'Bearer ' + token
            authorization = authorization.replace('\\', '\\\\').replace('"', '\\"')
            config = ('header = "Authorization: ' + authorization + '"\n').encode('utf-8')
            remaining = entry.deadline - time.monotonic()
            if remaining <= 0:
                return SecretConsumerObservation('uncertain', 'deadline_uncertain')
            command = ['/usr/bin/curl', '--disable', '--silent', '--globoff', '--request', 'GET',
                '--proxy', '', '--noproxy', '*', '--proto', '=https', '--proto-redir', '=https',
                '--max-redirs', '0', '--connect-timeout', f'{remaining:.6f}',
                '--max-time', f'{remaining:.6f}', '--max-filesize', str(_BODY_LIMIT),
                '--cacert', roots, '--header', 'Accept: application/json', '--config', '-',
                '--write-out', _MARKER.decode('ascii') + '%{http_code}\n%{content_type}',
                '--url', self._enrollment._url]
            await self._check(entry)
            process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, limit=8192)
            wait_task = asyncio.create_task(process.wait())
            await self._check(entry)

            async def send():
                try:
                    await self._check(entry)
                    process.stdin.write(config)
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except ContractError:
                    if process.returncode is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                    raise
                finally:
                    process.stdin.close()
                    try:
                        await process.stdin.wait_closed()
                    except (BrokenPipeError, ConnectionResetError):
                        pass

            async def receive():
                chunks, size = [], 0
                while True:
                    chunk = await process.stdout.read(8192)
                    if not chunk:
                        return b''.join(chunks)
                    size += len(chunk)
                    if size > _BODY_LIMIT + 256:
                        raise ValueError('response_limit')
                    chunks.append(chunk)

            input_task, output_task = asyncio.create_task(send()), asyncio.create_task(receive())
            remaining = entry.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            await asyncio.wait_for(asyncio.shield(input_task), remaining)
            remaining = entry.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            raw = await asyncio.wait_for(asyncio.shield(output_task), remaining)
            remaining = entry.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            await asyncio.wait_for(asyncio.shield(wait_task), remaining)
            if process.returncode != 0:
                return result
            body, metadata = raw.rsplit(_MARKER, 1)
            status, content_type = metadata.decode('ascii').split('\n', 1)
            if status != '200':
                return SecretConsumerObservation('rejected', 'http_refused')
            if len(body) > _BODY_LIMIT or content_type.split(';', 1)[0].strip().lower() != 'application/json':
                return SecretConsumerObservation('uncertain', 'response_refused')
            document = strict_loads(body)
            key = 'accountId' if self._enrollment.deployment == 'cloud' else 'name'
            if type(document) is not dict or not _text(document.get(key)):
                return SecretConsumerObservation('uncertain', 'response_refused')
            if document[key] != self._enrollment.expected_account:
                return SecretConsumerObservation('rejected', 'account_mismatch')
            return SecretConsumerObservation('accepted', 'account_matched')
        except TimeoutError:
            return SecretConsumerObservation('uncertain', 'deadline_uncertain')
        except Exception:
            return result
        finally:
            # No private reference is released until this exact subprocess and both
            # readers/writers have stopped. Observer cancellation cannot reach here.
            if process is not None:
                process.stdin.close()
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await process.wait()
                try:
                    await process.stdin.wait_closed()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                if input_task is not None:
                    await asyncio.gather(input_task, return_exceptions=True)
                if output_task is not None:
                    await asyncio.gather(output_task, return_exceptions=True)
                if wait_task is not None:
                    await asyncio.gather(wait_task, return_exceptions=True)
            if roots is not None:
                try:
                    os.unlink(roots)
                except OSError:
                    pass
