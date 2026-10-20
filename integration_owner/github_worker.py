"""Managed GitHub writes through one explicitly enrolled native ``gh`` client.

The client keeps its credentials in its own supported store. Agentmux pins only
the resolved executable and configuration namespace metadata; it never reads or
copies ``hosts.yml``. The integration owner still supplies current authority,
the durable dispatch claim and retained reconciliation state.
"""
import asyncio
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from .github_requests import PreparedGithubRequest, prepare_github_request
from .intent import DIGEST, ID, intent, reference
from .observations import github_ack, observation


MAX_OUTPUT = 4096
PROCESS_TIMEOUT = 45.0
ENROLLMENT_PURPOSE = 'agentmux-github-client-enrollment-v1'


@dataclass(frozen=True, slots=True)
class GithubProcessResult:
    returncode: int | None
    stdout: bytes
    failure: str | None
    stdin_bytes: int = 0


def _capture_process(arguments, stdin, environment, cwd, *, popen=None,
                     selector_factory=None, clock=None, read=None, killpg=None,
                     set_blocking=None, write=None):
    """Drain bounded stdout and reap the same process and process group."""
    popen = subprocess.Popen if popen is None else popen
    selector_factory = selectors.DefaultSelector if selector_factory is None else selector_factory
    clock = time.monotonic if clock is None else clock
    read = os.read if read is None else read
    write = os.write if write is None else write
    killpg = os.killpg if killpg is None else killpg
    set_blocking = os.set_blocking if set_blocking is None else set_blocking
    process = readers = None
    output = bytearray()
    failure = None
    written = 0
    deadline = clock() + PROCESS_TIMEOUT
    try:
        try:
            process = popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, shell=False, start_new_session=True,
                cwd=cwd, env=environment)
        except OSError as error:
            if (isinstance(error, FileNotFoundError) and error.errno == errno.ENOENT
                    and error.filename == os.fsdecode(arguments[0])):
                return GithubProcessResult(None, b'', 'not-started')
            raise
        readers = selector_factory()
        set_blocking(process.stdin.fileno(), False)
        set_blocking(process.stdout.fileno(), False)
        readers.register(process.stdout, selectors.EVENT_READ, 'stdout')
        pending = memoryview(stdin)
        if pending:
            readers.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
        else:
            process.stdin.close()
        while readers.get_map():
            remaining = deadline - clock()
            if remaining <= 0:
                failure = 'timeout'
                break
            for key, _ in readers.select(min(remaining, 0.1)):
                if key.data == 'stdin':
                    count = write(key.fileobj.fileno(), pending[written:])
                    if type(count) is not int or count <= 0 or written + count > len(pending):
                        raise OSError('invalid process input write')
                    written += count
                    if written == len(pending):
                        readers.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    chunk = read(key.fileobj.fileno(), min(4096, MAX_OUTPUT + 1 - len(output)))
                    if not chunk:
                        readers.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_OUTPUT:
                            failure = 'output-limit'
                            break
            if failure is not None:
                break
        if failure is None:
            try:
                process.wait(timeout=max(0, deadline - clock()))
            except subprocess.TimeoutExpired:
                failure = 'timeout'
        if failure is not None:
            try:
                killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                process.wait()
        return GithubProcessResult(process.returncode, bytes(output), failure, written)
    except BaseException:
        if process is not None:
            try:
                killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                process.wait()
        raise
    finally:
        try:
            if readers is not None:
                readers.close()
        finally:
            if process is not None:
                for stream in (process.stdin, process.stdout):
                    try:
                        if stream is not None and not stream.closed:
                            stream.close()
                    except OSError:
                        pass


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _binding(credential_ref, executable, config_dir):
    try:
        copied = strict_loads(canonical_bytes(credential_ref))
        reference(copied)
        binary = Path(executable)
        config = Path(config_dir)
        if (not binary.is_absolute() or not config.is_absolute()
                or '..' in binary.parts or '..' in config.parts):
            raise ValueError
        binary = binary.resolve(strict=True)
        config = config.resolve(strict=True)
        return canonical_bytes(copied), binary, config
    except Exception:
        raise ContractError('integration_credential_configuration') from None


def _snapshot(binding):
    try:
        binary, config = binding[1], binding[2]
        executable = binary.lstat()
        directory = config.lstat()
        parent = config.parent.lstat()
        hosts = (config / 'hosts.yml').lstat()
        try:
            settings = (config / 'config.yml').lstat()
        except FileNotFoundError:
            settings = None
        if (not stat.S_ISREG(executable.st_mode) or executable.st_nlink != 1
                or executable.st_uid not in (0, os.getuid())
                or stat.S_IMODE(executable.st_mode) & 0o022
                or not stat.S_IMODE(executable.st_mode) & 0o111
                or not os.access(binary, os.X_OK)
                or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
                or stat.S_IMODE(directory.st_mode) & 0o022
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) & 0o022
                or not stat.S_ISREG(hosts.st_mode) or hosts.st_uid != os.getuid()
                or hosts.st_nlink != 1 or stat.S_IMODE(hosts.st_mode) & 0o077):
            raise ValueError
        if (settings is not None and (not stat.S_ISREG(settings.st_mode)
                or settings.st_uid != os.getuid() or settings.st_nlink != 1
                or stat.S_IMODE(settings.st_mode) & 0o077)):
            raise ValueError
        return (_file_identity(executable), _directory_identity(directory),
                _directory_identity(parent), _file_identity(hosts),
                None if settings is None else _file_identity(settings))
    except Exception:
        raise ContractError('integration_credential_unavailable') from None


@dataclass(frozen=True, slots=True, repr=False)
class GithubClientPin:
    _binding: tuple
    _snapshot: tuple

    def __repr__(self):
        return '<GithubClientPin private; no credentials>'


def pin_github_client(credential_ref, *, executable, config_dir):
    """Pin an explicit native client namespace without opening its credential file."""
    binding = _binding(credential_ref, executable, config_dir)
    return GithubClientPin(binding, _snapshot(binding))


@dataclass(frozen=True, slots=True, repr=False)
class PrivateGithubClient:
    executable: str
    config_dir: str

    def __repr__(self):
        return '<PrivateGithubClient private; native credentials>'


@dataclass(frozen=True, slots=True, repr=False, init=False)
class GithubCredentialResolver:
    _binding: tuple
    _pin: GithubClientPin

    def __init__(self, credential_ref, *, executable, config_dir, client_pin):
        binding = _binding(credential_ref, executable, config_dir)
        if type(client_pin) is not GithubClientPin or client_pin._binding != binding:
            raise ContractError('integration_credential_configuration')
        object.__setattr__(self, '_binding', binding)
        object.__setattr__(self, '_pin', client_pin)

    def __repr__(self):
        return '<GithubCredentialResolver private; no credentials>'

    def resolve(self, credential_ref):
        try:
            copied = strict_loads(canonical_bytes(credential_ref))
            reference(copied)
        except Exception:
            raise ContractError('integration_credential_refused') from None
        if canonical_bytes(copied) != self._binding[0]:
            raise ContractError('integration_credential_refused')
        if _snapshot(self._binding) != self._pin._snapshot:
            raise ContractError('integration_credential_changed')
        return PrivateGithubClient(str(self._binding[1]), str(self._binding[2]))


def github_enrollment_bytes(pin):
    """Serialize private pin metadata without opening the native credential file."""
    if type(pin) is not GithubClientPin:
        raise ContractError('integration_enrollment_invalid')
    executable, directory = pin._binding[1], pin._binding[2]
    return canonical_bytes({'purpose': ENROLLMENT_PURPOSE,
        'credentialRef': strict_loads(pin._binding[0]), 'executable': str(executable),
        'configDirectory': str(directory),
        'executableIdentity': [str(value) for value in pin._snapshot[0]],
        'directoryIdentity': [str(value) for value in pin._snapshot[1]],
        'parentIdentity': [str(value) for value in pin._snapshot[2]],
        'hostsIdentity': [str(value) for value in pin._snapshot[3]],
        'configIdentity': (None if pin._snapshot[4] is None else
                           [str(value) for value in pin._snapshot[4]])})


def write_github_enrollment(path, pin):
    """Create one private enrollment file and return its separate digest."""
    from identity.application_enrollment import _read_material, _write_material
    raw = github_enrollment_bytes(pin)
    _write_material(path, strict_loads(raw), max_bytes=65536)
    if _read_material(path, max_bytes=65536, return_bytes=True) != raw:
        raise ContractError('integration_enrollment_unavailable')
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def load_github_enrollment(raw, *, credential_ref):
    """Restore the exact selected pin and reject changed client metadata."""
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 65536:
            raise ValueError
        value = strict_loads(raw)
        keys = {'purpose', 'credentialRef', 'executable', 'configDirectory',
                'executableIdentity', 'directoryIdentity', 'parentIdentity',
                'hostsIdentity', 'configIdentity'}
        if (type(value) is not dict or set(value) != keys
                or value['purpose'] != ENROLLMENT_PURPOSE
                or value['credentialRef'] != credential_ref):
            raise ValueError
        for key in ('executable', 'configDirectory'):
            if (type(value[key]) is not str or not 1 <= len(value[key]) <= 4096
                    or any(ord(character) < 32 or ord(character) == 127 for character in value[key])):
                raise ValueError
        identities = []
        for key, count in (('executableIdentity', 9), ('directoryIdentity', 5),
                           ('parentIdentity', 5), ('hostsIdentity', 9)):
            parts = value[key]
            if (type(parts) is not list or len(parts) != count
                    or any(type(part) is not str
                           or not re.fullmatch(r'0|[1-9][0-9]{0,29}', part)
                           for part in parts)):
                raise ValueError
            identities.append(tuple(int(part) for part in parts))
        settings = value['configIdentity']
        if settings is None:
            identities.append(None)
        elif (type(settings) is list and len(settings) == 9
                and all(type(part) is str
                        and re.fullmatch(r'0|[1-9][0-9]{0,29}', part) for part in settings)):
            identities.append(tuple(int(part) for part in settings))
        else:
            raise ValueError
        binding = _binding(credential_ref, Path(value['executable']), Path(value['configDirectory']))
        pin = GithubClientPin(binding, tuple(identities))
        resolver = GithubCredentialResolver(credential_ref, executable=binding[1],
            config_dir=binding[2], client_pin=pin)
        resolver.resolve(credential_ref)
        return resolver
    except Exception:
        raise ContractError('integration_enrollment_unavailable') from None


@dataclass(frozen=True, slots=True, repr=False)
class PreparedGithubDispatch:
    original_id: str
    original_digest: str
    attempt_id: str
    prepared: PreparedGithubRequest
    _client: PrivateGithubClient

    def __repr__(self):
        return '<PreparedGithubDispatch private; not authority>'


class GithubWorker:
    def __init__(self, resolver):
        if type(resolver) is not GithubCredentialResolver:
            raise ContractError('integration_worker_configuration')
        self._resolver = resolver
        self._tasks = {}
        self._prepared = {}
        self._closed = False

    def __repr__(self):
        return '<GithubWorker private>'

    def prepare(self, original_id, original_digest, attempt_id, proposal, content):
        if (self._closed or not isinstance(original_id, str) or not ID.fullmatch(original_id)
                or not isinstance(attempt_id, str) or not ID.fullmatch(attempt_id)
                or attempt_id == original_id or not isinstance(original_digest, str)
                or not DIGEST.fullmatch(original_digest)):
            raise ContractError('integration_worker_refused')
        body = intent(proposal)
        if payload_digest(body) != original_digest:
            raise ContractError('integration_original_identity_conflict')
        client = self._resolver.resolve(body['credentialRef'])
        prepared = prepare_github_request(body, content)
        return PreparedGithubDispatch(original_id, original_digest, attempt_id, prepared, client)

    def _environment(self, client):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(('GH_', 'GITHUB_'))}
        environment.update(GH_CONFIG_DIR=client.config_dir, GH_HOST='github.com',
            GH_PROMPT_DISABLED='1', GH_NO_UPDATE_NOTIFIER='1', CLICOLOR='0', NO_COLOR='1')
        return environment

    def _run(self, client, argv, stdin):
        return _capture_process([client.executable, *argv], stdin,
            self._environment(client), client.config_dir)

    def _current_client(self, job):
        current = self._resolver.resolve(strict_loads(self._resolver._binding[0]))
        if current != job._client:
            raise ContractError('integration_credential_changed')
        return current

    def _perform(self, job):
        try:
            client = self._current_client(job)
        except ContractError:
            return observation(job.original_id, job.original_digest, job.attempt_id, kind='not-dispatched')
        try:
            result = self._run(client, job.prepared.argv, job.prepared.stdin)
            if result.failure == 'not-started':
                return observation(job.original_id, job.original_digest, job.attempt_id,
                                   kind='not-dispatched')
            if (result.failure is not None or result.returncode != 0
                    or type(result.stdout) is not bytes or len(result.stdout) > MAX_OUTPUT):
                raise ContractError('integration_provider_receipt_invalid')
            return github_ack(job.original_id, job.original_digest, job.attempt_id,
                              job.prepared, result.stdout)
        except Exception:
            return observation(job.original_id, job.original_digest, job.attempt_id, kind='uncertain')

    def _start(self, job):
        if self._closed or type(job) is not PreparedGithubDispatch:
            raise ContractError('integration_worker_refused')
        existing = self._tasks.get(job.attempt_id)
        if existing is not None:
            if self._prepared[job.attempt_id] is not job:
                raise ContractError('integration_attempt_conflict')
            return existing
        if len(self._tasks) >= 8:
            raise ContractError('integration_worker_capacity')
        self._current_client(job)
        task = asyncio.create_task(asyncio.to_thread(self._perform, job))
        self._prepared[job.attempt_id] = job
        self._tasks[job.attempt_id] = task
        return task

    async def wait(self, attempt_id):
        task = self._tasks.get(attempt_id)
        if task is None:
            raise ContractError('integration_attempt_unavailable')
        return await asyncio.shield(task)

    def _release(self, attempt_id, observed):
        task = self._tasks.get(attempt_id)
        if task is None:
            return
        if not task.done() or task.cancelled() or task.result()._encoded != observed._encoded:
            raise ContractError('integration_cleanup_incomplete')
        del self._tasks[attempt_id]
        del self._prepared[attempt_id]

    def _start_read(self, operation_id, original_id, original_digest, attempt_id, proposal):
        if self._closed:
            raise ContractError('integration_worker_refused')
        body = intent(proposal)
        identity = (original_id, original_digest, attempt_id, canonical_bytes(body))
        if operation_id in self._tasks:
            if self._prepared[operation_id] != identity:
                raise ContractError('integration_attempt_conflict')
            return self._tasks[operation_id]
        if len(self._tasks) >= 8:
            raise ContractError('integration_worker_capacity')
        client = self._resolver.resolve(body['credentialRef'])
        task = asyncio.create_task(asyncio.to_thread(self._read, original_id,
            original_digest, attempt_id, body, client))
        self._prepared[operation_id] = identity
        self._tasks[operation_id] = task
        return task

    def _read(self, original_id, original_digest, attempt_id, proposal, enrolled_client):
        target, action = proposal['target'], proposal['action']
        resource = (target['owner'] + '/' + target['name']
                    if action == 'github-repo-create' else target['repository'])
        try:
            current = self._resolver.resolve(proposal['credentialRef'])
            if current != enrolled_client:
                raise ContractError('integration_credential_changed')
        except ContractError:
            return observation(original_id, original_digest, attempt_id, kind='read-only',
                               identity={'presence': 'unavailable', 'resourceId': resource})
        presence = 'unavailable'
        if action == 'github-repo-create':
            try:
                result = self._run(current, ('repo', 'view', 'github.com/' + resource,
                    '--json', 'nameWithOwner'), b'')
                if (result.failure is None and result.returncode == 0
                        and type(result.stdout) is bytes and len(result.stdout) <= MAX_OUTPUT):
                    data = strict_loads(result.stdout)
                    name = data.get('nameWithOwner') if type(data) is dict else None
                    if (type(data) is dict and set(data) == {'nameWithOwner'} and type(name) is str
                            and name.casefold() == resource.casefold()):
                        presence = 'present'
            except Exception:
                pass
        return observation(original_id, original_digest, attempt_id, kind='read-only',
                           identity={'presence': presence, 'resourceId': resource})

    async def close(self, *, timeout=5.0):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ContractError('integration_cleanup_invalid')
        self._closed = True
        if self._tasks:
            done, pending = await asyncio.wait(tuple(self._tasks.values()), timeout=timeout)
            for task in done:
                if not task.cancelled():
                    task.exception()
            if pending:
                raise ContractError('integration_cleanup_incomplete')
