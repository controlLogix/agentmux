"""Read and explicitly publish a repository's untrusted central-profile ID.

This module selects no storage root and admits no profile or application access.
Callers must separately admit the referenced central enrollment. Explicit client
--selection handling is unchanged. No HTTP route invokes these writers.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from taskmgmt import profile_owner as filesystem

_LIMIT = 4096
_PROFILE = re.compile(r'profile_[0-9a-f]{32}\Z')


class RepositoryProfileError(ValueError):
    """Closed diagnostic with private retained-file or cleanup information."""
    def __init__(self, code, *, recovery=None, cleanup_owners=()):
        super().__init__(code)
        self.recovery = recovery
        self.cleanup_owners = tuple(cleanup_owners)


@dataclass(frozen=True)
class RepositoryProfileReference:
    """Untrusted selection input; never proof of enrollment or permission."""
    profile_id: str

    def __post_init__(self):
        if type(self.profile_id) is not str or not _PROFILE.fullmatch(self.profile_id):
            raise RepositoryProfileError('repository_profile_invalid')


@dataclass(frozen=True)
class RepositoryProfilePlan:
    repository: str = field(repr=False)
    reference: RepositoryProfileReference
    outcome: str
    _repository_identity: tuple = field(repr=False)
    _directory_identity: tuple | None = field(repr=False)
    _file_identity: tuple | None = field(repr=False)
    _before: bytes | None = field(repr=False)


@dataclass(repr=False)
class RetainedRepositoryFiles:
    repository: str
    staging_name: str | None
    published: bool
    directory_created: bool = False
    _directory: int | None = None
    _writer: int | None = None
    _parent: int | None = None
    _directory_creation_attempted: bool = False
    _uncertain: tuple = ()

    def close(self):
        """Consume exact retained handles once; never retry descriptor numbers."""
        descriptors = [fd for fd in (self._writer, self._directory, self._parent) if fd is not None]
        self._writer = self._directory = self._parent = None
        failures = list(self._uncertain)
        for fd in descriptors:
            try:
                os.close(fd)
            except BaseException:
                failures.append(fd)
        self._uncertain = tuple(failures)
        if failures:
            raise RepositoryProfileError('repository_profile_cleanup_pending', recovery=self, cleanup_owners=(self,))


def _cleanup_owners(*errors, exclude=None):
    result = []
    for error in errors:
        owners = (*getattr(error, 'cleanup_owners', ()), getattr(error, 'recovery', None))
        if isinstance(error, filesystem.NativeCleanupFailure):
            owners += (error,)
        for owner in owners:
            if owner is not None and owner is not exclude and all(owner is not item for item in result):
                result.append(owner)
    return tuple(result)


def _close_after(owner, failure=None):
    try:
        owner.close()
    except BaseException as error:
        raise RepositoryProfileError('repository_profile_cleanup_pending',
            cleanup_owners=_cleanup_owners(failure, error) + (owner,)) from None


def _check(deadline):
    if type(deadline) not in (int, float) or not time.monotonic() < deadline < float('inf'):
        raise RepositoryProfileError('repository_profile_deadline')


def _deadline(value):
    value = time.monotonic() + 10 if value is None else value
    _check(value)
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _decode(raw):
    try:
        if not 0 < len(raw) <= _LIMIT:
            raise ValueError
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
        if (type(value) is not dict or set(value) != {'schemaVersion', 'profileId'}
                or value['schemaVersion'] != '1.0.0'):
            raise ValueError
        return RepositoryProfileReference(value['profileId'])
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RepositoryProfileError('repository_profile_invalid') from None


def _identity(info):
    return filesystem.identity(info)


def _directory_identity(fd):
    return _identity(os.fstat(fd))[:5]


class _RepositoryDirectory:
    """Retain no-follow ancestors; reuse the existing native filesystem policy."""
    def __init__(self, repository, deadline):
        if (type(repository) is not str or not 0 < len(repository) <= 4096
                or not os.path.isabs(repository) or os.path.normpath(repository) != repository
                or repository.startswith('//') or repository == '/'
                or any(ord(c) < 32 or ord(c) == 127 or '\ud800' <= c <= '\udfff' for c in repository)
                or len(Path(repository).parts) > 128 or os.getuid() != os.geteuid()):
            raise RepositoryProfileError('repository_profile_path_invalid')
        self.project, self.deadline = Path(repository), deadline
        self.handles, self.identities, self.uncertain = [], [], []
        try:
            for index, name in enumerate(('/', *self.project.parts[1:])):
                _check(deadline)
                parent = self.handles[-1] if self.handles else None
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
                self.handles.append(fd)
                filesystem._directory(fd, owner=index == len(self.project.parts) - 1)
                self.identities.append(_directory_identity(fd))
            self._fd, self.project_identity = self.handles[-1], self.identities[-1]
            self.recheck()
        except BaseException as error:
            _close_after(self, error)
            raise

    def recheck(self):
        _check(self.deadline)
        for index, fd in enumerate(self.handles):
            filesystem._directory(fd, owner=index == len(self.handles) - 1)
            if _directory_identity(fd) != self.identities[index]:
                raise RepositoryProfileError('repository_profile_changed')
            if index:
                slot = os.stat(self.project.parts[index], dir_fd=self.handles[index - 1], follow_symlinks=False)
                if _identity(slot)[:5] != self.identities[index]:
                    raise RepositoryProfileError('repository_profile_changed')
        _check(self.deadline)

    def close(self):
        handles, self.handles = self.handles, []
        for fd in reversed(handles):
            try:
                os.close(fd)
            except BaseException:
                self.uncertain.append(fd)
        if self.uncertain:
            raise RepositoryProfileError('repository_profile_cleanup_pending', cleanup_owners=(self,))


@contextmanager
def _repository(repository, deadline):
    owner, failure = None, None
    try:
        owner = _RepositoryDirectory(repository, deadline)
        try:
            fcntl.flock(owner._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RepositoryProfileError('repository_profile_busy') from None
        yield owner
        owner.recheck()
    except BaseException as error:
        failure = error
        if isinstance(error, RepositoryProfileError):
            raise
        if isinstance(error, filesystem.NativeCleanupFailure):
            raise RepositoryProfileError('repository_profile_cleanup_pending', cleanup_owners=(error,)) from None
        if isinstance(error, (OSError, filesystem.ProfileError, TypeError, ValueError)):
            raise RepositoryProfileError('repository_profile_path_invalid') from None
        raise
    finally:
        if owner is not None:
            try:
                owner.close()
            except RepositoryProfileError as error:
                raise RepositoryProfileError('repository_profile_cleanup_pending',
                    recovery=getattr(failure, 'recovery', None),
                    cleanup_owners=_cleanup_owners(error, failure)) from (failure or error)


def _open_directory(owner):
    try:
        fd = os.open('.agentmux', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=owner._fd)
    except FileNotFoundError:
        return None
    try:
        filesystem._directory(fd, owner=True)
        _recheck_directory(owner, fd)
        return fd
    except BaseException as error:
        _close_after(RetainedRepositoryFiles('', None, False, _directory=fd), error)
        raise


def _recheck_directory(owner, fd):
    owner.recheck()
    filesystem._directory(fd, owner=True)
    current = os.stat('.agentmux', dir_fd=owner._fd, follow_symlinks=False)
    if _identity(current)[:5] != _directory_identity(fd):
        raise RepositoryProfileError('repository_profile_changed')


def _read(fd, deadline):
    failure = None
    try:
        source = os.open('config.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None, None, None
    try:
        before = os.fstat(source)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid() or before.st_mode & 0o022
                or not 0 < before.st_size <= _LIMIT):
            raise RepositoryProfileError('repository_profile_invalid')
        filesystem._native(source, False)
        _check(deadline)
        raw = os.read(source, _LIMIT + 1)
        filesystem._native(source, False)
        _check(deadline)
        if (len(raw) != before.st_size or _identity(os.fstat(source)) != _identity(before)
                or _identity(os.stat('config.json', dir_fd=fd, follow_symlinks=False)) != _identity(before)):
            raise RepositoryProfileError('repository_profile_changed')
        return _decode(raw), raw, _identity(before)
    except BaseException as error:
        failure = error
        raise
    finally:
        _close_after(RetainedRepositoryFiles('', None, False, _writer=source), failure)


def _snapshot(owner, deadline):
    fd = _open_directory(owner)
    if fd is None:
        return None, None, None, None
    failure = None
    try:
        reference, raw, identity = _read(fd, deadline)
        _recheck_directory(owner, fd)
        return reference, raw, identity, _directory_identity(fd)
    except BaseException as error:
        failure = error
        raise
    finally:
        _close_after(RetainedRepositoryFiles('', None, False, _directory=fd), failure)


def read_repository_profile(repository, *, deadline=None):
    """Return an untrusted ID, or None when the selected repo has no reference."""
    deadline = _deadline(deadline)
    with _repository(repository, deadline) as owner:
        return _snapshot(owner, deadline)[0]


class _RepositoryAncestor:
    """Borrow the original working directory's retained ancestor handles."""
    def __init__(self, origin, index):
        self.origin, self._fd = origin, origin.handles[index]
        self.project = Path(*origin.project.parts[:index + 1])

    def recheck(self):
        self.origin.recheck()
        filesystem._directory(self._fd, owner=True)


def _git_boundary(owner):
    try:
        os.stat('.git', dir_fd=owner._fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


@dataclass
class _DiscoveredRepository:
    repository: str
    reference: RepositoryProfileReference
    _observed: list = field(repr=False)
    _deadline: float = field(repr=False)

    def recheck(self):
        for owner, snapshot in self._observed:
            owner.recheck()
            if _snapshot(owner, self._deadline) != snapshot:
                raise RepositoryProfileError('repository_profile_changed')
            if snapshot[0] is None and _git_boundary(owner):
                raise RepositoryProfileError('repository_profile_changed')


@contextmanager
def discover_repository_profile(directory, *, deadline=None):
    """Retain the nearest reference until handoff; central admission remains required."""
    deadline = _deadline(deadline)
    with _repository(directory, deadline) as origin:
        observed = []
        # The original reader bounds path depth to 128 and rejects symlink components.
        # Never select the filesystem root or cross a nearer unconfigured Git root.
        for index in range(len(origin.handles) - 1, 0, -1):
            owner = _RepositoryAncestor(origin, index)
            owner.recheck()
            try:
                fcntl.flock(owner._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RepositoryProfileError('repository_profile_busy') from None
            snapshot = _snapshot(owner, deadline)
            observed.append((owner, snapshot))
            if snapshot[0] is not None:
                selected = _DiscoveredRepository(str(owner.project), snapshot[0], observed, deadline)
                selected.recheck()
                yield selected
                selected.recheck()
                return
            if snapshot[3] is not None or _git_boundary(owner):
                raise RepositoryProfileError('repository_profile_missing')
        raise RepositoryProfileError('repository_profile_missing')


def prepare_repository_profile(repository, profile_id, *, deadline=None):
    """Preview a create-only write without creating directories or files."""
    deadline, wanted = _deadline(deadline), RepositoryProfileReference(profile_id)
    with _repository(repository, deadline) as owner:
        existing, raw, identity, directory = _snapshot(owner, deadline)
        if existing is not None and existing != wanted:
            raise RepositoryProfileError('repository_profile_conflict')
        return RepositoryProfilePlan(str(owner.project), wanted, 'unchanged' if existing else 'create',
                                     owner.project_identity[:5], directory, identity, raw)


def publish_repository_profile(plan, *, deadline=None):
    """Apply an explicit preview; never replace an existing config.json.

    Uncertain publication retains exact directory/file handles. The caller owns
    recovery.close(), including when cleanup uncertainty has consumed a handle.
    """
    if (type(plan) is not RepositoryProfilePlan or type(plan.reference) is not RepositoryProfileReference
            or type(plan.repository) is not str or plan.outcome not in ('create', 'unchanged')
            or type(plan._repository_identity) is not tuple or len(plan._repository_identity) != 5
            or plan._directory_identity is not None and (type(plan._directory_identity) is not tuple
                                                        or len(plan._directory_identity) != 5)
            or plan._file_identity is not None and (type(plan._file_identity) is not tuple or len(plan._file_identity) != 9)
            or plan._before is not None and (type(plan._before) is not bytes or len(plan._before) > _LIMIT)):
        raise RepositoryProfileError('repository_profile_plan_required')
    RepositoryProfileReference(plan.reference.profile_id)
    deadline = _deadline(deadline)
    retained = RetainedRepositoryFiles(plan.repository, None, False)
    try:
        with _repository(plan.repository, deadline) as owner:
            existing, raw, identity, directory = _snapshot(owner, deadline)
            if (owner.project_identity[:5] != plan._repository_identity or directory != plan._directory_identity
                    or identity != plan._file_identity or raw != plan._before):
                raise RepositoryProfileError('repository_profile_changed')
            if existing is not None:
                if existing != plan.reference:
                    raise RepositoryProfileError('repository_profile_conflict')
                return 'unchanged'
            if directory is None:
                # Keep the exact admitted parent before mkdir. A failure before
                # child admission still has an owner, without guessing by path.
                retained._parent = os.dup(owner._fd)
                retained._directory_creation_attempted = True
                os.mkdir('.agentmux', 0o700, dir_fd=owner._fd)
                retained.directory_created = True
                directory = _identity(os.stat('.agentmux', dir_fd=owner._fd, follow_symlinks=False))[:5]
            retained._directory = fd = _open_directory(owner)
            if fd is None or _directory_identity(fd) != directory:
                raise RepositoryProfileError('repository_profile_changed')
            if retained.directory_created:
                # Parent durability can fail after creating the directory. Its
                # descriptor must already belong to recovery before this flush.
                os.fsync(retained._parent)
            candidate = '.profile-reference-' + secrets.token_hex(16)
            retained._writer = writer = os.open(candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            retained.staging_name = candidate
            filesystem._native(writer, True)
            opened = _identity(os.fstat(writer))
            body = (json.dumps({'schemaVersion': '1.0.0', 'profileId': plan.reference.profile_id},
                               sort_keys=True, separators=(',', ':')) + '\n').encode()
            remaining = memoryview(body)
            while remaining:
                _check(deadline)
                count = os.write(writer, remaining)
                if count <= 0:
                    raise OSError
                remaining = remaining[count:]
            os.fsync(writer)
            filesystem._native(writer, True)
            _recheck_directory(owner, fd)
            if _identity(os.stat(candidate, dir_fd=fd, follow_symlinks=False)) != _identity(os.fstat(writer)):
                raise RepositoryProfileError('repository_profile_changed')
            _check(deadline)
            os.link(candidate, 'config.json', src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            retained.published = True
            current = os.stat('config.json', dir_fd=fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != opened[:2]:
                raise RepositoryProfileError('repository_profile_changed')
            current = os.stat(candidate, dir_fd=fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != opened[:2]:
                raise RepositoryProfileError('repository_profile_changed')
            os.unlink(candidate, dir_fd=fd)
            retained.staging_name = None
            os.fsync(fd)
            selected, checked, _ = _read(fd, deadline)
            if selected != plan.reference or checked != body:
                raise RepositoryProfileError('repository_profile_changed')
            _recheck_directory(owner, fd)
        # Keep publication state and exact handles through the final ancestor
        # checks and directory-lock owner cleanup, not just the file rename.
        retained.close()
        return 'created'
    except BaseException as error:
        if retained._directory_creation_attempted or retained.staging_name is not None or retained.published:
            raise RepositoryProfileError('repository_profile_publication_uncertain', recovery=retained,
                cleanup_owners=_cleanup_owners(error, exclude=retained)) from None
        try:
            retained.close()
        except RepositoryProfileError as cleanup:
            raise RepositoryProfileError('repository_profile_cleanup_pending', recovery=retained,
                cleanup_owners=_cleanup_owners(error, cleanup, exclude=retained)) from None
        raise
