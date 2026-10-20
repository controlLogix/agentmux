"""Publish reviewed Desktop registration using retained native admission.

No installed setup command or HTTP route calls this module yet. The public
composition requires a native-issued application owner and admits the settings
path itself. The lower-level callback is a mutation-boundary recheck, not admission
evidence. Agentmux writers lock the directory; external editors must be quiescent.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager
import fcntl
import os
import secrets
import time

from native_security import descriptor_admission as native_admission

from dashboard.resource_registration import (DesktopRegistrationEdit, RegistrationConflict,
                                            prepare_desktop_registration)

_LIMIT = 1024 * 1024


class SettingsPublicationError(RegistrationConflict):
    """Closed outcome with private, exact recovery ownership for the caller."""
    def __init__(self, code, *, recovery=None, staging_name=None, cleanup_owners=()):
        super().__init__(code)
        self.recovery = recovery
        self.staging_name = staging_name
        self.cleanup_owners = tuple(cleanup_owners)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _admit(fd, purpose, deadline):
    if time.monotonic() >= deadline:
        raise RegistrationConflict('settings_deadline')
    try:
        accepted = native_admission.check_descriptor(fd, purpose=purpose, deadline=deadline)
    except native_admission.AdmissionError as exc:
        code = ('settings_cleanup_pending' if str(exc) == 'native_admission_cleanup'
                else 'settings_native_admission_failed')
        raise RegistrationConflict(code) from None
    if accepted is not True:
        raise RegistrationConflict('settings_native_admission_failed')
    if time.monotonic() >= deadline:
        raise RegistrationConflict('settings_deadline')


def _directory(fd, deadline):
    _admit(fd, native_admission.DescriptorPurpose.PRIVATE_DIRECTORY, deadline)
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        # The number may already have been consumed. Report uncertainty, never retry.
        raise RegistrationConflict('settings_cleanup_pending') from None


def _read(parent, name, deadline):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=parent)
    try:
        _admit(fd, native_admission.DescriptorPurpose.PRIVATE_FILE, deadline)
        before = os.fstat(fd)
        if not 0 <= before.st_size <= _LIMIT:
            raise RegistrationConflict('settings_permissions')
        chunks, remaining = [], _LIMIT + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        _admit(fd, native_admission.DescriptorPurpose.PRIVATE_FILE, deadline)
        after = os.fstat(fd)
        if len(raw) > _LIMIT or len(raw) != before.st_size or _identity(before) != _identity(after):
            raise RegistrationConflict('configuration_changed')
        return fd, raw, _identity(after)
    except BaseException:
        _close(fd)
        raise


def _read_optional(parent, name, deadline):
    try:
        return _read(parent, name, deadline)
    except FileNotFoundError:
        return None, None, None


def _supported_edit(edit):
    if isinstance(edit, DesktopRegistrationEdit):
        return True
    from dashboard.claude_hook_registration import ClaudeHookRegistrationEdit
    return isinstance(edit, ClaudeHookRegistrationEdit)


@dataclass
class _Publication:
    """Retain the exact published file and receipt until the caller persists it.

    Close once after installation ownership is durably stored. An uncertain close
    is consumed and reported; descriptor numbers are never retried.
    """
    edit: DesktopRegistrationEdit = field(repr=False)
    _fd: int | None = field(repr=False)
    cleanup_pending: bool = False
    _directory_owner: object = field(default=None, repr=False)
    _original_fd: int | None = field(default=None, repr=False)
    _admission: object = field(default=None, repr=False)
    _lock_fd: int | None = field(default=None, repr=False)
    _published_identity: tuple | None = field(default=None, repr=False)

    def close(self):
        pending = self.cleanup_pending
        for attribute in ('_fd', '_original_fd'):
            fd = getattr(self, attribute)
            setattr(self, attribute, None)
            if fd is not None:
                try:
                    _close(fd)
                except BaseException:
                    pending = True
        if self._directory_owner is not None:
            owner, self._directory_owner = self._directory_owner, None
            try:
                owner.close()
            except BaseException:
                self._directory_owner = owner
                pending = True
        if self._lock_fd is not None:
            fd, self._lock_fd = self._lock_fd, None
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except BaseException:
                pending = True
            try:
                _close(fd)
            except BaseException:
                pending = True
        self.cleanup_pending = pending
        if pending:
            raise SettingsPublicationError('settings_cleanup_pending', recovery=self)


def _publish_desktop_at(parent, edit, *, recheck, deadline=None, expected_identity=None, retain_lock=False):
    """Use a separate directory description so reused caller handles still lock."""
    now = time.monotonic()
    if deadline is None:
        deadline = now + 1
    if type(deadline) not in (int, float) or not now < deadline < float('inf'):
        raise RegistrationConflict('settings_deadline')
    owned = None
    result = None
    failure = None
    try:
        identity = _directory(parent, deadline)
        owned = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent)
        if _directory(owned, deadline) != identity:
            raise RegistrationConflict('settings_permissions')
        result = _publish_locked(owned, edit, recheck=recheck, deadline=deadline,
                                 expected_identity=expected_identity, retain_lock=retain_lock)
        if result._lock_fd == owned:
            owned = None
        return result
    except BaseException as exc:
        failure = exc
        if isinstance(exc, SettingsPublicationError) and exc.recovery is not None and exc.recovery._lock_fd == owned:
            owned = None
        if isinstance(exc, OSError):
            raise RegistrationConflict('settings_permissions') from None
        raise
    finally:
        if owned is not None:
            try:
                _close(owned)
            except RegistrationConflict:
                recovery = failure.recovery if isinstance(failure, SettingsPublicationError) else result
                if recovery is not None:
                    recovery.cleanup_pending = True
                raise SettingsPublicationError('settings_cleanup_pending', recovery=recovery,
                    staging_name=failure.staging_name if isinstance(failure, SettingsPublicationError) else None,
                    cleanup_owners=failure.cleanup_owners if isinstance(failure, SettingsPublicationError) else ()) from None


def _publish_locked(parent, edit, *, recheck, deadline, expected_identity=None, retain_lock=False):
    """Compare under the retained directory lock, then atomically replace one file.

    Internal primitive only. The caller owns the admitted directory and application
    through publication, supplies a recheck that raises on loss of admission, and
    persists the returned ownership receipt before reporting setup complete. This
    is not filesystem CAS against writers that ignore the directory lock. Existing
    A supported edit may explicitly require an absent file; that path uses an
    atomic non-replacing link in an already admitted private directory.
    """
    if (not _supported_edit(edit) or not callable(recheck)
            or not isinstance(edit.after, bytes) or len(edit.after) > _LIMIT):
        raise RegistrationConflict('settings_selection_invalid')
    name = os.path.basename(edit.configuration_path)
    if not name or name in ('.', '..'):
        raise RegistrationConflict('settings_selection_invalid')
    held = None
    stage = None
    staged_fd = None
    published = False
    result = None
    failure = None
    try:
        directory_identity = _directory(parent, deadline)
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except RegistrationConflict:
        raise
    except (OSError, ValueError):
        raise RegistrationConflict('settings_busy') from None
    try:
        recheck()
        held, raw, expected = _read_optional(parent, name, deadline)
        if expected_identity is not None and expected != expected_identity:
            raise RegistrationConflict('configuration_changed')
        edit.for_snapshot(raw, configuration_path=edit.configuration_path)
        if edit.after == raw:
            if time.monotonic() >= deadline:
                raise RegistrationConflict('settings_deadline')
            result = _Publication(edit, held, _published_identity=expected)
            held = None
            return result
        candidate = '.agentmux-settings-' + secrets.token_hex(16)
        staged_fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=parent)
        stage = candidate
        _admit(staged_fd, native_admission.DescriptorPurpose.PRIVATE_FILE, deadline)
        remaining = memoryview(edit.after)
        while remaining:
            written = os.write(staged_fd, remaining)
            if written <= 0:
                raise RegistrationConflict('settings_write_failed')
            remaining = remaining[written:]
        os.fsync(staged_fd)
        recheck()
        # Verify the exact staging inode and bytes, and the source after staging.
        staged_read, body, staged_identity = _read(parent, stage, deadline)
        try:
            if body != edit.after or _identity(os.fstat(staged_fd)) != staged_identity:
                raise RegistrationConflict('settings_staging_changed')
            current, body, identity = _read_optional(parent, name, deadline)
            try:
                if (identity != expected or body != edit.before
                        or (held is not None and _identity(os.fstat(held)) != expected)):
                    raise RegistrationConflict('configuration_changed')
            finally:
                if current is not None:
                    _close(current)
            if _directory(parent, deadline) != directory_identity:
                raise RegistrationConflict('settings_permissions')
            if edit.before is None:
                os.link(stage, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
                published = True
                os.unlink(stage, dir_fd=parent)
                stage = None
            else:
                os.rename(stage, name, src_dir_fd=parent, dst_dir_fd=parent)
                published = True
                stage = None
            os.fsync(parent)
            current, body, identity = _read(parent, name, deadline)
            try:
                # Rename may change ctime; require the retained inode and content.
                if identity[:2] != staged_identity[:2] or body != edit.after:
                    raise RegistrationConflict('settings_publication_uncertain')
            finally:
                _close(current)
            recheck()
            if time.monotonic() >= deadline:
                raise RegistrationConflict('settings_deadline')
            result = _Publication(edit, staged_read, _published_identity=identity)
            staged_read = None
            return result
        finally:
            if staged_read is not None:
                _close(staged_read)
    except BaseException as exc:
        # Transfer the original descriptor and exact name on any staged failure.
        # A caller must retain this recovery owner; do not rediscover by prefix.
        recovery = _Publication(edit, staged_fd) if staged_fd is not None else None
        staged_fd = None
        if recovery is not None and isinstance(exc, RegistrationConflict) and str(exc) == 'settings_cleanup_pending':
            recovery.cleanup_pending = True
        code = ('settings_publication_uncertain' if published else
                str(exc) if isinstance(exc, RegistrationConflict) else
                'settings_interrupted' if not isinstance(exc, Exception) else 'settings_write_failed')
        failure = SettingsPublicationError(code, recovery=recovery,
                    staging_name=stage,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ())
        raise failure from None
    finally:
        # Keep an uncertain staging entry for inspection. Never guess at ownership
        # to remove it or restore bytes after another writer may have changed them.
        pending = False
        for fd in (held, staged_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pending = True
        recovery = result if failure is None else failure.recovery
        if retain_lock and recovery is not None:
            recovery._lock_fd = parent
        else:
            try:
                fcntl.flock(parent, fcntl.LOCK_UN)
            except OSError:
                pending = True
        if pending:
            recovery = result if failure is None else failure.recovery
            if recovery is not None:
                recovery.cleanup_pending = True
            raise SettingsPublicationError('settings_cleanup_pending',
                        recovery=recovery, staging_name=stage if not published else None,
                        cleanup_owners=() if failure is None else failure.cleanup_owners) from None


@contextmanager
def desktop_registration(configuration_path, *, admission, owned=None, remove=False, deadline=None,
                         expected_before=None, expected_identity=None, on_accept=None):
    """Publish exactly the admitted Desktop entry while retaining all owners.

    Only a native-issued InstalledClientAdmission is accepted. The trusted setup
    caller may commit its receipt through on_accept, after final validation while
    the settings lock is held. A caller failure retains recovery and reports a
    pending receipt; no whole-file rollback is attempted. This is not an HTTP endpoint.
    """
    import json
    from hub.installed_client_admission import (InstalledClientAdmission, InstalledClientError,
                                               _RetainedPath, _canonical)
    if type(admission) is not InstalledClientAdmission:
        raise RegistrationConflict('settings_application_admission_required')
    if not _canonical(configuration_path) or type(remove) is not bool:
        raise RegistrationConflict('settings_selection_invalid')
    if deadline is None:
        deadline = time.monotonic() + 10
    now = time.monotonic()
    if type(deadline) not in (int, float) or not now < deadline < float('inf'):
        raise RegistrationConflict('settings_deadline')
    directory, original, publication, failure = None, None, None, None
    try:
        with admission.hold(deadline=deadline) as declaration:
            if declaration.client_id != 'claude-desktop' or declaration.transport != 'stdio':
                raise RegistrationConflict('settings_application_admission_required')
            directory = _RetainedPath(os.path.dirname(configuration_path),
                    purpose=native_admission.DescriptorPurpose.PRIVATE_DIRECTORY, deadline=deadline)
            original, raw, identity = _read(directory.fd, os.path.basename(configuration_path), deadline)
            if (expected_before is not None and raw != expected_before
                    or expected_identity is not None and identity != expected_identity):
                raise RegistrationConflict('configuration_changed')
            edit = prepare_desktop_registration(raw, installation_id=declaration.installation_id,
                configuration_path=configuration_path, command=declaration.command,
                arguments=declaration.arguments, owned=owned, remove=remove)
            if remove:
                entry = json.loads(owned.entry_json)
                if entry != {'command': declaration.command, 'args': list(declaration.arguments)}:
                    raise RegistrationConflict('settings_registration_declaration_mismatch')

            directory_binding = directory
            def recheck():
                try:
                    directory_binding.recheck(deadline=deadline)
                    admission.recheck(deadline=deadline)
                except InstalledClientError as exc:
                    raise SettingsPublicationError('settings_admission_lost',
                            cleanup_owners=() if exc.cleanup is None else (exc.cleanup,)) from None

            try:
                publication = _publish_desktop_at(directory.fd, edit, recheck=recheck,
                                                  deadline=deadline, expected_identity=identity, retain_lock=True)
            except SettingsPublicationError as exc:
                if exc.recovery is not None:
                    exc.recovery._directory_owner, directory = directory, None
                    exc.recovery._original_fd, original = original, None
                    exc.recovery._admission = admission
                raise
            publication._directory_owner, directory = directory, None
            publication._original_fd, original = original, None
            publication._admission = admission
            try:
                yield publication
            except BaseException as exc:
                raise SettingsPublicationError('settings_receipt_pending', recovery=publication,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ()) from None
            try:
                recheck()
                if publication._lock_fd is None or publication._fd is None:
                    raise RegistrationConflict('settings_publication_uncertain')
                current, body, identity = _read(publication._lock_fd,
                                               os.path.basename(configuration_path), deadline)
                try:
                    if (identity != publication._published_identity or body != edit.after
                            or _identity(os.fstat(publication._fd)) != publication._published_identity):
                        raise RegistrationConflict('settings_publication_uncertain')
                finally:
                    _close(current)
            except BaseException as exc:
                raise SettingsPublicationError('settings_publication_uncertain', recovery=publication,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ()) from None
            try:
                if on_accept is not None:
                    on_accept()
            except BaseException as exc:
                raise SettingsPublicationError('settings_receipt_pending', recovery=publication,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ()) from None
            publication.close()
    except BaseException as exc:
        failure = exc
        if isinstance(exc, InstalledClientError):
            raise SettingsPublicationError('settings_admission_lost',
                    cleanup_owners=() if exc.cleanup is None else (exc.cleanup,)) from None
        if isinstance(exc, RegistrationConflict):
            raise
        if isinstance(exc, (OSError, ValueError, TypeError)):
            raise RegistrationConflict('settings_selection_invalid') from None
        raise
    finally:
        cleanup = []
        if original is not None:
            try:
                _close(original)
            except RegistrationConflict:
                cleanup.append('consumed_settings_descriptor')
        if directory is not None:
            try:
                directory.close()
            except InstalledClientError as exc:
                cleanup.append(exc.cleanup if exc.cleanup is not None else directory)
        if cleanup:
            prior = failure if isinstance(failure, SettingsPublicationError) else None
            if isinstance(failure, InstalledClientError) and failure.cleanup is not None:
                cleanup.append(failure.cleanup)
            raise SettingsPublicationError('settings_cleanup_pending',
                recovery=prior.recovery if prior is not None else publication,
                staging_name=prior.staging_name if prior is not None else None,
                cleanup_owners=tuple(cleanup) + (() if prior is None else prior.cleanup_owners)) from None


@dataclass(frozen=True)
class DesktopSettingsSnapshot:
    raw: bytes = field(repr=False)
    identity: tuple = field(repr=False)


@contextmanager
def desktop_settings_snapshot(configuration_path, *, admission, deadline, on_accept=None):
    """Hold native settings read-only while preparing or reconciling a receipt."""
    from hub.installed_client_admission import InstalledClientAdmission, InstalledClientError, _RetainedPath, _canonical
    if type(admission) is not InstalledClientAdmission or not _canonical(configuration_path):
        raise RegistrationConflict('settings_application_admission_required')
    directory, current, failure = None, None, None
    locked = False
    try:
        with admission.hold(deadline=deadline):
            directory = _RetainedPath(os.path.dirname(configuration_path),
                purpose=native_admission.DescriptorPurpose.PRIVATE_DIRECTORY, deadline=deadline)
            try:
                fcntl.flock(directory.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RegistrationConflict('settings_busy') from None
            locked = True
            current, raw, identity = _read(directory.fd, os.path.basename(configuration_path), deadline)
            yield DesktopSettingsSnapshot(raw, identity)
            directory.recheck(deadline=deadline)
            admission.recheck(deadline=deadline)
            checked, body, now = _read(directory.fd, os.path.basename(configuration_path), deadline)
            try:
                if body != raw or now != identity or _identity(os.fstat(current)) != identity:
                    raise RegistrationConflict('configuration_changed')
            finally:
                _close(checked)
            if on_accept is not None:
                on_accept()
    except BaseException as exc:
        failure = exc
        if isinstance(exc, InstalledClientError):
            raise SettingsPublicationError('settings_admission_lost',
                cleanup_owners=() if exc.cleanup is None else (exc.cleanup,)) from None
        if isinstance(exc, OSError):
            raise RegistrationConflict('settings_selection_invalid') from None
        raise
    finally:
        cleanup = []
        if current is not None:
            try:
                _close(current)
            except BaseException:
                cleanup.append('consumed_settings_descriptor')
        if directory is not None:
            if locked:
                try:
                    fcntl.flock(directory.fd, fcntl.LOCK_UN)
                except BaseException:
                    cleanup.append(directory)
            try:
                directory.close()
            except BaseException:
                cleanup.append(directory)
        if cleanup:
            if isinstance(failure, InstalledClientError) and failure.cleanup is not None:
                cleanup.append(failure.cleanup)
            if isinstance(failure, SettingsPublicationError):
                cleanup.extend(failure.cleanup_owners)
            raise SettingsPublicationError('settings_cleanup_pending', cleanup_owners=cleanup) from None


@dataclass(frozen=True)
class ClaudeHookSettingsSnapshot:
    raw: bytes | None = field(repr=False)
    identity: tuple | None = field(repr=False)


@contextmanager
def claude_hook_settings_snapshot(configuration_path, *, admission, deadline, on_accept=None):
    """Hold an existing or absent Claude user settings file for one receipt decision."""
    from hub.installed_client_admission import InstalledClientAdmission, InstalledClientError, _RetainedPath, _canonical
    if type(admission) is not InstalledClientAdmission or not _canonical(configuration_path):
        raise RegistrationConflict('settings_application_admission_required')
    directory, current, failure = None, None, None
    locked = False
    try:
        with admission.hold(deadline=deadline):
            directory = _RetainedPath(os.path.dirname(configuration_path),
                purpose=native_admission.DescriptorPurpose.PRIVATE_DIRECTORY, deadline=deadline)
            try:
                fcntl.flock(directory.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise RegistrationConflict('settings_busy') from None
            locked = True
            current, raw, identity = _read_optional(directory.fd, os.path.basename(configuration_path), deadline)
            yield ClaudeHookSettingsSnapshot(raw, identity)
            directory.recheck(deadline=deadline)
            admission.recheck(deadline=deadline)
            checked, body, now = _read_optional(directory.fd, os.path.basename(configuration_path), deadline)
            try:
                if (body != raw or now != identity
                        or (current is not None and _identity(os.fstat(current)) != identity)):
                    raise RegistrationConflict('configuration_changed')
            finally:
                if checked is not None:
                    _close(checked)
            if on_accept is not None:
                on_accept()
    except BaseException as exc:
        failure = exc
        if isinstance(exc, InstalledClientError):
            raise SettingsPublicationError('settings_admission_lost',
                cleanup_owners=() if exc.cleanup is None else (exc.cleanup,)) from None
        if isinstance(exc, OSError):
            raise RegistrationConflict('settings_selection_invalid') from None
        raise
    finally:
        cleanup = []
        if current is not None:
            try:
                _close(current)
            except BaseException:
                cleanup.append('consumed_settings_descriptor')
        if directory is not None:
            if locked:
                try:
                    fcntl.flock(directory.fd, fcntl.LOCK_UN)
                except BaseException:
                    cleanup.append(directory)
            try:
                directory.close()
            except BaseException:
                cleanup.append(directory)
        if cleanup:
            if isinstance(failure, InstalledClientError) and failure.cleanup is not None:
                cleanup.append(failure.cleanup)
            if isinstance(failure, SettingsPublicationError):
                cleanup.extend(failure.cleanup_owners)
            raise SettingsPublicationError('settings_cleanup_pending', cleanup_owners=cleanup) from None


@contextmanager
def claude_hook_registration(configuration_path, *, admission, selection, owned=None, remove=False,
                             restore=None, deadline=None, expected_before=None,
                             expected_identity=None, on_accept=None):
    """Publish one fixed admitted Claude Code hook and retain receipt ownership."""
    from dashboard.claude_hook_registration import prepare_claude_hook_registration
    from hub.installed_client_admission import (InstalledClientAdmission, InstalledClientError,
                                               STABLE_FRONTEND, _RetainedPath, _canonical)
    if (type(admission) is not InstalledClientAdmission or not _canonical(configuration_path)
            or not _canonical(selection) or type(remove) is not bool):
        raise RegistrationConflict('settings_application_admission_required')
    if deadline is None:
        deadline = time.monotonic() + 10
    now = time.monotonic()
    if type(deadline) not in (int, float) or not now < deadline < float('inf'):
        raise RegistrationConflict('settings_deadline')
    directory, original, publication, failure = None, None, None, None
    try:
        with admission.hold(deadline=deadline) as declaration:
            if (declaration.command != STABLE_FRONTEND
                    or declaration.enrollment_selection != selection
                    or declaration.transport != 'stdio'):
                raise RegistrationConflict('settings_application_admission_required')
            arguments = ('claude-code-hook', '--client-installation', declaration.installation_id,
                         '--selection', selection)
            directory = _RetainedPath(os.path.dirname(configuration_path),
                    purpose=native_admission.DescriptorPurpose.PRIVATE_DIRECTORY, deadline=deadline)
            original, raw, identity = _read_optional(
                directory.fd, os.path.basename(configuration_path), deadline)
            if (expected_before != raw or expected_identity != identity):
                raise RegistrationConflict('configuration_changed')
            edit = prepare_claude_hook_registration(raw,
                installation_id=declaration.installation_id,
                configuration_path=configuration_path, command=declaration.command,
                arguments=arguments, owned=owned, remove=remove, restore=restore)

            directory_binding = directory
            def recheck():
                try:
                    directory_binding.recheck(deadline=deadline)
                    admission.recheck(deadline=deadline)
                except InstalledClientError as exc:
                    raise SettingsPublicationError('settings_admission_lost',
                            cleanup_owners=() if exc.cleanup is None else (exc.cleanup,)) from None

            try:
                publication = _publish_desktop_at(directory.fd, edit, recheck=recheck,
                                                  deadline=deadline, expected_identity=identity,
                                                  retain_lock=True)
            except SettingsPublicationError as exc:
                if exc.recovery is not None:
                    exc.recovery._directory_owner, directory = directory, None
                    exc.recovery._original_fd, original = original, None
                    exc.recovery._admission = admission
                raise
            publication._directory_owner, directory = directory, None
            publication._original_fd, original = original, None
            publication._admission = admission
            try:
                yield publication
            except BaseException as exc:
                raise SettingsPublicationError('settings_receipt_pending', recovery=publication,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ()) from None
            try:
                recheck()
                if publication._lock_fd is None or publication._fd is None:
                    raise RegistrationConflict('settings_publication_uncertain')
                current, body, identity = _read(publication._lock_fd,
                                                os.path.basename(configuration_path), deadline)
                try:
                    if (identity != publication._published_identity or body != edit.after
                            or _identity(os.fstat(publication._fd)) != publication._published_identity):
                        raise RegistrationConflict('settings_publication_uncertain')
                finally:
                    _close(current)
            except BaseException as exc:
                raise SettingsPublicationError('settings_publication_uncertain', recovery=publication,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ()) from None
            try:
                if on_accept is not None:
                    on_accept()
            except BaseException as exc:
                raise SettingsPublicationError('settings_receipt_pending', recovery=publication,
                    cleanup_owners=exc.cleanup_owners if isinstance(exc, SettingsPublicationError) else ()) from None
            publication.close()
    except BaseException as exc:
        failure = exc
        if isinstance(exc, InstalledClientError):
            raise SettingsPublicationError('settings_admission_lost',
                    cleanup_owners=() if exc.cleanup is None else (exc.cleanup,)) from None
        if isinstance(exc, RegistrationConflict):
            raise
        if isinstance(exc, (OSError, ValueError, TypeError)):
            raise RegistrationConflict('settings_selection_invalid') from None
        raise
    finally:
        cleanup = []
        if original is not None:
            try:
                _close(original)
            except RegistrationConflict:
                cleanup.append('consumed_settings_descriptor')
        if directory is not None:
            try:
                directory.close()
            except InstalledClientError as exc:
                cleanup.append(exc.cleanup if exc.cleanup is not None else directory)
        if cleanup:
            prior = failure if isinstance(failure, SettingsPublicationError) else None
            if isinstance(failure, InstalledClientError) and failure.cleanup is not None:
                cleanup.append(failure.cleanup)
            raise SettingsPublicationError('settings_cleanup_pending',
                recovery=prior.recovery if prior is not None else publication,
                staging_name=prior.staging_name if prior is not None else None,
                cleanup_owners=tuple(cleanup) + (() if prior is None else prior.cleanup_owners)) from None
