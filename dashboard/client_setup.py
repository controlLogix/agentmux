"""Explicit terminal setup for one native Claude Desktop registration.

No HTTP route calls this module. The installed bootstrap may call main() only
through its reviewed client-setup route. Package and enrollment are explicit;
Desktop configuration follows the native user's home. No services are started.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pwd
import secrets
import sys
import time

from native_security import descriptor_admission as native
from hub.installed_client_admission import (InstalledClientError, _Descriptors, _RetainedPath,
    _canonical, _admit, admit_installed_client)
from dashboard.resource_registration import (OwnedDesktopRegistration, RegistrationConflict,
    _unique, _invalid_constant, _valid_entry, _document, prepare_desktop_registration)
from dashboard.resource_settings import (SettingsPublicationError, _identity, _read,
    desktop_registration, desktop_settings_snapshot)

_RECEIPT_LIMIT = 256 * 1024
_OPERATIONS = ('install', 'remove', 'restore', 'recover')


class ClientSetupError(ValueError):
    """Closed terminal diagnostic; private recovery owners are never serialized."""
    def __init__(self, code, *, recovery=None):
        super().__init__(code)
        self.recovery = recovery


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _encode(value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
    if len(raw) > _RECEIPT_LIMIT:
        raise ClientSetupError('client_setup_receipt_invalid')
    return raw


def _owner_wire(owner):
    if owner is None:
        return None
    return {'installationId': owner.installation_id, 'configurationPath': owner.configuration_path,
            'entry': json.loads(owner.entry_json), 'createdContainer': owner.created_container}


def _owner(value, configuration):
    import re
    if value is None:
        return None
    try:
        if (type(value) is not dict or set(value) != {'installationId', 'configurationPath', 'entry', 'createdContainer'}
                or type(value['installationId']) is not str or not re.fullmatch(r'[0-9a-f]{64}', value['installationId'])
                or value['configurationPath'] != configuration or type(value['createdContainer']) is not bool
                or not _valid_entry(value['entry'])):
            raise ValueError
        from hub.installed_client_admission import STABLE_FRONTEND
        entry = value['entry']
        if (entry['command'] != STABLE_FRONTEND or len(entry['args']) != 5
                or entry['args'][:3] != ['mcp', '--client-installation', value['installationId']]
                or entry['args'][3] != '--selection' or not _canonical(entry['args'][4])):
            raise ValueError
        return OwnedDesktopRegistration(value['installationId'], configuration,
            json.dumps(entry, sort_keys=True).encode(), value['createdContainer'])
    except (ValueError, TypeError, KeyError):
        raise ClientSetupError('client_setup_receipt_invalid') from None


def _state(value, configuration):
    if type(value) is not dict or set(value) != {'current', 'saved'}:
        raise ClientSetupError('client_setup_receipt_invalid')
    _owner(value['current'], configuration)
    _owner(value['saved'], configuration)
    return value


def _receipt(raw, configuration):
    import re
    if raw is None:
        return {'schemaVersion': '1.0.0', 'kind': 'desktop-registration-receipt',
                'configurationPath': configuration, 'state': {'current': None, 'saved': None}, 'pending': None}
    try:
        if not 0 < len(raw) <= _RECEIPT_LIMIT:
            raise ValueError
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_invalid_constant)
        if (type(value) is not dict or set(value) != {'schemaVersion', 'kind', 'configurationPath', 'state', 'pending'}
                or value['schemaVersion'] != '1.0.0' or value['kind'] != 'desktop-registration-receipt'
                or value['configurationPath'] != configuration):
            raise ValueError
        _state(value['state'], configuration)
        pending = value['pending']
        if pending is not None:
            if (type(pending) is not dict or set(pending) != {'operation', 'installationId', 'enrollmentSelection',
                    'beforeDigest', 'afterDigest', 'afterState'} or pending['operation'] not in _OPERATIONS[:3]
                    or type(pending['installationId']) is not str
                    or not re.fullmatch(r'[0-9a-f]{64}', pending['installationId'])
                    or not _canonical(pending['enrollmentSelection'])
                    or any(type(pending[key]) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', pending[key])
                           for key in ('beforeDigest', 'afterDigest'))):
                raise ValueError
            _state(pending['afterState'], configuration)
            before, after = value['state'], pending['afterState']
            def matches(owner):
                return (owner is not None and owner['installationId'] == pending['installationId']
                        and owner['entry']['args'][4] == pending['enrollmentSelection'])
            if before['current'] is not None and before['current']['installationId'] != pending['installationId']:
                raise ValueError
            if pending['operation'] == 'remove':
                if not matches(before['current']) or after != {'current': None, 'saved': before['current']}:
                    raise ValueError
            else:
                if not matches(after['current']) or after['saved'] != before['saved']:
                    raise ValueError
                if pending['operation'] == 'restore' and (before['current'] is not None
                        or not matches(before['saved']) or after['current']['entry'] != before['saved']['entry']):
                    raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ClientSetupError('client_setup_receipt_invalid') from None


class _ReceiptStore:
    """One explicitly selected private receipt, locked through its whole operation."""
    def __init__(self, path, *, deadline):
        if not _canonical(path):
            raise ClientSetupError('client_setup_receipt_path_invalid')
        self.path, self.deadline = path, deadline
        self.parent, self.fd, self.raw, self.identity = None, None, None, None
        self.owners, self.locked, self.pending = _Descriptors(), False, False
        self.incomplete = False
        self.staging_name = None
        try:
            self.parent = _RetainedPath(os.path.dirname(path),
                purpose=native.DescriptorPurpose.PRIVATE_DIRECTORY, deadline=deadline)
            try:
                fcntl.flock(self.parent.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ClientSetupError('client_setup_receipt_busy') from None
            self.locked = True
            self.fd, self.raw, self.identity = self._current()
        except BaseException:
            self.close()
            raise

    def _current(self):
        try:
            fd, raw, identity = _read(self.parent.fd, os.path.basename(self.path), self.deadline)
        except FileNotFoundError:
            return None, None, None
        self.owners.add(fd)
        if len(raw) > _RECEIPT_LIMIT:
            raise ClientSetupError('client_setup_receipt_invalid')
        return fd, raw, identity

    def _compare(self):
        self.parent.recheck(deadline=self.deadline)
        fd, raw, identity = self._current()
        try:
            if (raw != self.raw or identity != self.identity
                    or self.fd is not None and _identity(os.fstat(self.fd)) != self.identity):
                raise ClientSetupError('client_setup_receipt_changed')
        finally:
            if fd is not None:
                self.owners.close(fd)

    def write(self, value):
        body = _encode(value)
        self._compare()
        staged = None
        published = False
        try:
            if self.fd is None:
                # Initial creation never replaces a path that appeared meanwhile.
                # A crash during this first write leaves an invalid private receipt;
                # native settings cannot change before its complete durable readback.
                staged = self.owners.add(os.open(os.path.basename(self.path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=self.parent.fd))
                published = True
            else:
                candidate = '.agentmux-receipt-' + secrets.token_hex(16)
                staged = self.owners.add(os.open(candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=self.parent.fd))
                self.staging_name = candidate
            _admit(staged, native.DescriptorPurpose.PRIVATE_FILE, self.deadline, owners=self.owners)
            remaining = memoryview(body)
            while remaining:
                if time.monotonic() >= self.deadline:
                    raise ClientSetupError('client_setup_deadline')
                written = os.write(staged, remaining)
                if written <= 0:
                    raise OSError
                remaining = remaining[written:]
            os.fsync(staged)
            if not published:
                checked, raw, identity = _read(self.parent.fd, self.staging_name, self.deadline)
                self.owners.add(checked)
                try:
                    if raw != body or identity != _identity(os.fstat(staged)):
                        raise ClientSetupError('client_setup_receipt_changed')
                finally:
                    self.owners.close(checked)
                self._compare()
                os.rename(self.staging_name, os.path.basename(self.path),
                          src_dir_fd=self.parent.fd, dst_dir_fd=self.parent.fd)
                published = True
                self.staging_name = None
            os.fsync(self.parent.fd)
            checked, raw, identity = self._current()
            if raw != body or identity[:2] != _identity(os.fstat(staged))[:2]:
                raise ClientSetupError('client_setup_receipt_changed')
            if self.fd is not None:
                self.owners.close(self.fd)
            self.fd, self.raw, self.identity = checked, raw, identity
        except BaseException:
            self.incomplete = True
            raise ClientSetupError('client_setup_receipt_incomplete', recovery=self) from None
        finally:
            if staged is not None:
                self.owners.close(staged)

    def close(self):
        pending = self.pending
        try:
            self.owners.close_all()
        except BaseException:
            pending = True
        if self.parent is not None:
            if self.locked:
                self.locked = False
                try:
                    fcntl.flock(self.parent.fd, fcntl.LOCK_UN)
                except BaseException:
                    pending = True
            try:
                self.parent.close()
            except BaseException:
                pending = True
        self.pending = pending
        if pending:
            raise ClientSetupError('client_setup_cleanup_pending', recovery=self)

    def sync(self):
        """Confirm an existing accepted record after an interrupted directory sync."""
        try:
            self._compare()
            if self.fd is not None:
                os.fsync(self.fd)
                os.fsync(self.parent.fd)
                self._compare()
        except BaseException:
            self.incomplete = True
            raise ClientSetupError('client_setup_receipt_incomplete', recovery=self) from None


def _configuration():
    try:
        uid = os.getuid()
        account = pwd.getpwuid(uid)
        if os.geteuid() != uid or account.pw_uid != uid or not _canonical(account.pw_dir):
            raise ValueError
        return os.path.join(account.pw_dir, 'Library/Application Support/Claude/claude_desktop_config.json')
    except (KeyError, OSError, ValueError, TypeError):
        raise ClientSetupError('client_setup_native_home_unavailable') from None


def _result(operation, outcome, *, settings):
    return {'schema_version': '1.0.0', 'kind': 'client-setup-result', 'client_id': 'claude-desktop',
            'operation': operation, 'outcome': outcome, 'settings': settings}


def run_setup(*, installation_id, selection, receipt, operation, apply=False, deadline=None):
    """Prepare a durable recovery record before any explicitly requested edit."""
    from hub.client_launch_selection import load_selection
    if operation not in _OPERATIONS or type(apply) is not bool:
        raise ClientSetupError('client_setup_arguments_invalid')
    if deadline is None:
        deadline = time.monotonic() + 30
    configuration = _configuration()
    if not _canonical(receipt) or receipt in (configuration, selection):
        raise ClientSetupError('client_setup_receipt_path_invalid')
    if os.path.dirname(receipt) == os.path.dirname(configuration):
        raise ClientSetupError('client_setup_receipt_directory_conflict')
    application, store, failure = None, None, None
    try:
        application = admit_installed_client(installation_id, selection, deadline=deadline)
        with application.hold(deadline=deadline) as declaration:
            enrolled = load_selection(selection, deadline=deadline)
            for workspace in enrolled.invocation.workspaces:
                root = os.path.realpath(workspace)
                for path in (receipt, configuration):
                    if os.path.commonpath((root, os.path.realpath(path))) == root:
                        raise ClientSetupError('client_setup_path_inside_workspace')
            store = _ReceiptStore(receipt, deadline=deadline)
            state = _receipt(store.raw, configuration)
            if operation == 'recover':
                def commit_recovery():
                    if apply:
                        if pending is None:
                            store.sync()
                        else:
                            store.write(dict(state, state=recovered, pending=None))
                with desktop_settings_snapshot(configuration, admission=application, deadline=deadline,
                                               on_accept=commit_recovery) as snapshot:
                    pending = state['pending']
                    if pending is None:
                        current = _owner(state['state']['current'], configuration)
                        actual = _document(snapshot.raw).get('mcpServers', {}).get('agentmux')
                        expected = None if current is None else json.loads(current.entry_json)
                        if actual != expected:
                            raise ClientSetupError('client_setup_recovery_conflict')
                        if current is not None and (current.installation_id != installation_id or expected !=
                                {'command': declaration.command, 'args': list(declaration.arguments)}):
                            raise ClientSetupError('client_setup_owner_mismatch')
                    else:
                        if (pending['installationId'] != installation_id or pending['enrollmentSelection'] != selection):
                            raise ClientSetupError('client_setup_owner_mismatch')
                        digest = _digest(snapshot.raw)
                        if digest == pending['afterDigest']:
                            recovered = pending['afterState']
                        elif digest == pending['beforeDigest']:
                            recovered = state['state']
                        else:
                            raise ClientSetupError('client_setup_recovery_conflict')
                # Final validation and receipt commitment share the settings lock.
                # Recovery never edits native settings.
                outcome = 'no_pending_change' if pending is None else 'recovered' if apply else 'recovery_ready'
                return _result(operation, outcome, settings='unchanged')
            with desktop_settings_snapshot(configuration, admission=application, deadline=deadline) as snapshot:
                if state['pending'] is not None:
                    raise ClientSetupError('client_setup_recovery_required')
                current = _owner(state['state']['current'], configuration)
                saved = _owner(state['state']['saved'], configuration)
                if operation == 'restore':
                    if current is not None or saved is None:
                        raise ClientSetupError('client_setup_restore_unavailable')
                    if (saved.installation_id != installation_id or json.loads(saved.entry_json) !=
                            {'command': declaration.command, 'args': list(declaration.arguments)}):
                        raise ClientSetupError('client_setup_owner_mismatch')
                if operation == 'remove' and current is None:
                    raise ClientSetupError('client_setup_registration_not_owned')
                plan = prepare_desktop_registration(snapshot.raw, installation_id=installation_id,
                    configuration_path=configuration, command=declaration.command,
                    arguments=declaration.arguments, owned=current, remove=operation == 'remove')
                after = {'current': _owner_wire(plan.ownership),
                         'saved': _owner_wire(current) if operation == 'remove' else state['state']['saved']}
                if not apply:
                    return _result(operation, 'ready', settings='unchanged')
                prepared = dict(state, pending={'operation': operation, 'installationId': installation_id,
                    'enrollmentSelection': selection, 'beforeDigest': _digest(plan.before),
                    'afterDigest': _digest(plan.after), 'afterState': after})
                store.write(prepared)
            # The prepared receipt is durable. A changed snapshot refuses publication
            # and remains explicitly pending for before/after reconciliation.
            with desktop_registration(configuration, admission=application, owned=current,
                    remove=operation == 'remove', deadline=deadline,
                    expected_before=snapshot.raw, expected_identity=snapshot.identity,
                    on_accept=lambda: store.write(dict(state, state=after, pending=None))) as publication:
                if publication.edit.after != plan.after or _owner_wire(publication.edit.ownership) != after['current']:
                    raise ClientSetupError('client_setup_plan_changed')
            return _result(operation, 'applied', settings='changed' if plan.before != plan.after else 'unchanged')
    except BaseException as exc:
        failure = exc
        raise
    finally:
        cleanup = []
        if isinstance(failure, SettingsPublicationError) and failure.recovery is not None:
            try:
                failure.recovery.close()
            except BaseException:
                cleanup.append(failure.recovery)
        if isinstance(failure, SettingsPublicationError):
            cleanup.extend(failure.cleanup_owners)
        if getattr(failure, 'cleanup', None) is not None:
            cleanup.append(failure.cleanup)
        for owner in (store, application):
            if owner is not None:
                try:
                    owner.close()
                except BaseException:
                    cleanup.append(owner)
        if cleanup:
            raise ClientSetupError('client_setup_cleanup_pending', recovery=cleanup) from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ClientSetupError('client_setup_arguments_invalid')


def main(argv=None):
    parser = _Parser(description='Review or apply one native Desktop registration. Settings and credentials stay native.')
    parser.add_argument('--client-installation', required=True)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--operation', choices=_OPERATIONS, required=True)
    parser.add_argument('--apply', action='store_true', help='Apply the selected change; otherwise only review prerequisites.')
    try:
        args = parser.parse_args(argv)
        result = run_setup(installation_id=args.client_installation, selection=args.selection,
                           receipt=args.receipt, operation=args.operation, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ClientSetupError, RegistrationConflict, InstalledClientError) as error:
        print('Client setup stopped: ' + str(error) + '.', file=sys.stderr)
        print('Keep the native configuration and ownership record. Resolve pending changes with --operation recover --apply.',
              file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print('Client setup stopped: client_setup_unavailable. Check private paths and native permissions.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
