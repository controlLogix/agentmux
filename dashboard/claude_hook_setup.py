"""Explicit durable setup for one admitted Claude Code SessionStart hook."""
import argparse
import json
import os
import re
import sys
import time

from dashboard import client_setup as durable
from dashboard.claude_hook_registration import (OwnedClaudeHookRegistration, _document, _owned_group,
    prepare_claude_hook_registration)
from dashboard.resource_registration import RegistrationConflict, _invalid_constant, _unique
from dashboard.resource_settings import (SettingsPublicationError, claude_hook_registration,
    claude_hook_settings_snapshot)
from hub.installed_client_admission import (InstalledClientError, _canonical,
                                             admit_installed_client)

_OPERATIONS = ('install', 'remove', 'restore', 'recover')
_DIGEST = re.compile(r'(?:absent|sha256:[0-9a-f]{64})')


class ClaudeHookSetupError(ValueError):
    """Closed diagnostic; private settings and recovery owners stay private."""
    def __init__(self, code, *, recovery=None):
        super().__init__(code)
        self.recovery = recovery


def _digest(raw):
    return 'absent' if raw is None else durable._digest(raw)


def _owner_wire(owner):
    if owner is None:
        return None
    return {
        'installationId': owner.installation_id,
        'configurationPath': owner.configuration_path,
        'group': json.loads(owner.group_json),
        'index': owner.index,
        'createdHooks': owner.created_hooks,
        'createdEvent': owner.created_event,
    }


def _owner(value, configuration):
    if value is None:
        return None
    try:
        if (type(value) is not dict or set(value) != {'installationId', 'configurationPath', 'group',
                'index', 'createdHooks', 'createdEvent'}
                or not re.fullmatch(r'[0-9a-f]{64}', value['installationId'])
                or value['configurationPath'] != configuration or type(value['index']) is not int
                or value['index'] < 0 or type(value['createdHooks']) is not bool
                or type(value['createdEvent']) is not bool):
            raise ValueError
        owner = OwnedClaudeHookRegistration(value['installationId'], configuration,
            json.dumps(value['group'], sort_keys=True, separators=(',', ':')).encode(),
            value['index'], value['createdHooks'], value['createdEvent'])
        group = _owned_group(owner, configuration)
        handler = group['hooks'][0]
        from hub.installed_client_admission import STABLE_FRONTEND
        if (handler['command'] != STABLE_FRONTEND or handler['args'][1] != '--client-installation'
                or handler['args'][2] != value['installationId']
                or handler['args'][3] != '--selection' or not _canonical(handler['args'][4])):
            raise ValueError
        return owner
    except (KeyError, TypeError, ValueError, RegistrationConflict):
        raise ClaudeHookSetupError('claude_hook_receipt_invalid') from None


def _state(value, configuration):
    if type(value) is not dict or set(value) != {'current', 'saved'}:
        raise ClaudeHookSetupError('claude_hook_receipt_invalid')
    _owner(value['current'], configuration)
    _owner(value['saved'], configuration)
    return value


def _matches(value, installation_id, selection, configuration):
    owner = _owner(value, configuration)
    if owner is None:
        return False
    group = json.loads(owner.group_json)
    return owner.installation_id == installation_id and group['hooks'][0]['args'][4] == selection


def _receipt(raw, configuration):
    if raw is None:
        return {'schemaVersion': '1.0.0', 'kind': 'claude-hook-receipt',
                'configurationPath': configuration,
                'state': {'current': None, 'saved': None}, 'pending': None}
    try:
        if not 0 < len(raw) <= durable._RECEIPT_LIMIT:
            raise ValueError
        value = json.loads(raw.decode(), object_pairs_hook=_unique, parse_constant=_invalid_constant)
        if (type(value) is not dict or set(value) != {'schemaVersion', 'kind', 'configurationPath',
                'state', 'pending'} or value['schemaVersion'] != '1.0.0'
                or value['kind'] != 'claude-hook-receipt'
                or value['configurationPath'] != configuration):
            raise ValueError
        _state(value['state'], configuration)
        pending = value['pending']
        if pending is not None:
            if (type(pending) is not dict or set(pending) != {'operation', 'installationId',
                    'enrollmentSelection', 'beforeDigest', 'afterDigest', 'afterState'}
                    or pending['operation'] not in _OPERATIONS[:3]
                    or not re.fullmatch(r'[0-9a-f]{64}', pending['installationId'])
                    or not _canonical(pending['enrollmentSelection'])
                    or any(type(pending[key]) is not str or _DIGEST.fullmatch(pending[key]) is None
                           for key in ('beforeDigest', 'afterDigest'))):
                raise ValueError
            _state(pending['afterState'], configuration)
            before, after = value['state'], pending['afterState']
            matches = lambda item: _matches(item, pending['installationId'],
                                            pending['enrollmentSelection'], configuration)
            if pending['operation'] == 'remove':
                if not matches(before['current']) or after != {'current': None, 'saved': before['current']}:
                    raise ValueError
            elif pending['operation'] == 'restore':
                before_saved = _owner(before['saved'], configuration)
                after_current = _owner(after['current'], configuration)
                if (before['current'] is not None or not matches(before['saved'])
                        or after['saved'] != before['saved'] or after_current is None
                        or after_current.installation_id != before_saved.installation_id
                        or after_current.group_json != before_saved.group_json
                        or after_current.created_hooks != before_saved.created_hooks
                        or after_current.created_event != before_saved.created_event):
                    raise ValueError
            elif not matches(after['current']) or after['saved'] != before['saved']:
                raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError, ClaudeHookSetupError):
        raise ClaudeHookSetupError('claude_hook_receipt_invalid') from None


def _configuration(configuration_path):
    if (not _canonical(configuration_path) or configuration_path == '/'
            or os.path.basename(configuration_path) != 'settings.json'):
        raise ClaudeHookSetupError('claude_hook_native_home_unavailable')
    return configuration_path


def _result(operation, outcome, *, settings):
    return {'schema_version': '1.0.0', 'kind': 'claude-hook-setup-result',
            'client_id': 'claude', 'operation': operation, 'outcome': outcome,
            'settings': settings}


def run_setup(*, installation_id, selection, receipt, operation, configuration_path,
              apply=False, deadline=None):
    """Prepare a durable receipt before one explicit Claude user-settings edit."""
    from hub.client_launch_selection import load_selection
    if operation not in _OPERATIONS or type(apply) is not bool:
        raise ClaudeHookSetupError('claude_hook_arguments_invalid')
    if deadline is None:
        deadline = time.monotonic() + 30
    configuration = _configuration(configuration_path)
    if (not _canonical(receipt) or receipt in (configuration, selection)
            or os.path.dirname(receipt) == os.path.dirname(configuration)):
        raise ClaudeHookSetupError('claude_hook_receipt_path_invalid')
    application, store, failure = None, None, None
    try:
        application = admit_installed_client(installation_id, selection, deadline=deadline)
        with application.hold(deadline=deadline) as declaration:
            enrolled = load_selection(selection, deadline=deadline)
            for workspace in enrolled.invocation.workspaces:
                root = os.path.realpath(workspace)
                for path in (receipt, configuration):
                    if os.path.commonpath((root, os.path.realpath(path))) == root:
                        raise ClaudeHookSetupError('claude_hook_path_inside_workspace')
            store = durable._ReceiptStore(receipt, deadline=deadline)
            state = _receipt(store.raw, configuration)
            if operation == 'recover':
                pending = state['pending']
                recovered = state['state']
                def commit_recovery():
                    if apply:
                        if pending is None:
                            store.sync()
                        else:
                            store.write(dict(state, state=recovered, pending=None))
                with claude_hook_settings_snapshot(configuration, admission=application,
                        deadline=deadline, on_accept=commit_recovery) as snapshot:
                    if pending is None:
                        current = _owner(state['state']['current'], configuration)
                        data = _document(snapshot.raw)
                        groups = data.get('hooks', {}).get('SessionStart', [])
                        expected = None if current is None else json.loads(current.group_json)
                        if expected is None:
                            if groups and any(isinstance(group, dict) and group.get('hooks') == [
                                    {'type': 'command', 'command': declaration.command,
                                     'args': ['claude-code-hook', '--client-installation', installation_id,
                                              '--selection', selection]}] for group in groups):
                                raise ClaudeHookSetupError('claude_hook_recovery_conflict')
                        elif sum(group == expected for group in groups) != 1:
                            raise ClaudeHookSetupError('claude_hook_recovery_conflict')
                        if current is not None and not _matches(
                                state['state']['current'], installation_id, selection, configuration):
                            raise ClaudeHookSetupError('claude_hook_owner_mismatch')
                    else:
                        if (pending['installationId'] != installation_id
                                or pending['enrollmentSelection'] != selection):
                            raise ClaudeHookSetupError('claude_hook_owner_mismatch')
                        digest = _digest(snapshot.raw)
                        if digest == pending['afterDigest']:
                            recovered = pending['afterState']
                        elif digest != pending['beforeDigest']:
                            raise ClaudeHookSetupError('claude_hook_recovery_conflict')
                outcome = 'no_pending_change' if pending is None else 'recovered' if apply else 'recovery_ready'
                return _result(operation, outcome, settings='unchanged')

            with claude_hook_settings_snapshot(configuration, admission=application,
                                                deadline=deadline) as snapshot:
                if state['pending'] is not None:
                    raise ClaudeHookSetupError('claude_hook_recovery_required')
                current = _owner(state['state']['current'], configuration)
                saved = _owner(state['state']['saved'], configuration)
                arguments = ('claude-code-hook', '--client-installation', installation_id,
                             '--selection', selection)
                if operation == 'restore':
                    if current is not None or saved is None:
                        raise ClaudeHookSetupError('claude_hook_restore_unavailable')
                    if not _matches(state['state']['saved'], installation_id, selection, configuration):
                        raise ClaudeHookSetupError('claude_hook_owner_mismatch')
                if operation == 'remove':
                    if current is None:
                        raise ClaudeHookSetupError('claude_hook_registration_not_owned')
                    if not _matches(state['state']['current'], installation_id, selection, configuration):
                        raise ClaudeHookSetupError('claude_hook_owner_mismatch')
                plan = prepare_claude_hook_registration(snapshot.raw,
                    installation_id=installation_id, configuration_path=configuration,
                    command=declaration.command, arguments=arguments, owned=current,
                    remove=operation == 'remove', restore=saved if operation == 'restore' else None)
                after = {'current': _owner_wire(plan.ownership),
                         'saved': _owner_wire(current) if operation == 'remove' else state['state']['saved']}
                if not apply:
                    return _result(operation, 'ready', settings='unchanged')
                prepared = dict(state, pending={'operation': operation,
                    'installationId': installation_id, 'enrollmentSelection': selection,
                    'beforeDigest': _digest(plan.before), 'afterDigest': _digest(plan.after),
                    'afterState': after})
                store.write(prepared)
            with claude_hook_registration(configuration, admission=application, selection=selection,
                    owned=current, remove=operation == 'remove',
                    restore=saved if operation == 'restore' else None, deadline=deadline,
                    expected_before=snapshot.raw, expected_identity=snapshot.identity,
                    on_accept=lambda: store.write(dict(state, state=after, pending=None))) as publication:
                if (publication.edit.after != plan.after
                        or _owner_wire(publication.edit.ownership) != after['current']):
                    raise ClaudeHookSetupError('claude_hook_plan_changed')
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
            raise ClaudeHookSetupError('claude_hook_cleanup_pending', recovery=cleanup) from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ClaudeHookSetupError('claude_hook_arguments_invalid')


def main(argv=None, *, configuration_path=None):
    parser = _Parser(description='Review or apply one admitted Claude Code SessionStart hook.')
    parser.add_argument('--client-installation', required=True)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--operation', choices=_OPERATIONS, required=True)
    parser.add_argument('--apply', action='store_true')
    try:
        args = parser.parse_args(argv)
        result = run_setup(installation_id=args.client_installation, selection=args.selection,
                           receipt=args.receipt, operation=args.operation,
                           configuration_path=configuration_path, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ClaudeHookSetupError, RegistrationConflict, InstalledClientError) as error:
        print('Claude hook setup stopped: ' + str(error) + '.', file=sys.stderr)
        print('Keep settings and the receipt. Resolve pending changes with --operation recover --apply.',
              file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print('Claude hook setup stopped: claude_hook_unavailable.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
