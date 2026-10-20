"""Plan one owned Claude Code SessionStart hook without writing settings."""
from dataclasses import dataclass, field
import json
import os

from dashboard.resource_registration import (_Number, _invalid_constant, _json_text,
                                             _unique, RegistrationConflict)


def _document(raw):
    if raw is None:
        return {}
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        raise RegistrationConflict('configuration_invalid')
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=_invalid_constant,
                           parse_float=_Number, parse_int=_Number)
        if not isinstance(value, dict):
            raise ValueError
        hooks = value.get('hooks', {})
        if not isinstance(hooks, dict) or not isinstance(hooks.get('SessionStart', []), list):
            raise ValueError
        _json_text(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RegistrationConflict('configuration_invalid') from None


def _installation(value):
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in '0123456789abcdef' for character in value)):
        raise RegistrationConflict('installation_identity_invalid')


def _path(value):
    try:
        return (isinstance(value, str) and os.path.isabs(value) and os.path.normpath(value) == value
                and value != '/' and not value.startswith('//') and len(value.encode()) <= 4096
                and len(value.split('/')) <= 128
                and not any(ord(character) < 32 or 127 <= ord(character) <= 159
                            or '\ud800' <= character <= '\udfff' for character in value))
    except (UnicodeError, ValueError, TypeError):
        return False


def _handler(command, arguments):
    if (not _path(command) or not isinstance(arguments, tuple) or len(arguments) != 5
            or arguments[0] != 'claude-code-hook' or arguments[1] != '--client-installation'
            or arguments[3] != '--selection' or not _path(arguments[4])):
        raise RegistrationConflict('application_command_invalid')
    _installation(arguments[2])
    return {'type': 'command', 'command': command, 'args': list(arguments)}


def _group(handler):
    return {'matcher': 'startup|resume|fork', 'hooks': [handler]}


def _contains_handler(value, handler):
    return (isinstance(value, dict) and isinstance(value.get('hooks'), list)
            and any(isinstance(candidate, dict)
                    and all(candidate.get(key) == handler[key] for key in ('type', 'command', 'args'))
                    for candidate in value['hooks']))


@dataclass(frozen=True)
class OwnedClaudeHookRegistration:
    installation_id: str
    configuration_path: str = field(repr=False)
    group_json: bytes = field(repr=False)
    index: int
    created_hooks: bool
    created_event: bool


def _owned_group(owner, configuration_path):
    if (not isinstance(owner, OwnedClaudeHookRegistration)
            or owner.configuration_path != configuration_path
            or type(owner.index) is not int or owner.index < 0
            or type(owner.created_hooks) is not bool or type(owner.created_event) is not bool):
        raise RegistrationConflict('registration_owner_invalid')
    _installation(owner.installation_id)
    try:
        group = json.loads(owner.group_json, object_pairs_hook=_unique,
                           parse_constant=_invalid_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RegistrationConflict('registration_owner_invalid') from None
    if (not isinstance(group, dict) or set(group) != {'matcher', 'hooks'}
            or group['matcher'] != 'startup|resume|fork' or not isinstance(group['hooks'], list)
            or len(group['hooks']) != 1 or not isinstance(group['hooks'][0], dict)
            or set(group['hooks'][0]) != {'type', 'command', 'args'}
            or group['hooks'][0].get('type') != 'command'):
        raise RegistrationConflict('registration_owner_invalid')
    try:
        expected = _handler(group['hooks'][0].get('command'), tuple(group['hooks'][0].get('args', ())))
    except RegistrationConflict:
        raise RegistrationConflict('registration_owner_invalid') from None
    if expected != group['hooks'][0] or expected['args'][2] != owner.installation_id:
        raise RegistrationConflict('registration_owner_invalid')
    return group


@dataclass(frozen=True)
class ClaudeHookRegistrationEdit:
    configuration_path: str = field(repr=False)
    before: bytes | None = field(repr=False)
    after: bytes = field(repr=False)
    ownership: OwnedClaudeHookRegistration | None = field(repr=False)
    outcome: str
    previous_ownership: OwnedClaudeHookRegistration | None = field(default=None, repr=False)

    def for_snapshot(self, current, *, configuration_path):
        if configuration_path != self.configuration_path or current != self.before:
            raise RegistrationConflict('configuration_changed')
        return self.after


def prepare_claude_hook_registration(raw, *, installation_id, configuration_path, command,
                                     arguments, owned=None, remove=False, restore=None):
    """Add, update, remove or restore exactly one receipt-owned matcher group."""
    _installation(installation_id)
    if not _path(configuration_path) or type(remove) is not bool or (remove and restore is not None):
        raise RegistrationConflict('operation_invalid')
    handler = _handler(command, arguments)
    if handler['args'][2] != installation_id:
        raise RegistrationConflict('application_command_invalid')
    desired = _group(handler)
    data = _document(raw)
    created_hooks = 'hooks' not in data
    hooks = data.setdefault('hooks', {})
    created_event = 'SessionStart' not in hooks
    groups = hooks.setdefault('SessionStart', [])
    previous = _owned_group(owned, configuration_path) if owned is not None else None
    restored = _owned_group(restore, configuration_path) if restore is not None else None
    if restored is not None and (restored != desired or restore.installation_id != installation_id):
        raise RegistrationConflict('registration_owner_mismatch')

    if previous is not None:
        if remove and (previous != desired or owned.installation_id != installation_id):
            raise RegistrationConflict('registration_owner_mismatch')
        matches = [index for index, group in enumerate(groups) if group == previous]
        if len(matches) != 1:
            raise RegistrationConflict('registration_changed')
        index = matches[0]
        if remove:
            groups.pop(index)
            ownership, outcome = None, 'removed'
            if not groups and owned.created_event:
                del hooks['SessionStart']
            if not hooks and owned.created_hooks:
                del data['hooks']
        else:
            if any(_contains_handler(group, handler) for offset, group in enumerate(groups) if offset != index):
                raise RegistrationConflict('registration_not_owned')
            groups[index] = desired
            ownership = OwnedClaudeHookRegistration(installation_id, configuration_path,
                json.dumps(desired, sort_keys=True, separators=(',', ':')).encode(), index,
                owned.created_hooks, owned.created_event)
            outcome = 'unchanged' if previous == desired else 'updated'
    elif restore is not None:
        if any(_contains_handler(group, handler) for group in groups):
            raise RegistrationConflict('registration_not_owned')
        index = min(restore.index, len(groups))
        groups.insert(index, desired)
        ownership = OwnedClaudeHookRegistration(installation_id, configuration_path,
            json.dumps(desired, sort_keys=True, separators=(',', ':')).encode(), index,
            restore.created_hooks, restore.created_event)
        outcome = 'restored'
    else:
        if remove:
            raise RegistrationConflict('registration_not_owned')
        if any(_contains_handler(group, handler) for group in groups):
            raise RegistrationConflict('registration_not_owned')
        index = len(groups)
        groups.append(desired)
        ownership = OwnedClaudeHookRegistration(installation_id, configuration_path,
            json.dumps(desired, sort_keys=True, separators=(',', ':')).encode(), index,
            created_hooks, created_event)
        outcome = 'added'

    after = (_json_text(data) + '\n').encode()
    if len(after) > 1024 * 1024:
        raise RegistrationConflict('configuration_too_large')
    return ClaudeHookRegistrationEdit(configuration_path, raw, after, ownership, outcome, owned)
