"""Prepare one owned Desktop MCP entry without writing native configuration.

The installation owner must supply an admitted application command and persist
the returned ownership record with its installation. These functions do not admit
commands, publish files, or register the runtime's NATS endpoint as an MCP server.
"""
from dataclasses import dataclass, field, replace
import json
import os


class RegistrationConflict(ValueError):
    """Closed diagnostic only; configuration and command contents stay private."""


class _Number(str):
    """Retain an unrelated JSON number's original token without float rounding."""


def _json_text(value, depth=0):
    if depth > 64:
        raise RegistrationConflict('configuration_invalid')
    if isinstance(value, _Number):
        return str(value)
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(key) + ':' + _json_text(item, depth + 1)
                              for key, item in value.items()) + '}'
    if isinstance(value, list):
        return '[' + ','.join(_json_text(item, depth + 1) for item in value) + ']'
    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RegistrationConflict('configuration_invalid')
        result[key] = value
    return result


def _document(raw):
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        raise RegistrationConflict('configuration_invalid')
    try:
        data = json.loads(raw, object_pairs_hook=_unique, parse_constant=_invalid_constant,
                          parse_float=_Number, parse_int=_Number)
        if not isinstance(data, dict) or not isinstance(data.get('mcpServers', {}), dict):
            raise ValueError
        _json_text(data)
        return data
    except (ValueError, UnicodeError, RecursionError):
        raise RegistrationConflict('configuration_invalid') from None


def _invalid_constant(_):
    raise ValueError


def _valid_entry(entry):
    return (isinstance(entry, dict) and set(entry) == {'command', 'args'}
            and type(entry['command']) is str and 0 < len(entry['command']) <= 4096
            and os.path.isabs(entry['command']) and os.path.normpath(entry['command']) == entry['command']
            and not any('\ud800' <= c <= '\udfff' or c == '\x00' for c in entry['command'])
            and isinstance(entry['args'], list)
            and len(entry['args']) <= 64
            and all(type(arg) is str and len(arg) <= 4096
                    and not any('\ud800' <= c <= '\udfff' or c == '\x00' for c in arg) for arg in entry['args']))


def _installation(value):
    if (not isinstance(value, str) or not value or len(value) > 128
            or any(not (c.isascii() and (c.isalnum() or c in '._-')) for c in value)):
        raise RegistrationConflict('installation_identity_invalid')


@dataclass(frozen=True)
class OwnedDesktopRegistration:
    installation_id: str
    configuration_path: str = field(repr=False)
    entry_json: bytes = field(repr=False)
    created_container: bool = False


@dataclass(frozen=True)
class DesktopRegistrationEdit:
    configuration_path: str = field(repr=False)
    before: bytes = field(repr=False)
    after: bytes = field(repr=False)
    ownership: OwnedDesktopRegistration | None = field(repr=False)
    outcome: str
    previous_ownership: OwnedDesktopRegistration | None = field(default=None, repr=False)

    def for_snapshot(self, current, *, configuration_path):
        """Reject a stale plan; this is not filesystem compare-and-swap.

        The future publisher must retain the admitted file/directory and its
        write ownership through publication. No file writer is exposed here.
        """
        if (not isinstance(current, bytes) or configuration_path != self.configuration_path
                or current != self.before):
            raise RegistrationConflict('configuration_changed')
        return self.after


def prepare_desktop_registration(raw, *, installation_id, configuration_path, command=None, arguments=(),
                                 owned=None, remove=False):
    """Plan add, update or removal of exactly mcpServers.agentmux.

    Only an explicit matching ownership record permits replacement or removal.
    Unknown top-level settings and other MCP entries are preserved. Authentication
    fields are not accepted in the new entry; credentials remain client-owned.
    """
    _installation(installation_id)
    if (not isinstance(configuration_path, str) or not os.path.isabs(configuration_path)
            or len(configuration_path) > 4096
            or any('\ud800' <= c <= '\udfff' or c == '\x00' for c in configuration_path)
            or os.path.normpath(configuration_path) != configuration_path):
        raise RegistrationConflict('configuration_path_invalid')
    if type(remove) is not bool:
        raise RegistrationConflict('operation_invalid')
    data = _document(raw)
    servers = data.get('mcpServers', {})
    present = 'agentmux' in servers
    if owned is not None:
        if (not isinstance(owned, OwnedDesktopRegistration) or owned.installation_id != installation_id
                or owned.configuration_path != configuration_path):
            raise RegistrationConflict('registration_owner_mismatch')
        try:
            if not isinstance(owned.entry_json, bytes) or len(owned.entry_json) > 1024 * 1024:
                raise ValueError
            previous = json.loads(owned.entry_json, object_pairs_hook=_unique)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise RegistrationConflict('registration_owner_invalid') from None
        if not _valid_entry(previous) or type(owned.created_container) is not bool:
            raise RegistrationConflict('registration_owner_invalid')
        if present and (not _valid_entry(servers['agentmux']) or servers['agentmux'] != previous):
            raise RegistrationConflict('registration_changed')
    elif present or remove:
        raise RegistrationConflict('registration_not_owned')

    if remove:
        if not present:
            return DesktopRegistrationEdit(configuration_path, raw, raw, None, 'already_absent', owned)
        del servers['agentmux']
        if not servers and owned.created_container:
            del data['mcpServers']
        ownership = None
        outcome = 'removed'
    else:
        # Shape validation only. The installation owner supplies command admission;
        # callers cannot use this plan as proof that an executable is trusted.
        if type(arguments) is not tuple:
            raise RegistrationConflict('application_command_invalid')
        entry = {'command': command, 'args': list(arguments)}
        if not _valid_entry(entry):
            raise RegistrationConflict('application_command_invalid')
        encoded = json.dumps(entry, ensure_ascii=True, allow_nan=False, sort_keys=True).encode()
        ownership = OwnedDesktopRegistration(installation_id, configuration_path, encoded,
                    owned.created_container if present else 'mcpServers' not in data)
        if present and servers['agentmux'] == entry:
            return DesktopRegistrationEdit(configuration_path, raw, raw, ownership, 'unchanged', owned)
        servers['agentmux'] = entry
        data['mcpServers'] = servers
        outcome = 'updated' if present else 'added'
    after = (_json_text(data) + '\n').encode()
    if len(after) > 1024 * 1024:
        raise RegistrationConflict('configuration_too_large')
    return DesktopRegistrationEdit(configuration_path, raw, after, ownership, outcome, owned)


def prepare_desktop_rollback(raw, *, published):
    """Reverse an owned entry change while preserving later unrelated settings.

    The trusted installation owner retains the published edit. This function does
    not authenticate a caller-supplied record or publish the resulting settings.
    """
    if not isinstance(published, DesktopRegistrationEdit):
        raise RegistrationConflict('registration_owner_invalid')
    previous, current = published.previous_ownership, published.ownership
    before = _document(published.before)
    current_document = _document(raw)
    if published.before == published.after:
        return DesktopRegistrationEdit(published.configuration_path, raw, raw, current, 'unchanged', current)
    after_servers = _document(published.after).get('mcpServers', {})
    if 'agentmux' in after_servers:
        actual = current_document.get('mcpServers', {}).get('agentmux')
        if (not _valid_entry(after_servers['agentmux']) or not _valid_entry(actual)
                or actual != after_servers['agentmux']):
            raise RegistrationConflict('registration_changed')
    originally_present = 'agentmux' in before.get('mcpServers', {})
    if not originally_present:
        previous = None
    if previous is None:
        if current is None:
            if originally_present:
                raise RegistrationConflict('registration_owner_invalid')
            return DesktopRegistrationEdit(published.configuration_path, raw, raw, None, 'unchanged')
        return prepare_desktop_registration(raw, installation_id=current.installation_id,
                    configuration_path=published.configuration_path, owned=current, remove=True)
    if (not isinstance(previous, OwnedDesktopRegistration)
            or previous.configuration_path != published.configuration_path
            or not isinstance(previous.entry_json, bytes) or len(previous.entry_json) > 1024 * 1024):
        raise RegistrationConflict('registration_owner_invalid')
    try:
        entry = json.loads(previous.entry_json)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RegistrationConflict('registration_owner_invalid') from None
    if not _valid_entry(entry) or entry != before['mcpServers']['agentmux']:
        raise RegistrationConflict('registration_owner_invalid')
    restored = prepare_desktop_registration(raw, installation_id=previous.installation_id,
                configuration_path=published.configuration_path, command=entry['command'],
                arguments=tuple(entry['args']), owned=current)
    return replace(restored, ownership=replace(restored.ownership,
                   created_container=previous.created_container))
