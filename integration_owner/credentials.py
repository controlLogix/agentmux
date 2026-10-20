"""Resolve one host-enrolled Atlassian credential without public secret data.

Enrollment pins are host-private metadata. Preserve the same pin across worker
restarts; capturing a new pin is an explicit enrollment change that needs a new
credential reference revision. Resolution cannot select a file or repin it.
This module performs no authorization, provider request or account check.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from taskmgmt import atlassian
from .intent import MAX_REVISION, reference


def _binding(credential_ref, provider, config_path, site_url, config_version):
    try:
        copied = strict_loads(canonical_bytes(credential_ref))
        reference(copied)
        if (provider not in ('jira', 'confluence') or not isinstance(config_path, Path)
                or not config_path.is_absolute() or '..' in config_path.parts
                or type(config_version) is not int or not 0 <= config_version <= MAX_REVISION
                or copied['revision'] != config_version or not isinstance(site_url, str)):
            raise ValueError
        # Use the actual client validator for the site's HTTPS rules. The fixed
        # placeholder is only validation input, never a stored or used token.
        site = atlassian.validate_config({'deployment': 'server', 'base_url': site_url,
                                         'api_token': 'unused-local-validation'})['base_url']
        return canonical_bytes(copied), provider, config_path, site, config_version
    except Exception:
        raise ContractError('integration_credential_configuration') from None


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _snapshot(path):
    """Call the real protected config reader and detect replacement during it."""
    try:
        directory_before = path.parent.lstat()
        before = path.lstat()
        if (not stat.S_ISDIR(directory_before.st_mode)
                or directory_before.st_uid != os.getuid()
                or stat.S_IMODE(directory_before.st_mode) & 0o022
                or not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)):
            raise ValueError
        config = atlassian.load_config(path)
        after = path.lstat()
        directory_after = path.parent.lstat()
        changed = (_file_identity(before) != _file_identity(after)
                   or _directory_identity(directory_before) != _directory_identity(directory_after))
        # This private config is not a shared contract payload. Preserve valid
        # legacy JSON values, including integers beyond the wire format's range.
        encoded = json.dumps(config, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
    except Exception:
        raise ContractError('integration_credential_unavailable') from None
    if changed:
        raise ContractError('integration_credential_changed')
    return encoded, _file_identity(after), _directory_identity(directory_after)


@dataclass(frozen=True, slots=True, repr=False)
class AtlassianConfigPin:
    _binding: tuple
    _file: tuple
    _directory: tuple
    _fingerprint: bytes

    def __repr__(self):
        return '<AtlassianConfigPin private>'


def pin_atlassian_config(credential_ref, *, provider, config_path, site_url, config_version):
    """Capture private metadata during explicit host enrollment, never dispatch.

    The host must bind this pin durably to the reference revision. Losing a pin
    requires host recovery or a new enrollment; resolving does not recreate it.
    """
    binding = _binding(credential_ref, provider, config_path, site_url, config_version)
    encoded, file_identity, directory_identity = _snapshot(binding[2])
    if json.loads(encoded)['base_url'] != binding[3]:
        raise ContractError('integration_credential_site_mismatch')
    return AtlassianConfigPin(binding, file_identity, directory_identity,
                              hashlib.sha256(encoded).digest())


@dataclass(frozen=True, slots=True, repr=False)
class PrivateAtlassianConfig:
    _encoded: bytes

    def __repr__(self):
        return '<PrivateAtlassianConfig private>'

    def private_copy(self):
        """Return a fresh dict only for the fixed provider worker's local call."""
        return json.loads(self._encoded)


@dataclass(frozen=True, slots=True, repr=False, init=False)
class AtlassianCredentialResolver:
    _binding: tuple
    _pin: AtlassianConfigPin

    def __init__(self, credential_ref, *, provider, config_path, site_url,
                 config_version, config_pin):
        binding = _binding(credential_ref, provider, config_path, site_url, config_version)
        if type(config_pin) is not AtlassianConfigPin or config_pin._binding != binding:
            raise ContractError('integration_credential_configuration')
        object.__setattr__(self, '_binding', binding)
        object.__setattr__(self, '_pin', config_pin)

    def __repr__(self):
        return '<AtlassianCredentialResolver private>'

    def resolve(self, credential_ref, *, provider, config_version):
        """Resolve the exact enrolled reference; callers cannot supply a path."""
        try:
            copied = strict_loads(canonical_bytes(credential_ref))
            reference(copied)
            if (canonical_bytes(copied) != self._binding[0]
                    or provider != self._binding[1]
                    or type(config_version) is not int or config_version != self._binding[4]):
                raise ValueError
        except Exception:
            raise ContractError('integration_credential_refused') from None
        encoded, file_identity, directory_identity = _snapshot(self._binding[2])
        if (file_identity != self._pin._file or directory_identity != self._pin._directory
                or hashlib.sha256(encoded).digest() != self._pin._fingerprint
                or json.loads(encoded)['base_url'] != self._binding[3]):
            raise ContractError('integration_credential_changed')
        return PrivateAtlassianConfig(encoded)
