"""Private durable Atlassian configuration pins; never command or reply data.

The host reads these bytes from its separately protected, digest-pinned selection.
Loading never creates a new pin or accepts changed provider configuration.
"""
from pathlib import Path
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from .credentials import AtlassianConfigPin, AtlassianCredentialResolver

PURPOSE = 'agentmux-atlassian-credential-enrollment-v1'


def enrollment_bytes(pin):
    """Export an explicitly captured pin for private host storage only."""
    if type(pin) is not AtlassianConfigPin:
        raise ContractError('integration_enrollment_invalid')
    credential, provider, path, site, version = pin._binding
    # Filesystem timestamps and inode numbers can exceed the shared JSON integer
    # range. Decimal strings preserve their exact private comparison values.
    return canonical_bytes({'purpose': PURPOSE, 'credentialRef': strict_loads(credential),
        'provider': provider, 'configPath': str(path), 'siteURL': site, 'configVersion': version,
        'fileIdentity': [str(v) for v in pin._file],
        'directoryIdentity': [str(v) for v in pin._directory],
        'configFingerprint': pin._fingerprint.hex()})


def write_atlassian_enrollment(path, pin):
    """Explicit create-only private enrollment; never called by service startup.

    Return the private file digest for the separate host selection. Existing
    material is never replaced. The host must keep this file outside workspaces.
    """
    from identity.application_enrollment import _read_material, _write_material
    raw = enrollment_bytes(pin)
    _write_material(path, strict_loads(raw), max_bytes=65536)
    if _read_material(path, max_bytes=65536, return_bytes=True) != raw:
        raise ContractError('integration_enrollment_unavailable')
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def load_atlassian_enrollment(raw, *, credential_ref, provider):
    """Restore the selected pin and verify its unchanged actual config file.

    Input must come from ApplicationServiceSelection.read_integration_enrollment,
    which verifies private-file ownership and the separately selected digest.
    These bytes are enrollment material, never an untrusted command payload.
    """
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 65536:
            raise ValueError
        value = strict_loads(raw)
        if (type(value) is not dict or set(value) != {'purpose', 'credentialRef', 'provider',
                'configPath', 'siteURL', 'configVersion', 'fileIdentity', 'directoryIdentity', 'configFingerprint'}
                or value['purpose'] != PURPOSE or value['credentialRef'] != credential_ref
                or value['provider'] != provider or type(value['configPath']) is not str
                or not 1 <= len(value['configPath']) <= 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in value['configPath'])
                or type(value['configFingerprint']) is not str
                or not re.fullmatch(r'[a-f0-9]{64}', value['configFingerprint'])):
            raise ValueError
        identities = []
        for key, count in (('fileIdentity', 9), ('directoryIdentity', 5)):
            parts = value[key]
            if (type(parts) is not list or len(parts) != count
                    or any(type(v) is not str or not re.fullmatch(r'0|[1-9][0-9]{0,29}', v) for v in parts)):
                raise ValueError
            identities.append(tuple(int(v) for v in parts))
        from .credentials import _binding
        metadata = dict(provider=provider, config_path=Path(value['configPath']),
            site_url=value['siteURL'], config_version=value['configVersion'])
        binding = _binding(credential_ref, **metadata)
        pin = AtlassianConfigPin(binding, identities[0], identities[1], bytes.fromhex(value['configFingerprint']))
        resolver = AtlassianCredentialResolver(credential_ref, **metadata, config_pin=pin)
        resolver.resolve(credential_ref, provider=provider, config_version=value['configVersion'])
        return resolver
    except Exception:
        raise ContractError('integration_enrollment_unavailable') from None
