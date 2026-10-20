"""Explicit application-attestor key custody; never invoked by warm startup.

This provisions an application signing key, not a broker user or an authorization
grant. An enrolled administrator must commit the returned enrollment payload and
exact membership/grant through the existing owner commands. The host separately
supplies a scoped application-attestor NATS credential, never its HOST credential.
"""
import base64
from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import secrets
import stat
import time
from native_security.descriptor_admission import check_descriptor, DescriptorPurpose, AdmissionError

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate


def _admit(fd, purpose):
    # This utility has only standard-library/native descriptor dependencies; no
    # hub service or business authority is imported or used as key authority.
    try:
        check_descriptor(fd, purpose=purpose, deadline=time.monotonic() + 1)
    except AdmissionError:
        raise ContractError('application_key_store_native_refused') from None


def _directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ContractError('application_key_store_invalid')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        _admit(fd, DescriptorPurpose.PRIVATE_ANCESTOR)
        for component in path.parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            _admit(fd, DescriptorPurpose.PRIVATE_ANCESTOR)
        _admit(fd, DescriptorPurpose.PRIVATE_DIRECTORY)
        meta = os.fstat(fd)
        if meta.st_uid != os.getuid() or meta.st_mode & 0o077:
            raise ContractError('application_key_store_invalid')
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


class ApplicationAttestorKey:
    def __init__(self, material):
        self._material = material
        self._seed = base64.b64decode(material['seed'], validate=True)
        if len(self._seed) != 32:
            raise ContractError('application_key_store_invalid')

    def __repr__(self):
        return '<ApplicationAttestorKey private>'

    @property
    def public_key(self):
        return base64.urlsafe_b64encode(bytes(SigningKey(self._seed).verify_key)).decode().rstrip('=')

    def sign(self, claims, *, now=None):
        purpose = claims.get('purpose')
        schema = {'agentmux-application-runtime-observation-v1': 'application-runtime-observation',
                  'agentmux-application-observation-update-v1': 'application-observation-update'}.get(purpose)
        if schema is None:
            raise ContractError('application_signing_purpose')
        for key in ('hubId', 'profileId'):
            if claims.get(key) != self._material[key]:
                raise ContractError('application_signing_binding')
        if schema == 'application-runtime-observation':
            if (claims.get('instanceId') != self._material['instanceId']
                    or claims.get('signingKeyRef') != self._material['issuerRef']):
                raise ContractError('application_signing_binding')
        elif (claims.get('authorityId') != self._material['authorityId']
              or claims.get('transportRef') != self._material['transportRef']):
            raise ContractError('application_signing_binding')
        now = now or datetime.now(timezone.utc)
        try:
            start, end = (datetime.fromisoformat(claims[k]) for k in ('issuedAt', 'expiresAt'))
            if not start <= now < end or end - start > timedelta(seconds=5):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ContractError('application_signing_time') from None
        wrapper = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519', 'canonicalization': 'RFC8785-JCS-UTF8',
                   'claims': claims, 'signature': sign_claims(claims, self._seed)}
        validate(schema, wrapper)
        raw = canonical_bytes(wrapper)
        if len(raw) > 65536:
            raise ContractError('owner_body_limit')
        return raw


def _read_material(path, *, max_bytes=4096, return_bytes=False):
    """Read a bounded private store through the shared native policy."""
    directory, name = _directory(path)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        meta = os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
                or meta.st_mode & 0o077 or meta.st_nlink != 1 or meta.st_size > max_bytes):
            raise ContractError('application_key_store_invalid')
        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
        raw = os.read(fd, max_bytes + 1)
        after = os.fstat(fd)
        if (len(raw) > max_bytes or len(raw) != meta.st_size
                or (meta.st_mtime_ns, meta.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)):
            raise ContractError('application_key_store_invalid')
        material = raw if return_bytes else strict_loads(raw)
        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
        return material
    except ContractError:
        raise
    except Exception:
        raise ContractError('application_key_store_invalid') from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def load_application_attestor(path):
    """Read an already-provisioned private store. Never create or rotate on load."""
    material = _read_material(path)
    required = {'purpose', 'seed', 'hubId', 'profileId', 'authorityId', 'instanceId',
                'identityRef', 'issuerRef', 'transportRef'}
    try:
        if set(material) != required or material['purpose'] != 'agentmux-application-attestor-key-v1':
            raise ValueError()
        return ApplicationAttestorKey(material)
    except Exception:
        raise ContractError('application_key_store_invalid') from None


def provision_application_attestor(path, *, profile_id, authority_id, instance_id,
        identity, issuer_ref, transport_ref, ingress_issuer_ref, issued_at, expires_at):
    """Explicit create-only provisioning. Return public owner enrollment, not access."""
    if identity.get('kind') != 'service' or identity.get('status') != 'active':
        raise ContractError('application_enrollment_identity')
    try:
        start, end = datetime.fromisoformat(issued_at), datetime.fromisoformat(expires_at)
        if (start.utcoffset() != timedelta(0) or end.utcoffset() != timedelta(0) or start >= end
                or any(r['revision'] != 1 or r['ownerHubId'] != identity['ref']['ownerHubId']
                       for r in (identity['ref'], issuer_ref, transport_ref))):
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise ContractError('application_enrollment_binding') from None
    seed = secrets.token_bytes(32)
    material = {'purpose': 'agentmux-application-attestor-key-v1', 'seed': base64.b64encode(seed).decode(),
        'hubId': identity['ref']['ownerHubId'], 'profileId': profile_id, 'authorityId': authority_id,
        'instanceId': instance_id, 'identityRef': identity['ref'], 'issuerRef': issuer_ref,
        'transportRef': transport_ref}
    signer = ApplicationAttestorKey(material)
    interval = {'issuedAt': issued_at, 'expiresAt': expires_at}
    issuer = {'ref': issuer_ref, 'identityRef': identity['ref'], 'status': 'active',
              'instanceId': instance_id, 'publicKey': signer.public_key, **interval}
    transport = {'ref': transport_ref, 'identityRef': identity['ref'], 'issuerRef': ingress_issuer_ref,
                 'status': 'active', 'method': 'nats-credential-mapping',
                 'publicKey': signer.public_key, **interval}
    def credential(record):
        proof = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': profile_id,
                 'authorityId': authority_id, 'credential': record}
        return {'record': record, 'proof': sign_claims(proof, seed)}
    payload = {'authorityId': authority_id, 'identity': identity,
               'issuers': [credential(issuer)], 'transports': [credential(transport)]}
    validate('identity-enroll', payload)
    _write_material(path, material)
    return payload


def _write_material(path, material, *, max_bytes=4096):
    data = canonical_bytes(material)
    if len(data) > max_bytes:
        raise ContractError('application_key_store_invalid')
    directory, name = _directory(path)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        _admit(fd, DescriptorPurpose.PRIVATE_FILE)
        written = 0
        while written < len(data):
            count = os.write(fd, data[written:])
            if count <= 0:
                raise ContractError('application_key_store_write_uncertain')
            written += count
        os.fsync(fd)
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)
