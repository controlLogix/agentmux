"""Explicit host selection writer. Startup independently admits every selected file."""
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
import re
import ssl

from agentmux_contracts import ContractError, canonical_bytes, validate
from .application_enrollment import _write_material


@dataclass(frozen=True)
class ApplicationHostSelectionReceipt:
    path: str
    digest: str


def _path(value):
    return (isinstance(value, str) and os.path.isabs(value)
            and os.path.normpath(value) == value and not value.startswith('//')
            and len(value) <= 4096 and all(ord(c) >= 32 and ord(c) != 127 for c in value))


def _nkey(value, prefix):
    raw = base64.b32decode(value)
    return (len(raw) == 35 and raw[0] == prefix
            and binascii.crc_hqx(raw[:-2], 0).to_bytes(2, 'little') == raw[-2:])


def _check_connection(connection, now):
    """Check explicit application TLS pins without opening a connection."""
    labels = connection['serverName'].split('.')
    roots = connection['rootsPEM'].strip()
    if (int(connection['endpoint'].rsplit(':', 1)[1]) > 65535
            or all(label.isdigit() for label in labels)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)
            or len(connection['rootsPEM'].encode()) > 16384
            or roots.count('-----BEGIN CERTIFICATE-----') != 1
            or roots.count('-----END CERTIFICATE-----') != 1
            or ssl.DER_cert_to_PEM_cert(ssl.PEM_cert_to_DER_cert(roots)).strip() != roots):
        raise ValueError()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=roots)
    authorities = context.get_ca_certs()
    if (len(authorities) != 1 or not ssl.cert_time_to_seconds(authorities[0]['notBefore'])
            <= now.timestamp() < ssl.cert_time_to_seconds(authorities[0]['notAfter'])):
        raise ValueError()


def write_application_attestor_host_selection(path, selection, *, now=None):
    """Create a private selection file and return its separately retained digest.

    This does not enroll an identity, grant access, or inspect credentials. The
    launcher checks these explicit pins against its admitted host and signer.
    """
    validate('application-attestor-host-selection', selection)
    raw = canonical_bytes(selection)
    now = now if now is not None else datetime.now(timezone.utc)
    try:
        _check_connection(selection['connection'], now)
        paths = [str(path), selection['hostPolicy'], selection['keyPath'],
                 selection['credentials']['path'], *selection['workspaces']]
        app, trust = selection['application'], selection['receiptTrust']
        refs = [app[k] for k in ('identityRef', 'issuerRef', 'transportRef', 'policyRef')]
        refs += [trust['issuerRef']]
        if app['workspaceRef'] is not None:
            refs.append(app['workspaceRef'])
        public = base64.urlsafe_b64decode(trust['publicKey'] + '=')
        if (len(raw) > 65536 or not all(_path(p) for p in paths)
                or selection['ownerUid'] != os.getuid()
                or any(r['ownerHubId'] != selection['kernelScope']['hubId'] for r in refs)
                or len(public) != 32
                or base64.urlsafe_b64encode(public).decode().rstrip('=') != trust['publicKey']
                or not datetime.fromisoformat(trust['notBefore']) <= now < datetime.fromisoformat(trust['expiresAt'])
                or not _nkey(selection['credentials']['accountPublicKey'], 0)
                or not _nkey(selection['credentials']['userPublicKey'], 160)):
            raise ValueError()
    except (ValueError, TypeError, KeyError, binascii.Error, ssl.SSLError):
        raise ContractError('application_host_selection_invalid') from None
    _write_material(path, selection, max_bytes=65536)
    return ApplicationHostSelectionReceipt(str(path), 'sha256:' + hashlib.sha256(raw).hexdigest())
