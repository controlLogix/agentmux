"""Read the explicit private connection selection; never infer broker authority."""
from dataclasses import dataclass, field
import os
import re
import ssl
import time

from hub.client_launch_imports import use_bundled_sdk
use_bundled_sdk()

from agentmux_contracts import canonical_bytes, strict_loads
from hub.client_launch_selection import DescriptorCleanup, DescriptorPurpose, SelectionError, _open_checked
from hub import native_descriptor_admission as native


@dataclass(frozen=True, repr=False)
class ApplicationConnectionSelection:
    document: bytes = field(repr=False)
    credentials: bytes = field(repr=False)

    def __repr__(self):
        return '<ApplicationConnectionSelection private>'

    @property
    def policy(self):
        return strict_loads(self.document)


def _outside_workspaces(path, workspaces):
    if (not isinstance(path, str) or not os.path.isabs(path) or os.path.normpath(path) != path
            or '\x00' in path):
        raise SelectionError('application_selection_invalid')
    for root in workspaces:
        approved = os.path.realpath(root)
        if os.path.commonpath((approved, os.path.realpath(path))) == approved:
            raise SelectionError('selection_inside_workspace')


def _private_bytes(path, limit, *, deadline):
    fd = _open_checked(path, purpose=DescriptorPurpose.PRIVATE_FILE,
                       descriptor_admission=native.check_descriptor, deadline=deadline)
    try:
        before = os.fstat(fd)
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if (time.monotonic() >= deadline or len(raw) > limit or before.st_size != len(raw)
                or (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)):
            raise SelectionError('application_selection_invalid')
        return raw
    finally:
        DescriptorCleanup().close(fd)


def load_connection_selection(path, *, workspaces, deadline):
    """Return bytes and explicit pins, not a connected or authorized client."""
    _outside_workspaces(path, workspaces)
    try:
        value = strict_loads(_private_bytes(path, 32768, deadline=deadline))
        fields = {'schemaVersion', 'endpoint', 'serverName', 'rootsPEM', 'leafCertificateSHA256',
                  'credentialsFile', 'accountPublicKey', 'userPublicKey', 'replyPrefix'}
        if (type(value) is not dict or set(value) != fields or value['schemaVersion'] != '1.0.0'
                or any(type(value[key]) is not str for key in fields - {'schemaVersion'})):
            raise ValueError()
        endpoint = re.fullmatch(r'tls://127\.0\.0\.1:([1-9][0-9]{0,4})', value['endpoint'])
        labels = value['serverName'].split('.')
        if (endpoint is None or int(endpoint[1]) > 65535 or len(value['serverName']) > 253
                or not labels or all(label.isdigit() for label in labels)
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', value['leafCertificateSHA256'])
                or not re.fullmatch(r'A[A-Z2-7]{55}', value['accountPublicKey'])
                or not re.fullmatch(r'U[A-Z2-7]{55}', value['userPublicKey'])
                or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}', value['replyPrefix'])):
            raise ValueError()
        roots = value['rootsPEM']
        if (len(roots.encode()) > 16384 or roots.count('-----BEGIN CERTIFICATE-----') != 1
                or roots.count('-----END CERTIFICATE-----') != 1):
            raise ValueError()
        # Only the enrolled roots are loaded; no ambient system CA directory.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=roots)
        _outside_workspaces(value['credentialsFile'], workspaces)
        credentials = _private_bytes(value['credentialsFile'], 65536, deadline=deadline)
        if not credentials or time.monotonic() >= deadline:
            raise ValueError()
        return ApplicationConnectionSelection(canonical_bytes(value), credentials)
    except SelectionError:
        raise
    except (ValueError, TypeError, KeyError, OSError):
        raise SelectionError('application_selection_invalid') from None


def tls_options(selection):
    """Use explicit enrolled roots/name; the shared factory enforces the leaf pin."""
    policy = selection.policy
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=policy['rootsPEM'])
    return {'servers': [policy['endpoint']], 'tls': context, 'tls_hostname': policy['serverName'],
            'tls_handshake_first': True,
            'inbox_prefix': policy['replyPrefix']}


def admit_connection_credential(enrollment, publish_subjects):
    """Run the shared credential guard on the selected connection's admitted bytes.

    The credential must be signed by the enrolled account, belong to the
    enrolled user, and grant exactly ``publish_subjects`` and this connection's
    own reply prefix; anything broader or different is refused.
    """
    from native_security.nats_credentials import validate

    policy = enrollment.policy
    credential = validate(enrollment.credentials, account_public_key=policy['accountPublicKey'],
        publish_subjects=publish_subjects, subscribe_subjects=[policy['replyPrefix'] + '.>'],
        private_inbox=True, application_publish=True)
    if credential.public_key != policy['userPublicKey']:
        raise ValueError('application_credential_mismatch')
    return credential


async def open_application_client(client_key_path, connection_path, *, selected, deadline, cleanup_deadline):
    """Admit private inputs, connect once and verify discovery/binding on that client."""
    import asyncio
    import base64
    import nkeys
    from identity.application_client import load_application_client
    from hub.client_launch_connection import _new_connection_owner, ConnectionFailure, selected_publish_subjects

    loop = asyncio.get_running_loop()
    owner = None
    try:
        remaining = deadline - loop.time()
        if not 0 < remaining <= 5:
            raise ValueError()
        _outside_workspaces(client_key_path, selected.invocation.workspaces)
        signer = load_application_client(client_key_path)
        pinned = signer.selection
        if (pinned['hubId'], pinned['profileId'], pinned['instanceId']) != (
                selected.hub_id, selected.profile_id, selected.instance_id):
            raise ValueError()
        enrollment = load_connection_selection(connection_path, workspaces=selected.invocation.workspaces,
                                              deadline=time.monotonic() + max(0, deadline - loop.time()))
        policy = enrollment.policy
        publish_subjects = selected_publish_subjects(signer)
        def checked_credential():
            if loop.time() >= deadline:
                raise ValueError('application_connection_deadline')
            return admit_connection_credential(enrollment, publish_subjects)
        checked_credential()
        options = tls_options(enrollment)
        owner = _new_connection_owner(signer, reply_prefix=policy['replyPrefix'],
                                      leaf_certificate_sha256=policy['leafCertificateSHA256'])
        def jwt():
            return checked_credential().jwt.encode('ascii')
        def signature(nonce):
            if not isinstance(nonce, str) or not 0 < len(nonce) <= 4096:
                raise ValueError('application_nonce_invalid')
            key = nkeys.from_seed(checked_credential().seed)
            try:
                return base64.b64encode(key.sign(nonce.encode('ascii')))
            finally:
                key.wipe()
        options.update(user_jwt_cb=jwt, signature_cb=signature)
        await owner._connect(options, deadline=deadline, cleanup_deadline=cleanup_deadline)
        await owner.authenticate(signer, deadline=deadline, cleanup_deadline=cleanup_deadline)
        return owner
    except BaseException as error:
        if owner is not None:
            try:
                await owner.close(deadline=cleanup_deadline)
            except BaseException as cleanup:
                raise ConnectionFailure('application_connection_cleanup_pending', owner, cleanup) from None
            raise ConnectionFailure('application_connection_unavailable', owner, error) from None
        if isinstance(error, SelectionError):
            raise
        if isinstance(error, (ValueError, OSError, TypeError, KeyError)):
            raise SelectionError('application_selection_invalid') from None
        raise
