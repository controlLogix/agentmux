"""Protected selection for the existing task record's workspace reader."""
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import ssl

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub.fed.policy import normalize_remote, rid_for_remote
from native_security.nats_credentials import validate_workspace_receiver
from .application_enrollment import _read_material
from .application_host_selection import _nkey


def _fail():
    raise ContractError('application_service_selection_invalid')


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _materials(value):
    if type(value) is dict:
        for key, child in value.items():
            if type(child) is str and (key == 'path' or key.endswith('Directory')):
                yield Path(os.path.realpath(child))
            else:
                yield from _materials(child)
    elif type(value) is list:
        for child in value:
            yield from _materials(child)


def check_workspace_selection(value):
    selected = value.get('workspace')
    if selected is None:
        return
    from .application_service_selection import _outside, _storage_entries
    task = value.get('task')
    if task is None or task['ledger']['scope']['projectId'] is None:
        _fail()
    receiver, repository = selected['receiver'], selected['repository']
    hub, reference = value['kernelScope']['hubId'], selected['resourceRef']
    if (reference['id'] != task['ledger']['entityId'] or reference['ownerHubId'] != hub
            or reference['revision'] < 1
            or selected['checkoutPath'] not in value['workspaces']
            or selected['checkoutPath'] != os.path.realpath(selected['checkoutPath'])
            or normalize_remote(repository['normalizedRemote']) != repository['normalizedRemote']
            or rid_for_remote(repository['normalizedRemote']) != repository['repositoryId']):
        _fail()
    credentials, issuer = receiver['credentials'], receiver['issuer']
    references = (reference, receiver['serviceIdentityRef'], receiver['requestSigningKeyRef'], issuer['issuerRef'])
    public = base64.urlsafe_b64decode(issuer['publicKey'] + '=')
    if (any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in references)
            or receiver['requestSigningKeyRef'] != value['identity']['issuer']['issuerRef']
            or len(public) != 32
            or base64.urlsafe_b64encode(public).decode().rstrip('=') != issuer['publicKey']
            or not _nkey(credentials['accountPublicKey'], 0)
            or not _nkey(credentials['userPublicKey'], 160)
            or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}', credentials['replyPrefix'])):
        _fail()
    entries = [value[key] for key in ('identity', 'definitions', 'integration',
        'configuration', 'task', 'orchestration', 'policy') if value.get(key)]
    if value.get('storage') is not None:
        entries.extend(_storage_entries(value).values())
    for entry in entries:
        if (credentials['userPublicKey'] == entry['credentials']['userPublicKey']
                or credentials['replyPrefix'] in (entry['credentials']['replyPrefix'], entry.get('requesterReplyPrefix'))
                or issuer['publicKey'] == entry.get('issuer', {}).get('publicKey')):
            _fail()
    private = [credentials['path'], issuer['keyFile']['path']]
    existing = list(_materials({key: child for key, child in value.items() if key != 'workspace'}))
    for index, path in enumerate(private):
        _outside(path, value['workspaces'])
        resolved = Path(os.path.realpath(path))
        if any(resolved.is_relative_to(other) or other.is_relative_to(resolved)
                for other in [*existing, *map(lambda p: Path(os.path.realpath(p)), private[index + 1:]),
                              *_materials(selected['source'])]):
            _fail()
    for pin in selected['source'].values():
        _outside(pin['path'], value['workspaces'])
    storage = value.get('storage', {})
    for name, source_key in (('messages', 'source'), ('board', 'auditMirror')):
        other = storage.get(name)
        if other is not None and os.path.realpath(other[source_key]['database']['path']) == os.path.realpath(selected['source']['database']['path']):
            if (other[source_key] != selected['source'] or other['repository'] is None
                    or any(other['repository'][key] != child for key, child in repository.items())
                    or other['localPeer'] != selected['localPeer']):
                _fail()
    connection = receiver['connection']
    labels = connection['serverName'].split('.')
    if (not re.fullmatch(r'tls://127\.0\.0\.1:[1-9][0-9]{0,4}', connection['endpoint'])
            or int(connection['endpoint'].rsplit(':', 1)[1]) > 65535
            or all(label.isdigit() for label in labels)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
        _fail()
    roots = connection['rootsPEM']
    if (len(roots.encode()) > 16384 or roots.count('-----BEGIN CERTIFICATE-----') != 1
            or roots.count('-----END CERTIFICATE-----') != 1):
        _fail()
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=roots)


def workspace_policy_inputs(selection):
    value = selection.policy
    selected = value['workspace']['receiver']
    return dict(hub_id=value['kernelScope']['hubId'], scope=value['task']['ledger']['scope'],
        reply_prefix=selected['credentials']['replyPrefix'])


def load_workspace_credentials(selection):
    selected = selection.policy['workspace']['receiver']['credentials']
    raw = _read_material(selected['path'], max_bytes=65536, return_bytes=True)
    if _digest(raw) != selected['sha256']:
        _fail()
    credential = validate_workspace_receiver(raw, account_public_key=selected['accountPublicKey'],
        **workspace_policy_inputs(selection))
    if credential.public_key != selected['userPublicKey']:
        _fail()
    return credential


def load_workspace_signing_seed(selection):
    value = selection.policy
    selected = value['workspace']['receiver']['issuer']
    pin = selected['keyFile']
    raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
    if _digest(raw) != pin['sha256']:
        _fail()
    key = strict_loads(raw)
    validate('application-service-key', key)
    expected = dict(serviceId='workspace-owner', hubId=value['kernelScope']['hubId'],
        profileId=value['kernelScope']['profileId'], authorityId=value['authorityId'], issuerRef=selected['issuerRef'])
    if any(key[name] != child for name, child in expected.items()):
        _fail()
    seed = base64.b64decode(key['seed'], validate=True)
    if (len(seed) != 32 or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=') != selected['publicKey']):
        _fail()
    return seed


def workspace_tls_options(selection):
    connection = selection.policy['workspace']['receiver']['connection']
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=connection['rootsPEM'])
    return dict(servers=[connection['endpoint']], tls=context,
        tls_hostname=connection['serverName'], tls_handshake_first=True)


async def check_workspace_authority(selection, identity):
    from .authority import _active, _indexes, _key
    authority, _ = selection.check_storage_identity_source(identity)
    snapshot = await authority.current()
    selection.check_storage_identity_source(identity)
    record = strict_loads(snapshot.record)
    index = _indexes(record['state'], record['ownerHubId'])
    selected = selection.policy['workspace']['receiver']
    now = datetime.now(timezone.utc)
    principal = index['identities'].get(_key(selected['serviceIdentityRef']))
    issuer = index['issuers'].get(_key(selected['issuer']['issuerRef']))
    if (principal is None or issuer is None or not _active(principal, now) or not _active(issuer, now)
            or principal['kind'] != 'service' or issuer['identityRef'] != principal['ref']
            or issuer['instanceId'] != selected['serviceInstanceId']
            or issuer['publicKey'] != selected['issuer']['publicKey']):
        _fail()
    return authority
