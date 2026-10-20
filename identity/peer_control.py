"""Protected peer control selection and current retained enrollment checks.

Control provenance uses the peer's enrolled NATS user key, not a local service
signature or a sender name. The public user JWT never includes its private seed.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import ssl
from datetime import datetime, timezone

import nkeys
from nacl.signing import VerifyKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from hub.fed.policy import normalize_remote, rid_for_remote
from native_security.nats_credentials import _base32, _closed, _current, _decode64, _JWT, _SEED
from .application_enrollment import _read_material
from .authority import _active, _indexes, _key, approval_reason


HEADER = 'Agentmux-Peer-Control-Signature'
CONTRACT = 'peer-control-revoke'


def _fail():
    raise ContractError('peer_control_refused')


def public_credential(token, *, account, user, peer=None):
    """Verify account signature and exact control-only broker permissions."""
    try:
        if type(token) is not str or not 0 < len(token) <= 16384:
            _fail()
        first, second, signature = token.encode('ascii').split(b'.')
        if strict_loads(_decode64(first)) != {'typ': 'JWT', 'alg': 'ed25519-nkey'}:
            _fail()
        claims = _closed(strict_loads(_decode64(second)), ('iss', 'sub', 'nats'),
            ('exp', 'nbf', 'iat', 'jti', 'name'))
        policy = _closed(claims['nats'], ('type', 'version', 'pub', 'sub'),
            ('issuer_account', 'resp', 'subs', 'data', 'payload', 'bearer_token'))
        if (claims['iss'] != account or claims['sub'] != user or policy['type'] != 'user'
                or type(policy['version']) is not int or policy['version'] != 2
                or policy.get('issuer_account', account) != account
                or policy.get('bearer_token', False) is not False or policy.get('resp') is not None):
            _fail()
        account_raw, user_raw = _base32(account.encode('ascii'), 35), _base32(user.encode('ascii'), 35)
        if account_raw[0] != nkeys.PREFIX_BYTE_ACCOUNT or user_raw[0] != nkeys.PREFIX_BYTE_USER:
            _fail()
        VerifyKey(account_raw[1:-2]).verify(first + b'.' + second, _decode64(signature))
        for direction in ('pub', 'sub'):
            part = _closed(policy[direction], ('allow',), ('deny',))
            if (type(part['allow']) is not list or any(type(x) is not str for x in part['allow'])
                    or len(set(part['allow'])) != len(part['allow'])):
                _fail()
        if peer is not None:
            if (not re.fullmatch(r'[a-z0-9_]{1,32}', peer)
                    or policy['pub'] != {'allow': ['am.ctl.' + peer]}
                    or policy['sub'] != {'allow': [], 'deny': ['>']}):
                _fail()
        elif policy['pub'] != {'allow': [], 'deny': ['>']}:
            _fail()
        _current(claims)
        return claims, user_raw[1:-2]
    except Exception:
        _fail()


def selected_route(selection, route_id):
    routes = selection.policy.get('peerControl', {}).get('routes', [])
    matches = [route for route in routes if route['routeId'] == route_id]
    if len(matches) != 1:
        _fail()
    return matches[0]


def check_peer_control_selection(value):
    selected = value.get('peerControl')
    if selected is None:
        return
    validate('peer-control-selection', selected)
    if len({route['routeId'] for route in selected['routes']}) != len(selected['routes']):
        _fail()
    keys = [(route['peer']['peerId'], canonical_bytes(route['scope']), canonical_bytes(route['resourceRef']))
        for route in selected['routes']]
    if len(set(keys)) != len(keys):
        _fail()
    for route in selected['routes']:
        _check_route(value, route)


def control_storage(value, selected):
    """Resolve one declared control resource across the supported domains."""
    storage = value.get('storage', {})
    matches = [(name, storage[name]) for name in ('knowledge', 'work')
        if storage.get(name) is not None for channel in storage[name]['channels']
        if channel['resourceRef'] == selected['resourceRef']]
    if len(matches) != 1:
        _fail()
    return matches[0]


def _check_route(value, selected):
    scope, repository = selected['scope'], selected['repository']
    _, storage = control_storage(value, selected)
    if (scope['organizationId'] != value['organizationId'] or scope['projectId'] is None
            or selected['resourceRef']['ownerHubId'] != value['kernelScope']['hubId']
            or normalize_remote(repository['normalizedRemote']) != repository['normalizedRemote']
            or rid_for_remote(repository['normalizedRemote']) != repository['repositoryId']
            or selected['localPeer'] == selected['peer']['peerId']
            or value['storage']['scope'] != scope
            or storage['repository'] != repository or storage['localPeer'] != selected['localPeer']
            or storage['localNode'] != selected['localNode']):
        _fail()
    roles = ('receiver', 'peer', 'publisher') if selected.get('publisher') else ('receiver', 'peer')
    for role in roles:
        for name in ('identityRef', 'transportRef'):
            if selected[role][name]['ownerHubId'] != value['kernelScope']['hubId']:
                _fail()
        if 'grantRef' in selected[role] and selected[role]['grantRef']['ownerHubId'] != value['kernelScope']['hubId']:
            _fail()
    users = [selected[r]['userPublicKey'] if r == 'peer' else selected[r]['credentials']['userPublicKey'] for r in roles]
    if len(set(users)) != len(users):
        _fail()
    from .application_service_selection import _outside
    from .workspace_selection import _materials
    existing = list(_materials({k: v for k, v in value.items() if k != 'peerControl'}))
    private = [selected[r]['credentials']['path'] for r in roles if r != 'peer']
    for path in private:
        _outside(path, value['workspaces'])
        resolved = Path(os.path.realpath(path))
        if any(resolved.is_relative_to(p) or p.is_relative_to(resolved) for p in existing):
            _fail()
    if len(set(map(os.path.realpath, private))) != len(private):
        _fail()
    public_credential(selected['peer']['credentialJWT'], account=selected['accountPublicKey'],
        user=selected['peer']['userPublicKey'], peer=selected['peer']['peerId'])
    connection = selected['connection']
    if (not re.fullmatch(r'tls://127\.0\.0\.1:[1-9][0-9]{0,4}', connection['endpoint'])
            or int(connection['endpoint'].rsplit(':', 1)[1]) > 65535
            or all(part.isdigit() for part in connection['serverName'].split('.'))):
        _fail()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=connection['rootsPEM'])


def local_credential(selected, *, publisher=False):
    pin = selected['publisher' if publisher else 'receiver']['credentials']
    raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != pin['sha256']:
        _fail()
    tokens, seeds = _JWT.findall(raw), _SEED.findall(raw)
    if len(tokens) != 1 or len(seeds) != 1:
        _fail()
    claims, _ = public_credential(tokens[0].decode('ascii'), account=selected['accountPublicKey'],
        user=pin['userPublicKey'], peer=selected['localPeer'] if publisher else None)
    if not publisher and claims['nats']['sub'] != {'allow': ['am.ctl.' + selected['peer']['peerId']]}:
        _fail()
    _base32(seeds[0], 36)
    key = nkeys.from_seed(seeds[0])
    try:
        if key.public_key.decode('ascii') != pin['userPublicKey']:
            _fail()
    finally:
        key.wipe()
    return tokens[0], seeds[0]


def receiver_credential(selected):
    return local_credential(selected)


def control_claims(selected, item, subject):
    return {'purpose': 'agentmux-peer-control-v1', 'eventId': item['id'],
        'eventDigest': payload_digest(item), 'subject': subject,
        'accountPublicKey': selected['accountPublicKey'], 'resourceRef': selected['resourceRef'],
        'scope': selected['scope'], 'repositoryId': selected['repository']['repositoryId']}


async def check_authority(selection, identity, *, route_id, publisher=False):
    """A retained public receipt cannot renew a revoked peer or scope."""
    selected = selected_route(selection, route_id)
    authority, _ = selection.check_storage_identity_source(identity)
    snapshot = await authority.current()
    selection.check_storage_identity_source(identity)
    record = strict_loads(snapshot.record)
    now = datetime.now(timezone.utc)
    index = _indexes(record['state'], record['ownerHubId'])
    roles = ('publisher',) if publisher else ('receiver', 'peer')
    for role in roles:
        pin = selected[role]
        principal = index['identities'].get(_key(pin['identityRef']))
        transport = index['transports'].get(_key(pin['transportRef']))
        user = pin['userPublicKey'] if role == 'peer' else pin['credentials']['userPublicKey']
        public = base64.urlsafe_b64encode(_base32(user.encode('ascii'), 35)[1:-2]).decode().rstrip('=')
        if (principal is None or principal['kind'] != 'service' or not _active(principal, now)
                or transport is None or not _active(transport, now)
                or transport['identityRef'] != pin['identityRef']
                or transport['method'] != 'nats-credential-mapping' or transport['publicKey'] != public
                or not any(_active(m, now) and m['identityRef'] == pin['identityRef']
                    and m['scope'] == selected['scope'] for m in index['memberships'].values())):
            _fail()
        issuer = index['issuers'].get(_key(transport['issuerRef']))
        issuer_identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or not _active(issuer, now) or issuer_identity is None
                or issuer_identity['kind'] != 'service' or not _active(issuer_identity, now)):
            _fail()
    peer = selected['publisher' if publisher else 'peer']
    matches = [g for g in index['grants'].values() if _active(g, now)
        and g['callerRef'] == peer['identityRef'] and g['actorRef'] == peer['identityRef']
        and g['scope'] == selected['scope'] and g['contractId'] == CONTRACT
        and g['resourceId'] == selected['resourceRef']['id']]
    grant = index['grants'].get(_key(peer['grantRef']))
    if (grant not in matches or grant['decision'] != 'allowed' or grant['delegationRef'] is not None
            or any(g['decision'] == 'denied' for g in matches)):
        _fail()
    # This narrow route has no approval payload. A review-required grant must
    # stay refused rather than borrowing an unrelated approval or device login.
    if approval_reason(index, grant, {'approvalRefs': []},
            audience={'hubId': record['ownerHubId'], 'serviceId': 'peer-control-owner'},
            scope=selected['scope'], contract=CONTRACT, now=now) is not None:
        _fail()
    if publisher:
        local_credential(selected, publisher=True)
    else:
        public_credential(peer['credentialJWT'], account=selected['accountPublicKey'],
            user=peer['userPublicKey'], peer=peer['peerId'])
        receiver_credential(selected)
    return snapshot
