"""Protected routes and publisher proof for the preserved core work protocol.

A NATS message does not name its publisher. The enrolled publisher signs the
original body and subject, while each receiving hub maps that key to its own
current authority records. This keeps shared role queues independent of a
particular receiving hub's local reference names.
"""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import re

import nkeys
from nacl.signing import VerifyKey

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from hub import names
from native_security.nats_credentials import _base32, _closed, _current, _decode64, _JWT, _SEED
from .application_enrollment import _read_material
from .authority import _active, _indexes, _key, approval_reason

HEADER = 'Agentmux-Core-Work-Signature'
INGEST = 'federation-work-ingest-legacy'
RESULT = 'federation-work-result-legacy'
CONTRACTS = frozenset((INGEST, RESULT))
QUERY_CONTRACTS = frozenset(('federation-work-inspect', 'federation-work-outcome'))


def refused():
    raise ContractError('core_work_transport_refused')


def identity_generation(identity):
    """Fence custody and physical history without a foreign DB connection."""
    authority, ingress = identity.reader, identity.ingress
    ledger = authority._ledger
    history = ledger._history
    try:
        if history._closed or history._file_fingerprint() != history._fingerprint:
            refused()
    except (OSError, ContractError):
        refused()
    return (authority, ingress, authority._hub, authority._profile, authority._entity,
        authority._organization, ledger, ledger._js, ledger._binding, ledger._stream,
        ledger._subject, ledger._identity, history, history._db, history._binding,
        history._source_identity, history._path, history._max_records, history._max_bytes,
        ingress._reader, ingress._issuer_ref, ingress._seed)


def selected_route(selection, route_id):
    matches = [r for r in selection.policy.get('coreWorkTransport', {}).get('routes', ())
               if r['routeId'] == route_id]
    if len(matches) != 1:
        refused()
    return matches[0]


def subjects(route, *, publisher=False):
    result_subjects = (['am.result.' + route['peer']['nodeId']]
        if publisher and route['resultSubjects'] else route['resultSubjects'])
    result = tuple(sorted((*route['workSubjects'], *result_subjects)))
    if not result or len(result) != len(set(result)) or len(result) > 64:
        refused()
    for subject in result:
        if (type(subject) is not str or len(subject) > 512
                or re.fullmatch(r'am\.(?:work\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,2}|result\.[a-z0-9_]{1,32})', subject) is None):
            refused()
    return result


def publication_subjects(route, *, publisher=False):
    pin = route['publisher' if publisher else 'peer']
    values = pin['publishSubjects']
    if (type(values) is not list or not values or len(values) > 128
            or len(values) != len(set(values)) or not set(subjects(route, publisher=publisher)) <= set(values)
            or any(type(s) is not str or re.fullmatch(
                r'am\.(?:work\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,2}|result\.[a-z0-9_]{1,32})', s) is None for s in values)):
        refused()
    return tuple(sorted(values))


def group_binding(route):
    return {k: route[k] for k in ('scope', 'resourceRef', 'repository', 'localNode',
                                 'accountPublicKey', 'connection', 'receiver')}


def receiver_subjects(selection, route):
    common = group_binding(route)
    return tuple(sorted({s for other in selection.policy['coreWorkTransport']['routes']
        if group_binding(other) == common for s in subjects(other)}))


def public_credential(token, *, account, user, publish, subscribe, now=None):
    """Verify the account signature and the exact finite broker permissions."""
    try:
        if type(token) is not str or not 0 < len(token) <= 16384:
            refused()
        first, second, signature = token.encode('ascii').split(b'.')
        if strict_loads(_decode64(first)) != {'typ': 'JWT', 'alg': 'ed25519-nkey'}:
            refused()
        claims = _closed(strict_loads(_decode64(second)), ('iss', 'sub', 'nats'),
                         ('exp', 'nbf', 'iat', 'jti', 'name'))
        policy = _closed(claims['nats'], ('type', 'version', 'pub', 'sub'),
                        ('issuer_account', 'resp', 'subs', 'data', 'payload', 'bearer_token'))
        if (claims['iss'] != account or claims['sub'] != user or policy['type'] != 'user'
                or type(policy['version']) is not int or policy['version'] != 2
                or policy.get('issuer_account', account) != account
                or policy.get('resp') is not None or policy.get('bearer_token', False) is not False):
            refused()
        account_raw, user_raw = _base32(account.encode('ascii'), 35), _base32(user.encode('ascii'), 35)
        if account_raw[0] != nkeys.PREFIX_BYTE_ACCOUNT or user_raw[0] != nkeys.PREFIX_BYTE_USER:
            refused()
        VerifyKey(account_raw[1:-2]).verify(first + b'.' + second, _decode64(signature))
        for direction, expected in (('pub', publish), ('sub', subscribe)):
            part = _closed(policy[direction], ('allow',), ('deny',))
            if (type(part['allow']) is not list or any(type(x) is not str for x in part['allow'])
                    or sorted(part['allow']) != sorted(expected) or len(part['allow']) != len(set(part['allow']))
                    or part.get('deny', []) not in ([], ['>'])
                    or expected and part.get('deny', []) or not expected and part.get('deny', []) != ['>']):
                refused()
        if now is None:
            _current(claims)
        else:
            stamp = now.timestamp()
            if (any(type(claims.get(k, 0)) is not int for k in ('iat', 'nbf', 'exp'))
                    or claims.get('iat', 0) > stamp + 1 or claims.get('nbf', 0) > stamp
                    or claims.get('exp', 0) and stamp >= claims['exp']):
                refused()
        return claims, user_raw[1:-2]
    except Exception:
        refused()


def local_credential(selection, route, *, publisher=False):
    pin = route['publisher' if publisher else 'receiver']['credentials']
    raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != pin['sha256']:
        refused()
    tokens, seeds = _JWT.findall(raw), _SEED.findall(raw)
    if len(tokens) != 1 or len(seeds) != 1:
        refused()
    public_credential(tokens[0].decode(), account=route['accountPublicKey'], user=pin['userPublicKey'],
        publish=publication_subjects(route, publisher=True) if publisher else (),
        subscribe=() if publisher else receiver_subjects(selection, route))
    _base32(seeds[0], 36)
    key = nkeys.from_seed(seeds[0])
    try:
        if key.public_key.decode() != pin['userPublicKey']:
            refused()
    finally:
        key.wipe()
    return tokens[0], seeds[0]


def check_core_work_selection(value):
    selected = value.get('coreWorkTransport')
    if selected is None:
        return
    validate('core-work-transport-selection', selected)
    from .application_service_selection import _outside, _work_channel_projection
    from .application_host_selection import _check_connection
    storage, hub = value.get('storage', {}), value['kernelScope']['hubId']
    work = storage.get('work')
    if work is None or len({r['routeId'] for r in selected['routes']}) != len(selected['routes']):
        refused()
    peers = set()
    from pathlib import Path
    import os
    from .workspace_selection import _materials
    existing = list(_materials({k: v for k, v in value.items() if k != 'coreWorkTransport'}))
    private_paths = {}
    for route in selected['routes']:
        channels = [c for c in work['channels'] if c['resourceRef'] == route['resourceRef']]
        if len(channels) != 1:
            refused()
        repository, scope = _work_channel_projection(storage, work, channels[0])
        if (repository != route['repository'] or scope != route['scope'] or repository is None
                or scope['projectId'] is None or route['localNode'] != work['localNode']
                or route['peer']['nodeId'] == route['localNode']
                or route['resourceRef']['ownerHubId'] != hub):
            refused()
        subjects(route)
        publication_subjects(route)
        if 'publisher' in route:
            publication_subjects(route, publisher=True)
        for subject in route['resultSubjects']:
            if subject != 'am.result.' + route['localNode']:
                refused()
        receiver_grants = route['receiver']['grantRefs']
        matches = [actor for actor in channels[0].get('legacyActors', ())
            if actor['caller'] == 'federation'
            and actor['identityRef'] == route['receiver']['identityRef']
            and actor['transportRef'] == route['receiver']['transportRef']
            and all(actor['grants'].get(contract) == grant for contract, grant in receiver_grants.items())]
        if len(matches) != 1:
            refused()
        grants = route['peer']['grantRefs']
        required = ({INGEST} if route['workSubjects'] else set()) | ({RESULT} if route['resultSubjects'] else set())
        if set(grants) != required or set(receiver_grants) != required | QUERY_CONTRACTS:
            refused()
        key = (canonical_bytes(route['resourceRef']), route['peer']['nodeId'])
        if key in peers:
            refused()
        peers.add(key)
        connection = route['connection']
        if (re.fullmatch(r'tls://(?:127\.0\.0\.1|[a-z0-9.-]+):[1-9][0-9]{0,4}', connection['endpoint']) is None
                or re.fullmatch(r'sha256:[a-f0-9]{64}', connection['leafCertificateSHA256']) is None):
            refused()
        try:
            _check_connection(connection, datetime.now(timezone.utc))
        except (ValueError, KeyError, TypeError):
            refused()
        roles = ('receiver', 'peer', 'publisher') if 'publisher' in route else ('receiver', 'peer')
        users = []
        for role in roles:
            pin = route[role]
            refs = [pin['identityRef'], pin['transportRef'], *pin.get('grantRefs', {}).values()]
            if any(r['ownerHubId'] != hub or r['revision'] < 1 for r in refs):
                refused()
            if role != 'peer':
                _outside(pin['credentials']['path'], value['workspaces'])
                resolved = Path(os.path.realpath(pin['credentials']['path']))
                if any(resolved.is_relative_to(path) or path.is_relative_to(resolved) for path in existing):
                    refused()
                prior = private_paths.get(resolved)
                current = (role, canonical_bytes(pin))
                if prior is not None and prior != current:
                    refused()
                private_paths[resolved] = current
                users.append(pin['credentials']['userPublicKey'])
            else:
                users.append(pin['userPublicKey'])
        if len(set(users)) != len(users):
            refused()
        if 'publisher' in route and set(route['publisher']['grantRefs']) != required:
            refused()
        # One physical subscription owns the finite union for all peers of a resource.
        same_resource = [r for r in selected['routes'] if r['resourceRef'] == route['resourceRef']]
        if any(group_binding(r) != group_binding(route) for r in same_resource):
            refused()


def body_route(route, body, subject, *, publisher=False):
    if type(body) is not bytes or not 0 < len(body) <= 1048576:
        refused()
    item = strict_loads(body)
    kind = item.get('type') if type(item) is dict else None
    node = route['localNode'] if publisher else route['peer']['nodeId']
    if kind == 'work':
        contract = INGEST
        allowed = route['workSubjects']
        if (item.get('origin_node') != node or item.get('origin') != node + ':' + str(item.get('origin_id'))
                or item.get('work', {}).get('repo') != route['repository']['localName']):
            refused()
        address = names.parse_address(item['work']['target'])
        if address.kind != 'role' or names.nats_subject(address, node) != subject:
            refused()
        destination = {'kind': 'role', 'scope': address.scope, 'role': address.name}
        event_id = 'work:' + item['origin']
    elif kind == 'result':
        contract = RESULT
        allowed = (['am.result.' + route['peer']['nodeId']]
            if publisher and route['resultSubjects'] else route['resultSubjects'])
        if item.get('node') != node:
            refused()
        destination = {'kind': 'node', 'node': subject.removeprefix('am.result.')}
        event_id = 'result:' + node + ':' + str(item.get('origin_id'))
    else:
        refused()
    if subject not in allowed:
        refused()
    # This reuses the exact preserved payload contract rather than a parallel schema.
    validate(contract, {'resourceRef': route['resourceRef'], 'attribution': 'federation',
                        'input': {'envelope': item}})
    return item, contract, event_id, destination


def signed_claims(route, body, subject, *, publisher=False):
    _, contract, event_id, destination = body_route(route, body, subject, publisher=publisher)
    pin = route['publisher'] if publisher else route['peer']
    user = pin['credentials']['userPublicKey'] if publisher else pin['userPublicKey']
    return {'purpose': 'agentmux-core-work-v1', 'accountPublicKey': route['accountPublicKey'],
        'subject': subject, 'scope': route['scope'], 'repository': route['repository'],
        'publisherUserPublicKey': user, 'publisherNode': route['localNode'] if publisher else pin['nodeId'],
        'eventId': event_id, 'bodySha256': 'sha256:' + hashlib.sha256(body).hexdigest(),
        'contractId': contract, 'destination': destination}


def verify_event(route, body, subject, signature, *, now=None):
    if type(signature) is not str or len(signature) > 128:
        refused()
    peer = route['peer']
    claims, public = public_credential(peer['credentialJWT'], account=route['accountPublicKey'],
        user=peer['userPublicKey'], publish=publication_subjects(route), subscribe=(), now=now)
    try:
        VerifyKey(public).verify(canonical_bytes(signed_claims(route, body, subject)),
                                 base64.b64decode(signature, validate=True))
    except Exception:
        refused()
    return claims


def check_snapshot(route, snapshot, contract, *, publisher=False, now=None):
    if contract not in CONTRACTS:
        refused()
    record = strict_loads(snapshot.record)
    now = now or datetime.now(timezone.utc)
    index = _indexes(record['state'], record['ownerHubId'])
    limits = [now + timedelta(seconds=5)]
    roles = ('publisher',) if publisher else ('receiver', 'peer')
    for role in roles:
        pin = route[role]
        principal = index['identities'].get(_key(pin['identityRef']))
        transport = index['transports'].get(_key(pin['transportRef']))
        user = pin['userPublicKey'] if role == 'peer' else pin['credentials']['userPublicKey']
        public = base64.urlsafe_b64encode(_base32(user.encode(), 35)[1:-2]).decode().rstrip('=')
        if (principal is None or not _active(principal, now) or principal['kind'] != 'service'
                or transport is None or not _active(transport, now)
                or transport['identityRef'] != pin['identityRef'] or transport['publicKey'] != public
                or transport['method'] != 'nats-credential-mapping'
                or not any(_active(m, now) and m['identityRef'] == pin['identityRef']
                           and m['scope'] == route['scope'] for m in index['memberships'].values())):
            refused()
        issuer = index['issuers'].get(_key(transport['issuerRef']))
        issuer_identity = None if issuer is None else index['identities'].get(_key(issuer['identityRef']))
        if (issuer is None or not _active(issuer, now) or issuer_identity is None
                or not _active(issuer_identity, now) or issuer_identity['kind'] != 'service'):
            refused()
        limits.extend(datetime.fromisoformat(r['expiresAt']) for r in (transport, issuer))
    pin = route['publisher' if publisher else 'peer']
    grant_ref = pin['grantRefs'].get(contract)
    grant = None if grant_ref is None else index['grants'].get(_key(grant_ref))
    candidates = [g for g in index['grants'].values() if _active(g, now)
        and g['callerRef'] == pin['identityRef'] and g['actorRef'] == pin['identityRef']
        and g['scope'] == route['scope'] and g['contractId'] == contract
        and g['resourceId'] == route['resourceRef']['id']]
    if (grant not in candidates or grant['decision'] != 'allowed' or grant['delegationRef'] is not None
            or any(g['decision'] == 'denied' for g in candidates)
            or approval_reason(index, grant, {'approvalRefs': []}, audience={
                'hubId': record['ownerHubId'], 'serviceId': 'storage-owner'},
                scope=route['scope'], contract=contract, now=now) is not None):
        refused()
    limits.append(datetime.fromisoformat(grant['expiresAt']))
    # Upcoming authority changes can shorten, but never extend, this operation.
    for collection in ('issuers', 'transports', 'grants', 'approvals'):
        for item in record['state'][collection]:
            if item['status'] == 'active':
                limits.extend(datetime.fromisoformat(item[k]) for k in ('issuedAt', 'expiresAt')
                              if datetime.fromisoformat(item[k]) > now)
    return min(limits)


async def check_authority(selection, identity, *, route_id, contract, publisher=False, snapshot=None):
    route = selected_route(selection, route_id)
    authority, _ = selection.check_storage_identity_source(identity)
    snapshot = snapshot or await authority.current()
    selection.check_storage_identity_source(identity)
    deadline = check_snapshot(route, snapshot, contract, publisher=publisher)
    if publisher:
        local_credential(selection, route, publisher=True)
    else:
        peer = route['peer']
        public_credential(peer['credentialJWT'], account=route['accountPublicKey'],
                          user=peer['userPublicKey'], publish=publication_subjects(route), subscribe=())
        local_credential(selection, route)
    return snapshot, deadline
