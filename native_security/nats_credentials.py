"""Validate enrolled NATS credential bytes without opening files or connections.

The caller supplies protected account and permission enrollment. File custody,
TLS trust and connection ownership remain with that caller.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hmac
import re
import time

import nkeys
from nacl.signing import VerifyKey
from agentmux_contracts.wire import strict_loads

MAX_BYTES = 64 * 1024
_SAFE_INTEGER = 9_007_199_254_740_991
_JWT = re.compile(rb'(?m)^-{3,}BEGIN NATS USER JWT-{3,}\r?\n([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\r?\n-{3,}END NATS USER JWT-{3,}\r?$')
_SEED = re.compile(rb'(?m)^-{3,}BEGIN USER NKEY SEED-{3,}\r?\n(SU[A-Z2-7]+)\r?\n-{3,}END USER NKEY SEED-{3,}\r?$')
_INBOX = re.compile(r'_INBOX\.[A-Za-z0-9_-]{16,64}\.>\Z')
_ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
_JS_TOKEN = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
_RESPONSE_TTL_NS = 5_000_000_000
_MARKERS = frozenset((b'BEGIN NATS USER JWT', b'END NATS USER JWT',
                      b'BEGIN USER NKEY SEED', b'END USER NKEY SEED'))


class CredentialError(ValueError):
    """A fixed diagnostic that does not include private credential material."""
    def __init__(self):
        super().__init__('nats_credential_invalid')


@dataclass(frozen=True, repr=False, slots=True)
class Credential:
    """Validated material, exposed only through explicit immutable accessors."""
    _jwt: str
    _seed: bytes
    _public_key: str

    def __repr__(self):
        return '<Credential private>'

    __str__ = __repr__

    @property
    def jwt(self):
        return self._jwt

    @property
    def seed(self):
        return self._seed

    @property
    def public_key(self):
        return self._public_key


def _closed(value, required, optional=()):
    if (type(value) is not dict or not set(required) <= value.keys()
            or value.keys() - set(required) - set(optional)
            or any(item is None and key != 'resp' for key, item in value.items())):
        raise CredentialError()
    return value


def _literal(value):
    return (type(value) is str and bool(value) and not any(c in value for c in '*> \t\r\n\x00')
            and all(value.split('.')))


_APPLICATION_INTEGRATION = re.compile(
    r'amx\.v1\.h\.[a-z][a-z0-9_-]{0,95}\.o\.[a-z][a-z0-9_-]{0,95}'
    r'\.integrations\.\*\.command\Z')


def _permissions(actual, expected, private=False, application_publish=False):
    if (type(actual) is not list or type(expected) not in (list, tuple)
            or not actual or len(actual) != len(expected)
            or any(type(v) is not str for v in (*actual, *expected))):
        return False
    if private:
        return len(actual) == 1 and actual[0] == expected[0] and _INBOX.fullmatch(actual[0]) is not None
    return (sorted(actual) == sorted(expected)
            and all(_literal(v) or application_publish
                    and _APPLICATION_INTEGRATION.fullmatch(v) is not None for v in actual))


def _base32(raw, size):
    decoded = base64.b32decode(raw + b'=' * (-len(raw) % 8))
    if len(decoded) != size or not hmac.compare_digest(nkeys.crc16_checksum(decoded[:-2]), decoded[-2:]):
        raise CredentialError()
    return decoded


def _decode64(raw):
    return base64.b64decode(raw + b'=' * (-len(raw) % 4), altchars=b'-_', validate=True)


def _integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= _SAFE_INTEGER:
        raise CredentialError()
    return value


def _current(claims):
    expires = _integer(claims.get('exp', 0))
    not_before = _integer(claims.get('nbf', 0))
    issued = _integer(claims.get('iat', 0))
    now = time.time()
    if (expires and expires <= int(now)) or not_before > int(now) or issued > int(now + 1):
        raise CredentialError()


def validate(raw: bytes, *, account_public_key: str, publish_subjects,
             subscribe_subjects, private_inbox: bool = False,
             application_publish: bool = False) -> Credential:
    """Match the shared Go enrolled-credential policy against bounded bytes.

    In private inbox mode, subscriptions must contain exactly the enrolled
    ``_INBOX.<principal>.>`` prefix. Otherwise every subject must be literal.
    Neither mode accepts response permissions, bearer tokens or discovery.
    Callers must compare ``public_key`` with their enrolled user key when pinned.
    """
    return _validate(raw, account_public_key=account_public_key,
                     publish_subjects=publish_subjects, subscribe_subjects=subscribe_subjects,
                     private_inbox=private_inbox, application_publish=application_publish)


def _validate(raw, *, account_public_key, publish_subjects, subscribe_subjects,
              private_inbox=False, service=None, publisher=None, application_publish=False,
              require_current=True):
    key = None
    try:
        policy = service if service is not None else publisher
        if service is not None and publisher is not None:
            raise CredentialError()
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES
                or type(account_public_key) is not str or type(private_inbox) is not bool
                or type(application_publish) is not bool):
            raise CredentialError()
        tokens, seeds = _JWT.findall(raw), _SEED.findall(raw)
        if len(tokens) != 1 or len(seeds) != 1:
            raise CredentialError()
        markers = 0
        for line in raw.replace(b'\r\n', b'\n').split(b'\n'):
            if line.startswith(b'---'):
                if line.strip(b'-') not in _MARKERS:
                    raise CredentialError()
                markers += 1
        if markers != 4:
            raise CredentialError()
        # nkeys 0.2.1's seed decoder does not validate its CRC. Check the same
        # checksum and payload length as Go before using its signing primitive.
        _base32(seeds[0], 36)
        prefix, seed_bytes = nkeys.decode_seed(seeds[0])
        if prefix != nkeys.PREFIX_BYTE_USER or len(seed_bytes) != 32:
            raise CredentialError()
        key = nkeys.from_seed(seeds[0])
        user = key.public_key.decode('ascii')
        token = tokens[0]
        header_text, claims_text, signature_text = token.split(b'.')
        header = _closed(strict_loads(_decode64(header_text)), ('typ', 'alg'))
        if header != {'typ': 'JWT', 'alg': 'ed25519-nkey'}:
            raise CredentialError()
        claims = _closed(strict_loads(_decode64(claims_text)), ('iss', 'sub', 'nats'),
                         ('exp', 'nbf', 'iat', 'jti', 'name'))
        if any(type(claims[k]) is not str for k in ('jti', 'name') if k in claims):
            raise CredentialError()
        permissions = _closed(claims['nats'], ('type', 'version', 'pub', 'sub'),
                              ('issuer_account', 'resp', 'subs', 'data', 'payload', 'bearer_token'))
        for direction in ('pub', 'sub'):
            item = _closed(permissions[direction], ('allow',), ('deny',))
            if 'deny' in item and (type(item['deny']) is not list or item['deny']):
                raise CredentialError()
        if service is None:
            if 'resp' in permissions and permissions['resp'] is not None:
                raise CredentialError()
        else:
            response = _closed(permissions.get('resp'), ('max', 'ttl'))
            if (_integer(response['max']) != 1
                    or _integer(response['ttl']) != service.response_permissions['ttl']):
                raise CredentialError()
        if 'bearer_token' in permissions and permissions['bearer_token'] is not False:
            raise CredentialError()
        for limit in ('subs', 'data', 'payload'):
            if limit in permissions:
                _integer(permissions[limit], -1)
        if (claims['iss'] != account_public_key or claims['sub'] != user
                or permissions['type'] != 'user' or type(permissions['version']) is not int
                or permissions['version'] != 2
                or type(permissions.get('issuer_account', '')) is not str
                or permissions.get('issuer_account', '') not in ('', account_public_key)
                or not (_permissions(permissions['pub']['allow'], publish_subjects,
                                     application_publish=application_publish) if policy is None
                        else _service_subjects(permissions['pub']['allow'], policy.publish_subjects))
                or not (_permissions(permissions['sub']['allow'], subscribe_subjects, private_inbox)
                        if policy is None else _service_subjects(permissions['sub']['allow'], policy.subscribe_subjects))):
            raise CredentialError()
        if require_current:
            _current(claims)
        account = _base32(account_public_key.encode('ascii'), 35)
        if account[0] != nkeys.PREFIX_BYTE_ACCOUNT:
            raise CredentialError()
        VerifyKey(account[1:-2]).verify(header_text + b'.' + claims_text, _decode64(signature_text))
        if require_current:
            _current(claims)
        return Credential(token.decode('ascii'), seeds[0], user)
    except Exception:
        raise CredentialError() from None
    finally:
        if key is not None:
            key.wipe()


@dataclass(frozen=True, repr=False, slots=True)
class ServicePolicy:
    """Finite permissions derived from one protected receiving-service selection."""
    role: str
    command_subject: str
    ledger_subject: str
    publish_subjects: tuple[str, ...]
    subscribe_subjects: tuple[str, ...]

    def __repr__(self):
        return '<ServicePolicy private>'

    @property
    def response_permissions(self):
        ttl = {'configuration': 12_000_000_000, 'task': 8_000_000_000}.get(self.role, _RESPONSE_TTL_NS)
        return {'max': 1, 'ttl': ttl}


def _service_subjects(actual, expected):
    return (type(actual) is list and len(actual) == len(expected)
            and all(type(v) is str for v in actual) and sorted(actual) == sorted(expected))


def service_policy(*, role: str, hub_id: str, entity_id: str, scope: dict,
                   stream: str, reply_prefix: str, jetstream_domain=None,
                   artifact_bucket=None, integration_routing=False,
                   additional_streams=()) -> ServicePolicy:
    """Derive exact receiving-service grants from trusted inputs.

    Identity is organization-scoped and writes only its own identity aggregate.
    Definitions writes its scoped catalog and uses a dedicated artifact bucket.
    Its borrowed authority reader uses the separate Identity connection. Only
    generated single-token Object Store suffixes are wildcarded for Definitions.
    Integration requires project scope and only reads a selected artifact bucket;
    omit that bucket for a service constructed without artifact access. Routed
    integration uses project-scoped command and ledger subjects, while stream API
    access remains an exact enrolled list. Broker routing grants no product
    authority. Its command and ledger domain are both ``integrations``. No stream provisioning,
    purge, delete, direct read, consumer management or broad inbox publication is granted.
    """
    try:
        if (role not in ('identity', 'definitions', 'integration', 'configuration', 'task',
                         'orchestration', 'policy')
                or any(type(v) is not str or not _ID.fullmatch(v) for v in (hub_id, entity_id))
                or type(scope) is not dict or set(scope) != {'organizationId', 'projectId', 'workspaceId'}
                or type(scope['organizationId']) is not str or not _ID.fullmatch(scope['organizationId'])
                or any(v is not None and (type(v) is not str or not _ID.fullmatch(v))
                       for v in (scope['projectId'], scope['workspaceId']))
                or scope['workspaceId'] is not None and scope['projectId'] is None
                or type(stream) is not str or not _JS_TOKEN.fullmatch(stream)
                or type(reply_prefix) is not str or not _INBOX.fullmatch(reply_prefix + '.>')
                or jetstream_domain is not None and (type(jetstream_domain) is not str
                                                     or not _JS_TOKEN.fullmatch(jetstream_domain))
                or type(integration_routing) is not bool
                or type(additional_streams) not in (tuple, list)
                or len(additional_streams) > 64
                or any(type(name) is not str or not _JS_TOKEN.fullmatch(name)
                       for name in additional_streams)
                or len(set(additional_streams)) != len(additional_streams)
                or stream in additional_streams):
            raise CredentialError()
        if (integration_routing and role != 'integration'
                or additional_streams and not integration_routing):
            raise CredentialError()
        if role == 'identity':
            if (scope['projectId'] is not None or scope['workspaceId'] is not None
                    or artifact_bucket is not None):
                raise CredentialError()
        else:
            if role == 'policy' and artifact_bucket is not None:
                raise CredentialError()
            if role == 'configuration' and artifact_bucket is not None:
                raise CredentialError()
            if role == 'integration' and scope['projectId'] is None:
                raise CredentialError()
            if role == 'orchestration' and scope['projectId'] is None:
                raise CredentialError()
            if ((role == 'definitions' and artifact_bucket is None)
                    or artifact_bucket is not None and (type(artifact_bucket) is not str
                        or not _JS_TOKEN.fullmatch(artifact_bucket)
                        or stream == 'OBJ_' + artifact_bucket
                        or 'OBJ_' + artifact_bucket in additional_streams)):
                raise CredentialError()
        prefixes = ('$JS.API.',) if jetstream_domain is None else ('$JS.API.', '$JS.' + jetstream_domain + '.API.')
        organization = scope['organizationId']
        base = 'amx.v1.h.' + hub_id + '.o.' + organization
        domain = 'integrations' if role == 'integration' else role
        ledger_domain = ('orchestration-operations' if role == 'orchestration' else
                         'policy-evaluations' if role == 'policy' else domain)
        command = base + '.' + domain + '.' + entity_id + '.command'
        ledger_entity = entity_id
        if integration_routing:
            command = base + '.integrations.*.command'
            ledger_entity = '*'
        if role in ('configuration', 'task', 'orchestration'):
            command = (base + '.p.' + (scope['projectId'] or '_') + '.w.' + (scope['workspaceId'] or '_')
                       + '.' + role + '.' + entity_id + '.command')
        if role == 'policy':
            command = (base + '.p.' + (scope['projectId'] or '_') + '.w.' + (scope['workspaceId'] or '_')
                       + '.capability.policy-owner.command')
        ledger = (base + '.p.' + (scope['projectId'] or '_') + '.w.' + (scope['workspaceId'] or '_')
                  + '.ledger.' + ledger_domain + '.' + ledger_entity)
        streams = [stream, *additional_streams]
        if artifact_bucket is not None:
            streams.append('OBJ_' + artifact_bucket)
        publish = [ledger]
        if role == 'configuration':
            publish.append(command.removesuffix('.command') + '.event.configuration-change')
        for name in streams:
            # The broker maps domain requests to its canonical API before
            # permission checks. Admit both spellings for only these resources.
            for prefix in prefixes:
                publish.extend((prefix + 'STREAM.INFO.' + name, prefix + 'STREAM.MSG.GET.' + name))
        if role == 'definitions':
            publish.extend(('$O.' + artifact_bucket + '.C.*', '$O.' + artifact_bucket + '.M.*'))
        subscribe = [command, reply_prefix + '.>']
        if role == 'configuration':
            subscribe.append(ledger)
        return ServicePolicy(role, command, ledger, tuple(sorted(publish)), tuple(sorted(subscribe)))
    except Exception:
        raise CredentialError() from None


def validate_service(raw: bytes, *, account_public_key: str, role: str, hub_id: str,
                     entity_id: str, scope: dict, stream: str, reply_prefix: str,
                     jetstream_domain=None, artifact_bucket=None,
                     integration_routing=False, additional_streams=()) -> Credential:
    """Validate one receiving-service JWT without widening the client policy.

    The role and resource inputs come from protected enrollment. Response
    permission is exactly one response within five seconds (twelve for
    configuration, eight for the task callback's total enforced deadline);
    a lost or late
    response remains an unconfirmed outcome under the owner's normal protocol.
    """
    policy = service_policy(role=role, hub_id=hub_id, entity_id=entity_id, scope=scope,
        stream=stream, reply_prefix=reply_prefix, jetstream_domain=jetstream_domain,
        artifact_bucket=artifact_bucket, integration_routing=integration_routing,
        additional_streams=additional_streams)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), service=policy)


def validate_service_enrollment(raw: bytes, *, account_public_key: str, role: str,
                     hub_id: str, entity_id: str, scope: dict, stream: str,
                     reply_prefix: str, jetstream_domain=None, artifact_bucket=None,
                     integration_routing=False, additional_streams=()) -> Credential:
    """Verify an immutable historic credential without treating it as usable now.

    This checks its signature, user seed and exact permissions while ignoring
    only its time window.  Connection owners must still call ``validate_service``
    on the selected current generation before sending the credential.
    """
    policy = service_policy(role=role, hub_id=hub_id, entity_id=entity_id,
        scope=scope, stream=stream, reply_prefix=reply_prefix,
        jetstream_domain=jetstream_domain, artifact_bucket=artifact_bucket,
        integration_routing=integration_routing,
        additional_streams=additional_streams)
    return _validate(raw, account_public_key=account_public_key,
        publish_subjects=(), subscribe_subjects=(), service=policy,
        require_current=False)


@dataclass(frozen=True, repr=False, slots=True)
class BoardPublisherPolicy:
    """Exact journal and board writes for a protected publisher selection."""
    ledger_subject: str
    publish_subjects: tuple[str, ...]
    subscribe_subjects: tuple[str, ...]

    def __repr__(self):
        return '<BoardPublisherPolicy private>'


def storage_receiver_policy(*, hub_id, scope, service_id, reply_prefix, additional_scopes=()):
    """Receive only the finite protected capability subjects, without owner access."""
    from agentmux_contracts import canonical_bytes
    from state_owner.ledger import OwnerBinding
    try:
        if (service_id not in ('storage-owner', 'outcome-owner')
                or type(reply_prefix) is not str or not _INBOX.fullmatch(reply_prefix + '.>')
                or type(additional_scopes) not in (list, tuple) or len(additional_scopes) > 64):
            raise CredentialError()
        subjects = []
        for selected in (scope, *additional_scopes):
            OwnerBinding(hub_id, 'plugin-private', 'selected', 'plugin-storage', canonical_bytes(selected))
            if (selected['organizationId'] != scope['organizationId']
                    or selected['workspaceId'] is not None and selected['projectId'] is None):
                raise CredentialError()
            command = '.'.join(('amx', 'v1', 'h', hub_id, 'o', selected['organizationId'],
                'p', selected['projectId'] or '_', 'w', selected['workspaceId'] or '_',
                'capability', service_id, 'command'))
            if command in subjects:
                raise CredentialError()
            subjects.append(command)
        return ServicePolicy('storage', subjects[0], '', (), tuple(sorted((*subjects, reply_prefix + '.>'))))
    except Exception:
        raise CredentialError() from None


def validate_storage_receiver(raw, *, account_public_key, **inputs):
    policy = storage_receiver_policy(**inputs)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), service=policy)


def workspace_receiver_policy(*, hub_id, scope, reply_prefix):
    """Receive only workspace reads; no owner ledger or arbitrary publication."""
    base = storage_receiver_policy(hub_id=hub_id, scope=scope,
        service_id='storage-owner', reply_prefix=reply_prefix)
    command = base.command_subject.removesuffix('storage-owner.command') + 'workspace-owner.command'
    return ServicePolicy('workspace', command, '', (), tuple(sorted((command, reply_prefix + '.>'))))


def validate_workspace_receiver(raw, *, account_public_key, **inputs):
    policy = workspace_receiver_policy(**inputs)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), service=policy)


def artifact_receiver_policy(*, hub_id, scope, reply_prefix):
    """Receive artifact reads without ledger, Object Store or arbitrary publish access."""
    base = storage_receiver_policy(hub_id=hub_id, scope=scope,
        service_id='storage-owner', reply_prefix=reply_prefix)
    command = base.command_subject.removesuffix('storage-owner.command') + 'artifact-owner.command'
    return ServicePolicy('artifact', command, '', (), tuple(sorted((command, reply_prefix + '.>'))))


def validate_artifact_receiver(raw, *, account_public_key, **inputs):
    policy = artifact_receiver_policy(**inputs)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), service=policy)


def authority_switch_receiver_policy(*, hub_id, entity_id, scope, stream,
                                     reply_prefix, jetstream_domain=None):
    """Receive one organization switch command and write only its owner ledger."""
    from agentmux_contracts import canonical_bytes
    from state_owner.ledger import OwnerBinding, owner_subject
    try:
        if (type(stream) is not str or not _JS_TOKEN.fullmatch(stream)
                or type(reply_prefix) is not str or not _INBOX.fullmatch(reply_prefix + '.>')
                or jetstream_domain is not None and
                    (type(jetstream_domain) is not str or not _JS_TOKEN.fullmatch(jetstream_domain))):
            raise CredentialError()
        binding = OwnerBinding(hub_id, 'authority-switch', entity_id,
            'authority-switch', canonical_bytes(scope))
        if scope['projectId'] is not None or scope['workspaceId'] is not None:
            raise CredentialError()
        command = '.'.join(('amx', 'v1', 'h', hub_id, 'o', scope['organizationId'],
                            'authority-switch', entity_id, 'command'))
        ledger = owner_subject(binding)
        prefixes = ['$JS.API.']
        if jetstream_domain is not None:
            prefixes.append('$JS.' + jetstream_domain + '.API.')
        publish = [ledger]
        for prefix in prefixes:
            publish.extend((prefix + 'STREAM.INFO.' + stream,
                            prefix + 'STREAM.MSG.GET.' + stream))
        return ServicePolicy('authority-switch', command, ledger,
            tuple(sorted(publish)), tuple(sorted((command, reply_prefix + '.>'))))
    except Exception:
        raise CredentialError() from None


def validate_authority_switch_receiver(raw, *, account_public_key, **inputs):
    policy = authority_switch_receiver_policy(**inputs)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), service=policy)


def private_storage_publisher_policy(*, hub_id, entity_id, scope, stream, reply_prefix,
                                     jetstream_domain=None):
    """Write one private namespace; no command or management permissions."""
    from agentmux_contracts import canonical_bytes
    from state_owner.ledger import OwnerBinding, owner_subject
    try:
        if (type(stream) is not str or not _JS_TOKEN.fullmatch(stream)
                or type(reply_prefix) is not str or not _INBOX.fullmatch(reply_prefix + '.>')
                or jetstream_domain is not None and
                    (type(jetstream_domain) is not str or not _JS_TOKEN.fullmatch(jetstream_domain))):
            raise CredentialError()
        binding = OwnerBinding(hub_id, 'plugin-private', entity_id, 'plugin-storage', canonical_bytes(scope))
        if scope['workspaceId'] is not None and scope['projectId'] is None:
            raise CredentialError()
        ledger = owner_subject(binding)
        publish = [ledger]
        prefixes = ('$JS.API.',) if jetstream_domain is None else ('$JS.API.', '$JS.' + jetstream_domain + '.API.')
        for prefix in prefixes:
            publish.extend((prefix + 'STREAM.INFO.' + stream, prefix + 'STREAM.MSG.GET.' + stream))
        return BoardPublisherPolicy(ledger, tuple(sorted(publish)), (reply_prefix + '.>',))
    except Exception:
        raise CredentialError() from None


def validate_private_storage_publisher(raw, *, account_public_key, **inputs):
    policy = private_storage_publisher_policy(**inputs)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), publisher=policy)


def board_publisher_policy(*, hub_id, entity_id, scope, stream, reply_prefix,
                           repository_id, card_key=None, counter_prefix=None,
                           jetstream_domain=None):
    """Derive board writes without command subscriptions or response grants."""
    from agentmux_contracts import canonical_bytes
    from state_owner.ledger import OwnerBinding, owner_subject
    try:
        if (type(scope) is not dict or scope.get('projectId') is None
                or type(stream) is not str or not _JS_TOKEN.fullmatch(stream) or stream == 'KV_am_board'
                or type(reply_prefix) is not str or not _INBOX.fullmatch(reply_prefix + '.>')
                or type(repository_id) is not str or not re.fullmatch(r'r[a-f0-9]{12}', repository_id)
                or (card_key is None) == (counter_prefix is None)
                or card_key is not None and (type(card_key) is not str or not re.fullmatch(r'[A-Z0-9_-]{1,96}', card_key))
                or counter_prefix is not None and (type(counter_prefix) is not str or not re.fullmatch(r'[A-Z0-9_-]{1,64}', counter_prefix))
                or jetstream_domain is not None and (type(jetstream_domain) is not str or not _JS_TOKEN.fullmatch(jetstream_domain))):
            raise CredentialError()
        binding = OwnerBinding(hub_id, 'federation-board-operations', entity_id, 'attempt', canonical_bytes(scope))
        ledger = owner_subject(binding)
        publish = [ledger]
        prefixes = ['$JS.API.']
        if jetstream_domain is not None:
            prefixes.append('$JS.' + jetstream_domain + '.API.')
        for name in (stream, 'KV_am_board'):
            for prefix in prefixes:
                publish.extend((prefix + 'STREAM.INFO.' + name, prefix + 'STREAM.MSG.GET.' + name))
        base = '$KV.am_board.' + repository_id
        if card_key is not None:
            publish.append(base + '.card.' + card_key)
        else:
            publish.extend((base + '.seq.' + counter_prefix, base + '.card.*'))
        return BoardPublisherPolicy(ledger, tuple(sorted(publish)), (reply_prefix + '.>',))
    except Exception:
        raise CredentialError() from None


def validate_board_publisher(raw, *, account_public_key, hub_id, entity_id, scope,
                             stream, reply_prefix, repository_id, card_key=None,
                             counter_prefix=None, jetstream_domain=None):
    """Validate signed board publisher credentials against protected enrollment."""
    policy = board_publisher_policy(hub_id=hub_id, entity_id=entity_id, scope=scope,
        stream=stream, reply_prefix=reply_prefix, repository_id=repository_id,
        card_key=card_key, counter_prefix=counter_prefix, jetstream_domain=jetstream_domain)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
                     subscribe_subjects=(), publisher=policy)
