"""Finite broker permissions for a dedicated federation policy aggregate.

Ordinary configuration keeps its existing policy and has no Object Store rights.
Only a protected federation-policy selection may select this separate validator.
"""
import re

from native_security.nats_credentials import CredentialError, ServicePolicy, _validate, service_policy


def federation_policy_service_policy(*, hub_id, entity_id, scope, stream, reply_prefix,
                                     artifact_bucket, jetstream_domain=None):
    if (type(artifact_bucket) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', artifact_bucket)
            or stream == 'OBJ_' + artifact_bucket):
        raise CredentialError()
    base = service_policy(role='configuration', hub_id=hub_id, entity_id=entity_id, scope=scope,
        stream=stream, reply_prefix=reply_prefix, jetstream_domain=jetstream_domain)
    prefixes = ['$JS.API.']
    if jetstream_domain is not None:
        prefixes.append('$JS.' + jetstream_domain + '.API.')
    publish = [*base.publish_subjects, '$O.'+artifact_bucket+'.C.*', '$O.'+artifact_bucket+'.M.*']
    for prefix in prefixes:
        publish.extend((prefix+'STREAM.INFO.OBJ_'+artifact_bucket, prefix+'STREAM.MSG.GET.OBJ_'+artifact_bucket))
    return ServicePolicy('configuration', base.command_subject, base.ledger_subject,
        tuple(sorted(publish)), base.subscribe_subjects)


def validate_federation_policy_service(raw, *, account_public_key, **inputs):
    policy = federation_policy_service_policy(**inputs)
    return _validate(raw, account_public_key=account_public_key, publish_subjects=(),
        subscribe_subjects=(), service=policy)


def _service(value):
    return value['federationPolicy']['service']


def policy_binding(value):
    from agentmux_contracts import canonical_bytes
    from state_owner.ledger import OwnerBinding
    ledger = _service(value)['ledger']
    return OwnerBinding(value['kernelScope']['hubId'], 'configuration', ledger['entityId'],
        'configuration', canonical_bytes(ledger['scope']))


def policy_target(value):
    from state_owner.federation_policy import FederationPolicyTarget
    selected = value['federationPolicy']['target']
    return FederationPolicyTarget.selected(policy_binding(value), source_ref=selected['sourceRef'],
        source=selected['source'], repository=selected['repository'], local_peer=selected['localPeer'])


def check_federation_policy_selection(value):
    """Validate a separate aggregate without changing the ordinary selection."""
    import copy
    import os
    from agentmux_contracts import canonical_bytes, validate
    from .application_service_selection import _check_fields, _outside, _fail
    from state_owner.federation_policy import SCHEMA_REF, FEDERATION_POLICY_SCHEMA
    selected, service = value['federationPolicy'], _service(value)
    validate('federation-policy-service-selection', selected)
    # Reuse the ordinary closed service checks on a disposable validation view.
    # No runtime selection or factory is created from this view.
    checked = copy.deepcopy(value)
    checked.pop('federationPolicy')
    checked['configuration'] = service
    _check_fields(checked)
    target = policy_target(value)
    if (service['schemaRef'] != SCHEMA_REF or set(service['schemaResources']) != {SCHEMA_REF}
            or service['ledger']['scope']['projectId'] is None
            or service['ledger']['scope'] != value.get('storage', {}).get('scope')):
        _fail()
    pins = selected['target']
    sources = [(value['storage'][name], key) for name, key in
        (('messages', 'source'), ('knowledge', 'source'), ('code', 'source'), ('board', 'auditMirror'))
        if name in value['storage']]
    if not any(item[key] == pins['source'] and item['localPeer'] == pins['localPeer']
            and item['repository'] == pins['repository'] for item, key in sources):
        _fail()
    hub = value['kernelScope']['hubId']
    refs = [selected['artifacts']['storeRef'], selected['key']['keyRef'],
        *selected['backupAuthority'].values(), *selected['projectionAuthority'].values()]
    if any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in refs):
        _fail()
    if selected['backupAuthority']['grantRef'] == selected['projectionAuthority']['grantRef']:
        _fail()
    _outside(selected['key']['path'], value['workspaces'])
    def paths(s):
        return [s['credentials']['path'], s['issuer']['keyFile']['path'],
            s['ledger']['history']['path'], s['ledger']['checkpoint']['path'],
            *[s['backup'][k] for k in ('backupDirectory','inventoryDirectory','keyDirectory')]]
    own_paths = paths(service) + [selected['key']['path'], service['producer']['keyFile']['path'],
        *[p['path'] for p in service['schemaResources'].values()]]
    if len(set(map(os.path.realpath, own_paths))) != len(own_paths):
        _fail()
    for name in ('identity', 'definitions', 'integration', 'task', 'orchestration', 'policy'):
        other = value.get(name)
        if other is None:
            continue
        if (service['ledger']['stream'] == other['ledger']['stream']
                or os.path.realpath(service['ledger']['checkpoint']['path']) == os.path.realpath(other['ledger']['checkpoint']['path'])
                or selected['artifacts']['bucket'] == other.get('artifacts', {}).get('bucket')):
            _fail()
    ordinary = value.get('configuration')
    if ordinary is not None:
        if (service['owner'] == ordinary['owner']
                or service['ledger']['entityId'] == ordinary['ledger']['entityId']
                or service['ledger']['stream'] == ordinary['ledger']['stream']
                or service['credentials']['userPublicKey'] == ordinary['credentials']['userPublicKey']
                or service['issuer']['publicKey'] == ordinary['issuer']['publicKey']
                or set(map(os.path.realpath, own_paths)) & set(map(os.path.realpath,
                    paths(ordinary) + [ordinary['producer']['keyFile']['path']]))):
            _fail()
    # Schema bytes are read again by the factory before construction.
    from .application_enrollment import _read_material
    from .application_service_selection import _digest
    pin = service['schemaResources'][SCHEMA_REF]
    raw = _read_material(pin['path'], max_bytes=262144, return_bytes=True)
    if raw != FEDERATION_POLICY_SCHEMA or _digest(raw) != pin['sha256']:
        _fail()
    return target


def policy_inputs(value):
    service = _service(value)
    ledger = service['ledger']
    return dict(hub_id=value['kernelScope']['hubId'], entity_id=ledger['entityId'],
        scope=ledger['scope'], stream=ledger['stream'], reply_prefix=service['credentials']['replyPrefix'],
        artifact_bucket=value['federationPolicy']['artifacts']['bucket'],
        jetstream_domain=service['connection']['jetstreamDomain'])


def load_policy_credentials(selection):
    from .application_enrollment import _read_material
    from .application_service_selection import _digest, _fail
    value = selection.policy
    pin = _service(value)['credentials']
    raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
    if _digest(raw) != pin['sha256']:
        _fail()
    credential = validate_federation_policy_service(raw, account_public_key=pin['accountPublicKey'],
        **policy_inputs(value))
    if credential.public_key != pin['userPublicKey']:
        _fail()
    return credential


def policy_tls_options(selection):
    import ssl
    connection = _service(selection.policy)['connection']
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=connection['rootsPEM'])
    return dict(servers=[connection['endpoint']], tls=context,
        tls_hostname=connection['serverName'], tls_handshake_first=True)


def load_policy_seed(selection):
    import base64
    from nacl.signing import SigningKey
    from agentmux_contracts import strict_loads, validate
    from .application_enrollment import _read_material
    from .application_service_selection import _digest, _fail
    value, service = selection.policy, _service(selection.policy)
    pin = service['issuer']['keyFile']
    raw = _read_material(pin['path'], return_bytes=True)
    key = strict_loads(raw)
    validate('application-service-key', key)
    if (_digest(raw) != pin['sha256'] or any(key[k] != wanted for k, wanted in {
            'serviceId':'configuration-owner', 'hubId':value['kernelScope']['hubId'],
            'profileId':value['kernelScope']['profileId'], 'authorityId':value['authorityId'],
            'issuerRef':service['issuer']['issuerRef']}.items())):
        _fail()
    seed = base64.b64decode(key['seed'], validate=True)
    if len(seed) != 32 or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=') != service['issuer']['publicKey']:
        _fail()
    return seed


def policy_event_producer(selection, authority, signing_seed):
    import base64
    from nacl.signing import SigningKey
    from .configuration_events import ConfigurationEventProducer
    from .application_enrollment import _read_material
    from .application_service_selection import _digest, _fail
    value, service = selection.policy, _service(selection.policy)
    producer = service['producer']
    seed = _read_material(producer['keyFile']['path'], max_bytes=32, return_bytes=True)
    if (len(seed) != 32 or _digest(seed) != producer['keyFile']['sha256']
            or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=') != producer['publicKey']):
        _fail()
    return ConfigurationEventProducer(authority, hub_id=value['kernelScope']['hubId'],
        profile_id=value['kernelScope']['profileId'], authority_id=value['authorityId'],
        configuration_id=service['ledger']['entityId'], scope=service['ledger']['scope'],
        identity_ref=producer['identityRef'], transport_ref=producer['transportRef'], grant_ref=producer['grantRef'],
        transport_seed=seed, issuer_ref=service['issuer']['issuerRef'], signing_seed=signing_seed)


async def check_policy_authority(selection, identity, signing_seed):
    import base64
    from datetime import datetime, timezone
    from nacl.signing import SigningKey
    from agentmux_contracts import strict_loads
    from .authority import _indexes, _key, _active
    from .application_service_selection import _fail
    authority, _ = selection.check_storage_identity_source(identity)
    snapshot = await authority.current()
    selection.check_storage_identity_source(identity)
    value = selection.policy
    selected, service = value['federationPolicy'], _service(value)
    index = _indexes(strict_loads(snapshot.record)['state'], value['kernelScope']['hubId'])
    now = datetime.now(timezone.utc)
    def current(collection, reference):
        item = index[collection].get(_key(reference))
        if item is None or not _active(item, now):
            _fail()
        return item
    route = selected['projectionAuthority']
    principal = current('identities', route['serviceIdentityRef'])
    signer = current('issuers', service['issuer']['issuerRef'])
    public = base64.urlsafe_b64encode(bytes(SigningKey(signing_seed).verify_key)).decode().rstrip('=')
    if (principal['kind'] != 'service' or signer['identityRef'] != principal['ref']
            or signer['publicKey'] != public or signer['publicKey'] != service['issuer']['publicKey']
            or not any(_active(m, now) and m['identityRef'] == principal['ref']
                and m['scope'] == service['ledger']['scope'] for m in index['memberships'].values())):
        _fail()
    for pins, contract in ((route, 'federation-policy-project'),
            (selected['backupAuthority'], 'configuration-read')):
        transport = current('transports', pins['transportRef'])
        grant = current('grants', pins['grantRef'])
        issuer = current('issuers', transport['issuerRef'])
        current('identities', issuer['identityRef'])
        if (transport['identityRef'] != principal['ref'] or transport['publicKey'] != public
                or transport['method'] != 'nats-credential-mapping'
                or transport['issuerRef'] != value['identity']['issuer']['issuerRef']
                or grant['callerRef'] != principal['ref'] or grant['actorRef'] != principal['ref']
                or grant['scope'] != service['ledger']['scope'] or grant['contractId'] != contract
                or grant['resourceId'] != service['ledger']['entityId'] or grant['delegationRef'] is not None
                or grant['decision'] != 'allowed'
                or any(_active(g, now) and g['callerRef'] == principal['ref'] and g['actorRef'] == principal['ref']
                    and g['scope'] == grant['scope'] and g['contractId'] == contract
                    and g['resourceId'] == grant['resourceId'] and g['decision'] == 'denied'
                    for g in index['grants'].values())):
            _fail()
    return snapshot
