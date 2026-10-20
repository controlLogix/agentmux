"""Explicit host selection for the fixed ordinary-secret consumer."""
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import ssl

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from native_security.nats_credentials import validate as validate_credential
from .application_enrollment import _read_material
from .authority import _active, _indexes, _key
from .ordinary_secret import validate_enrollment


def _fail():
    raise ContractError('application_secret_selection_invalid') from None


def receiver_policy(*, hub_id, scope, service_id, reply_prefix):
    from native_security.nats_credentials import ServicePolicy, storage_receiver_policy
    if service_id not in ('secret-owner', 'outcome-owner'):
        _fail()
    base = storage_receiver_policy(hub_id=hub_id, scope=scope,
        service_id='outcome-owner', reply_prefix=reply_prefix)
    command = base.command_subject.replace('.outcome-owner.command', '.' + service_id + '.command')
    return ServicePolicy('storage', command, '', (), tuple(sorted((command, reply_prefix + '.>'))))


def selection_objects(pin):
    from capability_owner.secret_consumer import AtlassianAccountCheckEnrollment
    from capability_owner.secret_journal_admission import SecretJournalPolicy
    from state_owner.retention import Retention
    consumer, journal = pin['consumer'], pin['journal']
    connection = journal['connection']
    enrollment = AtlassianAccountCheckEnrollment(canonical_bytes(pin['record']),
        consumer['baseURL'], consumer['deployment'], consumer['email'],
        consumer['expectedAccount'], consumer['rootsPEM'].encode('ascii'))
    policy = SecretJournalPolicy(journal['namespace'], canonical_bytes(pin['scope']),
        journal['accountPublicKey'], connection['endpoint'], connection['serverName'],
        connection['rootsPEM'].encode('ascii'), connection['leafCertificateSHA256'],
        Retention(journal['retention']['maxBytes'], journal['retention']['reserveBytes'],
            journal['retention']['replicas']), journal['maxJournals'], journal['maxTotalBytes'],
        connection['jetstreamDomain'])
    return enrollment, policy


def check_secret_selection(value):
    pin = value.get('ordinarySecret')
    if pin is None:
        return
    from .application_service_selection import _outside, _storage_entries
    from .workspace_selection import _materials
    validate('ordinary-secret-selection', pin)
    enrollment, policy = selection_objects(pin)
    record, hub = pin['record'], value['kernelScope']['hubId']
    if (record['ref'] != record['generationRef'] or record['ref']['revision'] != 1
            or record['profileId'] != value['kernelScope']['profileId']
            or record['scope']['organizationId'] != value['organizationId']
            or any(record['scope'][k] != pin['scope'][k] for k in ('organizationId', 'projectId'))
            or record['scope']['workspaceId'] not in (None, pin['scope']['workspaceId'])):
        _fail()
    refs = [record[k] for k in ('ref', 'generationRef', 'ownerIdentityRef',
        'callerIdentityRef', 'consumerRef', 'purposeRef')]
    refs += [pin['pluginIdentityRef'], pin['signer']['transportRef'], pin['signer']['resolveGrant'],
        *pin['signer']['phaseGrants'].values(), pin['account']['accountRef'],
        pin['account']['transportRef'], pin['account']['grantRef']]
    receivers = pin['receivers']
    existing = [value[k] for k in ('identity', 'definitions', 'integration', 'configuration',
        'task', 'orchestration', 'policy') if value.get(k)]
    if value.get('storage') is not None:
        existing.extend(_storage_entries(value).values())
    existing.extend(value[k]['receiver'] for k in ('workspace', 'artifact') if value.get(k))
    for name, receiver in receivers.items():
        refs += [receiver['serviceIdentityRef'], receiver['issuer']['issuerRef'], receiver['requestSigningKeyRef']]
        if receiver['requestSigningKeyRef'] != value['identity']['issuer']['issuerRef']:
            _fail()
        credential, issuer = receiver['credentials'], receiver['issuer']
        for other in [*existing, *(r for key, r in receivers.items() if key != name)]:
            if (credential['userPublicKey'] == other['credentials']['userPublicKey']
                    or credential['replyPrefix'] == other['credentials']['replyPrefix']
                    or credential['replyPrefix'] == other.get('requesterReplyPrefix')
                    or issuer['publicKey'] == other.get('issuer', {}).get('publicKey')):
                _fail()
        receiver_policy(hub_id=hub, scope=pin['scope'], service_id=name+'-owner',
            reply_prefix=credential['replyPrefix'])
    if any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in refs):
        _fail()
    private = [pin['custodyRoot'], pin['accountCustodyRoot'], pin['journal']['inventoryRoot'],
        pin['journal']['observationRoot'], pin['signer']['keyFile']['path'], pin['account']['keyFile']['path']]
    private += [r[k]['path'] if k == 'credentials' else r[k]['keyFile']['path']
        for r in receivers.values() for k in ('credentials', 'issuer')]
    for path in private:
        _outside(path, value['workspaces'])
    # Material pins cannot alias existing credentials, keys or owner files.
    materials = list(_materials({k: v for k, v in value.items() if k != 'ordinarySecret'}))
    for path in private[4:]:
        actual = Path(os.path.realpath(path))
        if any(actual == other for other in materials):
            _fail()
    if len(set(map(os.path.realpath, private[4:]))) != len(private[4:]):
        _fail()


def load_material(pin):
    raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != pin['sha256']:
        _fail()
    return raw


def load_signer(pin):
    seed = load_material(pin['keyFile'])
    if (len(seed) != 32 or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
            != pin['publicKey']):
        _fail()
    return seed


def load_receiver(selection, name):
    pin = selection.policy['ordinarySecret']
    receiver = pin['receivers'][name]
    credential = receiver['credentials']
    policy = receiver_policy(hub_id=selection.policy['kernelScope']['hubId'], scope=pin['scope'],
        service_id=name+'-owner', reply_prefix=credential['replyPrefix'])
    from native_security.nats_credentials import _validate
    admitted = _validate(load_material(credential), account_public_key=credential['accountPublicKey'],
        publish_subjects=(), subscribe_subjects=(), service=policy)
    if admitted.public_key != credential['userPublicKey']:
        _fail()
    key = strict_loads(load_material(receiver['issuer']['keyFile']))
    validate('application-service-key', key)
    value = selection.policy
    expected = {'serviceId': name+'-owner', 'hubId': value['kernelScope']['hubId'],
        'profileId': value['kernelScope']['profileId'], 'authorityId': value['authorityId'],
        'issuerRef': receiver['issuer']['issuerRef']}
    if any(key[k] != v for k, v in expected.items()):
        _fail()
    seed = base64.b64decode(key['seed'], validate=True)
    if (len(seed) != 32 or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
            != receiver['issuer']['publicKey']):
        _fail()
    return admitted, seed


async def check_secret_authority(selection, identity):
    authority, _ = selection.check_storage_identity_source(identity)
    snapshot = await authority.current()
    selection.check_storage_identity_source(identity)
    pin, now = selection.policy['ordinarySecret'], datetime.now(timezone.utc)
    record = strict_loads(snapshot.record)
    index = _indexes(record['state'], record['ownerHubId'])
    def current(collection, reference):
        item = index[collection].get(_key(reference))
        if item is None or not _active(item, now):
            _fail()
        return item
    actual = current('ordinarySecretReferences', pin['record']['ref'])
    if actual != pin['record']:
        _fail()
    validate_enrollment(record['state'], index, actual, record['ownerHubId'])
    if current('identities', pin['pluginIdentityRef'])['kind'] != 'plugin':
        _fail()
    for receiver in pin['receivers'].values():
        principal = current('identities', receiver['serviceIdentityRef'])
        issuer = current('issuers', receiver['issuer']['issuerRef'])
        if (principal['kind'] != 'service' or issuer['identityRef'] != principal['ref']
                or issuer['instanceId'] != receiver['serviceInstanceId']
                or issuer['publicKey'] != receiver['issuer']['publicKey']):
            _fail()
    for signer in (pin['signer'], pin['account']):
        transport = current('transports', signer['transportRef'])
        if transport['publicKey'] != signer['publicKey'] or transport['issuerRef'] != selection.policy['identity']['issuer']['issuerRef']:
            _fail()
    return authority
