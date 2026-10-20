"""Provision the distinct installed signed-recovery live fixture.

The baseline installed-service fixture owns the setup connection and bootstrap
permit.  This extension adds only the exact authority-switch owner, client
route and already-fenced legacy Store needed by the recovery check.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import uuid

from agentmux_contracts import canonical_bytes, sign_claims, strict_loads
from hub.store import Store
from identity.application_client import load_application_client
from identity.application_enrollment import _write_material
from identity.application_service_selection import provision_application_service_issuer
from identity.authority import LedgerAuthorityReader
from identity.ingress import EnrolledIngress
from native_security.nats_credentials import (
    authority_switch_receiver_policy, validate_authority_switch_receiver)
from state_owner.authority_switch import (
    AuthoritySwitchHost, AuthoritySwitchOwner, authority_switch_id)
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject

from installed_service_enrollment import (
    Preparation, RETENTION, digest, private_bytes, stamp, user_credential)


def _comparison_digest(store, source_ref, application_version):
    """Match Hub's logical pre-fence comparison token for this actual Store."""
    logical = hashlib.sha256()
    fence_insert = 'INSERT INTO "fed_state" VALUES(\'migration.legacy-writer-fence\','
    for line in store.db.iterdump():
        if line.startswith(fence_insert):
            continue
        logical.update(line.encode())
        logical.update(b'\n')
    database_digest = 'sha256:' + logical.hexdigest()
    token = hashlib.sha256(b'amx-legacy-writer-fence-comparison-v1\0')
    fields = (json.dumps(source_ref, sort_keys=True, separators=(',', ':')).encode(),
              application_version.encode(), database_digest.encode())
    for field in fields:
        token.update(len(field).to_bytes(8, 'big'))
        token.update(field)
    return 'sha256:' + token.hexdigest()


def _replace_private(path, value):
    """Replace one setup-owned private document without widening its mode."""
    temporary = path.with_name(path.name + '.next')
    private_bytes(temporary, canonical_bytes(value))
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class AuthoritySwitchPreparation(Preparation):
    """Add one service-owned switch route without broad broker authority."""
    def prepare_selected_materials(self, now, connection, interval_args):
        self._prepared_at = now
        # Admission binds the host policy and preparation directory to one
        # disposable parent. Its owner removes custody with that whole fixture.
        custody = Path(self.value['authoritySwitch']['custodyDirectory'])
        custody.mkdir(mode=0o700)
        directory = self.directory / 'authority-switch-service'
        directory.mkdir(mode=0o700)
        service_identity = {'ref': self.ref('switch_service'), 'kind': 'service',
            'status': 'active', 'principalId': 'fixture_switch_service',
            'externalIdentity': None}
        payload, receipt = provision_application_service_issuer(
            directory / 'issuer.json', service_id='authority-switch-owner',
            profile_id=self.plan['host']['kernelScope']['profileId'],
            authority_id=self.authority,
            instance_id='fixture_switch_instance', identity=service_identity,
            issuer_ref=self.ref('switch_issuer'), **interval_args)
        self.payloads.append(payload)

        legacy = self.directory / 'authority-switch-legacy'
        legacy.mkdir(mode=0o700)
        self.legacy_database = legacy / 'hub.db'
        store = Store(str(self.legacy_database))
        try:
            source_ref = self.ref('legacy_source')
            application_version = 'installed-legacy-v1'
            comparison = _comparison_digest(store, source_ref, application_version)
            fence = store.fence_legacy_writer()
        finally:
            store.db.close()
        self.source = {'sourceRef': source_ref,
            'applicationVersion': application_version,
            'comparisonDigest': comparison, 'fenceId': fence['fenceId'],
            'fenceGeneration': fence['generation']}
        self.switch_id = authority_switch_id(self.source)
        stream = 'INSTALLED_AUTHORITY_SWITCH'
        prefix = '_INBOX.installed_authority_switch_0001'
        options = dict(hub_id=self.plan['host']['kernelScope']['hubId'],
            entity_id=self.switch_id, scope=self.org_scope, stream=stream,
            reply_prefix=prefix,
            jetstream_domain=self.plan['broker']['domain'])
        permissions = authority_switch_receiver_policy(**options)
        raw = user_credential(self.account, permissions.publish_subjects,
            permissions.subscribe_subjects, response=permissions.response_permissions)
        admitted = validate_authority_switch_receiver(raw,
            account_public_key=self.account.public_key.decode(), **options)
        credential_path = directory / 'user.creds'
        private_bytes(credential_path, raw)
        issuer = {'keyFile': {'path': receipt.path, 'sha256': receipt.digest},
            'issuerRef': self.ref('switch_issuer'),
            'publicKey': payload['issuers'][0]['record']['publicKey']}
        receiver = {'connection': dict(connection),
            'credentials': {'path': str(credential_path), 'sha256': digest(raw),
                'accountPublicKey': self.account.public_key.decode(),
                'userPublicKey': admitted.public_key, 'replyPrefix': prefix},
            'issuer': issuer, 'serviceIdentityRef': service_identity['ref'],
            'serviceInstanceId': 'fixture_switch_instance',
            'requestSigningKeyRef': self.value['identity']['issuer']['issuerRef']}
        ledger = {'entityId': self.switch_id, 'scope': self.org_scope,
            'stream': stream,
            'retention': {'maxBytes': RETENTION.max_bytes,
                'reserveBytes': RETENTION.reserve_bytes, 'replicas': 1},
            'history': {'path': str(directory / 'history.sqlite'),
                'maxRecords': 1000000, 'maxBytes': 1073741824},
            'checkpoint': {'path': str(directory / 'checkpoint'),
                'commitRef': self.ref('switch_checkpoint')}}
        self.value['authoritySwitch']['binding'] = {'switchId': self.switch_id,
            'source': self.source, 'receiver': receiver, 'ledger': ledger}

    def extend_client_selection(self, selection):
        binding = self.value['authoritySwitch']['binding']
        receiver = binding['receiver']
        selection['authoritySwitchRecovery'] = {
            'subject': '.'.join(('amx', 'v1', 'h', selection['hubId'], 'o',
                self.organization, 'authority-switch', self.switch_id, 'command')),
            'grantRef': self.ref('switch_grant'),
            'replyIssuerRef': receiver['issuer']['issuerRef'],
            'replyIssuerPublicKey': receiver['issuer']['publicKey'],
            'transportRef': self.ref('switch_transport'),
            'switchId': self.switch_id, 'source': self.source,
            # The real creation time is filled before the client key is written.
            # Use a temporary valid value and rewrite the key after provisioning.
            'streamIdentity': {'created': stamp(self._prepared_at),
                               'minimumSequence': 0},
            'serviceIdentityRef': receiver['serviceIdentityRef'],
            'serviceInstanceId': receiver['serviceInstanceId']}
        self._client_selection = selection

    def client_publish_subjects(self):
        return [self.identity_command,
            self._client_selection['authoritySwitchRecovery']['subject']]

    def extend_initial_authority(self, state):
        super().extend_initial_authority(state)
        state['grants'].append({'ref': self.ref('switch_grant'),
            'callerRef': self.ref('client'), 'actorRef': self.ref('client'),
            'scope': self.org_scope, 'contractId': 'authority-switch',
            'resourceId': self.switch_id, 'decision': 'allowed',
            'delegationRef': None, 'definitionTarget': None,
            **self.interval, 'status': 'active'})

    async def provision_selected_resources(self, js):
        binding = self.value['authoritySwitch']['binding']
        ledger = binding['ledger']
        owner_binding = OwnerBinding(self.plan['host']['kernelScope']['hubId'],
            'authority-switch', self.switch_id, 'authority-switch',
            canonical_bytes(self.org_scope))
        info = await js.add_stream(RETENTION.stream_config(
            stream=ledger['stream'], subject=owner_subject(owner_binding)))
        RETENTION.validate(info, stream=ledger['stream'],
                           subject=owner_subject(owner_binding))
        if info.state.messages != 0 or info.state.last_seq != 0:
            raise ValueError('installed authority-switch stream occupied')
        ledger['streamIdentity'] = {'created': stamp(info.created),
                                    'minimumSequence': 0}
        # The client key is still private setup material. Replace it before the
        # bootstrap proof set and live client selection become authoritative.
        material = strict_loads(self.client_key.read_bytes())
        material['authoritySwitchRecovery']['streamIdentity'] = dict(
            ledger['streamIdentity'])
        _replace_private(self.client_key, material)

    async def provision_confirmed_resources(self, js, receipt):
        binding_value = self.value['authoritySwitch']['binding']
        ledger_value = binding_value['ledger']
        stream = ledger_value['streamIdentity']
        identity = self.value['identity']
        identity_binding = OwnerBinding(self.plan['host']['kernelScope']['hubId'],
            'identity', self.authority, 'identity-authority',
            canonical_bytes(self.org_scope))
        identity_ledger = OwnerLedger(js, stream=identity['ledger']['stream'],
            subject=owner_subject(identity_binding), binding=identity_binding,
            retention=RETENTION,
            stream_identity=StreamIdentity(
                datetime.fromisoformat(identity['ledger']['streamIdentity']['created']),
                receipt.sequence))
        reader = LedgerAuthorityReader(identity_ledger,
            hub_id=identity_binding.hub_id, entity_id=identity_binding.entity_id,
            profile_id=self.plan['host']['kernelScope']['profileId'],
            organization_id=self.organization)
        ingress = EnrolledIngress(reader,
            issuer_ref=identity['issuer']['issuerRef'],
            signing_seed=self._identity_signing_seed())
        switch_binding = OwnerBinding(identity_binding.hub_id, 'authority-switch',
            self.switch_id, 'authority-switch', canonical_bytes(self.org_scope))
        switch_identity = StreamIdentity(datetime.fromisoformat(stream['created']), 0)
        switch_ledger = OwnerLedger(js, stream=ledger_value['stream'],
            subject=owner_subject(switch_binding), binding=switch_binding,
            retention=RETENTION, stream_identity=switch_identity)
        host = AuthoritySwitchHost(self.value['authoritySwitch']['custodyDirectory'],
            binding=switch_binding, stream_identity=switch_identity)
        owner = AuthoritySwitchOwner(reader, switch_ledger, host=host)
        key = load_application_client(self.client_key)
        route = key.selection['authoritySwitchRecovery']
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1',
            **{name: key.selection[name]
               for name in ('hubId', 'profileId', 'authorityId')},
            'transportRef': route['transportRef'],
            'grantRef': route['grantRef'],
            'operationId': 'fixture_record_source_fence',
            'expectedVersion': 0, 'contractId': 'authority-switch',
            'approvalRefs': [],
            'payload': {'action': 'record-source-fence',
                'switchId': self.switch_id, 'source': self.source},
            'replySubject': '_INBOX.installed_authority_switch_seed.reply',
            'issuedAt': stamp(now),
            'expiresAt': stamp(now + timedelta(seconds=60))}
        request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, key._seed)})
        admitted = await ingress.admit(request, cancellation_ref={
            'id': 'switch_seed_cancel_' + uuid.uuid4().hex,
            'ownerHubId': identity_binding.hub_id, 'revision': 1})
        if admitted.envelope is None or admitted.decision.outcome != 'allowed':
            raise ValueError('installed authority-switch source fence refused')
        stored = await owner.handle(admitted.envelope)
        if stored.sequence != 1 or stored.replayed:
            raise ValueError('installed authority-switch source fence unconfirmed')
        ledger_value['streamIdentity']['minimumSequence'] = stored.sequence
        material = strict_loads(self.client_key.read_bytes())
        route_stream = material['authoritySwitchRecovery']['streamIdentity']
        if route_stream != {'created': stream['created'], 'minimumSequence': 0}:
            raise ValueError('installed authority-switch client stream changed')
        route_stream['minimumSequence'] = stored.sequence
        _replace_private(self.client_key, material)

    def _identity_signing_seed(self):
        from identity.application_service_selection import ApplicationServiceSelection
        # Before the stream floor is raised, the complete protected selection is
        # already valid and can read only its pinned private issuer key.
        return ApplicationServiceSelection(canonical_bytes(self.value)).load_signing_seed('identity')

    def write_selections(self, selection, sequence):
        result = super().write_selections(selection, sequence)
        material = {'schemaVersion': '1.0.0',
            'clientSelection': {'path': result['enrollment'],
                'sha256': result['sha256']},
            'serviceSelection': {'path': str(self.directory / 'service-selection.json'),
                'sha256': digest(canonical_bytes(selection.policy))},
            'database': {'path': str(self.legacy_database)},
            'switchId': self.switch_id, 'source': self.source}
        path = self.directory / 'authority-switch-recovery-material.json'
        _write_material(path, material, max_bytes=16384)
        result['recoveryMaterial'] = {'path': str(path),
                                      'sha256': digest(canonical_bytes(material))}
        return result
