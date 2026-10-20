"""Closed native Secret.Use adapter over the retained approved-consumer owner."""
import asyncio
from datetime import datetime, timedelta, timezone
import secrets

from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads, validate
from identity.authority import LedgerAuthorityReader
from identity.ingress import EnrolledIngress
from identity.ordinary_secret import NativeSecretProof, authorize_native_secret_proof
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from state_owner.ledger import OwnerBinding
from .ordinary_secret import OrdinarySecretOwner
from .secret_consumer import AtlassianAccountCheckConsumer
from .secret_journal import PHASE_CONTRACTS, SecretPhaseSigner
from .secret_journal_admission import SecretJournalAdmission


def _refuse():
    raise ContractError('capability_secret_unavailable') from None


class SecretResolveSigner:
    """Host-selected signers; request data cannot choose credentials or grants."""
    def __init__(self, ingress, *, enrollment, custody_transport, custody_seed,
                 resolve_grant, phase_grants, account_transport, account_seed,
                 account_grant, account_ref, account_public_key):
        if (type(ingress) is not EnrolledIngress or type(custody_seed) is not bytes
                or len(custody_seed) != 32 or type(account_seed) is not bytes or len(account_seed) != 32
                or set(phase_grants) != PHASE_CONTRACTS):
            _refuse()
        self._caller_ingress, self._reader, self._enrollment = ingress, ingress._reader, enrollment
        self._ingress = EnrolledIngress(ingress._reader, issuer_ref=strict_loads(ingress._issuer_ref),
            signing_seed=ingress._seed)
        self._custody_transport, self._custody_seed = canonical_bytes(custody_transport), custody_seed
        self._resolve_grant, self._phase_grants = canonical_bytes(resolve_grant), canonical_bytes(phase_grants)
        self._account_transport, self._account_seed = canonical_bytes(account_transport), account_seed
        self._account_grant, self._account_ref = canonical_bytes(account_grant), canonical_bytes(account_ref)
        self._account_public = account_public_key

    def __repr__(self):
        return '<SecretResolveSigner private>'

    async def _admit(self, contract, payload, *, account=False, expires, cancellation):
        now = datetime.now(timezone.utc)
        end = min(expires, now + timedelta(seconds=30 if account else 5))
        if now >= end:
            _refuse()
        stamp = lambda value: value.isoformat(timespec='microseconds').replace('+00:00', 'Z')
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': self._reader._hub,
            'profileId': self._reader._profile, 'authorityId': self._reader._entity,
            'transportRef': strict_loads(self._account_transport if account else self._custody_transport),
            'grantRef': strict_loads(self._account_grant if account else self._resolve_grant),
            'operationId': 'secret-resolve-' + secrets.token_hex(24), 'expectedVersion': 0,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(end)}
        raw = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, self._account_seed if account else self._custody_seed)})
        admitted = await self._ingress.admit(raw, cancellation_ref=cancellation)
        if admitted.decision.outcome != 'allowed' or admitted.envelope is None:
            _refuse()
        if account and strict_loads(admitted.envelope)['operation']['caller']['kind'] != 'service':
            _refuse()
        return admitted.envelope

    async def resolve(self, original, proof):
        snapshot = await self._reader.current()
        now = datetime.now(timezone.utc)
        end = await authorize_native_secret_proof(proof, self._reader, snapshot, original, now=now)
        if proof.caller_ingress is not self._caller_ingress or datetime.now(timezone.utc) >= end:
            _refuse()
        envelope = strict_loads(original)
        record = strict_loads(self._enrollment.record)
        payload = {name: record[name] for name in ('generationRef', 'profileId', 'consumerRef', 'purposeRef')}
        payload.update(authorityId=self._reader._entity, secretRef=record['ref'],
            scope=envelope['operation']['scope'], originalEnvelope=envelope)
        return await self._admit('identity-ordinary-secret-resolve', payload, expires=end,
            cancellation=envelope['operation']['cancellationRef'])

    async def account(self, original, proof):
        snapshot = await self._reader.current()
        end = await authorize_native_secret_proof(proof, self._reader, snapshot, original, now=datetime.now(timezone.utc))
        if proof.caller_ingress is not self._caller_ingress or datetime.now(timezone.utc) >= end:
            _refuse()
        envelope = strict_loads(original)
        scope = {**envelope['operation']['scope'], 'workspaceId': None}
        return await self._admit('identity-application-account-resolve', {
            'authorityId': self._reader._entity, 'accountRef': strict_loads(self._account_ref),
            'profileId': self._reader._profile, 'scope': scope, 'accountPublicKey': self._account_public},
            # Journal completion belongs to this enrolled service after the
            # native observer ends. This does not authorize secret use or a
            # public reply, which retain their unchanged original proof.
            account=True, expires=datetime.now(timezone.utc)+timedelta(seconds=30),
            cancellation=envelope['operation']['cancellationRef'])

    def phases(self, journal):
        return SecretPhaseSigner(journal, self._ingress,
            transport_ref=strict_loads(self._custody_transport), grants=strict_loads(self._phase_grants),
            signing_seed=self._custody_seed)


class OrdinarySecretResource:
    """One selected generation and fixed consumer, with per-original owners."""
    def __init__(self, admission, signer, *, custody_root, plugin_identity, instance_id, package_id):
        if (type(admission) is not SecretJournalAdmission or type(signer) is not SecretResolveSigner
                or signer._reader is not admission._reader or signer._enrollment != admission._enrollment
                or type(admission._reader) is not LedgerAuthorityReader):
            _refuse()
        self._admission, self._signer = admission, signer
        self._reader, self._enrollment = admission._reader, admission._enrollment
        record = strict_loads(self._enrollment.record)
        self.binding = OwnerBinding(self._reader._hub, 'ordinary-secrets', record['ref']['id'],
            'secret-generation', admission._policy.scope)
        self._record, self._custody_root = record, custody_root
        self._plugin_identity = canonical_bytes(plugin_identity)
        self._instance, self._package = instance_id, package_id
        self._owners, self._gate = {}, asyncio.Lock()
        self._closed = False

    def __repr__(self):
        return '<OrdinarySecretResource private>'

    def _current(self):
        if self._closed or self._admission._closed:
            _refuse()

    def check_request(self, snapshot, claims):
        self._current()
        rows = [row for row in strict_loads(snapshot.record)['state'].get('nativeInstances', [])
            if row['owner'] == claims['owner']]
        if (len(rows) != 1 or canonical_bytes(rows[0]['identityRef']) != self._plugin_identity
                or rows[0]['owner']['instanceId'] != self._instance
                or rows[0]['owner']['pin']['packageId'] != self._package
                or canonical_bytes(claims['scope']) != self.binding.scope
                or claims['resourceRef'] != self._record['generationRef']):
            _refuse()

    def _proof(self, service_raw):
        return NativeSecretProof(service_raw, self._plugin_identity, self._instance, self._package,
            self._signer._caller_ingress)

    async def authorize(self, authority, raw, service_raw):
        if authority is not self._reader:
            _refuse()
        snapshot = await authority.current()
        proof = self._proof(service_raw)
        await authorize_native_secret_proof(proof, self._reader, snapshot, raw, now=datetime.now(timezone.utc))
        self.check_request(snapshot, strict_loads(service_raw)['claims'])
        # The generic receiver also compares the exact admitted operation.
        return await authority.evaluate(raw, audience={'hubId': self.binding.hub_id,
            'serviceId': strict_loads(raw)['destinationServiceId']})

    async def call(self, raw, service_raw):
        self._current()
        proof = self._proof(service_raw)
        envelope = strict_loads(raw)
        query = envelope['contractId'] == 'capability-outcome-query'
        account = await self._signer.account(raw, proof)
        resolve = None if query else await self._signer.resolve(raw, proof)
        async with self._gate:
            self._current()
            if query:
                journal = await self._admission.reopen_query(raw, account_request=account, native_proof=proof)
            else:
                journal = await self._admission.open(resolve, account_request=account, native_proof=proof)
            identifier = journal._binding.entity_id
            owner = self._owners.get(identifier)
            if owner is None:
                custody = OrdinarySecretCustody(self._custody_root, self._reader)
                consumer = AtlassianAccountCheckConsumer(self._reader, self._enrollment)
                owner = OrdinarySecretOwner(journal, self._signer.phases(journal), custody, consumer)
                self._owners[identifier] = owner
            elif owner._journal is not journal or owner._closed:
                _refuse()
        result = (await owner.reconcile(raw, native_proof=proof) if query
            else await owner.use(resolve, native_proof=proof))
        self._current()
        validate('capability-outcome-query-reply' if query else 'capability-secret-use-reply', result)
        return result

    async def close(self):
        self._closed = True
        for owner in self._owners.values():
            await owner.close()
