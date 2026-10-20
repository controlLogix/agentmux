"""Admit one fresh fixture operation against the selected live identity ledger.

The installed test owner invokes this after native readiness. It reuses the
enrolled ingress implementation and keys; it creates no grant or native owner.
Only the admitted envelope is returned. This helper never dispatches a write.
"""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import sys
import uuid

import nkeys
from agentmux_contracts import ContractError, canonical_bytes, sign_claims, strict_loads
from hub.nats_transport import new_client
from identity.application_enrollment import _read_material
from identity.application_service_selection import ApplicationServiceSelection
from identity.authority import LedgerAuthorityReader
from identity.ingress import EnrolledIngress
from integration_owner.live_broker import close_client
from native_security.nats_credentials import validate as validate_credential
from state_owner.ledger import OwnerLedger, owner_subject
from installed_service_enrollment import digest, stamp, closed, PreparationFailure, hold_before_reporting, keep_owner


def pinned(pin, limit):
    closed(pin, ('path', 'sha256'))
    raw = _read_material(pin['path'], max_bytes=limit, return_bytes=True)
    if digest(raw) != pin['sha256']:
        raise ContractError('installed_storage_operation_material_changed')
    return raw


class OperationAdmission:
    def __init__(self, request):
        closed(request, ('contractMaterial', 'provider', 'contractId', 'operationId', 'expectedVersion', 'resourceRef', 'input'))
        material = strict_loads(pinned(request['contractMaterial'], 16384))
        closed(material, ('schemaVersion', 'serviceSelection', 'nativeSigners', 'nativeBroker',
                          'instanceId', 'packageId', 'projectScope', 'operationGrants', 'connection',
                          'interval', 'accountPublicKey', 'enrollment', 'resources', 'privateBindingDigest', 'services',
                          'nativePackage', 'configuration'))
        self.selection = ApplicationServiceSelection(pinned(material['serviceSelection'], 65536))
        selected = self.selection.policy['storage']
        provider, contract = request['provider'], request['contractId']
        if (material['schemaVersion'] != '1.0.0' or provider not in ('private', 'card')
                or contract not in ('capability-storage-read', 'capability-storage-write', 'capability-outcome-query')
                or material['projectScope'] != selected['scope']
                or material['instanceId'] != selected['privateStorage']['instanceId']
                or material['packageId'] != selected['privateStorage']['packageId']):
            raise ContractError('installed_storage_operation_invalid')
        reference = request['resourceRef']
        expected = (selected['privateStorage']['ledger']['entityId'] if provider == 'private'
                    else selected['board']['resourceRef']['id'])
        if (type(reference) is not dict or set(reference) != {'id', 'ownerHubId', 'revision'}
                or reference['id'] != expected or reference['ownerHubId'] != self.selection.policy['kernelScope']['hubId']):
            raise ContractError('installed_storage_operation_invalid')
        self.request, self.material = request, material
        self.client = None
        self.failures = []
        self.protocol_error = False

    async def broker_error(self, _error):
        self.protocol_error = True

    async def admit(self):
        selected, material = self.selection, self.material
        broker = material['nativeBroker']
        credential = broker['credentials']['host']
        raw = pinned({key: credential[key] for key in ('path', 'sha256')}, 65536)
        identity = selected.service('identity')
        admitted = validate_credential(raw, account_public_key=identity['credentials']['accountPublicKey'],
            publish_subjects=broker['publishSubjects'], subscribe_subjects=[broker['replyPrefix'] + '.>'], private_inbox=True)
        if admitted.public_key != credential['userPublicKey']:
            raise ContractError('installed_storage_operation_credential_changed')
        self.client = new_client(require_tls=True,
            leaf_certificate_sha256=identity['connection']['leafCertificateSHA256'])
        def signature(nonce):
            key = nkeys.from_seed(admitted.seed)
            try:
                return base64.b64encode(key.sign(nonce.encode()))
            finally:
                key.wipe()
        options = selected.tls_options('identity')
        options.update(user_jwt_cb=lambda: admitted.jwt.encode(), signature_cb=signature,
            inbox_prefix=broker['replyPrefix'], tls_handshake_first=True, allow_reconnect=False,
            max_reconnect_attempts=1, connect_timeout=3, error_cb=self.broker_error)
        await self.client.connect(**options)
        domain = identity['connection']['jetstreamDomain']
        js = self.client.jetstream(domain=domain) if domain else self.client.jetstream()
        binding = selected.binding('identity')
        ledger = OwnerLedger(js, stream=identity['ledger']['stream'], subject=owner_subject(binding),
            binding=binding, retention=selected.retention('identity'), stream_identity=selected.stream_identity('identity'))
        self.reader = LedgerAuthorityReader(ledger, hub_id=binding.hub_id, entity_id=binding.entity_id,
            profile_id=selected.policy['kernelScope']['profileId'], organization_id=selected.policy['organizationId'])
        self.ingress = EnrolledIngress(self.reader, issuer_ref=identity['issuer']['issuerRef'],
                                      signing_seed=selected.load_signing_seed('identity'))
        caller = material['nativeSigners']['storage_user']
        seed = pinned(caller['keyFile'], 32)
        now, request = datetime.now(timezone.utc), self.request
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': binding.hub_id,
            'profileId': selected.policy['kernelScope']['profileId'], 'authorityId': binding.entity_id,
            'transportRef': caller['transportRef'],
            'grantRef': material['operationGrants'][request['provider']][request['contractId']],
            'operationId': request['operationId'], 'expectedVersion': request['expectedVersion'],
            'contractId': request['contractId'], 'payload': {'resourceRef': request['resourceRef'], 'input': request['input']},
            'approvalRefs': [], 'issuedAt': stamp(now), 'expiresAt': stamp(now + timedelta(seconds=60))}
        admission = await self.ingress.admit(canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
            'signature': sign_claims(claims, seed)}), cancellation_ref={
                'id': 'storage_cancel_' + uuid.uuid4().hex, 'ownerHubId': binding.hub_id, 'revision': 1})
        if admission.decision.outcome != 'allowed' or admission.envelope is None or self.protocol_error:
            raise ContractError('installed_storage_operation_refused')
        return admission.envelope


async def main():
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ContractError('installed_storage_operation_invalid')
    owner = OperationAdmission(strict_loads(raw))
    try:
        envelope = await owner.admit()
    finally:
        if owner.client is not None:
            try:
                await close_client(owner.client)
            except BaseException as error:
                owner.failures.append(error)
                failure = PreparationFailure(owner, error)
                await hold_before_reporting(lambda: print('installed operation cleanup held', file=sys.stderr, flush=True),
                                            lambda: keep_owner(failure))
    if owner.protocol_error:
        raise ContractError('installed_storage_operation_broker_failure')
    sys.stdout.buffer.write(envelope + b'\n')
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except BaseException:
        print('installed storage operation refused', file=sys.stderr)
        raise SystemExit(1) from None
