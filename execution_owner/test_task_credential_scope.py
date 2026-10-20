"""Signed C owner boundaries and retained credential selection."""
import base64
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib

import nkeys
from nacl.signing import SigningKey

from agentmux_contracts import (
    ContractError, canonical_bytes, sign_claims, strict_loads, verify_envelope,
)
from identity.test_authority import ref, SEED
from . import test_task_credentials as support
from .task_credentials import TaskCredentialOwner


class TaskCredentialScopeTests(support.TaskCredentialTests):
    def original_snapshot(self):
        return {
            'messages': tuple(message.data for message in self.credential_js.messages),
            'privateDigest': hashlib.sha256(self.credentials._private(self.credential_record)).digest(),
            'execCount': self.engine.exec_fixed.await_count,
            'commands': tuple(self.commands), 'policy': self.credential_policy.pin(),
        }

    async def assert_original_untouched(self, original):
        # Do not include private bytes in assertion failure output.
        self.assertTrue(tuple(message.data for message in self.credential_js.messages) == original['messages'],
            'A refusal changed the retained original')
        state = self.credentials._history(await self.credential_ledger.current())
        self.assertEqual(state['phase'], 'prepared')
        self.assertTrue(state['record'] == self.credential_record, 'A refusal changed the credential generation')
        self.assertTrue(hashlib.sha256(self.credentials._private(self.credential_record)).digest() == original['privateDigest'],
            'A refusal changed private custody')
        self.assertEqual(self.engine.exec_fixed.await_count, original['execCount'])
        self.assertEqual(tuple(self.commands), original['commands'])
        self.assertEqual(self.credentials._policy.pin(), original['policy'])
        with self.credentials._store.access(self.credential_record['generationRef']) as directory:
            self.assertTrue(self.credentials._store.read(directory, 'delivery.json') is None,
                'A refusal retained an unexpected delivery claim')
            self.assertTrue(self.credentials._store.read(directory, 'acknowledged.json') is None,
                'A refusal retained an unexpected delivery acknowledgement')

    async def invoke_delivery(self, raw, owner=None):
        return await (owner or self.credentials).deliver(raw, self.admission,
            task_inspection=self.inspection(), account_request=self.account_request, intent=self.intent)

    def selected_owner(self, policy):
        owner = TaskCredentialOwner(self.service.reader, self.credential_ledger, self.account_custody,
            self.adapter, self.task_service, policy=policy, custody_root=self.custody_root,
            owner_identity_ref=ref('administrator'))
        self.addAsyncCleanup(owner.close)
        return owner

    async def test_signed_other_organization_and_project_refuse_before_delivery(self):
        await self.ready(physical=True)
        original = self.original_snapshot()
        payload = {'credentialRef': ref('credential'), 'runRef': self.run_ref}
        for field, value in (('organizationId', 'other-organization'), ('projectId', 'other-project')):
            with self.subTest(scope=field):
                scope = {**self.scope, field: value}
                # The existing fixture signs the changed operation inside the
                # ingress attestation. This is not damaged unsigned JSON.
                raw = self.request('task-credential-deliver', payload, expected=1, scope=scope)
                envelope = strict_loads(raw)
                claims = verify_envelope(envelope, bytes(SigningKey(SEED).verify_key),
                    {'hubId': 'hub-one', 'serviceId': 'process-owner'}, datetime.now(timezone.utc))
                self.assertEqual(claims['operation']['scope'], scope)
                with self.assertRaisesRegex(ContractError, '^task_credential_owner_required$'):
                    await self.invoke_delivery(raw)
                await self.assert_original_untouched(original)

    async def test_current_enrolled_different_service_actor_is_not_the_credential_owner(self):
        await self.ready(physical=True)
        original = self.original_snapshot()
        previous = copy.deepcopy(self.record['state'])
        try:
            grant = copy.deepcopy(next(item for item in self.record['state']['grants']
                if item['ref'] == ref('task-credential-deliver-grant')))
            grant.update(ref=ref('worker-credential-deliver-grant'), callerRef=ref('worker'), actorRef=ref('worker'))
            self.record['state']['grants'].append(grant)
            self.sync()
            record = self.credential_record
            claims = {
                'purpose': 'agentmux-client-possession-v1', 'profileId': record['profileId'],
                'hubId': record['runRef']['ownerHubId'], 'authorityId': record['authorityId'],
                'transportRef': record['transportRef'], 'grantRef': grant['ref'],
                'operationId': 'worker-cannot-own-credential-delivery', 'expectedVersion': 1,
                'contractId': 'task-credential-deliver',
                'payload': {'credentialRef': record['credentialRef'], 'runRef': record['runRef']},
                'approvalRefs': [], 'issuedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'expiresAt': datetime.fromtimestamp(record['expiresUnix'], timezone.utc).isoformat().replace('+00:00', 'Z'),
            }
            _, credential = self.credentials._decode(self.credentials._private(record), record)
            key = nkeys.from_seed(credential.seed)
            try:
                proof = base64.urlsafe_b64encode(key.sign(canonical_bytes(claims))).decode().rstrip('=')
            finally:
                key.wipe()
            request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims, 'signature': proof})
            admitted = await self.service.ingress.admit(request, cancellation_ref=ref('worker-delivery-cancel'))
            self.assertEqual(admitted.decision.outcome, 'allowed')
            operation = strict_loads(admitted.envelope)['operation']
            self.assertEqual(operation['caller']['kind'], 'service')
            self.assertEqual(operation['caller']['authenticatedIdentityRef'], ref('worker'))
            with self.assertRaisesRegex(ContractError, '^task_credential_owner_required$'):
                await self.invoke_delivery(admitted.envelope)
            await self.assert_original_untouched(original)
        finally:
            self.record['state'] = previous
            self.sync()

    async def test_selected_consumer_issuer_and_changed_tls_policy_cannot_replace_original(self):
        await self.ready(physical=True)
        original = self.original_snapshot()
        policy = self.credential_policy
        for name, changes in (
                ('consumer', {'consumer_ref': canonical_bytes(ref('other-consumer'))}),
                ('identity issuer generation', {'identity_issuer_ref': canonical_bytes({**ref('issuer'), 'revision': 2})})):
            with self.subTest(selection=name), self.assertRaisesRegex(ContractError, '^task_credential_configuration$'):
                self.selected_owner(replace(policy, **changes))
            await self.assert_original_untouched(original)
        for name, changes in (
                ('endpoint', {'endpoint': 'tls://127.0.0.1:4223'}),
                ('TLS name', {'server_name': 'other.agentmux.invalid'}),
                ('TLS pin', {'leaf_certificate_sha256': 'sha256:'+'b'*64}),
                ('TLS roots', {'trust_pem': self.pem+b'\n'})):
            with self.subTest(selection=name):
                owner = self.selected_owner(replace(policy, **changes))
                try:
                    with self.assertRaisesRegex(ContractError, '^task_credential_history_invalid$'):
                        await self.invoke_delivery(self.phase('deliver'), owner)
                finally:
                    await owner.close()
                await self.assert_original_untouched(original)

    async def test_changed_retained_destination_refuses_before_private_delivery(self):
        await self.ready(physical=True)
        original = self.original_snapshot()
        message = self.credential_js.messages[0]
        retained = message.data
        try:
            changed = strict_loads(retained)
            changed['state']['record']['destinationRef'] = ref('other-consumer')
            message.data = canonical_bytes(changed)
            with self.assertRaisesRegex(ContractError, '^task_credential_history_invalid$'):
                await self.invoke_delivery(self.phase('deliver'))
        finally:
            message.data = retained
        await self.assert_original_untouched(original)

    async def test_current_account_issuer_rotation_does_not_switch_original_generation(self):
        await self.ready(physical=True)
        original = self.original_snapshot()
        previous = copy.deepcopy(self.record['state'])
        try:
            old_issuer = self.credential_record['accountIssuerRef']
            new_issuer = {**old_issuer, 'revision': old_issuer['revision']+1}
            issuer = next(item for item in self.record['state']['secretReferences'] if item['ref'] == old_issuer)
            issuer['ref'] = new_issuer
            account = next(item for item in self.record['state']['applicationAccounts']
                if item['ref'] == self.credential_record['accountRef'])
            account['accountIssuerRef'] = new_issuer
            self.sync()
            # Account authority itself resolves the new valid selection. C must
            # still refuse switching the issuer retained by the original run.
            current = await self.credentials._account.resolve(self.account_request)
            self.assertEqual(current.account_issuer_ref, new_issuer)
            with self.assertRaisesRegex(ContractError, '^task_credential_refused$'):
                await self.invoke_delivery(self.phase('deliver'))
            await self.assert_original_untouched(original)
        finally:
            self.record['state'] = previous
            self.sync()


for _name in dir(support.TaskCredentialTests):
    if _name.startswith('test_') and _name not in vars(TaskCredentialScopeTests):
        setattr(TaskCredentialScopeTests, _name, None)
