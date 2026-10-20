"""Concrete OwnerLedger integration with a controlled offline JetStream boundary."""
import asyncio
import copy
from datetime import datetime, timedelta
from types import SimpleNamespace
import unittest
import tempfile
from pathlib import Path
from state_owner.history import OwnerHistory
from unittest.mock import patch, AsyncMock

from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads, ContractError, validate
from identity.service import IdentityService, verify_receipt
from identity.legacy_identity import LegacyIdentityAdapter
from identity.ingress import verify_possession
from identity.test_commands import command_fixture
from identity.test_authority import ref, SEED, NOW
from identity.test_transitions import ACCOUNT
from identity.transitions import transition
from state_owner.ledger import StreamIdentity
from state_owner.retention import Retention
from state_owner.test_ledger import FakeJetStream, CREATED


class _ClockMeta(type):
    def __instancecheck__(cls, value):
        return isinstance(value, datetime)


class _Clock(datetime, metaclass=_ClockMeta):
    @classmethod
    def now(cls, tz=None):
        return NOW


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.record, env = command_fixture()
        self.record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        self.record['operation']['scope'] = copy.deepcopy(env['operation']['scope'])
        self.record['operation']['expectedVersion'] = 0
        self.policy = Retention(2_097_152, 262_144)
        self.js = FakeJetStream(self.policy)
        connection = SimpleNamespace(jetstream=lambda: self.js)
        self.service = IdentityService(connection, stream='OWNER',
            stream_identity=StreamIdentity(CREATED, 1), retention=self.policy,
            hub_id='hub-one', entity_id='authority-one', profile_id='profile-one',
            organization_id='org-one', issuer_ref=ref('issuer'), signing_seed=SEED)
        subject = self.service.ledger._subject
        self.js.config = self.policy.stream_config(stream='OWNER', subject=subject)
        self.js.messages = [SimpleNamespace(subject=subject, seq=1, data=canonical_bytes(self.record))]
        self.claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('grant'),
            'operationId': 'revoke-operation', 'expectedVersion': 1,
            'contractId': 'identity-revoke', 'payload': env['payload'], 'approvalRefs': [],
            'issuedAt': '2026-10-09T12:00:01Z', 'expiresAt': '2026-10-09T12:00:30Z'}
        for module in ('identity.ingress', 'identity.commands', 'identity.service', 'state_owner.ledger'):
            patch(module + '.datetime', _Clock).start()
        self.addCleanup(patch.stopall)

    def install_history(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name).resolve()
        history = OwnerHistory(path / 'history.sqlite', self.service._binding,
                               stream_identity=self.service._stream_identity)
        self.service._history = history
        self.service.ledger._history = history
        self.service._checkpoint_path = path / 'checkpoint.json'
        self.checkpoint_receipts = []
        async def committed(receipt):
            self.checkpoint_receipts.append(receipt)
        self.service._checkpoint_committed = committed
        from state_owner.backup_host import BackupHost
        from state_owner.backup_lifecycle import OwnerBackupLifecycle
        directories = [path / name for name in ('backup', 'inventory', 'keys')]
        for directory in directories:
            directory.mkdir(mode=0o700)
        self.backup_host = BackupHost(*directories, destination_id='identity-backup',
            binding=self.service._binding, stream_identity=self.service._stream_identity)
        self.backup_host.enroll_key('backup-one')
        self.service._backup = OwnerBackupLifecycle(history, self.service._binding,
            self.service._stream_identity, self.backup_host, key_id='backup-one',
            retrieve_artifact=self.service._unexpected_artifact)
        self.service._connection.subscribe = AsyncMock(return_value=SimpleNamespace(drain=AsyncMock()))
        self.service._connection.flush = AsyncMock()
        self.addAsyncCleanup(self.service.close)

    async def test_indexed_history_recovers_before_command_and_closes(self):
        self.install_history()
        await self.service.start()
        await self.service.handle(self.request())
        self.assertEqual(self.service._history.verified_cursor, 2)
        self.service._cadence._dirty_since = 0
        self.service._checkpoint_if_due()
        await self.service._checkpoint_work
        self.assertTrue(Path(self.checkpoint_receipts[-1].manifest_path).exists())
        await self.service.close()
        self.assertTrue(self.service._history._closed)

    async def test_checkpoint_writer_yields_and_close_joins_before_cache_close(self):
        import threading
        from state_owner.checkpoints import export_checkpoint
        self.install_history()
        await self.service.start()
        await self.service.handle(self.request())
        entered, release = threading.Event(), threading.Event()
        def writer(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test_writer_timeout')
            return export_checkpoint(*args, **kwargs)
        with patch('state_owner.checkpoints.export_checkpoint', writer):
            self.service._cadence._dirty_since = 0
            self.service._checkpoint_if_due()
            try:
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(.001)
                self.assertTrue(entered.is_set())
                closing = asyncio.create_task(self.service.close())
                await asyncio.sleep(.01)
                self.assertFalse(closing.done())
                self.assertFalse(self.service._history._closed)
            finally:
                release.set()
            await closing
        self.assertTrue(self.service._history._closed)

    async def test_close_stops_paged_startup_before_subscription(self):
        self.install_history()
        entered = asyncio.Event()
        async def page():
            entered.set()
            await asyncio.sleep(0)
            return SimpleNamespace(ready=False)
        self.service.ledger.prepare_history = page
        self.service._connection.subscribe = AsyncMock()
        startup = asyncio.create_task(self.service.start())
        await entered.wait()
        await asyncio.wait_for(self.service.close(), 1)
        with self.assertRaisesRegex(ContractError, 'identity_service_closed'):
            await startup
        self.service._connection.subscribe.assert_not_awaited()
        self.assertTrue(self.service._history._closed)

    async def test_failed_subscription_releases_cache_on_repeated_close(self):
        self.install_history()
        self.service._connection.subscribe = AsyncMock(side_effect=RuntimeError('subscribe_failed'))
        with self.assertRaisesRegex(RuntimeError, 'subscribe_failed'):
            await self.service.start()
        await self.service.close()
        await self.service.close()
        self.assertTrue(self.service._history._closed)

    async def test_backup_recovery_inventory_health_and_close_are_owned(self):
        self.install_history()
        self.service._connection.subscribe = AsyncMock(return_value=SimpleNamespace(drain=AsyncMock()))
        self.service._connection.flush = AsyncMock()
        await self.service.start()
        inventory = self.backup_host.latest()
        self.assertIsNotNone(inventory)
        self.assertEqual(inventory.receipt.cursor, 1)
        self.service.check_health()
        original_count = len(self.js.messages)
        with patch.object(self.service._backup, 'check', side_effect=ContractError('backup_inventory_unavailable')):
            with self.assertRaisesRegex(ContractError, 'backup_inventory_unavailable'):
                self.service.check_health()
            with self.assertRaisesRegex(ContractError, 'backup_inventory_unavailable'):
                await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), original_count)
        await self.service.close()
        self.assertTrue(self.service._backup._closed)
        self.assertTrue(self.service._backup._closing.done())
        self.assertTrue(self.service._history._closed)

    async def test_trusted_backup_floor_refuses_lower_recovered_history(self):
        self.install_history()
        self.service._connection.subscribe = AsyncMock()
        inventory = SimpleNamespace(source_identity=StreamIdentity(CREATED, 2),
                                    receipt=SimpleNamespace(cursor=2))
        with patch.object(self.backup_host, 'latest', return_value=inventory):
            with self.assertRaisesRegex(ContractError, 'owner_recovery_required'):
                await self.service.start()
        self.service._connection.subscribe.assert_not_awaited()
        self.assertEqual(len(self.js.messages), 1)
        with self.assertRaisesRegex(ContractError, 'identity_service_closed'):
            self.service.check_health()
        await self.service.close()
        self.assertTrue(self.service._history._closed)

    def request(self):
        return canonical_bytes({'schemaVersion': '1.0.0', 'claims': self.claims,
                                'signature': sign_claims(self.claims, bytes(reversed(SEED)))})

    async def test_actual_ledger_commits_revocation_and_signed_receipt(self):
        request = self.request()
        response = await self.service.handle(request)
        receipt = verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['sequence']), ('allowed', 2))
        committed = strict_loads(self.js.messages[-1].data)
        self.assertEqual(committed['state']['transports'][0]['status'], 'revoked')
        self.assertEqual(committed['authorizationDecision']['actorRef'], ref('human'))
        with self.assertRaisesRegex(ContractError, 'credential_unavailable'):
            await self.service.handle(request)
        changed = copy.deepcopy(self.claims); changed['operationId'] = 'other-operation'
        wrong = canonical_bytes({'schemaVersion': '1.0.0', 'claims': changed,
            'signature': sign_claims(changed, bytes(reversed(SEED)))})
        with self.assertRaisesRegex(ContractError, 'identity_receipt_binding'):
            verify_receipt(response, wrong,
                public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))

    async def test_application_account_resolution_is_signed_current_and_read_only(self):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        state = self.record['state']
        interval = {'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
                    'expiresAt': '2026-10-09T12:10:00Z'}
        admin = {'ref': ref('account-admin'), 'principalId': 'application-account-admin',
                 'kind': 'service', 'status': 'active', 'externalIdentity': None}
        state['identities'].append(admin)
        transport = copy.deepcopy(state['transports'][0])
        transport.update(ref=ref('account-admin-transport'), identityRef=admin['ref'])
        state['transports'].append(transport)
        state['memberships'].append({'ref': ref('account-admin-member'),
            'identityRef': admin['ref'], 'scope': scope, 'status': 'active'})
        credential = {'ref': ref('account-admin-credential'),
            'kind': 'nats-administrator-credential', 'scope': scope,
            'profileId': 'profile-one', 'ownerIdentityRef': admin['ref'], **interval}
        issuer = {'ref': ref('account-issuer-secret'), 'kind': 'nats-account-issuer',
            'scope': scope, 'profileId': 'profile-one', 'ownerIdentityRef': admin['ref'], **interval}
        account = {'ref': ref('application-account'), 'profileId': 'profile-one',
            'scope': scope, 'accountPublicKey': ACCOUNT,
            'administratorIdentityRef': admin['ref'],
            'administratorTransportRef': transport['ref'],
            'administratorCredentialRef': credential['ref'], 'accountIssuerRef': issuer['ref'], **interval}
        state = transition(state, 'identity-application-account-set', {
            'authorityId': 'authority-one', 'record': account, 'previousRef': None,
            'administratorCredential': {'record': credential, 'previousRef': None},
            'accountIssuer': {'record': issuer, 'previousRef': None}}, hub_id='hub-one')
        state['memberships'][0]['scope'] = scope
        state['grants'][0].update(scope=scope, contractId='identity-application-account-resolve',
                                         resourceId='application-account')
        self.record['state'] = state
        self.js.messages[0].data = canonical_bytes(self.record)
        self.claims.update(contractId='identity-application-account-resolve',
            operationId='resolve-account-one', expectedVersion=0,
            payload={'authorityId': 'authority-one', 'accountRef': account['ref'],
                     'profileId': 'profile-one', 'scope': scope, 'accountPublicKey': ACCOUNT})
        request = self.request()
        response = strict_loads(await self.service.handle(request))
        validate('identity-application-account-resolution', response)
        verify_possession(response['claims'], response['signature'],
            self.record['state']['issuers'][0]['publicKey'])
        claims = response['claims']
        self.assertEqual(claims['requestDigest'], payload_digest(strict_loads(request)))
        self.assertEqual(claims['administratorCredentialRef'], ref('account-admin-credential'))
        self.assertEqual(claims['accountIssuerRef'], ref('account-issuer-secret'))
        self.assertEqual((claims['accountPublicKey'], claims['authoritySequence']), (ACCOUNT, 1))
        self.assertEqual(len(self.js.messages), 1)
        self.record['state']['grants'][0]['decision'] = 'denied'
        self.js.messages[0].data = canonical_bytes(self.record)
        self.claims['operationId'] = 'resolve-account-denied'
        with self.assertRaisesRegex(ContractError, 'application_account_not_authorized'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)

    async def test_legacy_alias_resolution_is_scoped_signed_and_read_only(self):
        await self._check_legacy_alias_resolution('alpha', 'worker', 'w1')

    async def test_legacy_alias_resolution_preserves_numeric_and_underscore_names(self):
        await self._check_legacy_alias_resolution('123', '_worker', '1')

    async def test_remote_legacy_alias_resolution_is_signed_scoped_and_read_only(self):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        state = self.record['state']
        state['memberships'][0]['scope'] = copy.deepcopy(scope)
        state['grants'][0].update(scope=copy.deepcopy(scope),
            contractId='identity-legacy-alias-resolve', resourceId='authority-one')
        state['legacyAliases'] = [{
            'ref': ref('legacy-remote'), 'status': 'active', 'identityRef': ref('human'),
            'sourceHubId': 'remote-hub', 'scope': copy.deepcopy(scope), 'instanceOwner': None,
            'registrationGeneration': 7, 'canonicalSession': 'repo_2-worker_3-agent_4',
            'alias': 'old-remote'}]
        self.js.messages[0].data = canonical_bytes(self.record)
        self.service.configure_legacy_identity(LegacyIdentityAdapter(self.service.reader,
            local_source_hub_id='hub-one', scope=scope))
        self.claims.update(contractId='identity-legacy-alias-resolve',
            operationId='resolve-remote-one', expectedVersion=0,
            payload={'authorityId': 'authority-one',
                     'remoteAddress': 'agent:repo_2-worker_3-agent_4'})
        request = self.request()
        response = strict_loads(await self.service.handle(request))
        validate('identity-legacy-alias-resolution', response)
        verify_possession(response['claims'], response['signature'],
            self.record['state']['issuers'][0]['publicKey'])
        claims = response['claims']
        self.assertEqual(claims['requestDigest'], payload_digest(strict_loads(request)))
        self.assertEqual(claims['remoteAddress'], 'agent:repo_2-worker_3-agent_4')
        self.assertNotIn('registrations', claims)
        self.assertEqual(claims['bindings'], [{
            'alias': 'old-remote', 'canonicalSession': 'repo_2-worker_3-agent_4',
            'sourceHubId': 'remote-hub', 'registrationGeneration': 7,
            'identityRef': ref('human'), 'scope': scope, 'instanceOwner': None,
            'aliasRef': ref('legacy-remote'), 'authoritySequence': 1}])
        self.assertEqual(len(self.js.messages), 1)

    async def test_remote_legacy_alias_resolution_rejects_ambiguous_or_cross_scope_mapping(self):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        other = {'organizationId': 'org-one', 'projectId': 'project-two', 'workspaceId': None}
        state = self.record['state']
        state['memberships'][0]['scope'] = copy.deepcopy(scope)
        state['grants'][0].update(scope=copy.deepcopy(scope),
            contractId='identity-legacy-alias-resolve', resourceId='authority-one')
        row = {'ref': ref('legacy-remote'), 'status': 'active', 'identityRef': ref('human'),
            'sourceHubId': 'remote-hub', 'scope': copy.deepcopy(scope), 'instanceOwner': None,
            'registrationGeneration': 7, 'canonicalSession': 'alpha-worker-w1',
            'alias': 'old-remote'}
        state['legacyAliases'] = [row, {**copy.deepcopy(row),
            'ref': ref('legacy-other'), 'sourceHubId': 'other-hub'}]
        self.js.messages[0].data = canonical_bytes(self.record)
        self.service.configure_legacy_identity(LegacyIdentityAdapter(self.service.reader,
            local_source_hub_id='hub-one', scope=scope))
        self.claims.update(contractId='identity-legacy-alias-resolve',
            operationId='resolve-remote-ambiguous', expectedVersion=0,
            payload={'authorityId': 'authority-one', 'remoteAddress': 'agent:alpha-worker-w1'})
        with self.assertRaisesRegex(ContractError, 'legacy_identity_ambiguous'):
            await self.service.handle(self.request())
        state['legacyAliases'] = [{**row, 'scope': other}]
        self.js.messages[0].data = canonical_bytes(self.record)
        self.claims['operationId'] = 'resolve-remote-cross-scope'
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)

    async def _check_legacy_alias_resolution(self, repository, role, agent):
        session = '-'.join((repository, role, agent))
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        state = self.record['state']
        state['memberships'][0]['scope'] = copy.deepcopy(scope)
        state['grants'][0].update(scope=copy.deepcopy(scope),
            contractId='identity-legacy-alias-resolve', resourceId='authority-one')
        state['legacyAliases'] = [{
            'ref': ref('legacy-one'), 'status': 'active', 'identityRef': ref('human'),
            'sourceHubId': 'hub-one', 'scope': copy.deepcopy(scope), 'instanceOwner': None,
            'registrationGeneration': 3, 'canonicalSession': session, 'alias': 'old-w1'}]
        self.js.messages[0].data = canonical_bytes(self.record)
        self.service.configure_legacy_identity(LegacyIdentityAdapter(self.service.reader,
            local_source_hub_id='hub-one', scope=scope))
        registration = {'requestedAddress': 'agent:' + session,
            'canonicalSession': session, 'registrationGeneration': 3,
            'repository': repository, 'role': role, 'agent': agent,
            'state': 'ready', 'legacyAlias': None}
        self.claims.update(contractId='identity-legacy-alias-resolve',
            operationId='resolve-legacy-one', expectedVersion=0,
            payload={'authorityId': 'authority-one', 'registrations': [registration]})
        request = self.request()
        response = strict_loads(await self.service.handle(request))
        validate('identity-legacy-alias-resolution', response)
        verify_possession(response['claims'], response['signature'],
            self.record['state']['issuers'][0]['publicKey'])
        claims = response['claims']
        self.assertEqual(claims['requestDigest'], payload_digest(strict_loads(request)))
        self.assertEqual((claims['scope'], claims['registrations']), (scope, [registration]))
        self.assertEqual(claims['callerRef'], ref('human'))
        self.assertEqual(claims['authoritySequence'], 1)
        self.assertEqual(claims['bindings'], [{
            'alias': 'old-w1', 'canonicalSession': session,
            'sourceHubId': 'hub-one', 'registrationGeneration': 3,
            'identityRef': ref('human'), 'scope': scope, 'instanceOwner': None,
            'aliasRef': ref('legacy-one'), 'authoritySequence': 1}])
        self.assertEqual(len(self.js.messages), 1)

        changed = copy.deepcopy(self.claims)
        changed['operationId'] = 'resolve-wrong-generation'
        changed['payload']['registrations'][0]['registrationGeneration'] = 4
        wrong = canonical_bytes({'schemaVersion': '1.0.0', 'claims': changed,
            'signature': sign_claims(changed, bytes(reversed(SEED)))})
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await self.service.handle(wrong)
        self.assertEqual(len(self.js.messages), 1)

    async def test_legacy_alias_resolution_requires_selected_project_grant(self):
        scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
        state = self.record['state']
        state['legacyAliases'] = [{
            'ref': ref('legacy-one'), 'status': 'active', 'identityRef': ref('human'),
            'sourceHubId': 'hub-one', 'scope': copy.deepcopy(scope), 'instanceOwner': None,
            'registrationGeneration': 1, 'canonicalSession': 'alpha-worker-w1', 'alias': 'old-w1'}]
        self.js.messages[0].data = canonical_bytes(self.record)
        self.service.configure_legacy_identity(LegacyIdentityAdapter(self.service.reader,
            local_source_hub_id='hub-one', scope=scope))
        self.claims.update(contractId='identity-legacy-alias-resolve',
            operationId='resolve-unscoped', expectedVersion=0,
            payload={'authorityId': 'authority-one', 'registrations': [{
                'requestedAddress': 'old-w1', 'canonicalSession': 'alpha-worker-w1',
                'registrationGeneration': 1, 'repository': 'alpha', 'role': 'worker',
                'agent': 'w1', 'state': 'ready', 'legacyAlias': 'old-w1'}]})
        with self.assertRaisesRegex(ContractError, 'legacy_identity_not_authorized'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)

    async def test_denied_ingress_is_durably_audited_without_mutation(self):
        self.record['state']['grants'][0]['decision'] = 'denied'
        self.js.messages[0].data = canonical_bytes(self.record)
        await self.service.handle(self.request())
        committed = strict_loads(self.js.messages[-1].data)
        self.assertEqual(committed['state'], self.record['state'])
        self.assertEqual(committed['authorizationDecision']['decision'], 'denied')
        self.assertEqual(committed['outcome'], 'rejected')

    async def test_recreated_stream_is_not_authority(self):
        self.js.created = NOW
        with self.assertRaisesRegex(ContractError, 'owner_recovery_required'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 1)

    async def test_lost_ack_is_unconfirmed_and_original_outcome_is_retained(self):
        self.js.lose_ack = True
        with self.assertRaisesRegex(ContractError, 'owner_commit_uncertain'):
            await self.service.handle(self.request())
        self.assertEqual(len(self.js.messages), 2)
        outcome = await self.service.ledger.outcome('revoke-operation',
            strict_loads(self.js.messages[-1].data)['operation']['payloadDigest'])
        self.assertTrue(outcome.replayed)

    async def test_authority_expiry_during_shared_ledger_read_prevents_publish(self):
        self.install_history()
        # The request remains fresh, but its selected grant expires while the
        # actual shared append awaits history/configuration. No fake append result
        # can satisfy this check: run the real OwnerLedger.append to its boundary.
        deadline = NOW + timedelta(seconds=2)
        self.record['state']['grants'][0]['expiresAt'] = deadline.isoformat().replace('+00:00', 'Z')
        self.js.messages[0].data = canonical_bytes(self.record)
        await self.service.start()

        class AdvancingClock(_Clock):
            current = NOW

            @classmethod
            def now(cls, tz=None):
                return cls.current

        for module in ('identity.ingress', 'identity.commands', 'state_owner.ledger'):
            patch(module + '.datetime', AdvancingClock).start()
        original_append = self.service.ledger.append
        original_info = self.js.stream_info
        append_started = False
        reads_after_proposal = 0

        async def append(*args, **kwargs):
            nonlocal append_started
            append_started = True
            self.assertEqual(kwargs['valid_until'], deadline)
            return await original_append(*args, **kwargs)

        async def stream_info(*args, **kwargs):
            nonlocal reads_after_proposal
            result = await original_info(*args, **kwargs)
            if append_started:
                reads_after_proposal += 1
                AdvancingClock.current = deadline + timedelta(seconds=1)
            return result

        self.service.ledger.append = append
        self.js.stream_info = stream_info
        self.js.publish = AsyncMock(wraps=self.js.publish)
        with self.assertRaisesRegex(ContractError, '^owner_authorization_expired$'):
            await self.service.handle(self.request())
        self.assertTrue(append_started)
        self.assertGreater(reads_after_proposal, 0)
        self.js.publish.assert_not_awaited()
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(strict_loads(self.js.messages[0].data), self.record)

    async def test_failed_request_reply_never_claims_rejection(self):
        self.service._connection.publish = AsyncMock()
        inbox = '_INBOX.' + 'a' * 24
        self.claims['replySubject'] = inbox
        request = strict_loads(self.request())
        request['signature'] = sign_claims(self.claims, SEED)
        await self.service._receive(SimpleNamespace(reply=inbox, data=canonical_bytes(request)))
        payload = self.service._connection.publish.await_args.args[1]
        self.assertEqual(strict_loads(payload)['error'], 'identity_outcome_unconfirmed')

    async def test_forbidden_ledger_reply_cannot_publish_or_change_history(self):
        self.service._connection.publish = AsyncMock()
        self.claims['replySubject'] = self.service.ledger._subject
        await self.service._receive(SimpleNamespace(reply=self.service.ledger._subject, data=self.request()))
        self.service._connection.publish.assert_not_awaited()
        self.assertEqual(len(self.js.messages), 1)

    async def test_substituted_reply_cannot_receive_signed_result(self):
        self.service._connection.publish = AsyncMock()
        self.claims['replySubject'] = '_INBOX.' + 'a' * 24
        await self.service._receive(SimpleNamespace(reply='_INBOX.' + 'b' * 24, data=self.request()))
        self.service._connection.publish.assert_not_awaited()
        self.assertEqual(len(self.js.messages), 1)

    async def test_malformed_or_unbound_requests_receive_no_reply(self):
        self.service._connection.publish = AsyncMock()
        inbox = '_INBOX.' + 'a' * 24
        for data in (b'not json', b'[]', b'{}', self.request()):
            with self.subTest(data=data[:20]):
                await self.service._receive(SimpleNamespace(reply=inbox, data=data))
        self.service._connection.publish.assert_not_awaited()
        self.assertEqual(len(self.js.messages), 1)

    async def test_signed_bound_inbox_receives_verified_committed_receipt(self):
        self.service._connection.publish = AsyncMock()
        inbox = '_INBOX.' + 'a' * 24 + '.request'
        self.claims['replySubject'] = inbox
        request = self.request()
        await self.service._receive(SimpleNamespace(reply=inbox, data=request))
        self.service._connection.publish.assert_awaited_once()
        destination, response = self.service._connection.publish.await_args.args
        self.assertEqual(destination, inbox)
        result = verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((result['decision'], result['sequence']), ('allowed', 2))

    async def test_close_during_start_joins_original_subscription(self):
        self.install_history()
        entered, release = asyncio.Event(), asyncio.Event()
        subscription = SimpleNamespace(drain=AsyncMock())

        async def subscribe(*args, **kwargs):
            entered.set()
            await release.wait()
            return subscription

        self.service._connection.subscribe = AsyncMock(side_effect=subscribe)
        self.service._connection.flush = AsyncMock()
        starting = asyncio.create_task(self.service.start())
        await entered.wait()
        closing = asyncio.create_task(self.service.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        release.set()
        await asyncio.gather(starting, closing)
        self.service._connection.subscribe.assert_awaited_once()
        subscription.drain.assert_awaited_once()
        self.assertIsNone(self.service._subscription)
        self.assertTrue(self.service._closed)

    async def test_concurrent_starts_keep_one_subscription(self):
        self.install_history()
        entered, release = asyncio.Event(), asyncio.Event()
        subscription = SimpleNamespace(drain=AsyncMock())

        async def subscribe(*args, **kwargs):
            entered.set()
            await release.wait()
            return subscription

        self.service._connection.subscribe = AsyncMock(side_effect=subscribe)
        self.service._connection.flush = AsyncMock()
        first = asyncio.create_task(self.service.start())
        await entered.wait()
        second = asyncio.create_task(self.service.start())
        release.set()
        await first
        with self.assertRaisesRegex(ContractError, 'identity_service_lifecycle'):
            await second
        self.service._connection.subscribe.assert_awaited_once()
        await self.service.close()
        subscription.drain.assert_awaited_once()

    async def test_canceled_close_retains_and_rejoins_original_drain(self):
        self.install_history()
        entered, release = asyncio.Event(), asyncio.Event()

        async def drain():
            entered.set()
            await release.wait()

        subscription = SimpleNamespace(drain=AsyncMock(side_effect=drain))
        self.service._connection.subscribe = AsyncMock(return_value=subscription)
        self.service._connection.flush = AsyncMock()
        await self.service.start()
        closing = asyncio.create_task(self.service.close())
        await entered.wait()
        original_drain = self.service._drain_task
        closing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await closing
        self.assertFalse(original_drain.cancelled())
        self.assertFalse(original_drain.done())
        retry = asyncio.create_task(self.service.close())
        release.set()
        await retry
        self.assertIs(self.service._drain_task, original_drain)
        self.assertTrue(original_drain.done())
        subscription.drain.assert_awaited_once()
        self.assertIsNone(self.service._subscription)

    async def test_close_joins_handle_not_long_lived_caller(self):
        entered, release = asyncio.Event(), asyncio.Event()
        handled, finish_caller = asyncio.Event(), asyncio.Event()
        original_handle = self.service._handle

        async def handle(request):
            entered.set()
            await release.wait()
            return await original_handle(request)

        self.service._handle = handle

        async def caller():
            try:
                await self.service.handle(self.request())
            except ContractError as error:
                # close prevents new work while this call waits at the boundary.
                self.assertEqual(error.code, 'identity_service_closed')
            handled.set()
            await finish_caller.wait()

        worker = asyncio.create_task(caller())
        await entered.wait()
        closing = asyncio.create_task(self.service.close())
        await asyncio.sleep(0)
        release.set()
        await handled.wait()
        try:
            await asyncio.wait_for(asyncio.shield(closing), 1)
            self.assertFalse(worker.done())
            self.assertEqual(self.service._active, set())
        finally:
            finish_caller.set()
            await asyncio.gather(worker, closing, return_exceptions=True)

    async def test_invalid_new_grant_is_audited_without_poisoning_authority(self):
        self.record['state']['grants'][0]['contractId'] = 'identity-grant-set'
        self.js.messages[0].data = canonical_bytes(self.record)
        new_grant = copy.deepcopy(self.record['state']['grants'][0])
        new_grant.update(ref=ref('new-grant'), contractId='task-inspect', resourceId='task-one')
        new_grant['expiresAt'] = '2026-99-09T12:10:00Z'
        self.claims.update(contractId='identity-grant-set', operationId='invalid-grant-operation',
            payload={'authorityId': 'authority-one', 'record': new_grant, 'previousRef': None})
        request = self.request()
        response = await self.service.handle(request)
        receipt = verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['reason'], receipt['entityVersion']),
                         ('denied', 'authority_time_invalid', 2))
        denied = strict_loads(self.js.messages[-1].data)
        self.assertEqual(denied['state'], self.record['state'])
        self.assertEqual(denied['outcome'], 'rejected')
        self.assertEqual(len(self.js.messages), 2)

        new_grant['expiresAt'] = '2026-10-09T12:10:00Z'
        self.claims.update(operationId='corrected-grant-operation', expectedVersion=2)
        corrected_request = self.request()
        response = await self.service.handle(corrected_request)
        corrected = verify_receipt(response, corrected_request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((corrected['decision'], corrected['sequence'], corrected['entityVersion']),
                         ('allowed', 3, 3))
        after = strict_loads(self.js.messages[-1].data)
        self.assertEqual(after['state']['grants'][-1], new_grant)
        self.assertEqual(after['state']['grants'][:-1], self.record['state']['grants'])
        self.assertEqual(len(self.js.messages), 3)

    async def test_canceled_start_retains_pending_subscription_for_close(self):
        self.install_history()
        registered, release = asyncio.Event(), asyncio.Event()
        subscription = SimpleNamespace(drain=AsyncMock())
        allocated = []

        async def subscribe(*args, **kwargs):
            # Match NATS: the resource exists before its final awaited send ends.
            allocated.append(subscription)
            registered.set()
            await release.wait()
            return subscription

        self.service._connection.subscribe = AsyncMock(side_effect=subscribe)
        self.service._connection.flush = AsyncMock()
        starting = asyncio.create_task(self.service.start())
        await registered.wait()
        original_subscribe = self.service._subscribe_task
        starting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await starting
        self.assertFalse(original_subscribe.cancelled())
        self.assertFalse(original_subscribe.done())
        closing = asyncio.create_task(self.service.close())
        await asyncio.sleep(0)
        self.assertFalse(closing.done())
        release.set()
        await closing
        self.assertIs(self.service._subscribe_task, original_subscribe)
        self.assertEqual(allocated, [subscription])
        self.service._connection.subscribe.assert_awaited_once()
        subscription.drain.assert_awaited_once()
        self.assertIsNone(self.service._subscription)

    async def test_near_capacity_enrollment_preserves_revocation_and_denial_audit(self):
        from identity.capacity import require_state_capacity, MAX_STATE_BYTES
        self.record['state']['grants'].append(copy.deepcopy(self.record['state']['grants'][0]))
        self.record['state']['grants'][-1].update(ref=ref('enroll-grant'), contractId='identity-enroll')
        enrolled = {'ref': ref('last-human'), 'principalId': 'last-user', 'kind': 'human',
                    'status': 'active', 'externalIdentity': None}
        candidate = copy.deepcopy(self.record['state'])
        candidate['identities'].append(enrolled)
        # Pick a boundary fixture without assuming how many identities fit. The
        # actual service below still supplies every admission and retained write.
        for number in range(100):
            item = {'ref': ref('padding-' + str(number)), 'principalId': 'padding-user-' + str(number),
                    'kind': 'human', 'status': 'active',
                    'externalIdentity': {'issuer': 'i' * 2048, 'subject': str(number).zfill(512)}}
            candidate['identities'].append(item)
            try:
                require_state_capacity(candidate)
            except ContractError as error:
                self.assertEqual(error.code, 'identity_capacity_exceeded')
                break
        else:
            self.fail('boundary fixture did not reach the capacity limit')
        low, high = 0, 2048
        while low < high:
            middle = (low + high + 1) // 2
            item['externalIdentity']['issuer'] = 'i' * middle
            try:
                require_state_capacity(candidate)
            except ContractError:
                high = middle - 1
            else:
                low = middle
        self.assertGreater(low, 0)
        item['externalIdentity']['issuer'] = 'i' * low
        require_state_capacity(candidate)
        item['externalIdentity']['issuer'] += 'i'
        with self.assertRaisesRegex(ContractError, 'identity_capacity_exceeded'):
            require_state_capacity(candidate)
        item['externalIdentity']['issuer'] = 'i' * low
        self.assertLessEqual(len(canonical_bytes(candidate)), MAX_STATE_BYTES)
        before_enrollment = copy.deepcopy(candidate)
        before_enrollment['identities'].remove(enrolled)
        self.record['state'] = before_enrollment
        self.js.messages[0].data = canonical_bytes(self.record)

        self.claims.update(contractId='identity-enroll', operationId='near-capacity-enroll',
            grantRef=ref('enroll-grant'), payload={'authorityId': 'authority-one',
                'identity': enrolled, 'issuers': [], 'transports': []})
        request = self.request()
        response = await self.service.handle(request)
        receipt = verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['entityVersion']), ('allowed', 2))
        admitted = strict_loads(self.js.messages[-1].data)['state']
        self.assertEqual({row['principalId'] for row in admitted['identities']},
                         {row['principalId'] for row in candidate['identities']})

        too_much = copy.deepcopy(enrolled)
        too_much.update(ref=ref('overflow-human'), principalId='overflow-user')
        self.claims.update(operationId='over-capacity-enroll', expectedVersion=2,
            payload={'authorityId': 'authority-one', 'identity': too_much, 'issuers': [], 'transports': []})
        request = self.request()
        response = await self.service.handle(request)
        receipt = verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['reason'], receipt['entityVersion']),
                         ('denied', 'identity_capacity_exceeded', 3))
        self.assertEqual(strict_loads(self.js.messages[-1].data)['state'], admitted)

        self.claims.update(contractId='identity-revoke', operationId='near-capacity-revoke',
            expectedVersion=3, grantRef=ref('grant'),
            payload={'authorityId': 'authority-one', 'targetRef': enrolled['ref']})
        request = self.request()
        response = await self.service.handle(request)
        receipt = verify_receipt(response, request,
            public_key=self.record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
        self.assertEqual((receipt['decision'], receipt['entityVersion']), ('allowed', 4))
        final = strict_loads(self.js.messages[-1].data)
        revoked = next(row for row in final['state']['identities'] if row['principalId'] == 'last-user')
        self.assertEqual((revoked['status'], revoked['ref']['revision']), ('revoked', 2))
        self.assertEqual(len(self.js.messages), 4)
        for message in self.js.messages:
            self.assertLessEqual(len(message.data), 65536)
            self.assertLessEqual(len(canonical_bytes(strict_loads(message.data)['operation'])), 8192)
