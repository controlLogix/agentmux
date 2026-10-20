"""AMUX-626: actual native identity/NATS ownership and fixed HTTPS consumer.

The coordinator must grant the live slot before this module runs. ACK-loss cases
discard the exact real JetStream client's response after the broker commits; they
do not replace the broker, identity reader, custody, consumer or ledger.
"""
import asyncio
import copy
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
import secrets
import ssl
import subprocess
import threading
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from capability_owner import test_secret_consumer as https_fixture
from capability_owner.ordinary_secret import OrdinarySecretOwner
from capability_owner.secret_consumer import (
    AtlassianAccountCheckConsumer, AtlassianAccountCheckEnrollment, SecretConsumerObservation)
from capability_owner.secret_journal import (
    PHASE_CONTRACTS, SecretOperationJournal, SecretPhaseSigner, secret_use_identity)
from capability_owner.test_live import packet, stamp
from identity import test_ordinary_secret_live as identity_fixture
from identity.service import verify_receipt
from identity.test_authority import ref, SEED
from identity.test_ordinary_secret import SCOPE
from native_security.nats_credentials import validate as validate_credential
from native_security.ordinary_secret_custody import OrdinarySecretCustody
from state_owner.ledger import OwnerBinding, OwnerLedger, owner_subject


class LiveOrdinarySecretOwnerTests(identity_fixture.LiveOrdinarySecretTests):
    test_tls_generation_replay_two_proof_authority_and_rotation = None
    source_role = 'secret-use'

    def configure_broker_policies(self, policies, reads):
        # This owner borrows the live identity reader. Its own credential can
        # read/write exactly one original-use ledger and cannot provision streams.
        self.bindings['DATA'] = OwnerBinding('hub-one', 'ordinary-secret-uses',
            secret_use_identity(SCOPE, 'ordinary-use-original'), 'effect', canonical_bytes(SCOPE))
        self.subjects['DATA'] = owner_subject(self.bindings['DATA'])
        self.inbox_prefixes[self.source_role] = '_INBOX.' + secrets.token_hex(16)
        self.secret_publish = [self.subjects['DATA'], *reads('DATA')]
        policies.pop('storage')
        policies[self.source_role] = {'publish': {'allow': self.secret_publish}, 'subscribe': {'allow': []}}

    def validate_source_credential(self):
        validate_credential(self.credentials[self.source_role].read_bytes(),
            account_public_key=self.account_public_key, publish_subjects=self.secret_publish,
            subscribe_subjects=[self.inbox_prefixes[self.source_role] + '.>'], private_inbox=True)

    def initial_authority(self):
        initial = super().initial_authority()
        grant = next(g for g in initial['state']['grants'] if g['ref'] == ref('ordinary-resolve-grant'))
        for contract in PHASE_CONTRACTS:
            initial['state']['grants'].append({**copy.deepcopy(grant),
                'ref': ref(contract), 'contractId': contract})
        return initial

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.owners, self.journals, self.custodies, self.consumers = [], [], [], []
        self.https_server = self.https_thread = None
        self.addAsyncCleanup(self.cleanup_ordinary)
        self.private_root = self.directory / 'ordinary-secret-private'
        self.private_root.mkdir(mode=0o700)
        self.configure_https()
        self.enrollment = AtlassianAccountCheckEnrollment(canonical_bytes(self.initial_secret),
            f'https://127.0.0.1:{self.https_server.server_port}', 'cloud',
            'fixture@example.test', 'expected-account', self.https_ca.read_bytes())
        self.secret_custody = self.new_custody()
        self.secret_js = self.source_connection.jetstream()

    def configure_https(self):
        config = self.directory / 'account-check.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n'
            '[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
            'basicConstraints=critical,CA:TRUE\n'
            'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n'
            'extendedKeyUsage=serverAuth\n')
        key, self.https_ca = self.directory / 'account-check-key.pem', self.directory / 'account-check-ca.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(key), '-out', str(self.https_ca), '-days', '1', '-config', str(config)],
            check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15, env={'PATH': '/usr/bin:/bin'})
        key.chmod(0o600)
        self.https_ca.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.https_ca, key)
        server = ThreadingHTTPServer(('127.0.0.1', 0), https_fixture._Handler)
        self.https_server = server
        server.daemon_threads = False
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.received, server.release = threading.Event(), threading.Event()
        server.requests, server.hold, server.cloud = [], False, True
        server.body, server.status = b'{"accountId":"expected-account"}', 200
        server.content_type, server.unknown_length = 'application/json', False
        self.https_thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02})
        self.https_thread.start()

    async def cleanup_ordinary(self):
        if self.https_server is not None:
            self.https_server.release.set()
        try:
            for owner in reversed(self.owners):
                await owner.close()
                self.assertFalse(owner._tasks)
            for consumer in self.consumers:
                await consumer.close()
                self.assertTrue(all(e.task is None or e.task.done() for e in consumer._entries.values()))
            for custody in self.custodies:
                await custody.close()
                self.assertIsNone(custody._store._fd)
            for journal in self.journals:
                await journal.close()
                self.assertFalse(journal._disk_tasks)
        finally:
            if self.https_thread is not None:
                await asyncio.to_thread(self.https_server.shutdown)
                await asyncio.to_thread(self.https_thread.join, 5)
                self.assertFalse(self.https_thread.is_alive())
            if self.https_server is not None:
                self.https_server.server_close()

    def new_custody(self):
        custody = OrdinarySecretCustody(self.private_root, self.identity.reader)
        self.custodies.append(custody)
        return custody

    def open_owner(self, *, custody=None):
        ledger = OwnerLedger(self.secret_js, stream='DATA', subject=self.subjects['DATA'],
            binding=self.bindings['DATA'], retention=self.policy,
            stream_identity=self.streams['DATA'], require_completion_budget=True)
        journal = SecretOperationJournal(ledger, self.identity.reader,
            enrollment=self.enrollment, observation_root=self.private_root)
        self.journals.append(journal)
        signer = SecretPhaseSigner(journal, self.identity.ingress,
            transport_ref=ref('custody-transport'), grants={name: ref(name) for name in PHASE_CONTRACTS},
            signing_seed=bytes(reversed(SEED)))
        consumer = AtlassianAccountCheckConsumer(self.identity.reader, self.enrollment)
        self.consumers.append(consumer)
        owner = OrdinarySecretOwner(journal, signer, custody or self.secret_custody, consumer)
        self.owners.append(owner)
        return owner

    async def possession(self, contract, payload, *, actor='human', grant=None, expected=None):
        snapshot = await self.identity.ledger.current()
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport' if actor == 'human' else 'custody-transport'),
            'grantRef': ref(grant or 'ordinary-set-grant'),
            'operationId': 'secret-fixture-' + secrets.token_hex(16),
            'expectedVersion': strict_loads(snapshot.latest.record)['entityVersion'] if expected is None else expected,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now + timedelta(seconds=20)),
            'replySubject': self.host.new_inbox()}
        return packet(claims, bytes(reversed(SEED)))

    async def stage(self, *, record=None, previous=None):
        record = record or self.initial_secret
        payload = {'authorityId': 'authority-one', 'record': record, 'previousRef': previous}
        raw = await self.possession('identity-ordinary-secret-set', payload)
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('secret-stage-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        await self.secret_custody.provision(admitted.envelope, secret=https_fixture._TOKEN)
        claims = strict_loads(raw)['claims']
        reply = await self.exchange(self.host, self.identity_subject, raw, claims['replySubject'])
        receipt = verify_receipt(reply, raw, public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertEqual(receipt['decision'], 'allowed', receipt)

    async def resolve_envelope(self, *, changes=None, allow_refusal=False):
        original = await self.original_request()
        payload = {'authorityId': 'authority-one', 'secretRef': ref('ordinary-one'),
            'generationRef': ref('ordinary-one'), 'profileId': 'profile-one', 'scope': SCOPE,
            'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one'), 'originalEnvelope': original}
        payload.update(changes or {})
        raw = await self.possession('identity-ordinary-secret-resolve', payload, actor='custody',
            grant='ordinary-resolve-grant', expected=0)
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('secret-resolve-cancel'))
        if admitted.decision.outcome != 'allowed' and allow_refusal:
            self.assertEqual(admitted.decision.outcome, 'denied')
            self.assertIsNone(admitted.envelope)
            return None
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        return admitted.envelope

    async def received(self):
        self.assertTrue(await asyncio.to_thread(self.https_server.received.wait, 3))

    async def test_real_current_identity_receipt_replay_restart_and_broker_boundaries(self):
        await self.stage()
        owner = self.open_owner()
        for changes in ({'consumerRef': ref('custody')}, {'purposeRef': ref('wrong-purpose')},
                        {'generationRef': ref('wrong-generation')}, {'profileId': 'wrong-profile'},
                        {'scope': {**SCOPE, 'projectId': 'wrong-project'}}):
            with self.subTest(field=next(iter(changes))):
                bad = await self.resolve_envelope(changes=changes, allow_refusal=True)
                if bad is None:
                    continue
                with self.assertRaises(ContractError): await owner.use(bad)
        self.assertIsNone(await owner._journal.current())
        self.assertEqual(self.https_server.requests, [])
        raw = await self.resolve_envelope()
        receipt = await owner.use(raw)
        validate('capability-secret-use-reply', receipt)
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertEqual(set(receipt), {'receiptRef', 'outcome'})
        self.assertEqual(await owner.recover(raw), receipt)
        self.assertEqual(await owner.use(raw), receipt)
        self.assertEqual(self.https_server.requests, [('GET', '/rest/api/3/myself', True)])
        snapshot = await owner._journal._ledger.current()
        self.assertEqual(snapshot.sequence, 3)
        self.assertEqual([strict_loads(r.record)['state']['phase'] for r in snapshot.records],
                         ['prepared', 'dispatching', 'finished'])
        public = b''.join(r.record for r in snapshot.records)
        for private in (https_fixture._TOKEN, self.enrollment.base_url.encode(),
                        self.enrollment.email.encode(), self.enrollment.expected_account.encode()):
            self.assertNotIn(private, public)
        await owner.close()
        replacement = self.open_owner(custody=self.new_custody())
        self.assertEqual(await replacement.recover(raw), receipt)
        self.assertEqual(len(self.https_server.requests), 1)
        for subject in ('$JS.API.STREAM.MSG.GET.IDENTITY', '$JS.API.STREAM.MSG.GET.OTHER',
                        '$JS.API.STREAM.CREATE.DATA', self.subjects['OTHER']):
            count = self.errors[self.source_role].count('permission')
            await self.source_connection.publish(subject, b'{}')
            await self.source_connection.flush(timeout=2)
            await self.wait_permissions(self.source_role, count + 1)
        self.assertEqual((await replacement._journal._ledger.current()).sequence, 3)
        self.success = True

    async def lost_ack(self, phase):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        original_publish = self.secret_js.publish
        lost = False
        async def publish(subject, data, **kwargs):
            nonlocal lost
            ack = await original_publish(subject, data, **kwargs)
            if subject == self.subjects['DATA'] and strict_loads(data)['state']['phase'] == phase and not lost:
                lost = True
                raise TimeoutError('owned acknowledgement discarded')
            return ack
        with patch.object(self.secret_js, 'publish', publish):
            receipt = await owner.use(raw)
        self.assertTrue(lost)
        self.assertEqual(receipt['outcome'], 'accepted' if phase == 'finished' else 'uncertain')
        expected_requests = 1 if phase == 'finished' else 0
        self.assertEqual(len(self.https_server.requests), expected_requests)
        await owner.close()
        replacement = self.open_owner(custody=self.new_custody())
        self.assertEqual(await replacement.recover(raw), receipt)
        self.assertEqual(await replacement.use(raw), receipt)
        self.assertEqual(len(self.https_server.requests), expected_requests)
        self.success = True

    async def test_real_lost_intent_ack_never_dispatches_after_restart(self):
        await self.lost_ack('prepared')

    async def test_real_lost_dispatch_ack_never_dispatches_after_restart(self):
        await self.lost_ack('dispatching')

    async def test_real_lost_completion_ack_recovers_original_receipt(self):
        await self.lost_ack('finished')

    async def test_real_failed_completion_recovers_retained_observation_after_restart(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        original_publish = self.secret_js.publish
        async def publish(subject, data, **kwargs):
            if subject == self.subjects['DATA'] and strict_loads(data)['state']['phase'] == 'finished':
                raise OSError('owned completion unavailable')
            return await original_publish(subject, data, **kwargs)
        with patch.object(self.secret_js, 'publish', publish):
            with self.assertRaises(ContractError): await owner.use(raw)
        group = await owner._journal.current()
        self.assertEqual(group['state']['phase'], 'dispatching')
        self.assertEqual((await owner._journal.load_observation(group)).status, 'accepted')
        await owner.close()
        replacement = self.open_owner(custody=self.new_custody())
        receipt = await replacement.recover(raw)
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertEqual((await replacement._journal.current())['state']['phase'], 'finished')
        self.assertEqual(len(self.https_server.requests), 1)
        self.success = True

    async def test_real_cancelled_observer_and_short_close_retain_original_worker(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        self.https_server.hold = True
        observer = asyncio.create_task(owner.use(raw))
        try:
            await self.received()
            original = tuple(owner._tasks)
            self.assertEqual(len(original), 1)
            observer.cancel()
            with self.assertRaises(asyncio.CancelledError): await observer
            with self.assertRaisesRegex(ContractError, 'ordinary_secret_owner_cleanup_incomplete'):
                await owner.close(timeout=0.02)
            self.assertFalse(original[0].done())
            self.assertIsNotNone(self.secret_custody._store._fd)
        finally:
            self.https_server.release.set()
            await owner.close()
        self.assertTrue(original[0].done())
        self.assertIsNone(self.secret_custody._store._fd)
        replacement = self.open_owner(custody=self.new_custody())
        self.assertEqual((await replacement.recover(raw))['outcome'], 'accepted')
        self.assertEqual(len(self.https_server.requests), 1)
        self.success = True

    async def test_real_current_caller_revocation_retains_effect_but_refuses_receipt(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        self.https_server.hold = True
        observer = asyncio.create_task(owner.use(raw))
        try:
            await self.received()
            await self.command('identity-revoke', ref('grant'),
                {'authorityId': 'authority-one', 'targetRef': ref('ordinary-use-grant')})
        finally:
            self.https_server.release.set()
        with self.assertRaises(ContractError): await observer
        group = await owner._journal.current()
        self.assertEqual((group['state']['phase'], group['state']['outcome']), ('finished', 'accepted'))
        self.assertEqual(len(self.https_server.requests), 1)
        with self.assertRaises(ContractError): await owner.recover(raw)
        with self.assertRaises(ContractError): await owner.use(raw)
        self.assertEqual(len(self.https_server.requests), 1)
        self.success = True

    async def test_real_rotation_during_effect_retires_old_generation_without_repeat(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        self.https_server.hold = True
        observer = asyncio.create_task(owner.use(raw))
        try:
            await self.received()
            rotated = copy.deepcopy(self.initial_secret)
            rotated.update(ref=ref('ordinary-two'), generationRef=ref('ordinary-two'))
            await self.stage(record=rotated, previous=ref('ordinary-one'))
        finally:
            self.https_server.release.set()
        with self.assertRaises(ContractError): await observer
        group = await owner._journal.current()
        self.assertEqual((group['state']['phase'], group['state']['outcome']), ('finished', 'accepted'))
        state = strict_loads((await self.identity.ledger.current()).latest.record)['state']
        old, new = state['ordinarySecretReferences']
        self.assertEqual((old['status'], old['ref']['revision']), ('revoked', 2))
        self.assertEqual(new['generationRef'], ref('ordinary-two'))
        with self.assertRaises(ContractError): await owner.recover(raw)
        with self.assertRaises(ContractError): await owner.use(raw)
        self.assertEqual(len(self.https_server.requests), 1)
        self.success = True


class LiveSecretOutcomeRecoveryTests(LiveOrdinarySecretOwnerTests):
    """AMUX-649: a new current query reads an unchanged expired original."""
    test_real_current_identity_receipt_replay_restart_and_broker_boundaries = None
    test_real_lost_intent_ack_never_dispatches_after_restart = None
    test_real_lost_dispatch_ack_never_dispatches_after_restart = None
    test_real_lost_completion_ack_recovers_original_receipt = None
    test_real_failed_completion_recovers_retained_observation_after_restart = None
    test_real_cancelled_observer_and_short_close_retain_original_worker = None
    test_real_current_caller_revocation_retains_effect_but_refuses_receipt = None
    test_real_rotation_during_effect_retires_old_generation_without_repeat = None

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        original = next(g for g in state['grants'] if g['ref'] == ref('ordinary-use-grant'))
        state['grants'].append({**copy.deepcopy(original), 'ref': ref('ordinary-query-grant'),
                                'contractId': 'capability-outcome-query'})
        other_scope = {**SCOPE, 'projectId': 'other-project'}
        state['memberships'].append({'ref': ref('query-other-project-member'),
            'identityRef': ref('human'), 'scope': other_scope, 'status': 'active'})
        for contract, suffix in (('capability-secret-use', 'use'), ('capability-outcome-query', 'query')):
            state['grants'].append({**copy.deepcopy(original), 'ref': ref('other-project-' + suffix),
                'contractId': contract, 'scope': other_scope})
        foreign = next(g for g in state['grants'] if g['ref'] == ref('ordinary-resolve-grant'))
        for contract, suffix in (('capability-secret-use', 'use'), ('capability-outcome-query', 'query')):
            state['grants'].append({**copy.deepcopy(foreign), 'ref': ref('other-caller-' + suffix),
                                    'contractId': contract})
        return initial

    async def original_request(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('ordinary-use-grant'),
            'operationId': 'ordinary-use-original', 'expectedVersion': 1,
            'contractId': 'capability-secret-use', 'payload': {'resourceRef': ref('ordinary-one'),
                'input': {'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}},
            'approvalRefs': [], 'issuedAt': stamp(now), 'expiresAt': stamp(now + timedelta(seconds=5))}
        admitted = await self.identity.ingress.admit(packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('ordinary-query-original-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        self.query_original = strict_loads(admitted.envelope)
        return self.query_original

    async def expire_original(self):
        before = canonical_bytes(self.query_original)
        expires = datetime.fromisoformat(self.query_original['operation']['deadline'])
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        self.assertLessEqual(remaining, 5)
        if remaining > 0:
            await asyncio.sleep(remaining + 0.05)
        self.assertGreaterEqual(datetime.now(timezone.utc), expires)
        self.assertEqual(canonical_bytes(self.query_original), before)

    async def outcome_query(self, *, input_changes=None, resource=None, actor='human', grant=None):
        original = self.query_original['operation']
        query_input = {'contractId': 'capability-secret-use', 'operationId': original['operationId'],
                       'payloadDigest': original['payloadDigest']}
        query_input.update(input_changes or {})
        raw = await self.possession('capability-outcome-query',
            {'resourceRef': resource or ref('ordinary-one'), 'input': query_input}, actor=actor,
            grant=grant or 'ordinary-query-grant', expected=1)
        admitted = await self.identity.ingress.admit(raw, cancellation_ref=ref('secret-query-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        current = await self.identity.reader.evaluate(admitted.envelope,
            audience={'hubId': 'hub-one', 'serviceId': 'outcome-owner'})
        self.assertEqual(current.outcome, 'allowed', current.reason)
        self.assertGreater(datetime.fromisoformat(strict_loads(admitted.envelope)['operation']['deadline']),
                           datetime.now(timezone.utc))
        return admitted.envelope

    async def test_expired_original_uses_fresh_query_and_current_permissions(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        receipt = await owner.use(raw)
        self.assertEqual(receipt['outcome'], 'accepted')
        retained = await owner._journal._ledger.current()
        original_bytes = canonical_bytes(self.query_original)
        await owner.close()
        await self.expire_original()
        replacement = self.open_owner(custody=self.new_custody())
        with self.assertRaises(ContractError): await replacement.recover(raw)
        with self.assertRaises(ContractError): await replacement.use(raw)
        query = await self.outcome_query()
        self.assertEqual(await replacement.recover_query(query), receipt)
        reconciled = await replacement.reconcile(query)
        validate('capability-outcome-query-reply', reconciled)
        self.assertEqual(reconciled['outcome'], 'committed')
        self.assertEqual(reconciled['recordRef'], receipt['receiptRef'])
        self.assertEqual(reconciled['operationId'], self.query_original['operation']['operationId'])
        self.assertEqual(reconciled['payloadDigest'], self.query_original['operation']['payloadDigest'])
        for wrong in (
                await self.outcome_query(input_changes={'payloadDigest': 'sha256:' + '0' * 64}),
                await self.outcome_query(input_changes={'operationId': 'foreign-original'}),
                await self.outcome_query(resource={**ref('ordinary-one'), 'revision': 2}),
                await self.outcome_query(actor='custody', grant='other-caller-query'),
                await self.outcome_query(grant='other-project-query')):
            with self.assertRaises(ContractError): await replacement.recover_query(wrong)
        # The exact previously admitted proof must fail when current authority
        # gains a hard denial. Removing that denial restores the positive control.
        current = strict_loads((await self.identity.ledger.current()).latest.record)['state']
        grant = next(g for g in current['grants'] if g['ref'] == ref('ordinary-query-grant'))
        denial = {**copy.deepcopy(grant), 'ref': ref('live-query-hard-denial'), 'decision': 'denied'}
        await self.command('identity-grant-set', ref('ordinary-grant-set'),
            {'authorityId': 'authority-one', 'record': denial, 'previousRef': None})
        with self.assertRaises(ContractError): await replacement.recover_query(query)
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': denial['ref']})
        query = await self.outcome_query()
        self.assertEqual(await replacement.recover_query(query), receipt)
        current = strict_loads((await self.identity.ledger.current()).latest.record)['state']
        grant = next(g for g in current['grants'] if g['ref'] == ref('ordinary-use-grant'))
        denial = {**copy.deepcopy(grant), 'ref': ref('live-use-hard-denial'), 'decision': 'denied'}
        await self.command('identity-grant-set', ref('ordinary-grant-set'),
            {'authorityId': 'authority-one', 'record': denial, 'previousRef': None})
        with self.assertRaises(ContractError): await replacement.recover_query(query)
        after = await replacement._journal._ledger.current()
        self.assertEqual(tuple(r.record for r in after.records), tuple(r.record for r in retained.records))
        self.assertEqual(canonical_bytes(self.query_original), original_bytes)
        self.assertEqual(len(self.https_server.requests), 1)
        self.assertFalse(replacement._consumer._entries)
        self.success = True

    async def test_expired_rejected_original_maps_only_to_rejected(self):
        await self.stage()
        self.https_server.body = b'{"accountId":"wrong-account"}'
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        first_receipt = None
        try:
            first_receipt = await owner.use(raw)
        except ContractError as error:
            # The original may expire after the physical result was recorded.
            # That correctly withholds its first reply; recovery still needs a
            # new current proof and the exact real retained rejection below.
            self.assertEqual(error.code, 'attestation_time_invalid')
            now = datetime.now(timezone.utc)
            self.assertGreaterEqual(now,
                datetime.fromisoformat(self.query_original['operation']['deadline']))
            self.assertGreaterEqual(now, datetime.fromisoformat(
                self.query_original['ingressAttestation']['claims']['expiresAt']))
        retained = await owner._journal.current()
        self.assertEqual((retained['state']['phase'], retained['state']['outcome']),
                         ('finished', 'rejected'))
        self.assertEqual(retained['latest'].sequence, 3)
        self.assertEqual(len(self.https_server.requests), 1)
        original_ref = owner._journal.ref(retained['latest'])
        if first_receipt is not None:
            self.assertEqual(first_receipt, {'receiptRef': original_ref, 'outcome': 'rejected'})
        await owner.close()
        await self.expire_original()
        replacement = self.open_owner(custody=self.new_custody())
        query = await self.outcome_query()
        self.assertEqual(await replacement.recover_query(query),
                         {'receiptRef': original_ref, 'outcome': 'rejected'})
        reply = await replacement.reconcile(query)
        validate('capability-outcome-query-reply', reply)
        self.assertEqual((reply['outcome'], reply['recordRef']), ('rejected', original_ref))
        self.assertEqual((await replacement._journal._ledger.current()).sequence, 3)
        self.assertEqual(len(self.https_server.requests), 1)
        self.success = True

    async def test_authorized_absent_query_never_prepares_an_intent(self):
        await self.stage()
        await self.resolve_envelope()
        owner = self.open_owner()
        await self.expire_original()
        query = await self.outcome_query()
        self.assertIsNone(await owner.recover_query(query))
        reply = await owner.reconcile(query)
        validate('capability-outcome-query-reply', reply)
        self.assertEqual((reply['outcome'], reply['recordRef']), ('absent', None))
        self.assertIsNone(await owner._journal.current())
        self.assertFalse(owner._consumer._entries)
        self.assertFalse(self.https_server.requests)
        self.success = True

    async def test_expired_pending_original_never_maps_to_committed(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        prepared = await owner._journal.prepare(raw)
        self.assertTrue(prepared.acknowledged)
        await owner.close()
        await self.expire_original()
        replacement = self.open_owner(custody=self.new_custody())
        query = await self.outcome_query()
        self.assertEqual((await replacement.recover_query(query))['outcome'], 'uncertain')
        with self.assertRaisesRegex(ContractError, '^ordinary_secret_outcome_uncertain$'):
            await replacement.reconcile(query)
        self.assertEqual((await replacement._journal._ledger.current()).sequence, 1)
        self.assertFalse(self.https_server.requests)
        self.assertFalse(replacement._consumer._entries)
        self.success = True

    async def test_expired_physical_uncertainty_never_maps_to_committed(self):
        await self.stage()
        self.https_server.body = b'not-an-account-response'
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        receipt = await owner.use(raw)
        self.assertEqual(receipt['outcome'], 'uncertain')
        await owner.close()
        await self.expire_original()
        replacement = self.open_owner(custody=self.new_custody())
        query = await self.outcome_query()
        self.assertEqual(await replacement.recover_query(query), receipt)
        with self.assertRaisesRegex(ContractError, '^ordinary_secret_outcome_uncertain$'):
            await replacement.reconcile(query)
        self.assertEqual((await replacement._journal._ledger.current()).sequence, 3)
        self.assertEqual(len(self.https_server.requests), 1)
        self.assertFalse(replacement._consumer._entries)
        self.success = True

    async def test_expired_original_recovers_private_observation_after_restart(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        original_publish = self.secret_js.publish
        async def publish(subject, data, **kwargs):
            if subject == self.subjects['DATA'] and strict_loads(data)['state']['phase'] == 'finished':
                raise OSError('owned completion unavailable')
            return await original_publish(subject, data, **kwargs)
        with patch.object(self.secret_js, 'publish', publish):
            with self.assertRaises(ContractError): await owner.use(raw)
        before = await owner._journal.current()
        self.assertEqual(before['state']['phase'], 'dispatching')
        self.assertEqual((await owner._journal.load_observation(before)).status, 'accepted')
        await owner.close()
        await self.expire_original()
        replacement = self.open_owner(custody=self.new_custody())
        query = await self.outcome_query()
        receipt = await replacement.recover_query(query)
        self.assertEqual(receipt['outcome'], 'accepted')
        self.assertEqual((await replacement.reconcile(query))['outcome'], 'committed')
        after = await replacement._journal._ledger.current()
        self.assertEqual(after.sequence, 3)
        self.assertEqual(tuple(r.record for r in after.records[:2]),
                         (before['claim'].record, before['latest'].record))
        self.assertEqual(len(self.https_server.requests), 1)
        self.assertFalse(replacement._consumer._entries)
        self.success = True


class LiveApprovedSecretOutcomeRecoveryTests(LiveSecretOutcomeRecoveryTests):
    """AMUX-654: current exact approval authorizes a new outcome read only."""
    test_expired_original_uses_fresh_query_and_current_permissions = None
    test_expired_rejected_original_maps_only_to_rejected = None
    test_authorized_absent_query_never_prepares_an_intent = None
    test_expired_pending_original_never_maps_to_committed = None
    test_expired_physical_uncertainty_never_maps_to_committed = None
    test_expired_original_recovers_private_observation_after_restart = None

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        original = next(g for g in state['grants'] if g['ref'] == ref('ordinary-use-grant'))
        approver = {**copy.deepcopy(original), 'ref': ref('ordinary-approver-grant'),
            'contractId': 'identity-approve', 'resourceId': original['ref']['id'], 'decision': 'allowed'}
        original['decision'] = 'review-required'
        state['grants'].append(approver)
        value = {'resourceRef': ref('ordinary-one'), 'input': {
            'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}}
        state['approvals'].append({'ref': ref('ordinary-use-approval'),
            'grantRef': original['ref'], 'approverRef': ref('human'), 'approverGrantRef': approver['ref'],
            'payloadDigest': payload_digest(value), 'audience': {'hubId': 'hub-one', 'serviceId': 'secret-owner'},
            'operationId': 'ordinary-use-original', 'expectedVersion': 1, 'decision': 'approved',
            'status': 'active', 'issuedAt': self.initial_secret['issuedAt'],
            'expiresAt': self.initial_secret['expiresAt']})
        return initial

    async def original_request(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('ordinary-use-grant'),
            'operationId': 'ordinary-use-original', 'expectedVersion': 1,
            'contractId': 'capability-secret-use', 'payload': {'resourceRef': ref('ordinary-one'),
                'input': {'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}},
            'approvalRefs': [ref('ordinary-use-approval')], 'issuedAt': stamp(now),
            'expiresAt': stamp(now + timedelta(seconds=5))}
        admitted = await self.identity.ingress.admit(packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('ordinary-approved-query-original-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed', admitted.decision.reason)
        self.query_original = strict_loads(admitted.envelope)
        self.assertEqual(self.query_original['operation']['approvalRefs'], [ref('ordinary-use-approval')])
        return self.query_original

    async def test_current_approval_recovers_expired_original_without_another_use(self):
        await self.stage()
        raw = await self.resolve_envelope()
        owner = self.open_owner()
        first_receipt = None
        try:
            first_receipt = await owner.use(raw)
        except ContractError as error:
            self.assertEqual(error.code, 'attestation_time_invalid')
            now = datetime.now(timezone.utc)
            self.assertGreaterEqual(now, datetime.fromisoformat(self.query_original['operation']['deadline']))
            self.assertGreaterEqual(now, datetime.fromisoformat(
                self.query_original['ingressAttestation']['claims']['expiresAt']))
        retained = await owner._journal.current()
        self.assertEqual((retained['state']['phase'], retained['state']['outcome']), ('finished', 'accepted'))
        self.assertEqual(retained['latest'].sequence, 3)
        original_ref = owner._journal.ref(retained['latest'])
        if first_receipt is not None:
            self.assertEqual(first_receipt, {'receiptRef': original_ref, 'outcome': 'accepted'})
        original_bytes = canonical_bytes(self.query_original)
        before = await owner._journal._ledger.current()
        await owner.close()
        await self.expire_original()
        replacement = self.open_owner(custody=self.new_custody())
        with self.assertRaises(ContractError): await replacement.use(raw)
        query = await self.outcome_query()
        state = strict_loads((await self.identity.ledger.current()).latest.record)['state']
        self.assertEqual(next(g for g in state['grants'] if g['ref'] == ref('ordinary-use-grant'))['decision'],
                         'review-required')
        self.assertEqual(next(g for g in state['grants'] if g['ref'] == ref('ordinary-query-grant'))['decision'],
                         'allowed')
        self.assertEqual(await replacement.recover_query(query), {'receiptRef': original_ref, 'outcome': 'accepted'})
        reply = await replacement.reconcile(query)
        validate('capability-outcome-query-reply', reply)
        self.assertEqual((reply['outcome'], reply['recordRef']), ('committed', original_ref))
        await self.command('identity-revoke', ref('grant'),
            {'authorityId': 'authority-one', 'targetRef': ref('ordinary-use-approval')})
        state = strict_loads((await self.identity.ledger.current()).latest.record)['state']
        retired = [a for a in state['approvals']
            if a['ref']['id'] == 'ordinary-use-approval' and a['ref']['ownerHubId'] == 'hub-one']
        self.assertEqual(len(retired), 1)
        self.assertEqual(retired[0]['ref'], {**ref('ordinary-use-approval'), 'revision': 2})
        self.assertEqual(retired[0]['status'], 'revoked')
        with self.assertRaises(ContractError): await replacement.recover_query(query)
        with self.assertRaises(ContractError): await replacement.reconcile(query)
        after = await replacement._journal._ledger.current()
        self.assertEqual(tuple(r.record for r in after.records), tuple(r.record for r in before.records))
        self.assertEqual(canonical_bytes(self.query_original), original_bytes)
        self.assertEqual(len(self.https_server.requests), 1)
        self.assertFalse(replacement._consumer._entries)
        self.success = True


class LiveSecretCloseRecoveryTests(LiveSecretOutcomeRecoveryTests):
    """AMUX-651: successful close retains a known actual consumer result."""
    test_expired_original_uses_fresh_query_and_current_permissions = None
    test_expired_rejected_original_maps_only_to_rejected = None
    test_authorized_absent_query_never_prepares_an_intent = None
    test_expired_pending_original_never_maps_to_committed = None
    test_expired_physical_uncertainty_never_maps_to_committed = None
    test_expired_original_recovers_private_observation_after_restart = None

    async def test_known_result_survives_failed_save_and_successful_close(self):
        await self.stage()
        raw = await self.resolve_envelope()
        original_bytes = canonical_bytes(self.query_original)
        original_id = self.query_original['operation']['operationId']
        owner = self.open_owner()
        expected = SecretConsumerObservation('accepted', 'account_matched')
        with patch.object(owner._journal, 'save_observation', side_effect=OSError('owned save unavailable')):
            with self.assertRaisesRegex(ContractError, '^ordinary_secret_outcome_uncertain$'):
                await owner.use(raw)
            group = await owner._journal.current()
            self.assertEqual((group['state']['phase'], group['latest'].sequence), ('dispatching', 2))
            handle = owner._jobs[original_id]
            self.assertEqual(owner._consumer.private_observation(handle), expected)
            self.assertEqual(owner._pending_observations[original_id][1], expected)
            self.assertEqual(self.https_server.requests, [('GET', '/rest/api/3/myself', True)])
            before = await owner._journal._ledger.current()
            with self.assertRaisesRegex(ContractError, '^ordinary_secret_owner_cleanup_incomplete$'):
                await owner.close()
            failed_close = owner._closing
            self.assertTrue(failed_close.done())
            self.assertFalse(owner._consumer._closed)
            self.assertIsNotNone(owner._custody._store._fd)
            self.assertIsNotNone(owner._journal._observations._fd)
            self.assertEqual(owner._consumer.private_observation(handle), expected)
            self.assertEqual(owner._pending_observations[original_id][1], expected)
        await owner.close()
        self.assertIsNot(owner._closing, failed_close)
        successful_close = owner._closing
        self.assertTrue(successful_close.done())
        self.assertTrue(owner._consumer._closed)
        self.assertIsNone(owner._custody._store._fd)
        self.assertIsNone(owner._journal._observations._fd)
        await owner.close()
        self.assertIs(owner._closing, successful_close)
        replacement = self.open_owner(custody=self.new_custody())
        self.assertEqual(await replacement._journal.load_observation(group), expected)
        self.assertEqual((await replacement._journal.current())['state']['phase'], 'dispatching')
        await self.expire_original()
        with self.assertRaises(ContractError): await replacement.use(raw)
        query = await self.outcome_query()
        receipt = await replacement.recover_query(query)
        self.assertEqual(receipt['outcome'], 'accepted')
        after = await replacement._journal._ledger.current()
        self.assertEqual(after.sequence, 3)
        self.assertEqual(tuple(r.record for r in after.records[:2]), tuple(r.record for r in before.records))
        self.assertEqual([strict_loads(r.record)['state']['phase'] for r in after.records],
                         ['prepared', 'dispatching', 'finished'])
        self.assertEqual(receipt['receiptRef'], replacement._journal.ref(after.latest))
        completion = strict_loads(after.latest.record)['operation']
        self.assertEqual(completion['caller']['authenticatedIdentityRef'], ref('custody'))
        self.assertEqual(completion['grantRef'], ref('ordinary-secret-complete'))
        reply = await replacement.reconcile(query)
        validate('capability-outcome-query-reply', reply)
        self.assertEqual((reply['outcome'], reply['recordRef']), ('committed', receipt['receiptRef']))
        self.assertEqual(canonical_bytes(self.query_original), original_bytes)
        self.assertEqual(len(self.https_server.requests), 1)
        self.assertFalse(replacement._consumer._entries)
        self.success = True
