"""Actual TLS/JWT identity owner, ordinary generation and two-proof refusals."""
import copy
from datetime import datetime, timedelta, timezone
import secrets

from agentmux_contracts import canonical_bytes, sign_claims, strict_loads
from capability_owner.test_live import packet, stamp
from identity.ordinary_secret import verify_resolution
from identity.service import verify_receipt
from identity.test_authority import ref, SEED
from identity.test_ordinary_secret import ordinary_record, ordinary_state, SCOPE
from identity.transitions import transition
from state_owner import test_task_live as fixture


class LiveOrdinarySecretTests(fixture.LiveTaskTests):
    seed_ready_task = False
    create_task_host = False
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    def initial_authority(self):
        initial = super().initial_authority()
        state = ordinary_state(initial['state'])
        base = copy.deepcopy(state['grants'][0])
        for name, contract in (('ordinary-set-grant', 'identity-ordinary-secret-set'),
                               ('ordinary-grant-set', 'identity-grant-set')):
            state['grants'].append({**copy.deepcopy(base), 'ref': ref(name), 'contractId': contract})
        # ordinary_state copied the existing interval for all transport/grant rows.
        self.initial_secret = ordinary_record()
        self.initial_secret.update(issuedAt=stamp(datetime.now(timezone.utc)-timedelta(seconds=10)),
            expiresAt=stamp(datetime.now(timezone.utc)+timedelta(minutes=5)))
        return initial

    async def request_owner(self, contract, payload, *, actor='human', grant=None,
                            operation=None, version=None):
        snapshot = await self.identity.ledger.current()
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport' if actor == 'human' else 'custody-transport'),
            'grantRef': ref(grant or 'ordinary-set-grant'),
            'operationId': operation or 'ordinary-'+secrets.token_hex(16),
            'expectedVersion': strict_loads(snapshot.latest.record)['entityVersion'] if version is None else version,
            'contractId': contract, 'payload': payload, 'approvalRefs': [],
            'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=20)),
            'replySubject': self.host.new_inbox()}
        raw = packet(claims, bytes(reversed(SEED)))
        response = await self.exchange(self.host, self.identity_subject, raw, claims['replySubject'], timeout=2)
        return raw, response

    async def original_request(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('ordinary-use-grant'),
            'operationId': 'ordinary-use-original', 'expectedVersion': 1,
            'contractId': 'capability-secret-use', 'payload': {'resourceRef': ref('ordinary-one'),
                'input': {'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}},
            'approvalRefs': [], 'issuedAt': stamp(now), 'expiresAt': stamp(now+timedelta(seconds=20))}
        admitted = await self.identity.ingress.admit(packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('ordinary-use-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return strict_loads(admitted.envelope)

    async def test_tls_generation_replay_two_proof_authority_and_rotation(self):
        payload = {'authorityId': 'authority-one', 'record': self.initial_secret, 'previousRef': None}
        raw, response = await self.request_owner('identity-ordinary-secret-set', payload,
            operation='ordinary-enrollment-original')
        first = verify_receipt(response, raw, public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertEqual((first['decision'], first['replayed']), ('allowed', False))
        replay = await self.exchange(self.host, self.identity_subject, raw, strict_loads(raw)['claims']['replySubject'])
        replayed = verify_receipt(replay, raw, public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertEqual((replayed['replayed'], replayed['sequence']), (True, first['sequence']))
        original = await self.original_request()
        resolve = {'authorityId': 'authority-one', 'secretRef': ref('ordinary-one'),
            'generationRef': ref('ordinary-one'), 'profileId': 'profile-one', 'scope': SCOPE,
            'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one'), 'originalEnvelope': original}
        async def resolve_current(value=resolve):
            return await self.request_owner('identity-ordinary-secret-resolve', value, actor='custody',
                grant='ordinary-resolve-grant', version=0)
        before = await self.identity.ledger.current()
        resolution_raw, resolution_reply = await resolve_current()
        verified = verify_resolution(resolution_reply, resolution_raw, public_key=self.issuer_public,
            issuer_ref=ref('issuer'), now=datetime.now(timezone.utc))
        self.assertEqual(verified['callerRef'], ref('human'))
        self.assertEqual(verified['originalOperationId'], 'ordinary-use-original')
        self.assertEqual((await self.identity.ledger.current()).sequence, before.sequence)
        # Public metadata cannot widen the signed original or change generations.
        for field, value in (('purposeRef', ref('other-purpose')), ('generationRef', ref('different-generation')),
                ('scope', {**SCOPE, 'projectId': 'different-project'})):
            wrong = copy.deepcopy(resolve); wrong[field] = value
            _, refused = await resolve_current(wrong)
            self.assertEqual(strict_loads(refused).get('error'), 'identity_outcome_unconfirmed')
        wrong = copy.deepcopy(resolve)
        wrong['originalEnvelope']['ingressAttestation']['signature'] = sign_claims({'unrelated': True}, SEED)
        _, refused = await resolve_current(wrong)
        self.assertEqual(strict_loads(refused).get('error'), 'identity_outcome_unconfirmed')
        # A current hard denial defeats the otherwise valid original proof.
        current = strict_loads((await self.identity.ledger.current()).latest.record)
        grant = next(row for row in current['state']['grants'] if row['ref']['id'] == 'ordinary-use-grant')
        denial = {**copy.deepcopy(grant), 'ref': ref('ordinary-live-denial'), 'decision': 'denied'}
        await self.command('identity-grant-set', ref('ordinary-grant-set'), {
            'authorityId': 'authority-one', 'record': denial, 'previousRef': None})
        _, refused = await resolve_current()
        self.assertEqual(strict_loads(refused).get('error'), 'identity_outcome_unconfirmed')
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': denial['ref']})
        # Revoke each actual current proof, and retain the original public state.
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('ordinary-use-grant')})
        _, refused = await resolve_current()
        self.assertEqual(strict_loads(refused).get('error'), 'identity_outcome_unconfirmed')
        await self.command('identity-revoke', ref('grant'), {
            'authorityId': 'authority-one', 'targetRef': ref('ordinary-resolve-grant')})
        _, refused = await resolve_current()
        self.assertEqual(strict_loads(refused).get('error'), 'identity_outcome_unconfirmed')
        new = copy.deepcopy(self.initial_secret)
        new.update(ref=ref('ordinary-two'), generationRef=ref('ordinary-two'))
        rotation_raw, rotation_reply = await self.request_owner('identity-ordinary-secret-set', {
            'authorityId': 'authority-one', 'record': new, 'previousRef': ref('ordinary-one')})
        rotated = verify_receipt(rotation_reply, rotation_raw,
            public_key=self.issuer_public, issuer_ref=ref('issuer'))
        self.assertEqual(rotated['decision'], 'allowed')
        rows = strict_loads((await self.identity.ledger.current()).latest.record)['state']['ordinarySecretReferences']
        self.assertEqual((rows[0]['status'], rows[0]['ref']['revision'], rows[1]['generationRef']),
            ('revoked', 2, ref('ordinary-two')))
        self.assertEqual(rows[0]['generationRef'], ref('ordinary-one'))
        self.assertFalse(self.errors['identity'])
        self.success = True
