"""Ordinary secret generations and current original/custody authorization."""
import copy
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads, validate
from identity.authority import AuthoritySnapshot, LedgerAuthorityReader
from identity.commands import prepare_change
from identity.ordinary_secret import OrdinarySecretAuthority, resolve_snapshot
from identity.test_authority import fixture, ref, NOW, SEED
from identity.transitions import transition


SCOPE = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
INTERVAL = {'status': 'active', 'issuedAt': '2026-10-09T12:00:00Z',
            'expiresAt': '2026-10-09T12:10:00Z'}


def ordinary_record(name='ordinary-one'):
    return {'ref': ref(name), 'generationRef': ref(name), 'profileId': 'profile-one',
        'scope': copy.deepcopy(SCOPE), 'ownerIdentityRef': ref('custody'),
        'ownerAudience': {'hubId': 'hub-one', 'serviceId': 'secret-owner'},
        'callerIdentityRef': ref('human'), 'consumerRef': ref('consumer'),
        'purposeRef': ref('purpose-one'), **INTERVAL}


def ordinary_state(state):
    """Extend existing public test enrollment, without any secret material."""
    for name in ('custody', 'consumer'):
        state['identities'].append({'ref': ref(name), 'principalId': name,
            'kind': 'service', 'status': 'active', 'externalIdentity': None})
        state['memberships'].append({'ref': ref(name + '-member'),
            'identityRef': ref(name), 'scope': copy.deepcopy(SCOPE), 'status': 'active'})
    state['memberships'] = [row for row in state['memberships']
        if not (row['identityRef'] == ref('human') and row['scope'] == SCOPE)]
    state['memberships'].append({'ref': ref('ordinary-caller-member'),
        'identityRef': ref('human'), 'scope': copy.deepcopy(SCOPE), 'status': 'active'})
    transport = copy.deepcopy(state['transports'][0])
    transport.update(ref=ref('custody-transport'), identityRef=ref('custody'))
    state['transports'].append(transport)
    grant = copy.deepcopy(state['grants'][0])
    for name, contract, actor in (
            ('ordinary-use-grant', 'capability-secret-use', 'human'),
            ('ordinary-resolve-grant', 'identity-ordinary-secret-resolve', 'custody')):
        state['grants'].append({**copy.deepcopy(grant), 'ref': ref(name),
            'callerRef': ref(actor), 'actorRef': ref(actor), 'contractId': contract,
            'scope': copy.deepcopy(SCOPE), 'resourceId': 'ordinary-one',
            'decision': 'allowed', 'delegationRef': None})
    return state


def signed_envelope(template, *, contract, payload, actor, grant, scope, version=0):
    request = copy.deepcopy(template)
    service = 'secret-owner' if contract == 'capability-secret-use' else 'identity-owner'
    request.update(contractId=contract, destinationServiceId=service, payload=copy.deepcopy(payload))
    operation = request['operation']
    operation.update(operationId='ordinary-' + contract, payloadDigest=payload_digest(payload),
        scope=copy.deepcopy(scope), expectedVersion=version, effectiveActorRef=ref(actor),
        grantRef=ref(grant), approvalRefs=[])
    operation['caller'].update(principalId='user-one' if actor == 'human' else actor,
        kind='human' if actor == 'human' else 'service', authenticatedIdentityRef=ref(actor))
    claims = request['ingressAttestation']['claims']
    claims.update(contractId=contract, operation=copy.deepcopy(operation),
        authenticatedTransportRef=ref('transport' if actor == 'human' else actor+'-transport'),
        audience={'hubId': 'hub-one', 'serviceId': service})
    request['ingressAttestation']['signature'] = sign_claims(claims, SEED)
    return request


def resolution_fixture():
    record, template = fixture()
    state = ordinary_state(record['state'])
    record['state'] = transition(state, 'identity-ordinary-secret-set', {
        'authorityId': 'authority-one', 'record': ordinary_record(), 'previousRef': None}, hub_id='hub-one')
    original = signed_envelope(template, contract='capability-secret-use',
        payload={'resourceRef': ref('ordinary-one'), 'input': {
            'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one')}},
        actor='human', grant='ordinary-use-grant', scope=SCOPE, version=1)
    payload = {'authorityId': 'authority-one', 'secretRef': ref('ordinary-one'),
        'generationRef': ref('ordinary-one'), 'profileId': 'profile-one', 'scope': copy.deepcopy(SCOPE),
        'consumerRef': ref('consumer'), 'purposeRef': ref('purpose-one'), 'originalEnvelope': original}
    outer = signed_envelope(template, contract='identity-ordinary-secret-resolve', payload=payload,
        actor='custody', grant='ordinary-resolve-grant', scope=SCOPE)
    return record, outer, template


class OrdinarySecretTests(unittest.TestCase):
    def setUp(self):
        self.record, self.outer, self.template = resolution_fixture()

    def resolve(self):
        return resolve_snapshot(AuthoritySnapshot(canonical_bytes(self.record), 17),
            canonical_bytes(self.outer), audience={'hubId': 'hub-one', 'serviceId': 'identity-owner'}, now=NOW)

    def resign(self):
        for envelope in (self.outer['payload']['originalEnvelope'], self.outer):
            envelope['operation']['payloadDigest'] = payload_digest(envelope['payload'])
            claims = envelope['ingressAttestation']['claims']
            claims.update(operation=copy.deepcopy(envelope['operation']))
            envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)

    def test_exact_two_proofs_return_immutable_public_references(self):
        result = self.resolve()
        self.assertEqual(result.claims()['callerRef'], ref('human'))
        self.assertEqual(result.claims()['custodyIdentityRef'], ref('custody'))
        self.assertEqual(result.claims()['generationRef'], ref('ordinary-one'))
        self.assertEqual(result.authority_sequence, 17)
        self.assertEqual(result.claims()['originalRequestDigest'], payload_digest(self.outer['payload']['originalEnvelope']))
        self.outer['payload']['originalEnvelope']['operation']['effectiveActorRef'] = ref('consumer')
        self.assertEqual(result.claims()['callerRef'], ref('human'))

    def test_outer_binding_substitutions_refuse(self):
        original = copy.deepcopy(self.outer)
        for key, value in (('profileId', 'different-profile'), ('secretRef', ref('missing')),
                ('generationRef', ref('different-generation')), ('consumerRef', ref('custody')),
                ('purposeRef', ref('other-purpose')), ('scope', {**SCOPE, 'projectId': 'other-project'})):
            with self.subTest(key=key):
                self.outer = copy.deepcopy(original)
                self.outer['payload'][key] = value
                self.resign()
                with self.assertRaises(ContractError): self.resolve()

    def test_original_caller_resource_purpose_and_audience_cannot_be_replaced(self):
        original = copy.deepcopy(self.outer)
        changes = (
            lambda e: e['operation'].update(effectiveActorRef=ref('custody')),
            lambda e: e['operation'].update(expectedVersion=2),
            lambda e: e['payload'].update(resourceRef=ref('different-secret')),
            lambda e: e['payload']['input'].update(consumerRef=ref('custody')),
            lambda e: e['payload']['input'].update(purposeRef=ref('other-purpose')),
            lambda e: e.update(destinationServiceId='storage-owner'),
            lambda e: e.update(contractId='capability-storage-read'))
        for change in changes:
            self.outer = copy.deepcopy(original)
            change(self.outer['payload']['originalEnvelope'])
            self.resign()
            with self.subTest(change=change), self.assertRaises(ContractError): self.resolve()

    def test_current_revocation_of_either_proof_or_enrollment_refuses(self):
        original = copy.deepcopy(self.record)
        for collection, name in (('grants', 'ordinary-use-grant'), ('grants', 'ordinary-resolve-grant'),
                ('identities', 'human'), ('identities', 'custody'), ('identities', 'consumer'),
                ('memberships', 'ordinary-caller-member'), ('memberships', 'consumer-member'),
                ('memberships', 'custody-member'), ('transports', 'transport'),
                ('transports', 'custody-transport'), ('ordinarySecretReferences', 'ordinary-one')):
            self.record = copy.deepcopy(original)
            next(row for row in self.record['state'][collection] if row['ref']['id'] == name)['status'] = 'revoked'
            with self.subTest(collection=collection, name=name), self.assertRaises(ContractError): self.resolve()

    def test_hard_denial_of_original_or_custody_overrides_allow(self):
        original = copy.deepcopy(self.record)
        for name in ('ordinary-use-grant', 'ordinary-resolve-grant'):
            self.record = copy.deepcopy(original)
            grant = next(row for row in self.record['state']['grants'] if row['ref']['id'] == name)
            self.record['state']['grants'].append({**copy.deepcopy(grant),
                'ref': ref('ordinary-denial'), 'decision': 'denied'})
            with self.subTest(name=name), self.assertRaises(ContractError): self.resolve()

    def test_review_required_on_original_is_not_satisfied_by_custody_grant(self):
        grant = next(row for row in self.record['state']['grants'] if row['ref']['id'] == 'ordinary-use-grant')
        grant['decision'] = 'review-required'
        with self.assertRaises(ContractError): self.resolve()

    def test_exact_original_approval_allows_but_never_overrides_hard_denial(self):
        state = self.record['state']
        original = self.outer['payload']['originalEnvelope']
        grant = next(row for row in state['grants'] if row['ref']['id'] == 'ordinary-use-grant')
        grant['decision'] = 'review-required'
        approving = {**copy.deepcopy(grant), 'ref': ref('ordinary-approver-grant'),
            'contractId': 'identity-approve', 'resourceId': grant['ref']['id'], 'decision': 'allowed'}
        state['grants'].append(approving)
        approval = {'ref': ref('ordinary-approval'), 'grantRef': grant['ref'],
            'approverRef': ref('human'), 'approverGrantRef': approving['ref'],
            'payloadDigest': original['operation']['payloadDigest'],
            'audience': {'hubId': 'hub-one', 'serviceId': 'secret-owner'},
            'operationId': original['operation']['operationId'], 'expectedVersion': 1,
            'decision': 'approved', **INTERVAL}
        state['approvals'].append(approval)
        original['operation']['approvalRefs'] = [approval['ref']]
        self.resign()
        self.assertEqual(self.resolve().claims()['callerRef'], ref('human'))
        state['grants'].append({**copy.deepcopy(grant), 'ref': ref('ordinary-hard-denial'),
            'decision': 'denied'})
        with self.assertRaises(ContractError): self.resolve()

    def test_invalid_inner_signature_never_uses_custody_authority_as_a_substitute(self):
        original = self.outer['payload']['originalEnvelope']
        original['ingressAttestation']['signature'] = sign_claims({'unrelated': True}, SEED)
        self.outer['operation']['payloadDigest'] = payload_digest(self.outer['payload'])
        claims = self.outer['ingressAttestation']['claims']
        claims['operation'] = copy.deepcopy(self.outer['operation'])
        self.outer['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        with self.assertRaises(ContractError): self.resolve()

    def test_workspace_child_requires_current_exact_child_grants_and_membership(self):
        child = {**SCOPE, 'workspaceId': 'workspace-one'}
        for envelope in (self.outer, self.outer['payload']['originalEnvelope']):
            envelope['operation']['scope'] = copy.deepcopy(child)
        self.outer['payload']['scope'] = child
        state = self.record['state']
        for actor in ('human', 'custody'):
            state['memberships'].append({'ref': ref(actor+'-child-member'), 'identityRef': ref(actor),
                'scope': copy.deepcopy(child), 'status': 'active'})
        for grant in state['grants']:
            if grant['ref']['id'].startswith('ordinary-'): grant['scope'] = copy.deepcopy(child)
        self.resign()
        self.assertEqual(strict_loads(self.resolve().scope), child)
        # A parent grant does not silently authorize an ungranted child request.
        next(row for row in state['grants'] if row['ref']['id'] == 'ordinary-use-grant')['scope'] = SCOPE
        with self.assertRaises(ContractError): self.resolve()

    def test_rotation_retires_original_and_never_rebinds_generation(self):
        old = copy.deepcopy(self.record['state'])
        payload = {'authorityId': 'authority-one', 'record': ordinary_record('ordinary-two'),
            'previousRef': ref('ordinary-one')}
        after = transition(old, 'identity-ordinary-secret-set', payload, hub_id='hub-one')
        first, second = after['ordinarySecretReferences']
        self.assertEqual((first['status'], first['ref']['revision']), ('revoked', 2))
        self.assertEqual(first['generationRef'], ref('ordinary-one'))
        self.assertEqual(second['generationRef'], ref('ordinary-two'))
        self.assertEqual(old, self.record['state'])
        self.record['state'] = after
        with self.assertRaises(ContractError): self.resolve()
        for mutate in (lambda p: p['record'].update(ref=ref('ordinary-one'), generationRef=ref('ordinary-one')),
                       lambda p: p['record'].update(generationRef=ref('ordinary-one')),
                       lambda p: p['record'].update(purposeRef=ref('other-purpose'))):
            candidate = copy.deepcopy(payload); mutate(candidate)
            with self.assertRaises(ContractError):
                transition(old, 'identity-ordinary-secret-set', candidate, hub_id='hub-one')

    def test_ordinary_enrollment_cannot_carry_admin_material_or_private_fields(self):
        for key in ('secretBytes', 'path', 'reasoning', 'administratorCredentialRef'):
            payload = {'authorityId': 'authority-one', 'record': ordinary_record('ordinary-new'), 'previousRef': None}
            payload['record'][key] = 'private-value'
            with self.subTest(key=key), self.assertRaises(ContractError):
                transition(self.record['state'], 'identity-ordinary-secret-set', payload, hub_id='hub-one')
        payload = {'authorityId': 'authority-one', 'record': ordinary_record('ordinary-new'), 'previousRef': None}
        payload['record']['consumerRef'] = ref('human')
        with self.assertRaisesRegex(ContractError, 'ordinary_secret_identity_unavailable'):
            transition(self.record['state'], 'identity-ordinary-secret-set', payload, hub_id='hub-one')

    def test_enrollment_audit_is_atomic_and_expired_enrollment_is_rejected(self):
        from identity.test_commands import command_fixture
        record, template = command_fixture()
        record['state'] = ordinary_state(record['state'])
        record['state']['grants'][0]['contractId'] = 'identity-ordinary-secret-set'
        payload = {'authorityId': 'authority-one', 'record': ordinary_record(), 'previousRef': None}
        outer = signed_envelope(template, contract='identity-ordinary-secret-set', payload=payload,
            actor='human', grant='grant', scope={'organizationId': 'org-one', 'projectId': None,
                'workspaceId': None}, version=record['entityVersion'])
        prepared = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7), canonical_bytes(outer), now=NOW)
        after = strict_loads(prepared.record)
        self.assertEqual(after['authorizationDecision']['decision'], 'allowed')
        self.assertEqual(after['state']['ordinarySecretReferences'][0], payload['record'])
        payload['record']['expiresAt'] = '2026-10-09T12:00:01Z'
        outer = signed_envelope(template, contract='identity-ordinary-secret-set', payload=payload,
            actor='human', grant='grant', scope={'organizationId': 'org-one', 'projectId': None,
                'workspaceId': None}, version=record['entityVersion'])
        rejected = prepare_change(AuthoritySnapshot(canonical_bytes(record), 7), canonical_bytes(outer), now=NOW)
        self.assertEqual((rejected.decision, rejected.reason), ('denied', 'ordinary_secret_validity_invalid'))
        self.assertNotIn('ordinarySecretReferences', strict_loads(rejected.record)['state'])


class OrdinarySecretAuthorityTests(unittest.IsolatedAsyncioTestCase):
    async def test_clock_is_sampled_after_current_owner_read(self):
        record, outer, _ = resolution_fixture()
        reader = object.__new__(LedgerAuthorityReader); reader._hub = 'hub-one'
        entered = False
        async def current():
            nonlocal entered
            entered = True
            return AuthoritySnapshot(canonical_bytes(record), 17)
        reader.current = current
        with patch('identity.ordinary_secret.datetime') as clock:
            def now(tz):
                self.assertTrue(entered)
                return datetime(2026, 10, 9, 12, 11, tzinfo=timezone.utc)
            clock.now.side_effect = now
            clock.fromisoformat.side_effect = datetime.fromisoformat
            with self.assertRaises(ContractError):
                await OrdinarySecretAuthority(reader).resolve(canonical_bytes(outer))
