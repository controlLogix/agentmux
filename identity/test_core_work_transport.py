"""Exact publisher proof and current authority for preserved core work bodies."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import time
import unittest

import nkeys

from agentmux_contracts import ContractError, canonical_bytes
from identity.authority import AuthoritySnapshot
from identity.test_authority import ref
from native_security.test_nats_credentials import credential
from .core_work_transport import (INGEST, RESULT, body_route, check_snapshot,
    public_credential, signed_claims, subjects, verify_event)


def core_credential(*, publish=(), subscribe=(), change=None):
    def update(claims):
        claims['nats']['pub'] = {'allow': list(publish)} if publish else {'allow': [], 'deny': ['>']}
        claims['nats']['sub'] = {'allow': list(subscribe)} if subscribe else {'allow': [], 'deny': ['>']}
        if change:
            change(claims)
    return credential(update)


def route_fixture():
    raw, account, user = core_credential(publish=('am.work.falcon.worker', 'am.result.mac'))
    scope = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None}
    return {'routeId': 'core-remote', 'scope': scope, 'resourceRef': ref('work-one'),
        'repository': {'localName': 'falcon'}, 'localNode': 'mac', 'accountPublicKey': account,
        'workSubjects': ['am.work.falcon.worker'], 'resultSubjects': ['am.result.mac'],
        'peer': {'publishSubjects': ['am.work.falcon.worker', 'am.result.mac'], 'nodeId': 'remote', 'identityRef': ref('core-peer'),
            'transportRef': ref('core-peer-transport'), 'userPublicKey': user,
            'credentialJWT': raw.splitlines()[1].decode(),
            'grantRefs': {INGEST: ref('core-ingest'), RESULT: ref('core-result')}},
        'receiver': {'identityRef': ref('core-receiver'), 'transportRef': ref('core-receiver-transport'),
            'credentials': {'userPublicKey': user}}, 'connection': {}}, raw


def original_work():
    return {'type': 'work', 'origin': 'remote:W-original', 'origin_node': 'remote',
        'origin_id': 'W-original', 'work': {'repo': 'falcon', 'target': 'role:falcon/worker',
        'title': 'Preserved work', 'created_by': 'operator', 'body': 'Original body'}}


def signature(route, body, subject):
    key = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
    try:
        return base64.b64encode(key.sign(canonical_bytes(signed_claims(route, body, subject)))).decode()
    finally:
        key.wipe()


class CoreWorkTransportTests(unittest.TestCase):
    def test_exact_original_bytes_and_logical_role_are_signed(self):
        route, _ = route_fixture()
        item = original_work()
        # Original formatting travels unchanged; a differently formatted body is
        # a different signed publication even when its parsed values are equal.
        body = json.dumps(item, indent=2).encode()
        subject = 'am.work.falcon.worker'
        signed = signature(route, body, subject)
        verify_event(route, body, subject, signed)
        claims = signed_claims(route, body, subject)
        self.assertEqual(claims['bodySha256'], 'sha256:' + hashlib.sha256(body).hexdigest())
        self.assertEqual(claims['destination'], {'kind': 'role', 'scope': 'falcon', 'role': 'worker'})
        self.assertEqual(claims['eventId'], 'work:remote:W-original')
        self.assertEqual(body_route(route, body, subject)[0], item)
        for bad_body, bad_subject in ((canonical_bytes(item), subject), (body, 'am.work.falcon.other')):
            with self.subTest(subject=bad_subject), self.assertRaises(ContractError):
                verify_event(route, bad_body, bad_subject, signed)

    def test_publisher_node_scope_repository_key_and_result_destination_refuse(self):
        route, _ = route_fixture()
        body = canonical_bytes(original_work())
        subject = 'am.work.falcon.worker'
        signed = signature(route, body, subject)
        for field in ('node', 'scope', 'repository', 'account', 'signature', 'origin', 'target'):
            candidate, candidate_body, candidate_signature = copy.deepcopy(route), body, signed
            item = original_work()
            if field == 'node': candidate['peer']['nodeId'] = 'impostor'
            elif field == 'scope': candidate['scope']['projectId'] = 'other-project'
            elif field == 'repository': candidate['repository']['localName'] = 'other'
            elif field == 'account': candidate['accountPublicKey'] = candidate['peer']['userPublicKey']
            elif field == 'signature': candidate_signature = base64.b64encode(bytes(64)).decode()
            elif field == 'origin':
                item['origin'] = 'impostor:W-original'
                candidate_body = canonical_bytes(item)
            else:
                item['work']['target'] = 'role:falcon/other'
                candidate_body = canonical_bytes(item)
            with self.subTest(field=field), self.assertRaises(ContractError):
                verify_event(candidate, candidate_body, subject, candidate_signature)
        result = canonical_bytes({'type': 'result', 'origin_id': 'W-original', 'node': 'remote',
                                  'state': 'done', 'result': 'Original result', 'by': 'falcon-worker-one'})
        signed = signature(route, result, 'am.result.mac')
        verify_event(route, result, 'am.result.mac', signed)
        self.assertEqual(signed_claims(route, result, 'am.result.mac')['destination'],
                         {'kind': 'node', 'node': 'mac'})
        with self.assertRaises(ContractError):
            verify_event(route, result, 'am.result.other', signed)

    def test_broker_credential_rejects_wildcards_wrong_accounts_and_expiry(self):
        route, raw = route_fixture()
        kwargs = {'account': route['accountPublicKey'], 'user': route['peer']['userPublicKey'],
                  'publish': subjects(route), 'subscribe': ()}
        public_credential(raw.splitlines()[1].decode(), **kwargs)
        changes = [lambda c: c['nats']['pub'].update(allow=['am.work.>']),
            lambda c: c['nats']['pub'].update(allow=['am.work.*.worker', 'am.result.mac']),
            lambda c: c['nats'].update(resp={'max': 1, 'ttl': 5000000000}),
            lambda c: c.update(exp=int(time.time()) - 1),
            lambda c: c['nats']['sub'].update(allow=['>']),
            lambda c: c['nats'].update(bearer_token=True)]
        for change in changes:
            altered, _, _ = core_credential(publish=subjects(route), change=change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                public_credential(altered.splitlines()[1].decode(), **kwargs)

    def test_fresh_authority_refuses_revocation_replacement_deny_and_review(self):
        route, _ = route_fixture()
        now = datetime.now(timezone.utc)
        public = base64.urlsafe_b64encode(__import__('base64').b32decode(
            route['peer']['userPublicKey'])[1:-2]).decode().rstrip('=')
        state = {k: [] for k in ('identities', 'issuers', 'transports', 'memberships', 'grants', 'approvals')}
        state['organizationId'] = 'org-one'
        start, end = (now - timedelta(seconds=5)).isoformat(), (now + timedelta(seconds=60)).isoformat()
        state['identities'].append({'ref': ref('core-issuer-service'), 'kind': 'service', 'status': 'active',
                                    'principalId': 'core-issuer-service', 'externalIdentity': None})
        state['issuers'].append({'ref': ref('core-issuer'), 'identityRef': ref('core-issuer-service'),
            'status': 'active', 'issuedAt': start, 'expiresAt': end})
        for role in ('peer', 'receiver'):
            pin = route[role]
            state['identities'].append({'ref': pin['identityRef'], 'kind': 'service', 'status': 'active',
                                       'principalId': 'core-' + role, 'externalIdentity': None})
            state['transports'].append({'ref': pin['transportRef'], 'identityRef': pin['identityRef'],
                'issuerRef': ref('core-issuer'), 'method': 'nats-credential-mapping', 'publicKey': public,
                'status': 'active', 'issuedAt': start, 'expiresAt': end})
            state['memberships'].append({'ref': ref('core-' + role + '-member'), 'identityRef': pin['identityRef'],
                                        'scope': route['scope'], 'status': 'active'})
        state['grants'].append({'ref': route['peer']['grantRefs'][INGEST], 'callerRef': route['peer']['identityRef'],
            'actorRef': route['peer']['identityRef'], 'scope': route['scope'], 'resourceId': 'work-one',
            'contractId': INGEST, 'decision': 'allowed', 'delegationRef': None, 'status': 'active',
            'issuedAt': start, 'expiresAt': end})
        def snapshot(value):
            return AuthoritySnapshot(canonical_bytes({'ownerHubId': 'hub-one', 'state': value}), 3)
        deadline = check_snapshot(route, snapshot(state), INGEST, now=now)
        self.assertLessEqual(deadline, now + timedelta(seconds=5))
        for kind in ('identity', 'transport', 'issuer', 'membership', 'grant', 'deny', 'review', 'replacement'):
            changed = copy.deepcopy(state)
            if kind == 'identity': changed['identities'][1]['status'] = 'revoked'
            elif kind == 'transport': changed['transports'][0]['status'] = 'revoked'
            elif kind == 'issuer': changed['issuers'][0]['status'] = 'revoked'
            elif kind == 'membership': changed['memberships'][0]['status'] = 'revoked'
            elif kind == 'grant': changed['grants'][0]['status'] = 'revoked'
            elif kind == 'deny':
                denied = copy.deepcopy(changed['grants'][0])
                denied.update(ref=ref('core-deny'), decision='denied')
                changed['grants'].append(denied)
            elif kind == 'review': changed['grants'][0]['decision'] = 'review-required'
            else: changed['transports'][0]['ref']['revision'] += 1
            with self.subTest(kind=kind), self.assertRaises(ContractError):
                check_snapshot(route, snapshot(changed), INGEST, now=now)
