"""Private-file and real credential checks; the network client is injected."""
import asyncio
import base64
import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ssl
import tempfile
import time
from types import SimpleNamespace
from urllib.parse import urlsplit
import unittest
from unittest.mock import AsyncMock, Mock, patch

from hub import client_launch_enrollment as enrollment
from agentmux_contracts import strict_loads, payload_digest, canonical_bytes, sign_claims
from identity.application_client import ApplicationClientKey
from hub.tests import test_client_launch_binding as binding_tests
from native_security.test_nats_credentials import credential


class ClientLaunchEnrollment(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.root.chmod(0o700)
        self.selection = SimpleNamespace(hub_id='hub-one', profile_id='profile-one', instance_id='instance-one',
                                        invocation=SimpleNamespace(workspaces=(str(self.root / 'project'),)))
        fixture = binding_tests.ClientLaunchBinding()
        fixture.setUp()
        pins = {key: fixture.request[key] for key in ('hubId', 'profileId', 'authorityId', 'instanceId',
            'releaseDigest', 'policyRef', 'workspaceRef', 'transportRef', 'grantRef')}
        pins.update(callerRef=binding_tests.ref('caller'), scope=fixture.scope,
                    replyIssuerRef=binding_tests.ref('issuer'), replyIssuerPublicKey=fixture.state._public_key)
        self.signer = ApplicationClientKey({**pins, 'purpose': 'agentmux-application-client-key-v1',
                                           'seed': base64.b64encode(binding_tests.SEED).decode()})
        self.command = 'amx.v1.h.hub-one.o.org-one.identity.authority-one.command'
        self.prefix = '_INBOX.application_000001'
        def permissions(claims):
            claims['nats']['pub']['allow'] = [self.command]
            claims['nats']['sub']['allow'] = [self.prefix + '.>']
        raw, account, user = credential(permissions)
        self.creds = self.root / 'client.creds'
        self.creds.write_bytes(raw)
        self.creds.chmod(0o600)
        # A public CA is test input only. Production never loads system roots.
        cert = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
        self.policy = {'schemaVersion': '1.0.0', 'endpoint': 'tls://127.0.0.1:4222',
            'serverName': 'agentmux.local', 'rootsPEM': ssl.DER_cert_to_PEM_cert(cert),
            'leafCertificateSHA256': 'sha256:' + 'a' * 64, 'credentialsFile': str(self.creds),
            'accountPublicKey': account, 'userPublicKey': user, 'replyPrefix': self.prefix}
        self.path = self.root / 'connection.json'
        self.write()
        self.native = patch('hub.client_launch_enrollment.native.check_descriptor', return_value=True)
        self.native.start()
        self.addCleanup(self.native.stop)

    def write(self):
        self.path.write_text(json.dumps(self.policy))
        self.path.chmod(0o600)

    def deadline(self):
        return asyncio.get_running_loop().time() + 4

    def client(self):
        client = SimpleNamespace(is_connected=False)
        client.requests, client.subscriptions, client.subjects = [], [], []
        async def connect(**options):
            client.options = options
            self.assertTrue(options['user_jwt_cb']())
            self.assertEqual(len(options['signature_cb']('test-nonce')), 88)
            client.is_connected = True
        async def close():
            client.is_connected = False
        async def publish(subject, raw, **options):
            from hub.client_launch_connection import selected_publish_subjects
            allowed = selected_publish_subjects(self.signer)
            patterns = [value for value in allowed if '*' in value]
            self.assertTrue(subject in allowed or any(
                subject.startswith(pattern.split('*', 1)[0])
                and subject.endswith(pattern.split('*', 1)[1]) for pattern in patterns))
            client.subjects.append(subject)
            client.requests.append(raw)
        async def subscribe(subject, **options):
            async def next_msg(**_):
                request = strict_loads(client.requests[-1])
                wanted = request['claims']
                if wanted['purpose'] == 'agentmux-client-possession-v1':
                    hook = getattr(self, 'query_hook', None)
                    if hook is not None:
                        await hook()
                    if wanted['contractId'] == 'identity-legacy-alias-resolve':
                        sequence = getattr(self, 'legacy_authority_sequence', 1)
                        scope = getattr(self, 'legacy_scope', self.signer.selection['scope'])
                        bindings = []
                        remote = 'remoteAddress' in wanted['payload']
                        registrations = ([{'legacyAlias': None,
                            'agent': wanted['payload']['remoteAddress'].rsplit('-', 1)[-1],
                            'canonicalSession': wanted['payload']['remoteAddress'][6:],
                            'registrationGeneration': 7}] if remote
                            else wanted['payload']['registrations'])
                        for registration in registrations:
                            bindings.append({'alias': registration['legacyAlias'] or 'old-' + registration['agent'],
                                'canonicalSession': registration['canonicalSession'],
                                'sourceHubId': 'remote-hub' if remote else self.signer.selection['hubId'],
                                'registrationGeneration': registration['registrationGeneration'],
                                'identityRef': self.signer.selection['callerRef'], 'scope': scope,
                                'instanceOwner': None, 'aliasRef': binding_tests.ref('legacy-alias'),
                                'authoritySequence': sequence})
                        selector = ({'remoteAddress': wanted['payload']['remoteAddress']} if remote
                                    else {'registrations': wanted['payload']['registrations']})
                        claims = {'purpose': 'agentmux-legacy-alias-resolution-v1',
                            **{k:wanted[k] for k in ('hubId','profileId','authorityId')},
                            'issuerRef': self.signer.selection['legacyAliasResolve']['replyIssuerRef'],
                            'requestDigest': payload_digest(request), 'operationId': wanted['operationId'],
                            'callerRef': self.signer.selection['callerRef'], 'scope': scope,
                            **selector, 'bindings': bindings,
                            'authoritySequence': sequence, 'issuedAt': wanted['issuedAt'],
                            'validUntil': wanted['expiresAt']}
                        return SimpleNamespace(subject=subject, data=canonical_bytes({
                            'schemaVersion':'1.0.0', 'algorithm':'Ed25519',
                            'canonicalization':'RFC8785-JCS-UTF8', 'claims':claims,
                            'signature':sign_claims(claims, binding_tests.SEED)}))
                    original_id = (wanted['operationId'] if wanted['contractId'] == 'integration-intent'
                                   else wanted['payload']['originalOperationId'])
                    original_digest = (payload_digest(wanted['payload'])
                                       if wanted['contractId'] == 'integration-intent'
                                       else wanted['payload']['originalPayloadDigest'])
                    receipt = {'operationId': wanted['operationId'],
                        'originalOperationId': original_id,
                        'originalPayloadDigest': original_digest,
                        'sequence': 1, 'attemptOperationId': None, 'phase': 'intent-committed'}
                    selected_route = ('integrationEffectCommands'
                        if wanted['transportRef'] == self.signer.selection.get(
                            'integrationEffectCommands', {}).get('transportRef')
                        else 'integrationEffectQuery')
                    claims = {'purpose': 'agentmux-integration-command-receipt-v1',
                        **{k:wanted[k] for k in ('hubId','profileId','authorityId')},
                        'issuerRef': self.signer.selection[selected_route]['replyIssuerRef'],
                        'requestDigest': payload_digest(request), 'receipt': receipt}
                    signature = sign_claims(claims, bytes([9])*32)
                    if getattr(self, 'bad_query_signature', False):
                        signature = 'A'*86
                    return SimpleNamespace(subject=subject, data=canonical_bytes({
                        'schemaVersion':'1.0.0', 'claims':claims, 'signature':signature}))
                discovery = wanted['purpose'] == 'agentmux-application-discovery-request-v1'
                claims = {key: value for key, value in wanted.items()
                          if key not in ('purpose', 'replySubject', 'expiresAt')}
                claims.update(purpose='agentmux-application-' + ('discovery' if discovery else 'binding') + '-response-v1',
                    generation=getattr(self, 'binding_generation', 3),
                    lifetimeId=getattr(self, 'binding_lifetime', 'f' * 64),
                    requestDigest=payload_digest(wanted),
                    callerRef=self.signer.selection['callerRef'], scope=self.signer.selection['scope'],
                    signingKeyRef=self.signer.selection['replyIssuerRef'], authorityRef=binding_tests.ref('authority-one'),
                    authoritySequence=1, validUntil=wanted['expiresAt'])
                return SimpleNamespace(subject=subject, data=binding_tests.signed(claims))
            sub = SimpleNamespace(next_msg=AsyncMock(side_effect=next_msg), unsubscribe=AsyncMock())
            client._agentmux_session.own_subscription(sub)
            client.subscriptions.append(sub)
            return sub
        client.connect, client.close = AsyncMock(side_effect=connect), AsyncMock(side_effect=close)
        client.publish, client.subscribe, client.flush = AsyncMock(side_effect=publish), AsyncMock(side_effect=subscribe), AsyncMock()
        return client

    async def open(self):
        return await enrollment.open_application_client(str(self.root / 'key.json'), str(self.path),
            selected=self.selection, deadline=self.deadline(), cleanup_deadline=self.deadline())

    def enroll_query(self):
        from integration_owner.intent import effect_id
        from nacl.signing import SigningKey
        material = strict_loads(self.signer._material)
        material['scope']['projectId'] = 'project-one'
        effect = effect_id(material['scope'], 'original-one')
        self.query_subject = 'amx.v1.h.hub-one.o.org-one.integrations.'+effect+'.command'
        material['integrationEffectQuery'] = {'subject':self.query_subject,
            'grantRef':binding_tests.ref('query-grant'), 'transportRef':binding_tests.ref('query-transport'),
            'originalOperationId':'original-one', 'originalPayloadDigest':'sha256:'+'b'*64,
            'replyIssuerRef':binding_tests.ref('integration-issuer'),
            'replyIssuerPublicKey':base64.urlsafe_b64encode(bytes(SigningKey(bytes([9])*32).verify_key)).decode().rstrip('=')}
        self.signer = ApplicationClientKey(material)
        self.query_credentials([self.command,self.query_subject])

    def enroll_legacy_alias_query(self):
        from hub.client_launch_connection import selected_publish_subjects
        material = strict_loads(self.signer._material)
        material['scope']['projectId'] = 'project-one'
        material['legacyAliasResolve'] = {'subject':self.command,
            'grantRef':binding_tests.ref('legacy-grant'),
            'transportRef':binding_tests.ref('legacy-transport'),
            'replyIssuerRef':material['replyIssuerRef'],
            'replyIssuerPublicKey':material['replyIssuerPublicKey']}
        self.signer = ApplicationClientKey(material)
        self.query_credentials(list(selected_publish_subjects(self.signer)))

    def enroll_commands(self):
        from nacl.signing import SigningKey
        from hub.client_launch_connection import selected_publish_subjects
        material = strict_loads(self.signer._material)
        material['scope']['projectId'] = 'project-one'
        material['integrationEffectCommands'] = {
            'contracts': ['integration-intent', 'integration-effect-query',
                'integration-attempt-start', 'integration-attempt-complete',
                'integration-effect-reconcile'],
            'transportRef': binding_tests.ref('integration-command-transport'),
            'replyIssuerRef': binding_tests.ref('integration-issuer'),
            'replyIssuerPublicKey': base64.urlsafe_b64encode(
                bytes(SigningKey(bytes([9]) * 32).verify_key)).decode().rstrip('=')}
        self.signer = ApplicationClientKey(material)
        self.query_credentials(list(selected_publish_subjects(self.signer)))

    def query_credentials(self, subjects):
        def permissions(claims):
            claims['nats']['pub']['allow'] = subjects
            claims['nats']['sub']['allow'] = [self.prefix+'.>']
        raw, account, user = credential(permissions)
        self.creds.write_bytes(raw)
        self.policy.update(accountPublicKey=account,userPublicKey=user)
        self.write()

    async def open_query(self):
        self.enroll_query()
        client = self.client()
        with patch('identity.application_client.load_application_client', return_value=self.signer), \
                patch('hub.nats_transport.new_client', return_value=client):
            owner = await self.open()
        async def close():
            await owner.close(deadline=self.deadline())
        self.addAsyncCleanup(close)
        return owner, client

    async def test_query_uses_exact_enrolled_route_and_same_bound_connection(self):
        owner, client = await self.open_query()
        receipt = await owner.query_integration_effect(operation_id='query-one', expected_version=1,
            deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(receipt['phase'],'intent-committed')
        self.assertEqual(client.subjects,[self.command,self.command,self.query_subject])
        self.assertEqual(owner.command_request,client.requests[-1])
        claims = strict_loads(owner.command_request)['claims']
        self.assertEqual(claims['transportRef'],binding_tests.ref('query-transport'))
        self.assertEqual(claims['grantRef'],binding_tests.ref('query-grant'))
        self.assertEqual(len({strict_loads(raw)['claims']['replySubject'] for raw in client.requests}),3)
        client.connect.assert_awaited_once()
        self.assertFalse(owner._subscriptions)

    async def test_dynamic_query_uses_exact_request_subject_and_scoped_broker_pattern(self):
        from integration_owner.intent import effect_id
        from hub.client_launch_connection import ConnectionFailure
        self.enroll_commands()
        client = self.client()
        with patch('identity.application_client.load_application_client', return_value=self.signer), \
                patch('hub.nats_transport.new_client', return_value=client):
            owner = await self.open()
        self.addAsyncCleanup(owner.close, deadline=self.deadline())
        selected = self.signer.selection
        original = 'fresh-operation'
        digest = 'sha256:' + 'b' * 64
        effect = effect_id(selected['scope'], original)
        receipt = await owner.integration_command(contract_id='integration-effect-query',
            operation_id='query-fresh-operation', expected_version=1,
            grant_ref=binding_tests.ref('fresh-query-grant'), approval_refs=[],
            payload={'effectRef': {'id': effect, 'ownerHubId': 'hub-one', 'revision': 1},
                'originalOperationId': original, 'originalPayloadDigest': digest},
            deadline=self.deadline(), cleanup_deadline=self.deadline())
        subject = self.signer.command_subject('integration-effect-query', original)
        self.assertEqual((receipt['originalOperationId'], receipt['originalPayloadDigest']),
                         (original, digest))
        self.assertEqual(client.subjects[-1], subject)
        self.assertEqual(owner.command_request, client.requests[-1])
        self.assertIn('amx.v1.h.hub-one.o.org-one.integrations.*.command',
                      owner._publish_subjects)
        wrong = subject.replace(effect, 'effect-' + 'f' * 64)
        published = len(client.subjects)
        with self.assertRaisesRegex(ConnectionFailure, '^application_request_refused$'):
            await owner._exchange(owner.command_request, subject=wrong,
                deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(len(client.subjects), published)

    async def test_legacy_alias_query_composes_with_integration_route_and_current_binding(self):
        self.enroll_query()
        self.enroll_legacy_alias_query()
        client = self.client()
        with patch('identity.application_client.load_application_client', return_value=self.signer), \
                patch('hub.nats_transport.new_client', return_value=client):
            owner = await self.open()
        self.addAsyncCleanup(owner.close, deadline=self.deadline())
        registration = {'requestedAddress':'agent:alpha-worker-w1',
            'canonicalSession':'alpha-worker-w1', 'registrationGeneration':3,
            'repository':'alpha', 'role':'worker', 'agent':'w1',
            'state':'ready', 'legacyAlias':None}
        resolution = await owner.query_legacy_aliases(registrations=[registration],
            operation_id='resolve-legacy-one', deadline=self.deadline(), cleanup_deadline=self.deadline())
        receipt = await owner.query_integration_effect(operation_id='query-one', expected_version=1,
            deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual((resolution.bindings[0].alias, resolution.bindings[0].canonical_session,
                          strict_loads(resolution.bindings[0].instance_owner)),
                         ('old-w1', 'alpha-worker-w1', None))
        self.assertGreater(resolution.valid_until, datetime.now(timezone.utc))
        self.assertEqual(receipt['phase'], 'intent-committed')
        self.assertEqual(client.subjects,
            [self.command, self.command, self.command, self.query_subject])
        alias_claims = strict_loads(client.requests[2])['claims']
        self.assertEqual((alias_claims['contractId'], alias_claims['expectedVersion'],
                          alias_claims['approvalRefs'], alias_claims['payload']),
            ('identity-legacy-alias-resolve', 0, [],
             {'authorityId':'authority-one', 'registrations':[registration]}))
        self.assertFalse(owner._subscriptions)

    async def test_expired_binding_renews_on_same_owner_before_new_alias_operation(self):
        self.enroll_legacy_alias_query()
        client = self.client()
        with patch('identity.application_client.load_application_client', return_value=self.signer), \
                patch('hub.nats_transport.new_client', return_value=client):
            owner = await self.open()
        self.addAsyncCleanup(owner.close, deadline=self.deadline())
        bound = strict_loads(owner.binding._binding)
        bound['validUntil'] = (datetime.now(timezone.utc) -
                               timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
        owner.binding._binding = canonical_bytes(bound)
        registration = {'requestedAddress': 'agent:alpha-worker-w1',
            'canonicalSession': 'alpha-worker-w1', 'registrationGeneration': 3,
            'repository': 'alpha', 'role': 'worker', 'agent': 'w1',
            'state': 'ready', 'legacyAlias': None}
        resolution = await owner.query_legacy_aliases(registrations=[registration],
            operation_id='resolve-after-expiry', deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(resolution.bindings[0].canonical_session, 'alpha-worker-w1')
        self.assertEqual(len(client.requests), 5)
        self.assertEqual(owner._binding_identity, (3, 'f' * 64))

    async def test_expired_binding_refuses_changed_lifetime_and_revoked_renewal(self):
        from hub.client_launch_connection import ConnectionFailure
        for case in ('lifetime', 'revoked'):
            with self.subTest(case=case):
                self.enroll_legacy_alias_query()
                client = self.client()
                with patch('identity.application_client.load_application_client', return_value=self.signer), \
                        patch('hub.nats_transport.new_client', return_value=client):
                    owner = await self.open()
                bound = strict_loads(owner.binding._binding)
                bound['validUntil'] = (datetime.now(timezone.utc) -
                    timedelta(seconds=1)).isoformat().replace('+00:00', 'Z')
                owner.binding._binding = canonical_bytes(bound)
                if case == 'lifetime':
                    self.binding_lifetime = 'e' * 64
                else:
                    client.subscribe.side_effect = OSError('synthetic-revoked')
                with self.assertRaises(ConnectionFailure):
                    await owner.query_legacy_aliases(registrations=[{
                        'requestedAddress': 'agent:alpha-worker-w1',
                        'canonicalSession': 'alpha-worker-w1', 'registrationGeneration': 3,
                        'repository': 'alpha', 'role': 'worker', 'agent': 'w1',
                        'state': 'ready', 'legacyAlias': None}], operation_id='resolve-refused',
                        deadline=self.deadline(), cleanup_deadline=self.deadline())
                client.close.assert_awaited_once()
                self.binding_lifetime = 'f' * 64

    async def test_legacy_alias_query_rejects_stale_epoch_scope_and_authority(self):
        from hub.client_launch_connection import ConnectionFailure
        self.enroll_legacy_alias_query()
        for case in ('epoch', 'scope', 'authority'):
            with self.subTest(case=case):
                client = self.client()
                with patch('identity.application_client.load_application_client', return_value=self.signer), \
                        patch('hub.nats_transport.new_client', return_value=client):
                    owner = await self.open()
                if case == 'epoch':
                    async def invalidate():
                        owner.binding.invalidate()
                    self.query_hook = invalidate
                elif case == 'scope':
                    self.legacy_scope = {'organizationId':'org-one',
                        'projectId':'other-project', 'workspaceId':None}
                else:
                    current = strict_loads(owner.binding._binding)
                    current['authoritySequence'] = 2
                    owner.binding._binding = canonical_bytes(current)
                    self.legacy_authority_sequence = 1
                registration = {'requestedAddress':'agent:alpha-worker-w1',
                    'canonicalSession':'alpha-worker-w1', 'registrationGeneration':3,
                    'repository':'alpha', 'role':'worker', 'agent':'w1',
                    'state':'ready', 'legacyAlias':None}
                with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
                    await owner.query_legacy_aliases(registrations=[registration],
                        operation_id='resolve-legacy-one', deadline=self.deadline(),
                        cleanup_deadline=self.deadline())
                client.close.assert_awaited_once()
                for name in ('query_hook', 'legacy_scope', 'legacy_authority_sequence'):
                    if hasattr(self, name):
                        delattr(self, name)

    async def test_remote_legacy_alias_query_uses_only_signed_address_selector(self):
        self.enroll_legacy_alias_query()
        client = self.client()
        with patch('identity.application_client.load_application_client', return_value=self.signer), \
                patch('hub.nats_transport.new_client', return_value=client):
            owner = await self.open()
        self.addAsyncCleanup(owner.close, deadline=self.deadline())
        resolution = await owner.query_legacy_aliases(
            remote_address='agent:alpha-worker-w1', operation_id='resolve-remote-one',
            deadline=self.deadline(), cleanup_deadline=self.deadline())
        self.assertEqual(len(resolution.bindings), 1)
        binding = resolution.bindings[0]
        self.assertEqual((binding.canonical_session, binding.source_hub_id,
                          binding.registration_generation, binding.local),
                         ('alpha-worker-w1', 'remote-hub', 7, False))
        claims = strict_loads(owner.command_request)['claims']
        self.assertEqual(claims['payload'], {'authorityId':'authority-one',
            'remoteAddress':'agent:alpha-worker-w1'})
        self.assertNotIn('registrations', claims['payload'])
        self.assertGreater(resolution.valid_until, datetime.now(timezone.utc))
        self.assertFalse(owner._subscriptions)

    async def test_legacy_alias_connection_refuses_missing_or_mixed_selector(self):
        from hub.client_launch_connection import ConnectionFailure
        self.enroll_legacy_alias_query()
        registration = {'requestedAddress':'agent:alpha-worker-w1',
            'canonicalSession':'alpha-worker-w1', 'registrationGeneration':3,
            'repository':'alpha', 'role':'worker', 'agent':'w1',
            'state':'ready', 'legacyAlias':None}
        for selector in ({}, {'registrations':[registration],
                              'remote_address':'agent:alpha-worker-w1'}):
            with self.subTest(selector=selector):
                client = self.client()
                with patch('identity.application_client.load_application_client', return_value=self.signer), \
                        patch('hub.nats_transport.new_client', return_value=client):
                    owner = await self.open()
                with self.assertRaisesRegex(ConnectionFailure, '^application_command_unconfirmed$'):
                    await owner.query_legacy_aliases(**selector,
                        operation_id='resolve-one', deadline=self.deadline(),
                        cleanup_deadline=self.deadline())
                client.close.assert_awaited_once()

    async def test_session_query_composes_with_actual_connection_owner(self):
        from hub.client_launch_session import ApplicationClientSession
        self.enroll_query()
        self.selection.application_client = str(self.root / 'key.json')
        self.selection.application_connection = str(self.path)
        client = self.client()
        session = ApplicationClientSession(self.selection)
        try:
            with patch('identity.application_client.load_application_client', return_value=self.signer), \
                    patch('hub.nats_transport.new_client', return_value=client):
                session.start(deadline=time.monotonic()+4)
                self.assertTrue(session.query_enabled())
                receipt = session.query_effect({'operationId':'query-one','expectedVersion':1},
                    deadline=time.monotonic()+4)
            self.assertEqual(receipt['phase'],'intent-committed')
            self.assertEqual(client.subjects,[self.command,self.command,self.query_subject])
            self.assertEqual(session._owner.command_request,client.requests[-1])
            client.connect.assert_awaited_once()
        finally:
            self.assertTrue(session.close(deadline=time.monotonic()+4))
            session.join_final()
        client.close.assert_awaited_once()

    async def test_session_legacy_alias_query_retains_verified_expiry(self):
        from hub.client_launch_session import ApplicationClientSession
        self.enroll_legacy_alias_query()
        self.selection.application_client = str(self.root / 'key.json')
        self.selection.application_connection = str(self.path)
        client = self.client()
        session = ApplicationClientSession(self.selection)
        registration = {'requestedAddress':'agent:alpha-worker-w1',
            'canonicalSession':'alpha-worker-w1', 'registrationGeneration':3,
            'repository':'alpha', 'role':'worker', 'agent':'w1',
            'state':'ready', 'legacyAlias':None}
        try:
            with patch('identity.application_client.load_application_client', return_value=self.signer), \
                    patch('hub.nats_transport.new_client', return_value=client):
                session.start(deadline=time.monotonic()+4)
                self.assertTrue(session.legacy_alias_query_enabled())
                local_resolution = session.query_legacy_aliases([registration],
                    operation_id='resolve-legacy-one', deadline=time.monotonic()+4)
                remote_resolution = session.query_legacy_aliases(
                    remote_address='agent:alpha-worker-w1', operation_id='resolve-remote-one',
                    deadline=time.monotonic()+4)
            self.assertEqual(local_resolution.bindings[0].canonical_session, 'alpha-worker-w1')
            self.assertTrue(local_resolution.bindings[0].local)
            self.assertGreater(local_resolution.valid_until, datetime.now(timezone.utc))
            self.assertEqual(remote_resolution.bindings[0].canonical_session, 'alpha-worker-w1')
            self.assertFalse(remote_resolution.bindings[0].local)
            self.assertGreater(remote_resolution.valid_until, datetime.now(timezone.utc))
            self.assertEqual(client.subjects, [self.command, self.command, self.command, self.command])
            self.assertEqual(session._owner.command_request, client.requests[-1])
            client.connect.assert_awaited_once()
        finally:
            self.assertTrue(session.close(deadline=time.monotonic()+4))
            session.join_final()
        client.close.assert_awaited_once()

    async def test_query_permissions_must_be_exact_before_connection_allocation(self):
        self.enroll_query()
        for subjects in ([self.command], [self.command,self.query_subject,'extra.command'],
                         [self.command,'>'], [self.command,self.query_subject,self.query_subject]):
            self.query_credentials(subjects)
            with patch('identity.application_client.load_application_client',return_value=self.signer), \
                    patch('hub.nats_transport.new_client') as allocate:
                with self.assertRaises(enrollment.SelectionError):
                    await self.open()
                allocate.assert_not_called()

    async def test_query_disconnect_before_publish_does_not_send(self):
        from hub.client_launch_connection import ConnectionFailure
        owner, client = await self.open_query()
        # flush receives a timeout keyword; keep the callback's signature explicit.
        async def disconnect(**_):
            await owner.disconnected()
        client.flush.side_effect = disconnect
        with self.assertRaises(ConnectionFailure):
            await owner.query_integration_effect(operation_id='query-one',expected_version=1,
                deadline=self.deadline(),cleanup_deadline=self.deadline())
        self.assertEqual(client.subjects,[self.command,self.command])
        self.assertIsNotNone(owner.command_request)
        client.close.assert_awaited_once()

    async def test_cancelled_query_joins_subscription_and_original_close(self):
        from hub.client_launch_connection import ConnectionFailure
        owner, client = await self.open_query()
        entered, released = asyncio.Event(), asyncio.Event()
        async def hold_reply():
            entered.set()
            await released.wait()
        self.query_hook = hold_reply
        caller = asyncio.create_task(owner.query_integration_effect(operation_id='query-one',expected_version=1,
            deadline=self.deadline(),cleanup_deadline=self.deadline()))
        await entered.wait()
        caller.cancel()
        with self.assertRaises(ConnectionFailure):
            await caller
        self.assertTrue(owner._exchange_task.done())
        self.assertFalse(owner._subscriptions)
        self.assertIsNotNone(owner.command_request)
        client.close.assert_awaited_once()
        for subscription in client.subscriptions:
            subscription.unsubscribe.assert_awaited_once()

    async def test_query_binding_expiry_before_publish_and_after_reply_is_refused(self):
        from hub.client_launch_connection import ConnectionFailure
        for stage in ('before-publish', 'after-reply'):
            with self.subTest(stage=stage):
                owner, client = await self.open_query()
                bound = owner.binding.current(client, now=datetime.now(timezone.utc))
                expiry = datetime.fromisoformat(bound['validUntil'])
                with patch('hub.client_launch_connection.datetime', wraps=datetime) as clock:
                    clock.now.side_effect = lambda _: datetime.now(timezone.utc)
                    async def expire(**_):
                        clock.now.side_effect = None
                        clock.now.return_value = expiry
                    if stage == 'before-publish':
                        client.flush.side_effect = expire
                    else:
                        self.query_hook = expire
                    with self.assertRaises(ConnectionFailure):
                        await owner.query_integration_effect(operation_id='query-one',expected_version=1,
                            deadline=self.deadline(),cleanup_deadline=self.deadline())
                self.assertEqual(len(client.requests), 2 if stage == 'before-publish' else 3)
                self.assertIsNotNone(owner.command_request)
                self.assertFalse(owner._subscriptions)
                client.close.assert_awaited_once()

    async def test_query_binding_expiry_during_verification_is_refused(self):
        from hub.client_launch_connection import ConnectionFailure
        owner, client = await self.open_query()
        bound = owner.binding.current(client, now=datetime.now(timezone.utc))
        expiry = datetime.fromisoformat(bound['validUntil'])
        verify = self.signer.verify_command_response
        with patch('hub.client_launch_connection.datetime', wraps=datetime) as clock:
            clock.now.side_effect = lambda _: datetime.now(timezone.utc)
            def verify_at_expiry(*args, **kwargs):
                clock.now.side_effect = None
                clock.now.return_value = expiry
                return verify(*args, **kwargs)
            with patch.object(self.signer, 'verify_command_response', side_effect=verify_at_expiry) as verified:
                with self.assertRaises(ConnectionFailure) as failure:
                    await owner.query_integration_effect(operation_id='query-one', expected_version=1,
                        deadline=self.deadline(), cleanup_deadline=self.deadline())
                verified.assert_called_once()
        self.assertEqual(str(failure.exception), 'application_command_unconfirmed')
        self.assertEqual(client.requests[-1], owner.command_request)
        self.assertFalse(owner._subscriptions)
        client.close.assert_awaited_once()

    async def test_query_deadline_crossing_during_verification_is_refused(self):
        from hub.client_launch_connection import ConnectionFailure
        owner, client = await self.open_query()
        verify, real_time = self.signer.verify_command_response, owner._loop.time
        deadline = real_time() + 4
        offset = 0
        def verify_after_deadline(*args, **kwargs):
            nonlocal offset
            offset = 4
            return verify(*args, **kwargs)
        with patch.object(owner._loop, 'time', side_effect=lambda: real_time()+offset), \
                patch.object(self.signer, 'verify_command_response', side_effect=verify_after_deadline) as verified:
            with self.assertRaises(ConnectionFailure) as failure:
                await owner.query_integration_effect(operation_id='query-one', expected_version=1,
                    deadline=deadline, cleanup_deadline=deadline+4)
            verified.assert_called_once()
        self.assertEqual(str(failure.exception), 'application_command_unconfirmed')
        self.assertEqual(client.requests[-1], owner.command_request)
        self.assertFalse(owner._subscriptions)
        client.close.assert_awaited_once()

    async def test_query_rejects_bad_receipt_and_binding_loss_before_return(self):
        from hub.client_launch_connection import ConnectionFailure
        owner, client = await self.open_query()
        async def lose_binding():
            owner.binding.invalidate()
        self.query_hook = lose_binding
        with self.assertRaises(ConnectionFailure):
            await owner.query_integration_effect(operation_id='query-one',expected_version=1,
                deadline=self.deadline(),cleanup_deadline=self.deadline())
        client.close.assert_awaited_once()

    async def test_query_rejects_untrusted_receipt_signature(self):
        from hub.client_launch_connection import ConnectionFailure
        owner, client = await self.open_query()
        self.bad_query_signature = True
        with self.assertRaises(ConnectionFailure):
            await owner.query_integration_effect(operation_id='query-one',expected_version=1,
                deadline=self.deadline(),cleanup_deadline=self.deadline())
        client.close.assert_awaited_once()

    async def test_fixed_factory_uses_real_account_guard_and_preconnect_leaf_pin(self):
        client = self.client()
        with patch('identity.application_client.load_application_client', return_value=self.signer), \
                patch('hub.nats_transport.new_client', return_value=client) as allocate:
            owner = await self.open()
        allocate.assert_called_once_with(require_tls=True, leaf_certificate_sha256=self.policy['leafCertificateSHA256'])
        self.assertEqual(len(client.requests), 2)
        self.assertEqual(client.options['servers'], [self.policy['endpoint']])
        self.assertEqual(client.options['tls_hostname'], self.policy['serverName'])
        self.assertIs(client.options['tls_handshake_first'], True)
        self.assertEqual(client.options['tls'].minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(client.options['tls'].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(client.options['tls'].check_hostname)
        self.assertEqual(len(client.options['tls'].get_ca_certs()), 1)
        await owner.close(deadline=self.deadline())
        client.close.assert_awaited_once()

    async def test_wrong_account_or_selected_user_never_allocates_connection(self):
        for field, value in (('accountPublicKey', 'A' * 56), ('userPublicKey', 'U' * 56)):
            original = self.policy[field]
            self.policy[field] = value
            self.write()
            with patch('identity.application_client.load_application_client', return_value=self.signer), \
                    patch('hub.nats_transport.new_client') as allocate:
                with self.assertRaises(enrollment.SelectionError):
                    await self.open()
            allocate.assert_not_called()
            self.policy[field] = original

    async def test_nonlocal_endpoint_extra_fields_and_unsafe_private_file_are_refused(self):
        for mutate in ('endpoint', 'extra', 'permissions'):
            original = dict(self.policy)
            if mutate == 'endpoint':
                self.policy['endpoint'] = 'tls://example.invalid:4222'
            elif mutate == 'extra':
                self.policy['extra'] = 'PRIVATE_SENTINEL'
            self.write()
            if mutate == 'permissions':
                self.path.chmod(0o644)
            with self.assertRaises(enrollment.SelectionError) as error:
                enrollment.load_connection_selection(str(self.path), workspaces=self.selection.invocation.workspaces,
                                                      deadline=self.deadline())
            self.assertNotIn('PRIVATE_SENTINEL', str(error.exception))
            self.policy = original

    async def test_workspace_connection_selection_is_refused_before_read(self):
        with self.assertRaises(enrollment.SelectionError):
            enrollment.load_connection_selection(str(self.root / 'project' / 'connection.json'),
                workspaces=self.selection.invocation.workspaces, deadline=self.deadline())

    async def test_production_options_use_tls_first_in_actual_pinned_client_connect(self):
        from hub.nats_transport import new_client, PairedTCPTransport
        certificate = b'controlled peer DER bytes for ordering check'
        matching = 'sha256:' + hashlib.sha256(certificate).hexdigest()
        selected = enrollment.ApplicationConnectionSelection(json.dumps(self.policy).encode(), b'')
        for pin in ('sha256:' + '0' * 64, matching):
            with self.subTest(matches=pin == matching):
                client = new_client(require_tls=True, leaf_certificate_sha256=pin)
                peer = SimpleNamespace(getpeercert=lambda **_: certificate)
                writer = SimpleNamespace(_reader=None, _protocol=SimpleNamespace(), transport=object(),
                    start_tls=AsyncMock(), get_extra_info=lambda _: peer,
                    wait_closed=AsyncMock(), close=Mock())
                responses = iter((b'INFO {"tls_required":true,"auth_required":true,"nonce":"fixture_nonce"}\r\n',
                                  b'PONG\r\n'))
                async def readline():
                    # This fixture models the real broker's TLS-first contract:
                    # no plaintext INFO is available before the TLS handshake.
                    writer.start_tls.assert_awaited_once()
                    return next(responses)
                raw = SimpleNamespace(_io_writer=writer, readline=AsyncMock(side_effect=readline),
                    drain=AsyncMock(), write=Mock(), close=Mock())
                transport = PairedTCPTransport(raw, True, pin)
                async def select_server():
                    client._transport = transport
                    client._current_server = SimpleNamespace(uri=urlsplit(self.policy['endpoint']),
                                                             tls_name=None, reconnects=0)
                client._select_next_server = select_server
                client._read_loop, client._ping_interval, client._flusher = AsyncMock(), AsyncMock(), AsyncMock()
                jwt, signature = Mock(return_value=b'FIXTURE_JWT'), Mock(return_value=b'FIXTURE_SIGNATURE')
                options = enrollment.tls_options(selected)
                options.update(allow_reconnect=False, max_reconnect_attempts=1, error_cb=AsyncMock(),
                               user_jwt_cb=jwt, signature_cb=signature)
                try:
                    if pin == matching:
                        await client.connect(**options)
                        self.assertTrue(client.is_connected)
                        jwt.assert_called_once_with()
                        signature.assert_called_once_with('fixture_nonce')
                        self.assertTrue(raw.write.call_args_list[0].args[0].startswith(b'CONNECT '))
                    else:
                        with self.assertRaises(ssl.SSLError):
                            await client.connect(**options)
                        jwt.assert_not_called()
                        signature.assert_not_called()
                        raw.readline.assert_not_awaited()
                        raw.write.assert_not_called()
                finally:
                    await client.close()
