"""Native tests for the fixed signer, not C's complete credential-use flow."""
import base64
import copy
from datetime import datetime, timezone
from pathlib import Path
import re
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate
from identity.test_authority import ref
from native_security.nats_credentials import validate as validate_credentials
from native_security.test_nats_credentials import PREFIX, credential
from state_owner.task_service import RESPONSE_LIMIT
from . import test_container_live as native_support
from .docker_engine import DockerEngine, DockerSelection
from .task_credential_program import PROOF


class NativeTaskCredentialProgramTests(native_support.NativeContainerTests):
    """Use the accepted A/B fixture and its exact owned private channel."""

    async def signer(self, name, *, expired=False):
        self.real_engine = DockerEngine(DockerSelection(
            str(Path('/Users/ryan/.docker/bin/docker').resolve()), 'desktop-linux',
            'unix:///Users/ryan/.docker/run/docker.sock',
            'bf61e5bf-20ff-4b43-a588-d6c46ed9e664', '29.8.2',
            str(Path.home()/'.docker'), native_support.IMAGE.split('@')[1]))
        workspace = await self.workspace(name)
        case = await self.case(name, workspace, None, None, b'import time;time.sleep(20)\n')
        adapter, admission, intent = case['adapter'], case['admission'], case['intent']
        binding = strict_loads(admission.binding)
        profile = case['profile']

        # These are disposable, known test credentials. Their real NKey/JWT
        # signatures are validated before B receives them. C's service authority
        # and enrollment are qualified separately by the integration owner.
        now = int(time.time())
        end = min(int(datetime.fromisoformat(binding['executionValidUntil']).timestamp()), now+30)
        scope = binding['scope']
        publish = '.'.join(('amx', 'v1', 'h', binding['runRef']['ownerHubId'],
            'o', scope['organizationId'], 'p', scope['projectId'], 'w', scope['workspaceId'] or '_',
            'task-credential', binding['credentialRef']['id'], 'command'))
        reply = PREFIX+'.task_reply_0000001'
        def finite_claims(claims):
            claims.update(iat=now, exp=end)
            claims['nats'].update(pub={'allow': [publish]}, sub={'allow': [reply]},
                subs=1, data=4*RESPONSE_LIMIT, payload=RESPONSE_LIMIT)
        material, account, user = credential(finite_claims)
        checked = validate_credentials(material, account_public_key=account,
            publish_subjects=[publish], subscribe_subjects=[reply], private_inbox=False)
        self.assertTrue(checked.public_key == user, 'Fixture key binding differs')
        record = {
            'schemaVersion': '1.0.0', 'credentialRef': binding['credentialRef'],
            'generationRef': ref(name+'-generation'), 'runRef': binding['runRef'],
            'planRef': binding['planRef'], 'taskRef': binding['taskRef'],
            'workerIdentityRef': binding['workerIdentityRef'], 'consumerRef': binding['consumerRef'],
            'destinationRef': binding['consumerRef'], 'workspaceRef': profile['workspaceRef'],
            'networkProfileRef': profile['network']['profileRef'], 'accountRef': ref(name+'-account'),
            'accountIssuerRef': ref(name+'-account-issuer'), 'transportRef': ref(name+'-worker-transport'),
            'identityIssuerRef': ref(name+'-identity-issuer'), 'taskReadGrantRef': ref(name+'-task-read'),
            'ownerIdentityRef': ref(name+'-credential-owner'), 'scope': binding['scope'],
            'profileId': profile['profileId'], 'authorityId': 'authority-one',
            'attemptId': binding['attemptId'], 'readOperationId': name+'-read',
            'prepareOperationId': name+'-prepare', 'bindingDigest': payload_digest(binding),
            'policyDigest': payload_digest({'fixture': name}), 'taskApprovalRefs': [ref(name+'-approval')],
            'accountPublicKey': account, 'userPublicKey': user,
            'replySubject': reply, 'issuedUnix': now, 'expiresUnix': end,
        }
        # This intentional malformed private record isolates PROOF's own expiry
        # refusal. Valid C custody would reject it before delivery as well.
        if expired:
            record['expiresUnix'] = now-1
        validate('task-credential-record', record)
        private = canonical_bytes({'format': 'agentmux-task-credential-private-v1', 'record': record,
            'credentialsBase64': base64.b64encode(material).decode('ascii')})
        prepared = await adapter.prepare(admission, task_inspection=await case['inspect'](), intent=intent)
        self.assertEqual(prepared.status, 'prepared')
        run_ref = strict_loads(prepared.run_ref)
        await adapter.deliver_private(run_ref, admission, task_inspection=await case['inspect'](), intent=intent,
            worker_ref=profile['workerIdentityRef'], consumer_ref=profile['consumerRef'], material=private)
        resource = strict_loads(prepared.resource_ref)
        return case, run_ref, resource['containerId'], record, user

    def signer_claims(self, record):
        now = datetime.now(timezone.utc)
        return {
            'purpose': 'agentmux-client-possession-v1', 'profileId': record['profileId'],
            'hubId': record['runRef']['ownerHubId'], 'authorityId': record['authorityId'],
            'transportRef': record['transportRef'], 'grantRef': record['taskReadGrantRef'],
            'operationId': record['readOperationId'], 'expectedVersion': record['taskRef']['revision'],
            'contractId': 'task-inspect', 'payload': {'taskId': record['taskRef']['id']},
            'approvalRefs': record['taskApprovalRefs'], 'issuedAt': native_support.stamp(now),
            'expiresAt': native_support.stamp(datetime.fromtimestamp(record['expiresUnix'], timezone.utc)),
            'replySubject': record['replySubject'],
        }

    def signer_request(self, record, purpose, **values):
        return {'purpose': purpose, 'generationRef': record['generationRef'],
            'runRef': record['runRef'], **values}

    async def proof(self, container_id, request):
        return await self.real_engine.exec_fixed(container_id, 501, PROOF, data=canonical_bytes(request))

    def verify_proof(self, output, message, public_key):
        # Assertions never include proof or credential bytes in their failure text.
        self.assertTrue(bool(re.fullmatch(rb'[A-Za-z0-9+/]{86}==', output)), 'Proof encoding differs')
        signature = base64.b64decode(output, validate=True)
        self.assertEqual(len(signature), 64)
        decoded = base64.b32decode(public_key+'='*(-len(public_key)%8))
        verified = True
        try:
            VerifyKey(decoded[1:-2]).verify(message, signature)
        except BadSignatureError:
            verified = False
        self.assertTrue(verified, 'Proof does not match the delivered user key and exact message')
        return signature

    async def finish(self, case, run_ref):
        self.assertEqual((await case['adapter'].stop(run_ref)).status, 'terminal')
        await case['adapter'].cleanup(run_ref)
        name = next(iter(case['adapter']._runs.values()))['spec']['name']
        self.assertIsNone(await self.real_engine.find(name))
        self.assertFalse(self.real_engine._jobs)

    async def test_native_nonce_and_closed_task_claims_use_delivered_key(self):
        case, run_ref, container_id, record, user = await self.signer('projectproof')
        try:
            # NATS v2.15 server/nkey.go encodes 11 random bytes as 15 URL-safe characters.
            nonce = base64.urlsafe_b64encode(b'nonce-bytes').decode('ascii').rstrip('=')
            self.assertEqual(len(nonce), 15)
            broker = self.signer_request(record, 'broker-nonce', nonce=nonce)
            self.verify_proof(await self.proof(container_id, broker), nonce.encode('ascii'), user)
            claims = self.signer_claims(record)
            task = self.signer_request(record, 'task-inspect', claims=claims)
            signature = self.verify_proof(await self.proof(container_id, task), canonical_bytes(claims), user)
            # EnrolledIngress expects canonical URL-safe, unpadded Base64;
            # the broker callback consumes its own standard Base64 form.
            normalized = base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
            self.assertTrue(bool(re.fullmatch(r'[A-Za-z0-9_-]{86}', normalized)), 'Ingress proof encoding differs')
            restored = base64.b64decode(normalized+'==', altchars=b'-_', validate=True)
            self.assertTrue(restored == signature, 'Ingress normalization changes the signature')

            wrong_run = copy.deepcopy(broker);wrong_run['runRef'] = ref('foreign-run')
            wrong_generation = copy.deepcopy(broker);wrong_generation['generationRef'] = ref('foreign-generation')
            requests = [('run', wrong_run), ('generation', wrong_generation),
                ('nonce', self.signer_request(record, 'broker-nonce', nonce='not a broker nonce')),
                ('short nonce', self.signer_request(record, 'broker-nonce', nonce=nonce[:-1])),
                ('oversized nonce', self.signer_request(record, 'broker-nonce', nonce='a'*513)),
                ('non-ASCII nonce', self.signer_request(record, 'broker-nonce', nonce='é'*15)),
                ('purpose', self.signer_request(record, 'arbitrary-signing', nonce=nonce))]
            replacements = {
                'purpose': 'another-purpose', 'profileId': 'another-profile', 'hubId': 'another-hub',
                'authorityId': 'another-authority', 'transportRef': ref('another-transport'),
                'grantRef': ref('another-grant'), 'operationId': 'another-read',
                'expectedVersion': record['taskRef']['revision']+1, 'contractId': 'task-reserve',
                'payload': {'taskId': 'another-task'}, 'approvalRefs': [],
                'replySubject': PREFIX+'.another_reply_0001',
            }
            for field, value in replacements.items():
                changed = copy.deepcopy(task);changed['claims'][field] = value
                requests.append((field, changed))
            extra = copy.deepcopy(task);extra['claims']['consumerRef'] = record['consumerRef']
            requests.append(('extra consumer claim', extra))
            for name, request in requests:
                with self.subTest(binding=name), self.assertRaisesRegex(ContractError, '^execution_engine_command_unknown$'):
                    await self.proof(container_id, request)
            # Refusals leave the immutable private file usable for its exact original.
            self.verify_proof(await self.proof(container_id, task), canonical_bytes(claims), user)
        finally:
            await self.finish(case, run_ref)

    async def test_native_expired_private_record_refuses_both_purposes(self):
        case, run_ref, container_id, record, _ = await self.signer('projectexpired', expired=True)
        try:
            for request in (self.signer_request(record, 'broker-nonce', nonce='nonce_fixture_0123456789abcdef'),
                    self.signer_request(record, 'task-inspect', claims=self.signer_claims(record))):
                with self.subTest(purpose=request['purpose']), self.assertRaisesRegex(ContractError, '^execution_engine_command_unknown$'):
                    await self.proof(container_id, request)
        finally:
            await self.finish(case, run_ref)


# Reuse fixture helpers without discovering accepted A/B tests again.
for _name in dir(native_support.NativeContainerTests):
    if _name.startswith('test_') and _name not in vars(NativeTaskCredentialProgramTests):
        setattr(NativeTaskCredentialProgramTests, _name, None)
