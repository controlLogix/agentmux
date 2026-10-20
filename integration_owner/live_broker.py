"""One real broker case, launched only by the existing Go TLS/JWT fixture.

No provider worker, external account, installed runtime or operator configuration
is used. The private fixture account key arrives on stdin, never in arguments.
"""
import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import secrets
import ssl
import sys
import time
import traceback

import nats
import nkeys
from agentmux_contracts import canonical_bytes, payload_digest, sign_claims, strict_loads
from identity.authority import LedgerAuthorityReader
from hub.nats_transport import new_client
from identity.test_authority import ref, SEED
from integration_owner.test_admission import AdmissionTests
from integration_owner.service import IntegrationService
from integration_owner.receipts import verify_receipt
from native_security.nats_credentials import service_policy, validate_service, validate
from state_owner.history import OwnerHistory
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.retention import Retention

STAGE = 'input'


def stage(value):
    global STAGE
    STAGE = value
    print('integration live stage: ' + value, file=sys.stderr, flush=True)


def require(value):
    if not value:
        raise AssertionError('integration_live_check_failed')


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')


def user_credential(account, publish, subscribe, *, response=None):
    key = nkeys.from_seed(nkeys.encode_seed(secrets.token_bytes(32), nkeys.PREFIX_BYTE_USER))
    try:
        now = int(time.time())
        claims = {'iat': now, 'exp': now + 300, 'iss': account.public_key.decode(),
                  'sub': key.public_key.decode(), 'name': 'disposable-integration-test'}
        claims['jti'] = base64.b32encode(hashlib.new('sha512_256', canonical_bytes(claims)).digest()).decode().rstrip('=')
        permissions = {'type': 'user', 'version': 2,
                       'pub': {'allow': list(publish)}, 'sub': {'allow': list(subscribe)},
                       'subs': -1, 'data': -1, 'payload': -1}
        if response is not None:
            permissions['resp'] = response
        claims['nats'] = permissions
        message = encoded({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encoded(claims)
        token = message + b'.' + base64.urlsafe_b64encode(account.sign(message)).rstrip(b'=')
        return (b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n'
                b'-----BEGIN USER NKEY SEED-----\n' + key.seed + b'\n------END USER NKEY SEED------\n')
    finally:
        key.wipe()


async def close_client(client):
    tasks = tuple(task for name in ('_reading_task', '_ping_interval_task', '_flusher_task', '_reconnection_task')
                  if isinstance((task := getattr(client, name, None)), asyncio.Task))
    try:
        await client.close()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def run(plan):
    directory = Path(plan['directory']).resolve()
    require(directory.is_dir())
    account = nkeys.from_seed(plan['accountSeed'].encode())
    clients, service, history = [], None, None
    denied = asyncio.Queue()
    other_errors = []

    async def errors(error):
        if 'permissions violation' in str(error).lower():
            denied.put_nowait(True)
            if STAGE == 'service-start':
                message = str(error).lower()
                detail = ('mapped-own-stream-info' if '$js.api.stream.info.effect' in message else
                          'selected-own-stream-info' if '$js.' + plan['domain'].lower() + '.api.stream.info.effect' in message else
                          'private-inbox' if '_inbox.integration_service_0001' in message else 'other')
                print('integration live permission denial: ' + detail, file=sys.stderr, flush=True)
        else:
            other_errors.append('broker_error')

    # Match ApplicationServiceSelection.tls_options rather than adding the
    # interpreter's unrelated create_default_context verification flags.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=plan['rootsPEM'])
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    async def connect(raw, prefix):
        # The account signs these fixture users. The real broker checks their
        # chain and nonce; production validators separately check exact grants.
        lines = raw.splitlines()
        token = lines[1]
        seed = lines[-2]
        def sign(nonce):
            signer = nkeys.from_seed(seed)
            try:
                return base64.b64encode(signer.sign(nonce.encode()))
            finally:
                signer.wipe()
        client = new_client(require_tls=True, leaf_certificate_sha256=plan['leafPin'])
        clients.append(client)
        try:
            await client.connect(servers=[plan['endpoint']], tls=context, tls_hostname=plan['serverName'],
                user_jwt_cb=lambda: token, signature_cb=sign, inbox_prefix=prefix,
                allow_reconnect=False, max_reconnect_attempts=1, connect_timeout=3, error_cb=errors)
        except BaseException as error:
            category = ('tls' if isinstance(error, ssl.SSLError) else
                        'authentication' if isinstance(error, nats.errors.AuthorizationError)
                            or 'authorization' in str(error).lower() or 'authentication' in str(error).lower() else
                        'broker' if isinstance(error, nats.errors.Error) else 'client')
            print('integration live connection failure: ' + category, file=sys.stderr, flush=True)
            if isinstance(error, ssl.SSLError):
                reason = getattr(error, 'reason', None)
                known = {'CERTIFICATE_VERIFY_FAILED', 'WRONG_VERSION_NUMBER', 'UNEXPECTED_EOF_WHILE_READING',
                         'TLSV1_ALERT_PROTOCOL_VERSION', 'SSLV3_ALERT_HANDSHAKE_FAILURE'}
                detail = (reason if reason in known else
                          'tls_required_info' if str(error) == "('NATS requires TLS before authentication',)" else
                          'certificate' if isinstance(error, ssl.SSLCertVerificationError) else 'other_tls')
                print('integration live TLS failure: ' + detail, file=sys.stderr, flush=True)
            raise
        return client

    try:
        stage('fixture-admin-connect')
        admin = await connect(user_credential(account, ['>'], ['>']), '_INBOX.integration_admin_0001')
        js = admin.jetstream(domain=plan['domain'], timeout=2)
        support = AdmissionTests()
        support.setUp()
        binding = support.binding
        scope = strict_loads(binding.scope)
        policy = Retention(1_048_576, 262144)
        authority_binding = OwnerBinding('hub-one', 'identity', 'authority-one', 'identity-authority',
            canonical_bytes({'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}))
        stage('fixture-stream-provisioning')
        authority_info = await js.add_stream(policy.stream_config(stream='AUTHORITY', subject=owner_subject(authority_binding)))
        effect_info = await js.add_stream(policy.stream_config(stream='EFFECT', subject=owner_subject(binding)))
        other_binding = OwnerBinding('hub-one', 'integrations', 'other-effect', 'effect',
            canonical_bytes({**scope, 'projectId': 'other-project'}))
        await js.add_stream(policy.stream_config(stream='OTHER', subject=owner_subject(other_binding)))
        record = copy.deepcopy(support.record)
        record.update(entityVersion=1, previousRevision=0, effects=[], artifacts=[], repository=None)
        record['operation'].update(expectedVersion=0, scope=strict_loads(authority_binding.scope))
        query_grant = copy.deepcopy(record['state']['grants'][0])
        query_grant.update(ref=ref('query-grant'), contractId='integration-effect-query')
        record['state']['grants'].append(query_grant)
        await js.publish(owner_subject(authority_binding), canonical_bytes(record),
                         headers={'Nats-Expected-Last-Subject-Sequence': '0', 'Nats-Expected-Stream': 'AUTHORITY'})

        identity_options = dict(role='identity', hub_id='hub-one', entity_id='authority-one',
            scope=strict_loads(authority_binding.scope), stream='AUTHORITY',
            reply_prefix='_INBOX.integration_identity_0001', jetstream_domain=plan['domain'])
        service_options = dict(role='integration', hub_id='hub-one', entity_id=binding.entity_id,
            scope=scope, stream='EFFECT', reply_prefix='_INBOX.integration_service_0001',
            jetstream_domain=plan['domain'])
        stage('exact-role-credentials')
        connections = []
        for options in (identity_options, service_options):
            permissions = service_policy(**options)
            raw = user_credential(account, permissions.publish_subjects, permissions.subscribe_subjects,
                                  response=permissions.response_permissions)
            validate_service(raw, account_public_key=account.public_key.decode(), **options)
            connections.append(await connect(raw, options['reply_prefix']))
        identity_connection, service_connection = connections
        stage('owner-composition')
        identity_ledger = OwnerLedger(identity_connection.jetstream(domain=plan['domain']),
            stream='AUTHORITY', subject=owner_subject(authority_binding), binding=authority_binding,
            retention=policy, stream_identity=StreamIdentity(authority_info.created, 1))
        reader = LedgerAuthorityReader(identity_ledger, hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        history = OwnerHistory(directory / 'effect.sqlite', binding,
                               stream_identity=StreamIdentity(effect_info.created, 0))
        async def checkpoint_committed(receipt):
            raise AssertionError('unexpected_checkpoint_in_bounded_case')
        service = IntegrationService.from_enrolled_host(service_connection, authority=reader,
            binding=binding, provider='jira', credential_ref=support.envelope['payload']['credentialRef'],
            stream='EFFECT', stream_identity=StreamIdentity(effect_info.created, 0), retention=policy,
            history=history, artifacts=None, issuer_ref=ref('issuer'), signing_seed=SEED,
            checkpoint_path=directory / 'checkpoint.json', checkpoint_committed=checkpoint_committed,
            jetstream_domain=plan['domain'])
        stage('service-start')
        await service.start()
        require(service.owner._worker is None)
        prefix = '_INBOX.integration_client_0001'
        raw = user_credential(account, [service.subject], [prefix + '.>'])
        validate(raw, account_public_key=account.public_key.decode(), publish_subjects=[service.subject],
                 subscribe_subjects=[prefix + '.>'], private_inbox=True)
        client = await connect(raw, prefix)

        async def exchange(contract, operation_id, version, payload, grant, approvals, suffix):
            now = datetime.now(timezone.utc)
            inbox = prefix + '.' + suffix
            claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one', 'profileId': 'profile-one',
                'authorityId': 'authority-one', 'transportRef': ref('transport'), 'grantRef': grant,
                'operationId': operation_id, 'expectedVersion': version, 'contractId': contract,
                'payload': payload, 'approvalRefs': approvals, 'replySubject': inbox,
                'issuedAt': (now - timedelta(seconds=1)).isoformat().replace('+00:00', 'Z'),
                'expiresAt': (now + timedelta(seconds=45)).isoformat().replace('+00:00', 'Z')}
            request = canonical_bytes({'schemaVersion': '1.0.0', 'claims': claims,
                'signature': sign_claims(claims, bytes(reversed(SEED)))})
            subscription = await client.subscribe(inbox)
            try:
                await client.publish(service.subject, request, reply=inbox)
                await client.flush()
                response = await subscription.next_msg(timeout=3)
                return verify_receipt(response.data, request,
                    public_key=record['state']['issuers'][0]['publicKey'], issuer_ref=ref('issuer'))
            finally:
                await subscription.unsubscribe()
                await client.flush()

        stage('signed-intent')
        original = await exchange('integration-intent', 'operation-one', 0, support.envelope['payload'],
                                  ref('grant'), [ref('approval')], 'intent')
        require(original['phase'] == 'intent-committed' and original['sequence'] == 1)
        query_payload = {'effectRef': {'id': binding.entity_id, 'ownerHubId': 'hub-one', 'revision': 1},
            'originalOperationId': 'operation-one', 'originalPayloadDigest': original['originalPayloadDigest']}
        stage('signed-query')
        result = await exchange('integration-effect-query', 'query-one', 1, query_payload,
                                ref('query-grant'), [], 'query')
        require(result['phase'] == 'intent-committed' and result['sequence'] == 1
                and result['originalOperationId'] == 'operation-one')
        require((await js.stream_info('EFFECT')).state.messages == 1)
        stage('own-stream-read')
        own = service_connection.jetstream(domain=plan['domain'], timeout=.4)
        require((await own.stream_info('EFFECT')).state.messages == 1)
        require((await own.get_msg('EFFECT', seq=1, direct=False)).subject == owner_subject(binding))

        # The service's broker credential must not borrow its reader's access or
        # reach another project's stream, even though the fixture admin can.
        stage('unrelated-stream-denial')
        for stream in ('AUTHORITY', 'OTHER'):
            try:
                await own.stream_info(stream)
            except nats.errors.TimeoutError:
                pass
            else:
                raise AssertionError('unrelated_stream_was_accessible')
            await asyncio.wait_for(denied.get(), 1)
        try:
            await own.get_msg('OTHER', seq=1, direct=False)
        except nats.errors.TimeoutError:
            pass
        else:
            raise AssertionError('unrelated_record_was_accessible')
        await asyncio.wait_for(denied.get(), 1)
        stage('unrelated-publication-denial')
        await service_connection.publish(owner_subject(other_binding), b'synthetic-forbidden')
        await service_connection.flush()
        await asyncio.wait_for(denied.get(), 1)
        require((await js.stream_info('OTHER')).state.messages == 0)
        require((await js.stream_info('EFFECT')).state.messages == 1)
        require(not other_errors and service.owner._worker is None)
    except BaseException as error:
        trace = traceback.extract_tb(error.__traceback__)
        if trace:
            last = trace[-1]
            # Source location only: exception messages and local values remain
            # private and cannot disclose a credential or request body.
            print('integration live failure location: ' + Path(last.filename).name + ':' + str(last.lineno),
                  file=sys.stderr, flush=True)
        raise
    finally:
        stage('cleanup-service')
        try:
            if service is not None:
                await service.close()
            elif history is not None:
                history.close()
        finally:
            try:
                stage('cleanup-clients')
                for client in reversed(clients):
                    await close_client(client)
            finally:
                account.wipe()
    stage('cleanup-done')
    require(service._drain_task.done() and history._closed)
    print('integration service broker checks passed; clients and service joined')


if __name__ == '__main__':
    try:
        plan = json.load(sys.stdin)
        asyncio.run(run(plan))
    except BaseException:
        print('integration service broker checks failed at ' + STAGE, file=sys.stderr)
        raise SystemExit(1) from None
