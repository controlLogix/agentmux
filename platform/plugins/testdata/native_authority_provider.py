"""Offline Go/Python protocol check using the real provider and retained ledger.

Only the broker boundary is controlled. This is not a production enrollment,
NATS service, or runtime dependency of the Go consumer.
"""
import asyncio
import base64
import copy
from datetime import datetime, timezone, timedelta
import json
import sys
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest
from capability_owner.test_reply_service import ReplyServiceTests
from capability_owner import test_reply_service
from identity.test_authority import NOW, ref
from identity.test_native_bridge import NativeBridgeTests


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


async def main():
    setup = json.loads(sys.stdin.readline())
    capability = bool(setup.get("capability"))
    case = ReplyServiceTests() if capability else NativeBridgeTests()
    case.setUp()
    try:
        delta = datetime.now(timezone.utc) - NOW

        def current_times(value):
            if isinstance(value, dict):
                return {k: current_times(v) for k, v in value.items()}
            if isinstance(value, list):
                return [current_times(v) for v in value]
            if isinstance(value, str) and value.startswith('2026-10-09T') and value.endswith('Z'):
                return (datetime.fromisoformat(value) + delta).isoformat(timespec='microseconds').replace('+00:00', 'Z')
            return value

        case.record = current_times(case.record)
        case.claims = current_times(case.claims)
        case.row = current_times(case.row)
        old_instance = case.row['owner']['instanceId']
        case.row.update(owner=setup['owner'], manifestDigest=setup['manifestDigest'],
                        configurationChecksum=setup['configurationChecksum'])
        for entry in ('grant', 'policy'):
            case.row['facts'][entry]['subjectInstanceId'] = setup['owner']['instanceId']
        for grant in case.record['state']['grants']:
            if grant['contractId'].startswith('native-authority-') and grant['resourceId'] == old_instance:
                grant['resourceId'] = setup['owner']['instanceId']
        parent_setup = setup.get('parent')
        parent_row = None
        if parent_setup is not None:
            parent_row = copy.deepcopy(case.row)
            parent_row.update(ref=ref('native-parent-instance'), owner=parent_setup['owner'],
                identityRef=ref('parent-plugin'), manifestDigest=parent_setup['manifestDigest'],
                configurationChecksum=parent_setup['configurationChecksum'])
            parent_row['facts']['grant'].update(grantId='native-parent-grant',
                subjectInstanceId=parent_setup['owner']['instanceId'], policyRef=ref('native-parent-policy'))
            parent_row['facts']['policy'].update(reference=ref('native-parent-policy'),
                subjectInstanceId=parent_setup['owner']['instanceId'])
            # Fixed fixture declaration: the parent package requests this one
            # read/storage tuple. Production Go still performs the intersection.
            parent_row['facts']['policy']['expiresAt'] = (datetime.now(timezone.utc)
                + timedelta(seconds=4)).isoformat(timespec='microseconds').replace('+00:00', 'Z')
            case.row.update(relationship='private', parentOwner=copy.deepcopy(parent_row['owner']))
            case.row['facts']['parentGrant'] = copy.deepcopy(parent_row['facts']['grant'])
            case.row['facts']['grant']['parentGrantRef'] = ref('native-parent-grant')
            case.row['facts']['parentAccess'] = [copy.deepcopy(parent_row['facts']['policy']['decisions'][0]['access'])]
            case.record['state']['identities'].append({'ref': ref('parent-plugin'), 'status': 'active',
                'kind': 'plugin', 'principalId': 'parent-plugin-one', 'externalIdentity': None})
            for original_grant in list(case.record['state']['grants']):
                if original_grant['contractId'].startswith('native-authority-') and original_grant['resourceId'] == setup['owner']['instanceId']:
                    grant = copy.deepcopy(original_grant)
                    grant.update(ref=ref('parent-' + original_grant['ref']['id']),
                        resourceId=parent_setup['owner']['instanceId'])
                    case.record['state']['grants'].append(grant)
            async def enroll_private():
                for version, row, operation in ((1, parent_row, 'enroll-parent'), (2, case.row, 'enroll-native')):
                    case.claims.update(operationId=operation, contractId='identity-native-instance-set',
                        grantRef=ref('native-admin'), expectedVersion=version,
                        payload={'authorityId': 'authority-one', 'record': row, 'previousRef': None})
                    response = await case.service.handle(case.request())
                    from agentmux_contracts import strict_loads
                    if strict_loads(response)['claims']['receipt']['decision'] != 'allowed':
                        raise ContractError('native_fixture_enrollment_refused')
            case.enroll = enroll_private
        case.js.messages[0].data = canonical_bytes(case.record)
        for module in ('identity.ingress', 'identity.commands', 'state_owner.ledger', 'identity.native_bridge', 'capability_owner.reply_service'):
            patch(module + '.datetime', datetime).start()
        if capability:
            patch('identity.authority._utc_now', side_effect=lambda: datetime.now(timezone.utc)).start()
            original_record = test_reply_service.record
            patch('capability_owner.test_reply_service.record', side_effect=lambda: current_times(original_record())).start()
            await case.asyncSetUp()
            original = case.inner
        else:
            await case.enroll()
            original = await case.operation_envelope()
        emit({'envelope': base64.b64encode(original).decode(),
              'publicKey': case.record['state']['issuers'][0]['publicKey'],
              'recordDigest': payload_digest(case.original) if capability else None,
              'parentPolicyExpiresAt': parent_row['facts']['policy']['expiresAt'] if parent_row else None})
        for line in sys.stdin:
            message = json.loads(line)
            try:
                if message.get('authorityState'):
                    snapshot = await case.service.reader.current()
                    emit({'state': base64.b64encode(snapshot.record).decode()})
                elif message.get('revoke') or message.get('revokeParent'):
                    snapshot = await case.service.reader.current()
                    from agentmux_contracts import strict_loads
                    version = strict_loads(snapshot.record)['entityVersion']
                    target = ref('native-parent-instance') if message.get('revokeParent') else ref('native-instance')
                    case.claims.update(operationId='revoke-native', contractId='identity-revoke',
                        grantRef=ref('grant'), expectedVersion=version,
                        payload={'authorityId': 'authority-one', 'targetRef': target})
                    await case.service.handle(case.request())
                    emit({'revoked': True})
                elif 'capabilityRequest' in message:
                    request = base64.b64decode(message['capabilityRequest'], validate=True)
                    result = await case.reply_service.handle(request, received_reply_subject=message['replySubject'])
                    emit({'response': base64.b64encode(result).decode()})
                else:
                    request = base64.b64decode(message['request'], validate=True)
                    result = await case.service.handle(request)
                    emit({'response': base64.b64encode(result).decode()})
            except ContractError as error:
                emit({'error': error.code})
    finally:
        if hasattr(case, "reply_service"):
            await case.reply_service.close()
        await case.service.close()
        case.doCleanups()


asyncio.run(main())
