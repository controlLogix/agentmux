"""The enrolled recovery caller may safely repeat the owner's exact operation."""
import asyncio
from datetime import datetime, timedelta, timezone
import unittest

from agentmux_contracts import canonical_bytes
from hub.authority_switch_recovery_client import EnrolledAuthoritySwitchRecovery
from hub.client_launch_session import ApplicationClientSession, ApplicationSessionFailure
from state_owner.authority_switch import authority_switch_id
from state_owner.authority_switch_service import VerifiedEnrolledRecovery


class _Session(ApplicationClientSession):
    def __init__(self, route, results):
        self.route = route
        self.results = list(results)
        self.operations = []

    def authority_switch_recovery_enabled(self):
        return True

    def authority_switch_recovery_route(self):
        return self.route

    def request_authority_switch_recovery(self, operation_id, *, deadline=None):
        self.operations.append(operation_id)
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def _authorization(public, *, seconds=5):
    result = object.__new__(VerifiedEnrolledRecovery)
    response = {'claims': {'switchRef': {'id': public['switchId'],
        'ownerHubId': 'hub-one', 'revision': 2}, 'hubId': 'hub-one',
        'source': public['source'], 'stream': {'created': public['streamIdentity']['created'],
        'minimumSequence': 2}}}
    object.__setattr__(result, '_response', canonical_bytes(response))
    object.__setattr__(result, '_valid_until',
                       datetime.now(timezone.utc) + timedelta(seconds=seconds))
    object.__setattr__(result, '_seal', object())
    object.__setattr__(result, '_request', b'{}')
    return result


class EnrolledRecoveryClientTests(unittest.IsolatedAsyncioTestCase):
    def binding(self):
        source = {'sourceRef': {'id': 'source-one', 'ownerHubId': 'hub-one', 'revision': 1},
            'applicationVersion': 'legacy-v1', 'comparisonDigest': 'sha256:' + 'a' * 64,
            'fenceId': 'f' + 'b' * 32, 'fenceGeneration': 1}
        public = {'switchId': authority_switch_id(source), 'source': source,
            'streamIdentity': {'created': '2026-10-16T00:00:00Z', 'minimumSequence': 1},
            'custodyDirectory': '/private/authority-switch'}
        route = {**public, 'subject': 'unused', 'grantRef': {}, 'replyIssuerRef': {},
            'replyIssuerPublicKey': 'A' * 43, 'transportRef': {},
            'serviceIdentityRef': {}, 'serviceInstanceId': 'switch-instance'}
        route.pop('custodyDirectory')
        return public, route

    async def test_expired_local_use_can_request_the_same_owner_operation_again(self):
        public, route = self.binding()
        first, second = _authorization(public, seconds=.02), _authorization(public)
        session = _Session(route, (first, second))
        caller = EnrolledAuthoritySwitchRecovery(session, public=public)
        fence = {'state': 'fenced', 'fenceId': public['source']['fenceId'],
                 'generation': 1}
        self.assertIs(await caller.authorize(fence=fence,
            fence_id=fence['fenceId']), first)
        await asyncio.sleep(.03)
        self.assertIs(await caller.authorize(fence=fence,
            fence_id=fence['fenceId']), second)
        self.assertEqual(len(set(session.operations)), 1)

    async def test_lost_reply_grants_nothing_and_restart_can_reconcile_exact_operation(self):
        public, route = self.binding()
        failed = _Session(route, (ApplicationSessionFailure(None),))
        caller = EnrolledAuthoritySwitchRecovery(failed, public=public)
        fence = {'state': 'fenced', 'fenceId': public['source']['fenceId'],
                 'generation': 1}
        with self.assertRaises(ApplicationSessionFailure):
            await caller.authorize(fence=fence, fence_id=fence['fenceId'])
        renewed = _authorization(public)
        restarted = _Session(route, (renewed,))
        recovered = EnrolledAuthoritySwitchRecovery(restarted, public=public)
        self.assertIs(await recovered.authorize(fence=fence,
            fence_id=fence['fenceId']), renewed)
        self.assertEqual(failed.operations, restarted.operations)


if __name__ == '__main__':
    unittest.main()
