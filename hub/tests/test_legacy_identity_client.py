import copy
import os
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes
from hub.client_launch_session import ApplicationClientSession
from hub.legacy_identity_client import EnrolledLegacyIdentityResolver
from hub.store import HubError, Store
from identity.legacy_identity import (
    LegacyIdentityBinding,
    LegacyRegistration,
    VerifiedLegacyAliasResolution,
)


def binding(session, generation, *, alias=None, source='hub-one', local=True, sequence=8):
    return LegacyIdentityBinding(alias or session, session, source, generation,
        canonical_bytes({'id': session}),
        canonical_bytes({'organizationId': 'org', 'projectId': 'project', 'workspaceId': 'workspace'}),
        canonical_bytes(None), canonical_bytes({'id': 'alias-' + session}), sequence, local)


def registration(session, generation=1, *, alias=None):
    repository, role, agent = session.split('-')
    return LegacyRegistration('agent:' + (alias or session), session, generation,
        repository, role, agent, 'ready', alias)


def session_with(handler):
    selected = ApplicationClientSession(None)
    selected.query_legacy_aliases = types.MethodType(handler, selected)
    return selected


class EnrolledResolverCase(unittest.IsolatedAsyncioTestCase):
    async def test_groups_by_repository_restores_order_and_uses_earliest_expiry(self):
        calls = []
        now = datetime.now(timezone.utc)

        def handler(valid_until):
            def query(_session, registrations=None, *, remote_address=None, operation_id, deadline):
                self.assertIsNone(remote_address)
                calls.append(copy.deepcopy(registrations))
                return VerifiedLegacyAliasResolution(tuple(
                    binding(row['canonicalSession'], row['registrationGeneration'],
                            alias=row['legacyAlias']) for row in registrations), valid_until)
            return query

        resolver = EnrolledLegacyIdentityResolver({
            'alpha': session_with(handler(now + timedelta(seconds=40))),
            'beta': session_with(handler(now + timedelta(seconds=20))),
        }, local_source_hub_id='hub-one')
        requested = (
            registration('alpha-worker-a1', 2),
            registration('beta-reviewer-b1', 3),
            registration('alpha-worker-a2', 4, alias='old-a2'),
        )
        result = await resolver.bind(requested)
        self.assertEqual([item.canonical_session for item in result.bindings],
                         [item.canonical_session for item in requested])
        self.assertEqual(result.valid_until, now + timedelta(seconds=20))
        self.assertEqual(sorted([row['repository'] for row in group] for group in calls),
                         [['alpha', 'alpha'], ['beta']])

    async def test_missing_route_refuses_before_any_query(self):
        calls = []

        def query(_session, registrations=None, **_kwargs):
            calls.append(registrations)
            raise AssertionError('query must not run')

        resolver = EnrolledLegacyIdentityResolver({'alpha': session_with(query)},
            local_source_hub_id='hub-one')
        with self.assertRaisesRegex(ContractError, 'legacy_identity_unavailable'):
            await resolver.bind((registration('alpha-worker-a1'), registration('beta-worker-b1')))
        self.assertEqual(calls, [])

    async def test_remote_address_uses_canonical_repository_route(self):
        calls = []
        remote = 'agent:beta-worker-b1'

        def query(_session, registrations=None, *, remote_address=None, operation_id, deadline):
            calls.append((registrations, remote_address, operation_id))
            return VerifiedLegacyAliasResolution(
                (binding('beta-worker-b1', 7, alias='old-b1', source='hub-two', local=False),),
                datetime.now(timezone.utc) + timedelta(seconds=20))

        resolver = EnrolledLegacyIdentityResolver({'beta': session_with(query)},
            local_source_hub_id='hub-one')
        result = await resolver.bind((), remote_address=remote)
        self.assertEqual(result.bindings[0].canonical_session, 'beta-worker-b1')
        self.assertEqual(calls[0][0:2], (None, remote))

    async def test_inbound_provenance_is_rechecked_against_current_owner(self):
        current = binding('alpha-worker-a1', 2, alias='old-a1', sequence=10)

        def query(_session, registrations=None, **_kwargs):
            self.assertEqual(registrations[0]['legacyAlias'], 'old-a1')
            return VerifiedLegacyAliasResolution((current,),
                datetime.now(timezone.utc) + timedelta(seconds=20))

        resolver = EnrolledLegacyIdentityResolver({'alpha': session_with(query)},
            local_source_hub_id='hub-one')
        provenance = current.wire()
        provenance['authoritySequence'] = 9
        result = await resolver.admit_remote(registration('alpha-worker-a1', 2), provenance)
        self.assertEqual(result.bindings, (current,))
        changed = dict(provenance, sourceHubId='other-hub')
        with self.assertRaisesRegex(ContractError, 'legacy_identity_provenance_invalid'):
            await resolver.admit_remote(registration('alpha-worker-a1', 2), changed)


class StoreSignedExpiryCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.directory.name, 'hub.db'))
        self.store.repo_add('alpha')
        self.session = self.store.register('alpha', 'worker', 'a1', 'codex', {})
        self.store.set_state(self.session, 'ready')
        self.store.configure_identity_fencing('hub-one', True)
        self.current = binding(self.session, 1)

    def tearDown(self):
        self.store.db.close()
        self.directory.cleanup()

    def test_signed_expiry_is_checked_inside_message_transaction(self):
        expired = VerifiedLegacyAliasResolution((self.current,),
            datetime.now(timezone.utc) - timedelta(microseconds=1))
        with self.assertRaisesRegex(HubError, 'resolution expired'):
            self.store.post('virtual:operator', 'agent:' + self.session, 'note', 'late',
                            identity_bindings=expired)
        self.assertEqual(self.store.q1('SELECT count(*) AS n FROM messages')['n'], 0)
        fresh = VerifiedLegacyAliasResolution((self.current,),
            datetime.now(timezone.utc) + timedelta(seconds=10))
        posted = self.store.post('virtual:operator', 'agent:' + self.session, 'note', 'current',
                                 identity_bindings=fresh)
        self.assertEqual(posted['recipients'], [self.session])

    def test_enrolled_store_refuses_unbounded_binding_tuple(self):
        with self.assertRaisesRegex(HubError, 'signed legacy identity resolution required'):
            self.store.post('virtual:operator', 'agent:' + self.session, 'note', 'unbounded',
                            identity_bindings=(self.current,))


class HubResolverIntegrationCase(unittest.IsolatedAsyncioTestCase):
    async def test_hub_preserves_verified_envelope_until_store_write(self):
        def query(_session, registrations=None, **_kwargs):
            row = registrations[0]
            return VerifiedLegacyAliasResolution((binding(
                row['canonicalSession'], row['registrationGeneration'], alias=row['legacyAlias']),),
                datetime.now(timezone.utc) + timedelta(seconds=10))

        resolver = EnrolledLegacyIdentityResolver({'alpha': session_with(query)},
            local_source_hub_id='hub-one')
        from hub import server
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(server, 'ROOT', directory), \
                patch.object(server, 'HUBDIR', os.path.join(directory, 'hub')):
            hub = server.Hub(legacy_identity=resolver)
            try:
                await hub.db(hub.store.repo_add, 'alpha')
                selected = await hub.db(hub.store.register, 'alpha', 'worker', 'a1', 'codex', {})
                await hub.db(hub.store.set_state, selected, 'ready')
                posted = await hub.dispatch('post', {
                    'to': 'agent:' + selected, 'kind': 'note', 'body': 'hello'}, 'operator')
                self.assertEqual(posted['recipients'], [selected])
            finally:
                hub.store.db.close()
                hub.dbx.shutdown(wait=True)
                hub.io.shutdown(wait=True)


if __name__ == '__main__':
    unittest.main()
