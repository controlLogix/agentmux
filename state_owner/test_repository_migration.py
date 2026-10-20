"""Legacy repository catalog preservation through the configuration owner."""
import base64
import copy
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from nacl.secret import SecretBox
from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from hub.store import MIGRATIONS, Store
from identity.authority import AuthorityReader
from identity.test_authority import NOW, SEED, fixture, ref
from identity.test_native_bridge import native_row
from identity.test_service import _Clock
from state_owner.configuration import ConfigurationOwner, verify_configuration_response
from state_owner.conversation_migration import ConversationKey
from state_owner.artifacts import OwnerArtifacts
from state_owner.ledger import OwnerBinding, OwnerLedger, StreamIdentity, owner_subject
from state_owner.repository_migration import (REPOSITORY_CATALOG_SCHEMA, TABLES,
    MEDIA_TYPE, RepositoryCatalogImporter, RepositoryCatalogSource,
    prepare_repository_catalog_artifact,
    repository_catalog_identity)
from state_owner.retention import Retention
from state_owner.test_ledger import CREATED, FakeJetStream
from state_owner import test_task_migration as legacy_support
from state_owner.task_migration import capture_tasks
from state_owner import test_artifacts as artifact_support


SCOPE = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}


class RepositoryCatalogSourceTests(unittest.TestCase):
    def setUp(self):
        self.legacy = legacy_support.TaskMigrationTests()
        self.legacy.setUp()
        self.addCleanup(self.legacy.doCleanups)
        store = self.legacy.store
        store.db.execute('INSERT INTO repo_aliases VALUES (?,?)', ('legacy-alpha', 'alpha'))
        store.db.execute('INSERT INTO repo_paths VALUES (?,?,?)',
            ('alpha', '/private/source/path-that-must-not-open', 'worktree'))
        store.db.execute('INSERT INTO groups VALUES (?,?)', ('reviewers', 'alpha'))
        self.snapshot = self.legacy.capture()
        self.identity = repository_catalog_identity(ref('legacy-source'),
            target_hub_id='hub-one', scope=SCOPE)
        self.binding = OwnerBinding('hub-one', 'configuration', self.identity['catalogId'],
            'configuration', canonical_bytes(SCOPE))
        self.source = RepositoryCatalogSource(self.snapshot,
            source_owner_organization_id='org-one')

    def document(self):
        return strict_loads(self.source.configuration_bytes(binding=self.binding))

    def test_exact_rows_relationships_ids_provenance_and_repeatability(self):
        prior_length_limit = self.snapshot._db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        first = self.source.configuration_bytes(binding=self.binding)
        repeated = self.source.configuration_bytes(binding=self.binding)
        self.assertEqual(repeated, first)
        self.assertEqual(self.snapshot._db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH),
            prior_length_limit)
        document = strict_loads(first)
        self.assertEqual(document['status'], 'reconciliation_required')
        self.assertFalse(document['writerAuthorityTransferred'])
        self.assertEqual(document['sourceRef'], ref('legacy-source'))
        self.assertEqual(document['captureDigest'], self.snapshot.inventory()['databaseDigest'])
        for table, (keys, _) in TABLES.items():
            expected = self.legacy.store.q('SELECT * FROM '+table+' ORDER BY '+
                ','.join(name+' COLLATE BINARY' for name in keys))
            family = document['families'][table]
            self.assertEqual(family['count'], len(expected))
            self.assertEqual([member['row'] for member in family['rows']], expected)
            self.assertEqual(len({member['memberId'] for member in family['rows']}), len(expected))
        aliases = document['families']['repo_aliases']['rows']
        paths = document['families']['repo_paths']['rows']
        groups = document['families']['groups']['rows']
        self.assertEqual(aliases[0]['row'], {'alias': 'legacy-alpha', 'repo': 'alpha'})
        self.assertEqual(paths[0]['row']['path'], '/private/source/path-that-must-not-open')
        self.assertEqual(groups[0]['row'], {'grp': 'reviewers', 'repo': 'alpha'})

    def test_identity_is_stable_across_capture_revision_and_changes(self):
        first = self.document()
        self.legacy.store.db.execute('INSERT INTO repo_aliases VALUES (?,?)', ('later-alpha', 'alpha'))
        later = self.legacy.capture('later.db')
        source = RepositoryCatalogSource(later, source_owner_organization_id='org-one')
        second = strict_loads(source.configuration_bytes(binding=self.binding))
        self.assertNotEqual(first['captureDigest'], second['captureDigest'])
        before = {member['row']['repo']: member['memberId']
            for member in first['families']['repos']['rows']}
        after = {member['row']['repo']: member['memberId']
            for member in second['families']['repos']['rows']}
        self.assertEqual(before, after)
        self.assertEqual(self.identity, repository_catalog_identity(
            ref('legacy-source') | {'revision': 2}, target_hub_id='hub-one', scope=SCOPE))

    def test_agent_rows_aliases_and_incarnation_generations_are_archived_only(self):
        store = self.legacy.store
        session = store.register('alpha', 'worker', 'w1', 'codex',
            {'prompt': 'original role', 'capabilities': ['python']}, transport='socket',
            handle='private-handle', pane_pid=4321, legacy='old-w1',
            token_sha='retained-token-digest')
        store.set_state(session, 'ready', 'original ready state')
        store.db.execute("UPDATE agents SET last_output=?, last_bell=?, term_name=? WHERE session=?",
            ('2026-10-09T12:01:00Z', '2026-10-09T12:02:00Z', 'legacy-pane', session))
        snapshot = self.legacy.capture('agents.db')
        source = RepositoryCatalogSource(snapshot, source_owner_organization_id='org-one')
        first = source.catalog_bytes(binding=self.binding)
        self.assertEqual(source.catalog_bytes(binding=self.binding), first)
        with self.assertRaisesRegex(ContractError, '^repository_catalog_artifact_required$'):
            source.configuration_bytes(binding=self.binding)
        document = strict_loads(first)
        self.assertFalse(document['identityEnrollmentActivated'])
        self.assertFalse(document['credentialsMinted'])
        self.assertFalse(document['membershipActivated'])
        agent = document['families']['agents']['rows'][0]
        alias = document['families']['legacy_names']['rows'][0]
        self.assertEqual(agent['row'], store.q1('SELECT * FROM agents WHERE session=?', (session,)))
        self.assertEqual(alias['row'], {'legacy': 'old-w1', 'session': session})
        self.assertEqual(agent['incarnation'], alias['incarnation'])
        self.assertEqual(agent['incarnation']['registrationGeneration'], 1)

        store.set_state(session, 'dead')
        store.register('alpha', 'worker', 'w1', 'codex', {}, legacy='old-w1')
        store.set_state(session, 'ready')
        later = RepositoryCatalogSource(self.legacy.capture('agents-later.db'),
            source_owner_organization_id='org-one')
        later_document = strict_loads(later.catalog_bytes(binding=self.binding))
        later_agent = later_document['families']['agents']['rows'][0]
        later_alias = later_document['families']['legacy_names']['rows'][0]
        self.assertEqual(later_agent['memberId'], agent['memberId'])
        self.assertEqual(later_alias['memberId'], alias['memberId'])
        self.assertEqual(later_agent['incarnation']['registrationGeneration'], 2)
        self.assertEqual(later_agent['incarnation'], later_alias['incarnation'])
        self.assertNotEqual(later_agent['incarnation']['incarnationId'],
            agent['incarnation']['incarnationId'])

    def test_older_agent_rows_remain_exact_without_inventing_a_generation(self):
        base_columns = TABLES['agents'][1][:-2]
        base_values = ('alpha-worker-w1', 'alpha', 'worker', 'w1', 'codex', '{}',
            'tmux', None, None, None, 'dead', None, None, None, None,
            '2026-10-09T12:00:00Z')
        for version in (1, 2):
            with self.subTest(version=version), patch('hub.store.MIGRATIONS', MIGRATIONS[:version]):
                store = Store(str(self.legacy.root/f'old-agents-{version}.db'))
            self.addCleanup(store.db.close)
            store.repo_add('alpha')
            columns = base_columns + (('term_name',) if version >= 2 else ())
            values = base_values + (('legacy-pane',) if version >= 2 else ())
            store.db.execute('INSERT INTO agents ('+','.join(columns)+') VALUES ('+
                ','.join('?' for _ in columns)+')', values)
            store.db.execute('INSERT INTO legacy_names VALUES (?,?)',
                ('old-w1', 'alpha-worker-w1'))
            store.db.execute('INSERT INTO teams VALUES (?,?,?,?)',
                ('alpha', 'builders', 'worker', '2026-10-09T12:03:00Z'))
            store.db.execute('INSERT INTO team_members VALUES (?,?,?)',
                ('alpha', 'builders', 'alpha-worker-w1'))
            snapshot = capture_tasks(store,
                self.legacy.root/f'old-agents-capture-{version}.db',
                source_ref=ref('legacy-source'), application_version=f'legacy-{version}')
            self.addCleanup(snapshot.close)
            source = RepositoryCatalogSource(snapshot,
                source_owner_organization_id='org-one')
            document = strict_loads(source.catalog_bytes(binding=self.binding))
            agent = document['families']['agents']['rows'][0]
            alias = document['families']['legacy_names']['rows'][0]
            team = document['families']['teams']['rows'][0]
            team_member = document['families']['team_members']['rows'][0]
            self.assertEqual(agent['row'], store.q1('SELECT * FROM agents'))
            self.assertEqual(team['row'], store.q1('SELECT * FROM teams'))
            self.assertEqual(team_member['row'], store.q1('SELECT * FROM team_members'))
            self.assertNotIn('generation', agent['row'])
            self.assertIsNone(agent['incarnation'])
            self.assertIsNone(alias['incarnation'])
            self.assertEqual(team_member['teamMemberOf'], team['memberId'])
            self.assertIsNone(team_member['incarnation'])
            with self.assertRaisesRegex(ContractError, '^repository_catalog_artifact_required$'):
                source.configuration_bytes(binding=self.binding)

    def test_team_rows_and_membership_relationships_are_archived_only(self):
        store = self.legacy.store
        session = store.register('alpha', 'worker', 'w1', 'codex',
            {'prompt': 'team worker'}, token_sha='retained-token-digest')
        store.set_state(session, 'ready')
        store.team_add('alpha', 'builders', [session], lead_role='worker')
        snapshot = self.legacy.capture('teams.db')
        source = RepositoryCatalogSource(snapshot, source_owner_organization_id='org-one')
        first = source.catalog_bytes(binding=self.binding)
        self.assertEqual(source.catalog_bytes(binding=self.binding), first)
        with self.assertRaisesRegex(ContractError, '^repository_catalog_artifact_required$'):
            source.configuration_bytes(binding=self.binding)
        document = strict_loads(first)
        team = document['families']['teams']['rows'][0]
        membership = document['families']['team_members']['rows'][0]
        agent = document['families']['agents']['rows'][0]
        self.assertEqual(team['row'], store.q1('SELECT * FROM teams'))
        self.assertEqual(membership['row'], store.q1('SELECT * FROM team_members'))
        self.assertEqual(membership['teamMemberOf'], team['memberId'])
        self.assertEqual(membership['incarnation'], agent['incarnation'])
        self.assertFalse(document['membershipActivated'])

        store.set_state(session, 'dead')
        store.register('alpha', 'worker', 'w1', 'codex', {})
        store.set_state(session, 'ready')
        store.team_add('alpha', 'builders', [session], lead_role='worker')
        later = RepositoryCatalogSource(self.legacy.capture('teams-later.db'),
            source_owner_organization_id='org-one')
        later_document = strict_loads(later.catalog_bytes(binding=self.binding))
        later_team = later_document['families']['teams']['rows'][0]
        later_membership = later_document['families']['team_members']['rows'][0]
        self.assertEqual(later_team['memberId'], team['memberId'])
        self.assertEqual(later_membership['memberId'], membership['memberId'])
        self.assertEqual(later_membership['teamMemberOf'], later_team['memberId'])
        self.assertEqual(later_membership['incarnation']['registrationGeneration'], 2)
        self.assertNotEqual(later_membership['incarnation']['incarnationId'],
            membership['incarnation']['incarnationId'])

    def test_scope_schema_change_and_oversize_refuse_without_source_mutation(self):
        other = OwnerBinding('hub-one', 'configuration', self.identity['catalogId'],
            'configuration', canonical_bytes(SCOPE | {'organizationId': 'other-org'}))
        with self.assertRaisesRegex(ContractError, '^repository_catalog_source_scope_mismatch$'):
            self.source.configuration_bytes(binding=other)
        wrong_entity = OwnerBinding('hub-one', 'configuration', 'other-catalog',
            'configuration', canonical_bytes(SCOPE))
        with self.assertRaisesRegex(ContractError, '^repository_catalog_binding_mismatch$'):
            self.source.configuration_bytes(binding=wrong_entity)
        self.legacy.store.db.executemany('INSERT INTO repo_aliases VALUES (?,?)',
            ((f'oversize-{number:03d}-'+'x'*200, 'alpha') for number in range(100)))
        oversized = RepositoryCatalogSource(self.legacy.capture('oversized.db'),
            source_owner_organization_id='org-one')
        with self.assertRaisesRegex(ContractError, '^repository_catalog_artifact_required$'):
            oversized.configuration_bytes(binding=self.binding)
        self.legacy.store.db.execute("DELETE FROM repo_aliases WHERE alias LIKE 'oversize-%'")
        self.legacy.store.db.execute('ALTER TABLE groups ADD COLUMN unreviewed TEXT')
        changed = RepositoryCatalogSource(self.legacy.capture('changed.db'),
            source_owner_organization_id='org-one')
        with self.assertRaisesRegex(ContractError, '^repository_catalog_source_invalid$'):
            changed.configuration_bytes(binding=self.binding)

    def test_database_cell_and_total_bounds_restore_connection_limit(self):
        self.legacy.store.db.execute('INSERT INTO repo_aliases VALUES (?,?)',
            ('x' * 2048, 'alpha'))
        cell_snapshot = self.legacy.capture('large-cell.db')
        cell_source = RepositoryCatalogSource(cell_snapshot,
            source_owner_organization_id='org-one')
        prior_length_limit = cell_snapshot._db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        with patch('state_owner.repository_migration.MAX_CATALOG_BYTES', 1024):
            with self.assertRaisesRegex(ContractError,
                    '^repository_catalog_source_unavailable$'):
                cell_source.catalog_bytes(binding=self.binding)
        self.assertEqual(cell_snapshot._db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH),
            prior_length_limit)

        self.legacy.store.db.executemany('INSERT INTO groups VALUES (?,?)',
            ((f'bounded-{number}', 'alpha') for number in range(4097)))
        total_source = RepositoryCatalogSource(self.legacy.capture('too-many-rows.db'),
            source_owner_organization_id='org-one')
        with self.assertRaisesRegex(ContractError, '^repository_catalog_artifact_required$'):
            total_source.catalog_bytes(binding=self.binding)


class RepositoryCatalogOwnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        configuration_clock = patch('state_owner.configuration.datetime', _Clock)
        ledger_clock = patch('state_owner.ledger.datetime', _Clock)
        configuration_clock.start(); ledger_clock.start()
        self.addCleanup(configuration_clock.stop); self.addCleanup(ledger_clock.stop)
        source_case = RepositoryCatalogSourceTests()
        source_case.setUp()
        self.addCleanup(source_case.doCleanups)
        self.source_case = source_case
        self.configuration_bytes = source_case.source.configuration_bytes(binding=source_case.binding)
        self.binding, self.identity = source_case.binding, source_case.identity
        self.record, self.envelope = fixture()
        self.owner = native_row()['owner']
        for membership in self.record['state']['memberships']:
            membership['scope'] = copy.deepcopy(SCOPE)
        grant = copy.deepcopy(self.record['state']['grants'][0])
        grant.update(ref=ref('repository-catalog-import'), contractId='configuration-set',
            resourceId=self.binding.entity_id, scope=copy.deepcopy(SCOPE))
        self.record['state']['grants'].append(grant)
        async def authority(*args, **kwargs):
            return SimpleNamespace(subject='identity.owner', seq=1, data=canonical_bytes(self.record))
        self.authority = AuthorityReader(SimpleNamespace(get_msg=authority), stream='IDENTITY',
            subject='identity.owner', hub_id='hub-one', entity_id='authority-one',
            profile_id='profile-one', organization_id='org-one')
        self.policy = Retention(16 * 131072, 131072)
        self.js = FakeJetStream(self.policy)
        self.js.config.subjects = [owner_subject(self.binding)]
        self.ledger = OwnerLedger(self.js, stream='OWNER', subject=owner_subject(self.binding),
            binding=self.binding, retention=self.policy, stream_identity=StreamIdentity(CREATED, 0),
            require_completion_budget=True)
        self.source = ConfigurationOwner(self.authority, self.ledger, owner=self.owner,
            schema_ref='repository-catalog.json',
            schema_resources={'repository-catalog.json': REPOSITORY_CATALOG_SCHEMA},
            issuer_ref=ref('issuer'), signing_seed=SEED, require_native_activation=False)
        self.addAsyncCleanup(self.source.close)

    def request(self, configuration_bytes=None, *, secret_references=()):
        configuration_bytes = self.configuration_bytes if configuration_bytes is None else configuration_bytes
        payload = {'configurationRef': {'id': self.binding.entity_id,
            'ownerHubId': self.binding.hub_id, 'revision': 0},
            'owner': copy.deepcopy(self.owner), 'schemaRef': 'repository-catalog.json',
            'configurationBytes': base64.b64encode(configuration_bytes).decode(),
            'secretReferences': list(secret_references)}
        envelope = copy.deepcopy(self.envelope)
        operation = envelope['operation']
        operation.update(operationId=self.identity['operationId'], expectedVersion=0,
            scope=copy.deepcopy(SCOPE), payloadDigest=payload_digest(payload),
            grantRef=ref('repository-catalog-import'), taskId=None, runId=None,
            attemptId=None, delegationRef=None)
        envelope.update(contractId='configuration-set', destinationServiceId='configuration-owner',
            payload=payload)
        claims = envelope['ingressAttestation']['claims']
        claims.update(contractId='configuration-set', operation=copy.deepcopy(operation),
            audience={'hubId': 'hub-one', 'serviceId': 'configuration-owner'})
        envelope['ingressAttestation']['signature'] = sign_claims(claims, SEED)
        return canonical_bytes(envelope)

    async def test_current_owner_import_replays_without_effect_or_writer_transfer(self):
        request = self.request()
        first_raw = await self.source.handle(request)
        repeated_raw = await self.source.handle(request)
        first = verify_configuration_response(first_raw, request,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'), now=NOW)
        repeated = verify_configuration_response(repeated_raw, request,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'), now=NOW)
        self.assertEqual(repeated['state'], first['state'])
        self.assertEqual(strict_loads(base64.b64decode(first['state']['configurationBytes'])),
            strict_loads(self.configuration_bytes))
        self.assertEqual(len(self.js.messages), 1)
        record = strict_loads(self.js.messages[0].data)
        self.assertEqual((record['effects'], record['artifacts']), ([], []))
        self.assertFalse(strict_loads(self.configuration_bytes)['writerAuthorityTransferred'])

    async def test_revoked_current_authority_refuses_without_commit(self):
        next(grant for grant in self.record['state']['grants']
            if grant['ref'] == ref('repository-catalog-import'))['status'] = 'revoked'
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await self.source.handle(self.request())
        self.assertEqual(self.js.messages, [])

    async def test_team_catalog_cannot_bypass_encrypted_artifact(self):
        self.source_case.legacy.store.team_add('alpha', 'builders', lead_role='worker')
        source = RepositoryCatalogSource(self.source_case.legacy.capture('team-inline.db'),
            source_owner_organization_id='org-one')
        catalog = source.catalog_bytes(binding=self.binding)
        self.assertLessEqual(len(catalog), 16_384)
        with self.assertRaisesRegex(ContractError, '^configuration_value_invalid$'):
            await self.source.handle(self.request(catalog))
        self.assertEqual(self.js.messages, [])

    async def test_large_catalog_uses_verified_encrypted_reference_and_replays(self):
        self.source_case.legacy.store.register('alpha', 'worker', 'w1', 'codex',
            {'source': 'legacy'}, legacy='old-w1', token_sha='retained-token-digest')
        self.source_case.legacy.store.team_add('alpha', 'builders',
            ['alpha-worker-w1'], lead_role='worker')
        private_source = RepositoryCatalogSource(
            self.source_case.legacy.capture('private-inline.db'),
            source_owner_organization_id='org-one')
        private_catalog = private_source.catalog_bytes(binding=self.binding)
        self.assertLessEqual(len(private_catalog), 16_384)
        with self.assertRaisesRegex(ContractError, '^configuration_value_invalid$'):
            await self.source.handle(self.request(private_catalog))
        self.assertEqual(self.js.messages, [])

        self.source_case.legacy.store.db.executemany('INSERT INTO repo_aliases VALUES (?,?)',
            ((f'large-{number:03d}-'+'x'*200, 'alpha') for number in range(100)))
        snapshot = self.source_case.legacy.capture('large-owner.db')
        source = RepositoryCatalogSource(snapshot, source_owner_organization_id='org-one')
        catalog = source.catalog_bytes(binding=self.binding)
        self.assertGreater(len(catalog), 16_384)
        key_path = self.source_case.legacy.root/'catalog.key'
        key_path.write_bytes(bytes(range(SecretBox.KEY_SIZE)))
        key_path.chmod(0o600)
        key = ConversationKey(key_path, key_ref=ref('repository-catalog-key'))
        self.addCleanup(key.close)
        store = artifact_support.Store()
        js = artifact_support.JS(store)
        artifacts = OwnerArtifacts(store, js, bucket='bucket', owner_hub_id='hub-one',
            store_ref=ref('repository-catalog-artifacts'), max_bytes=4_194_304)
        encrypted = bytes(SecretBox(key.read()).encrypt(catalog))
        wrong_ref = await artifacts.upload(encrypted, media_type='application/octet-stream')
        retrieval = AsyncMock(wraps=artifacts.retrieve)
        with (patch.object(source, '_catalog_bytes', wraps=source._catalog_bytes) as catalog_read,
                patch.object(artifacts, 'retrieve', retrieval)):
            with self.assertRaisesRegex(ContractError,
                    '^repository_catalog_artifact_selection_invalid$'):
                await prepare_repository_catalog_artifact(source, binding=self.binding,
                    artifacts=artifacts, key=key, artifact_ref=wrong_ref)
        catalog_read.assert_not_called()
        retrieval.assert_not_awaited()
        wrong_key_path = self.source_case.legacy.root/'other-catalog.key'
        wrong_key_path.write_bytes(bytes(range(SecretBox.KEY_SIZE)))
        wrong_key_path.chmod(0o600)
        wrong_key_ref = dict(ref('repository-catalog-key'), ownerHubId='other-hub')
        wrong_key = ConversationKey(wrong_key_path, key_ref=wrong_key_ref)
        self.addCleanup(wrong_key.close)
        retrieval = AsyncMock(wraps=artifacts.retrieve)
        with (patch.object(source, '_catalog_bytes', wraps=source._catalog_bytes) as catalog_read,
                patch.object(artifacts, 'retrieve', retrieval)):
            with self.assertRaisesRegex(ContractError,
                    '^repository_catalog_artifact_selection_invalid$'):
                await prepare_repository_catalog_artifact(source, binding=self.binding,
                    artifacts=artifacts, key=wrong_key, artifact_ref=wrong_ref)
        catalog_read.assert_not_called()
        retrieval.assert_not_awaited()
        with self.assertRaisesRegex(ContractError,
                '^repository_catalog_artifact_selection_invalid$'):
            RepositoryCatalogImporter(self.source, source=source,
                artifacts=artifacts, key=wrong_key)
        artifact_ref = await artifacts.upload(encrypted, media_type=MEDIA_TYPE)
        wrong_store_ref = copy.deepcopy(artifact_ref)
        wrong_store_ref['storeRef'] = ref('other-artifact-store')
        retrieval = AsyncMock(wraps=artifacts.retrieve)
        with (patch.object(source, '_catalog_bytes', wraps=source._catalog_bytes) as catalog_read,
                patch.object(artifacts, 'retrieve', retrieval)):
            with self.assertRaisesRegex(ContractError, '^owner_artifact_reference$'):
                await prepare_repository_catalog_artifact(source, binding=self.binding,
                    artifacts=artifacts, key=key, artifact_ref=wrong_store_ref)
        catalog_read.assert_not_called()
        retrieval.assert_not_awaited()
        descriptor = await prepare_repository_catalog_artifact(source, binding=self.binding,
            artifacts=artifacts, key=key, artifact_ref=artifact_ref)
        self.assertLessEqual(len(descriptor), 16_384)
        store.data = b'corrupt'
        with self.assertRaisesRegex(ContractError, '^owner_artifact_corrupt$'):
            await prepare_repository_catalog_artifact(source, binding=self.binding,
                artifacts=artifacts, key=key, artifact_ref=artifact_ref)
        store.data = encrypted
        authority_state = canonical_bytes(self.record['state'])
        document = strict_loads(descriptor)
        importer = RepositoryCatalogImporter(self.source, source=source,
            artifacts=artifacts, key=key)
        retrieve = artifacts.retrieve
        artifacts.retrieve = AsyncMock(wraps=retrieve)
        with self.assertRaisesRegex(ContractError, '^repository_catalog_binding_mismatch$'):
            await importer.handle(self.request(descriptor))
        artifacts.retrieve.assert_not_awaited()
        artifacts.retrieve = retrieve
        request = self.request(descriptor, secret_references=[document['keyRef']])
        for name, value in (('schemaRef', 'other-schema.json'),
                ('owner', dict(self.owner, instanceId='other-instance'))):
            changed = strict_loads(request)
            changed['payload'][name] = value
            changed['operation']['payloadDigest'] = payload_digest(changed['payload'])
            claims = changed['ingressAttestation']['claims']
            claims['operation'] = copy.deepcopy(changed['operation'])
            changed['ingressAttestation']['signature'] = sign_claims(claims, SEED)
            artifacts.retrieve = AsyncMock(wraps=retrieve)
            with self.subTest(name=name):
                with self.assertRaisesRegex(ContractError,
                        '^configuration_binding_mismatch$'):
                    await importer.handle(canonical_bytes(changed))
                artifacts.retrieve.assert_not_awaited()
        artifacts.retrieve = retrieve
        self.source_case.legacy.store.db.execute('INSERT INTO repo_aliases VALUES (?,?)',
            ('changed-after-stage', 'alpha'))
        changed_source = RepositoryCatalogSource(
            self.source_case.legacy.capture('changed-after-stage.db'),
            source_owner_organization_id='org-one')
        changed_importer = RepositoryCatalogImporter(self.source, source=changed_source,
            artifacts=artifacts, key=key)
        with self.assertRaisesRegex(ContractError,
                '^repository_catalog_artifact_unavailable$'):
            await changed_importer.handle(request)
        self.assertEqual(self.js.messages, [])
        first = await importer.handle(request)
        confirmed = verify_configuration_response(first, request,
            public_key=self.record['state']['issuers'][0]['publicKey'],
            issuer_ref=ref('issuer'), now=NOW)
        self.assertEqual(base64.b64decode(confirmed['state']['configurationBytes']), descriptor)
        self.assertEqual(confirmed['state']['secretReferences'], [document['keyRef']])
        repeated_descriptor = await prepare_repository_catalog_artifact(source,
            binding=self.binding, artifacts=artifacts, key=key, artifact_ref=artifact_ref)
        repeated = await importer.handle(self.request(repeated_descriptor,
            secret_references=[document['keyRef']]))
        self.assertEqual(repeated, first)
        self.assertEqual(len(self.js.messages), 1)
        self.assertEqual(document['artifactRef'], artifact_ref)
        self.assertEqual(document['families']['repo_aliases'], 101)
        self.assertEqual(document['families']['agents'], 1)
        self.assertEqual(document['families']['legacy_names'], 1)
        self.assertEqual(document['families']['teams'], 1)
        self.assertEqual(document['families']['team_members'], 1)
        self.assertFalse(document['writerAuthorityTransferred'])
        self.assertFalse(document['identityEnrollmentActivated'])
        self.assertFalse(document['credentialsMinted'])
        self.assertFalse(document['membershipActivated'])
        record = strict_loads(self.js.messages[0].data)
        self.assertEqual((record['effects'], record['artifacts']), ([], []))
        self.assertEqual(canonical_bytes(self.record['state']), authority_state)

        grant = next(grant for grant in self.record['state']['grants']
            if grant['ref'] == ref('repository-catalog-import'))
        grant['status'] = 'revoked'
        artifacts.retrieve = AsyncMock(wraps=artifacts.retrieve)
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await importer.handle(request)
        artifacts.retrieve.assert_not_awaited()
        grant['status'] = 'active'
        retrieve = artifacts.retrieve
        async def revoke_after_retrieval(reference):
            result = await retrieve(reference)
            grant['status'] = 'revoked'
            return result
        artifacts.retrieve = AsyncMock(side_effect=revoke_after_retrieval)
        with self.assertRaisesRegex(ContractError, '^configuration_access_refused$'):
            await importer.handle(request)
        artifacts.retrieve.assert_awaited_once()
        self.assertEqual(len(self.js.messages), 1)

        grant['status'] = 'active'
        with patch.object(artifacts, 'retrieve', AsyncMock(side_effect=TimeoutError)):
            with self.assertRaisesRegex(ContractError,
                    '^repository_catalog_deadline_exceeded$'):
                await importer.handle(request)
        self.assertEqual(len(self.js.messages), 1)


if __name__ == '__main__':
    unittest.main()
