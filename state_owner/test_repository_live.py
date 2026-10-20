"""Repository catalog import and replay through the existing real broker fixture."""
import base64
import copy
from datetime import datetime, timedelta, timezone

from nacl.secret import SecretBox
from agentmux_contracts import canonical_bytes, strict_loads
from capability_owner.test_live import packet, stamp
from identity.test_authority import ref, SEED
from identity.test_native_bridge import native_row
from native_security.nats_credentials import validate
from state_owner.artifacts import OwnerArtifacts
from state_owner.configuration import ConfigurationOwner, verify_configuration_response
from state_owner.conversation_migration import ConversationKey
from state_owner.ledger import OwnerLedger
from state_owner.repository_migration import (MEDIA_TYPE, REPOSITORY_CATALOG_SCHEMA,
    RepositoryCatalogImporter, RepositoryCatalogSource, prepare_repository_catalog_artifact,
    repository_catalog_identity)
from state_owner import test_repository_migration as source_fixture
from state_owner import test_task_live as tls_fixture


class LiveRepositoryCatalogImportTests(tls_fixture.LiveTaskTests):
    seed_ready_task = False
    create_task_host = False
    data_domain = data_kind = 'configuration'
    source_role = 'other-scope'
    broker_stream_limit = 4
    bucket = 'REPOSITORY'
    store_bytes = 1_000_000
    test_tls_task_inspect_reserve_restart_replay_and_refusals = None

    def configure_broker_policies(self, policies, reads):
        self.import_permissions = [self.subjects['DATA']] + reads('DATA', 'OBJ_'+self.bucket)
        policies[self.source_role] = {
            'publish': {'allow': self.import_permissions}, 'subscribe': {'allow': []}}

    def validate_source_credential(self):
        validate(self.credentials[self.source_role].read_bytes(),
            account_public_key=self.account_public_key,
            publish_subjects=self.import_permissions,
            subscribe_subjects=[self.inbox_prefixes[self.source_role]+'.>'],
            private_inbox=True)

    def initial_authority(self):
        initial = super().initial_authority()
        grant = copy.deepcopy(initial['state']['grants'][0])
        grant.update(ref=ref('repository-catalog-import'), contractId='configuration-set',
            resourceId=self.task_id)
        initial['state']['grants'].append(grant)
        return initial

    async def asyncSetUp(self):
        self.source_test = source_fixture.RepositoryCatalogSourceTests()
        self.source_test.setUp()
        self.addCleanup(self.source_test.doCleanups)
        snapshot = self.source_test.legacy.capture('live-repository.db')
        self.catalog_source = RepositoryCatalogSource(snapshot,
            source_owner_organization_id='org-one')
        scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.import_identity = repository_catalog_identity(snapshot._source,
            target_hub_id='hub-one', scope=scope)
        self.task_id = self.import_identity['catalogId']
        await super().asyncSetUp()

        provisioner_js = self.connections[0].jetstream()
        store = await provisioner_js.create_object_store(
            bucket=self.bucket, max_bytes=self.store_bytes)
        staging = OwnerArtifacts(store, provisioner_js, bucket=self.bucket,
            owner_hub_id='hub-one', store_ref=ref('repository-catalog-artifacts'),
            max_bytes=self.store_bytes)
        selected_store = await self.source_connection.jetstream().object_store(self.bucket)
        artifacts = OwnerArtifacts(selected_store, self.source_connection.jetstream(),
            bucket=self.bucket, owner_hub_id='hub-one',
            store_ref=ref('repository-catalog-artifacts'), max_bytes=self.store_bytes)
        key_path = self.source_test.legacy.root/'live-repository.key'
        key_path.write_bytes(bytes(range(SecretBox.KEY_SIZE)))
        key_path.chmod(0o600)
        self.key = ConversationKey(key_path, key_ref=ref('repository-catalog-key'))
        self.addCleanup(self.key.close)
        catalog = self.catalog_source.catalog_bytes(binding=self.bindings['DATA'])
        artifact_ref = await staging.upload(
            bytes(SecretBox(self.key.read()).encrypt(catalog)), media_type=MEDIA_TYPE)
        descriptor = await prepare_repository_catalog_artifact(self.catalog_source,
            binding=self.bindings['DATA'], artifacts=artifacts, key=self.key,
            artifact_ref=artifact_ref)

        ledger = OwnerLedger(self.source_connection.jetstream(), stream='DATA',
            subject=self.subjects['DATA'], binding=self.bindings['DATA'],
            retention=self.policy, stream_identity=self.streams['DATA'],
            require_completion_budget=True)
        self.receiver = ConfigurationOwner(self.identity.reader, ledger,
            owner=native_row()['owner'], schema_ref='repository-catalog.json',
            schema_resources={'repository-catalog.json': REPOSITORY_CATALOG_SCHEMA},
            issuer_ref=ref('issuer'), signing_seed=SEED,
            require_native_activation=False)
        self.importer = RepositoryCatalogImporter(self.receiver,
            source=self.catalog_source, artifacts=artifacts, key=self.key)
        document = strict_loads(descriptor)
        self.payload = {'configurationRef': {'id': self.task_id,
                'ownerHubId': 'hub-one', 'revision': 0},
            'owner': native_row()['owner'], 'schemaRef': 'repository-catalog.json',
            'configurationBytes': base64.b64encode(descriptor).decode(),
            'secretReferences': [document['keyRef']]}

    async def admitted(self):
        now = datetime.now(timezone.utc)
        claims = {'purpose': 'agentmux-client-possession-v1', 'hubId': 'hub-one',
            'profileId': 'profile-one', 'authorityId': 'authority-one',
            'transportRef': ref('transport'), 'grantRef': ref('repository-catalog-import'),
            'operationId': self.import_identity['operationId'], 'expectedVersion': 0,
            'contractId': 'configuration-set', 'payload': self.payload,
            'approvalRefs': [], 'issuedAt': stamp(now),
            'expiresAt': stamp(now+timedelta(seconds=30))}
        admitted = await self.identity.ingress.admit(
            packet(claims, bytes(reversed(SEED))),
            cancellation_ref=ref('repository-catalog-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return admitted.envelope

    async def test_tls_repository_catalog_import_and_replay(self):
        request = await self.admitted()
        first = await self.importer.handle(request)
        repeated = await self.importer.handle(request)
        verified = verify_configuration_response(first, request,
            public_key=self.issuer_public, issuer_ref=ref('issuer'),
            now=datetime.now(timezone.utc))
        replayed = verify_configuration_response(repeated, request,
            public_key=self.issuer_public, issuer_ref=ref('issuer'),
            now=datetime.now(timezone.utc))
        self.assertEqual(replayed['state'], verified['state'])
        self.assertEqual(verified['state']['secretReferences'],
            self.payload['secretReferences'])
        current = await self.receiver._ledger.current()
        self.assertEqual((current.sequence, current.latest.sequence), (1, 1))
        record = strict_loads(current.latest.record)
        self.assertEqual((record['effects'], record['artifacts']), ([], []))
        self.assertFalse(strict_loads(base64.b64decode(
            verified['state']['configurationBytes']))['writerAuthorityTransferred'])
        self.success = True

