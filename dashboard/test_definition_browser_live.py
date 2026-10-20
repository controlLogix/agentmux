"""AMUX-41 browser flow using the existing disposable enrolled TLS fixture."""
import asyncio
import copy
import os
from pathlib import Path
import threading
from unittest.mock import patch

from agentmux_contracts import canonical_bytes, strict_loads
from state_owner import test_task_live as fixture
from state_owner.artifacts import OwnerArtifacts
from state_owner.ledger import OwnerBinding, owner_subject
from identity.test_authority import ref, SEED
from native_security.nats_credentials import service_policy, validate_service
from definition_command_service import DefinitionCommandService
from definition_service import DefinitionScope
from application_service_host import ApplicationServiceHost
from local_browser_auth import LocalBrowserAuth
import server


class DefinitionBrowserLive(fixture.LiveLegacyAliasApplicationTests):
    broker_stream_limit = 4
    response_ttls = {'storage': '5s'}

    def configure_broker_policies(self, policies, reads):
        super().configure_broker_policies(policies, reads)
        self.definition_scope = {'organizationId': 'org-one', 'projectId': 'project-one',
                                 'workspaceId': None}
        binding = OwnerBinding('hub-one', 'definitions', 'catalog-one', 'definition-catalog',
                               canonical_bytes(self.definition_scope))
        self.bindings['DATA'] = binding
        self.subjects['DATA'] = owner_subject(binding)
        selected = service_policy(role='definitions', hub_id='hub-one', entity_id='catalog-one',
            scope=self.definition_scope, stream='DATA', reply_prefix=self.inbox_prefixes['storage'],
            artifact_bucket='DEFINITIONS')
        policies['storage'] = {'publish': {'allow': list(selected.publish_subjects)},
                               'subscribe': {'allow': [selected.command_subject]}}

    def validate_source_credential(self):
        validate_service(self.credentials['storage'].read_bytes(),
            account_public_key=self.account_public_key, role='definitions', hub_id='hub-one',
            entity_id='catalog-one', scope=self.definition_scope, stream='DATA',
            reply_prefix=self.inbox_prefixes['storage'], artifact_bucket='DEFINITIONS')

    def initial_authority(self):
        initial = super().initial_authority()
        state = initial['state']
        for contract in ('definition-save', 'definition-drop', 'definition-effect-complete'):
            grant = copy.deepcopy(state['grants'][0])
            grant.update(ref=ref(contract), callerRef=ref('human'), actorRef=ref('human'),
                scope=self.definition_scope, contractId=contract, resourceId='definition-one',
                definitionTarget={'scope': 'repo', 'name': 'writer'})
            state['grants'].append(grant)
        return initial

    async def test_enrolled_browser_definition_edits_and_revocation(self):
        loop = asyncio.get_running_loop()
        admin = await self.connect('provisioner')
        await admin.jetstream().create_object_store(bucket='DEFINITIONS', max_bytes=2_097_152)
        js = self.source_connection.jetstream()
        objects = await js.object_store('DEFINITIONS')
        artifacts = OwnerArtifacts(objects, js, bucket='DEFINITIONS', owner_hub_id='hub-one',
            store_ref=ref('definition-content'), max_bytes=65536)
        root = self.directory / 'project'
        root.mkdir(mode=0o700)
        scope = DefinitionScope(root, self.directory/'home', self.directory/'global', 'project-one')
        history, _, checkpoint = self.custody('definitions', 'DATA')
        async def committed(receipt):
            await checkpoint.committed(receipt)
        service = DefinitionCommandService.from_enrolled_host(self.source_connection,
            scope=scope, authority=self.identity.reader, binding=self.bindings['DATA'],
            stream='DATA', stream_identity=self.streams['DATA'], retention=self.policy,
            history=history, artifacts=artifacts, issuer_ref=ref('issuer'), signing_seed=SEED,
            checkpoint_path=checkpoint.checkpoint_prefix, checkpoint_committed=committed)
        host = object.__new__(ApplicationServiceHost)
        host._closed, host._connection_failure, host._loop = False, None, loop
        host._definitions, host._browser_write_timeout = service, 10
        httpd = server.BacklogServer(('127.0.0.1', 0), server.Handler, application_host=host)
        host._browser_origin = f'http://127.0.0.1:{httpd.server_port}'
        host._browser_auth = LocalBrowserAuth(httpd.server_port)
        thread = threading.Thread(target=httpd.serve_forever)
        process = output = errors = None
        stop_refresh = asyncio.Event()
        async def refresh():
            while not stop_refresh.is_set():
                self.refresh_application_observation()
                try:
                    await asyncio.wait_for(stop_refresh.wait(), 1)
                except TimeoutError:
                    pass
        refresh_task = asyncio.create_task(refresh())
        with (patch.object(server, 'HOME_DIR', self.directory),
              patch.object(server.ccstore, 'DB_PATH', self.directory/'cc.db'),
              patch.object(server.boardagents, '_service', return_value=service.owner._service)):
            try:
                await service.start()
                self.identity.configure_local_browser_host(host)
                thread.start()
                owner = await self.open_application()
                process = await asyncio.create_subprocess_exec(os.environ['AMX_BROWSER_NODE'],
                    str(Path(__file__).with_suffix('.mjs')), host._browser_origin,
                    os.environ['AMX_BROWSER_DRIVER'], os.environ['AMX_BROWSER_EXECUTABLE'],
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
                # Retain the original reader and child until cleanup completes.
                errors = asyncio.create_task(process.stderr.read())
                deadline = loop.time() + 15
                while not host._browser_auth._pairings and loop.time() < deadline:
                    if process.returncode is not None:
                        break
                    await asyncio.sleep(.02)
                self.assertTrue(host._browser_auth._pairings, 'browser did not request pairing')
                await owner.local_browser_session_open(challenge='2345-6789-ABCD-EFGH-JKMP',
                    origin=host._browser_origin, operation_id='definition-browser-open',
                    deadline=loop.time()+3, cleanup_deadline=loop.time()+5)
                line = await asyncio.wait_for(process.stdout.readline(), 30)
                if line != b'READY_FOR_REVOCATION\n':
                    await process.wait()
                    self.fail('browser edit checks failed: ' + (await errors).decode()[-2000:])
                snapshot = await service.ledger.current()
                self.assertEqual(snapshot.sequence, 8)
                stored = strict_loads(snapshot.latest.record)
                self.assertEqual(stored['operation']['caller']['authenticatedIdentityRef'], ref('human'))
                self.assertEqual(stored['operation']['effectiveActorRef'], ref('human'))
                self.assertEqual(stored['operation']['scope'], self.definition_scope)
                path = root/'.agentmux/agents/writer.md'
                before = path.read_bytes()
                await self.command('identity-revoke', ref('grant'),
                    {'authorityId': 'authority-one', 'targetRef': ref('application-member')})
                process.stdin.write(b'continue\n')
                await process.stdin.drain()
                output = asyncio.create_task(process.stdout.read())
                self.assertEqual(await asyncio.wait_for(process.wait(), 15), 0,
                                 'browser revocation check failed')
                self.assertIn(b'PASS:', await output)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual((await service.ledger.current()).sequence, 8)
                self.assertFalse(self.errors['storage'] or self.errors['identity'])
                self.success = True
            finally:
                if process is not None:
                    if process.returncode is None:
                        process.terminate()
                    await process.wait()
                    if output is not None:
                        await output
                    if errors is not None:
                        await errors
                    process.stdin.close()
                    await process.stdin.wait_closed()
                stop_refresh.set()
                await refresh_task
                host._browser_auth.close()
                if thread.ident is not None:
                    await asyncio.to_thread(httpd.shutdown)
                    await asyncio.to_thread(thread.join)
                httpd.server_close()
                await service.close()
