"""A remote work release keeps both return and knowledge obligations."""
import json
from unittest.mock import patch

from hub.fed import envelope, ledger
from hub.fed.plugin_adapter import TrustedPluginAdapter, builtin_context_factory
from hub.fed.plugins.work import Work
from hub.fed.work_services import reference
from identity.test_service import _Clock
from .federated_work_client import FederatedWorkCommandClient
from .legacy_work_client import LegacyWorkCommandClient
from .local_work_client import LocalWorkClient
from .test_federated_work_client import FederatedWorkTests
from .test_work_capture_hub import WorkCaptureHubTests


class WorkCapturePipelineTests(WorkCaptureHubTests):
    async def prepare_capture_work(self):
        timer = patch('capability_owner.federated_work_client.datetime', _Clock)
        timer.start()
        self.addCleanup(timer.stop)
        await self.hub._work_rpc.close(timeout=None)
        await self.commands.close(timeout=None)
        await self.replace(owner=self.fed)
        human = self.session_for('human', 'falcon', self.endpoint)
        service = FederatedWorkTests.session_for(self, 'service')
        self.commands = LegacyWorkCommandClient(self.hub, (human, service))
        self.addAsyncCleanup(self.commands.close, timeout=None)
        self.client = LocalWorkClient(self.hub, self.commands)
        self.install_client()
        self.fed.loop = self.fed.wake = None
        self.fed._qualified_work = True
        self.fed._work_commands = FederatedWorkCommandClient(self.fed, self.commands)
        work = TrustedPluginAdapter(Work(), builtin_context_factory('work'))
        self.fed.plugin_adapters = {'work': work}

    async def test_remote_release_stages_return_before_exact_original_capture(self):
        item = self.item()
        admitted = await self.work_call(self.work_request('ingest', self.incoming(item), operation='remote-ingest'))
        self.assertEqual(admitted['result']['outcome'], 'delivered')
        row = admitted['result']['work']
        flags = json.loads(row['fed_flags'])
        grant = envelope.make('work_grant', 'alice', 'remote', item['rid'], 'nick', {
            **reference(flags), 'executor_peer': 'nick', 'executor_node': 'mac',
            'selected': True, 'grant_id': 'grant-original'})
        grant['id'] = 'grant-original'
        accepted = await self.work_call(self.work_request('grant-envelope', {
            'envelope': grant, 'subject': envelope.subject('msg', 'alice', 'nick'), 'localNode': 'mac'},
            operation='remote-grant', revision=admitted['resourceRef']['revision']))
        self.assertEqual(accepted['result']['outcome'], 'delivered')
        target = self.target()
        claimed = await self.packet('claim', {'work_id': row['id']},
            operation_id='remote-claim', target=target)
        self.assertTrue(claimed['ok'], claimed)
        arguments = {'work_id': row['id'], 'outcome': 'done', 'result': 'Original remote result'}
        released = await self.packet('release', arguments, operation_id='remote-release', target=target)
        returned = [json.loads(record['payload']) for record in ledger.outbox_pending(self.store)
            if json.loads(record['payload'])['type'] == 'result']
        self.assertEqual(len(returned), 1)
        self.assertEqual(returned[0]['data']['grant_id'], 'grant-original')
        self.assertEqual(returned[0]['data']['result'], 'Original remote result')
        current = self.store.q1('SELECT * FROM work_items WHERE id=?', (row['id'],))
        self.assertFalse(json.loads(current['fed_flags'])['result_pending'])
        if not released['ok']:
            # Keep the real caller deadline. A reply that missed it must recover
            # the original operation, without another release or finding.
            self.assertEqual(released['error'], 'authenticated work request expired', released)
            released = await self.packet('release', arguments, operation_id='remote-release', target=target)
        self.assertTrue(released['ok'], released)
        self.assertTrue(json.loads(released['result']['fed_flags'])['result_pending'])
        self.assertEqual(await self.packet('release', arguments, operation_id='remote-release', target=target), released)
        self.assertEqual(len(self.mutations('release')), 1)
        findings = self.store.q('SELECT * FROM p_knowledge_items')
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]['body'], findings[0]['source']), ('Original remote result', 'auto:work'))
        returned_after = [json.loads(record['payload']) for record in ledger.outbox_pending(self.store)
            if json.loads(record['payload'])['type'] == 'result']
        self.assertEqual(returned_after, returned)
