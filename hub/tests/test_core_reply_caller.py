"""Keep one current final caller check and the original disclosure deadline."""
import asyncio
import json
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from capability_owner.test_work_rpc import WorkRpcTests
from hub.core_endpoint import SelectedCoreRequest, selected_core_request
from hub.store import HubError


class CoreReplyCallerTests(WorkRpcTests):
    async def reply(self, *, initial=(None, False), final=None, attribution=None,
                    changed_peer=False, changed_attribution=False, expire=False,
                    changed_target=False, permission_failure=False):
        self.hub._selected_endpoint = SimpleNamespace(check=Mock(),
            route=SimpleNamespace(binding={'repositories': {'/falcon': 'falcon'}}))
        request = {'verb': 'ping', 'args': {}}
        if attribution is not None:
            request['as'] = attribution
        reader = SimpleNamespace(readline=AsyncMock(return_value=json.dumps(request).encode()))
        replies, probes, deadlines = [], [], []
        socket = object()
        writer = SimpleNamespace(write=lambda raw: replies.append(json.loads(raw)),
            get_extra_info=lambda name: socket, drain=AsyncMock(), close=Mock())
        after_dispatch = False
        clock = [time.monotonic()]
        timer = Mock(wraps=time)
        timer.monotonic.side_effect = lambda: clock[0]

        def peer(value):
            self.assertIs(value, socket)
            return (702 if changed_peer and after_dispatch else 701, os.getuid())

        def identify(pid):
            probes.append((pid, threading.get_ident()))
            if len(probes) == 1:
                return initial
            if expire:
                clock[0] += 6
            if isinstance(final, Exception):
                raise final
            return initial if final is None else final

        original_dispatch = self.hub.dispatch
        async def dispatch(verb, arguments, caller):
            nonlocal after_dispatch
            result = await original_dispatch(verb, arguments, caller)
            task = asyncio.current_task()
            admitted = self.hub._work_reply_identity[task][0]
            deadlines.append(admitted.expires_monotonic)
            if changed_target:
                name = self.store.register('falcon', 'worker', 'target', 'codex', {})
                generation = self.store.agent(name)['generation']
                self.hub._work_read_targets = {task: {name: generation}}
                self.store.set_state(name, 'dead')
                self.store.register('falcon', 'worker', 'target', 'codex', {})
            if changed_attribution:
                # handle_conn's original request is still checked after dispatch.
                request['as'] = 'falcon-worker-other'
            after_dispatch = True
            return result

        original_targets = self.hub._check_work_targets
        async def targets():
            await original_targets()
            deadlines.append(self.hub._work_reply_identity[asyncio.current_task()][0].expires_monotonic)

        async def invoke():
            token = selected_core_request.set(SelectedCoreRequest(
                self.hub._selected_endpoint, 'falcon', '/falcon', asyncio.current_task()))
            try:
                await self.hub.handle_conn(reader, writer)
            finally:
                selected_core_request.reset(token)

        with patch.object(self.hub, 'peer', side_effect=peer), \
                patch.object(self.hub, 'identify_qualified', side_effect=identify), \
                patch.object(self.hub, 'dispatch', side_effect=dispatch), \
                patch.object(self.hub, '_check_work_targets', side_effect=targets), \
                patch('hub.server.time', timer):
            if permission_failure:
                with patch.object(self.commands, 'check', side_effect=HubError('permission revoked')):
                    await asyncio.create_task(invoke())
            elif changed_attribution:
                original_loads = json.loads
                def load(raw, *args, **kwargs):
                    value = original_loads(raw, *args, **kwargs)
                    if isinstance(value, dict) and value.get('verb') == 'ping' and isinstance(raw, bytes):
                        request.clear()
                        request.update(value)
                        return request
                    return value
                with patch('hub.server.json.loads', side_effect=load):
                    await asyncio.create_task(invoke())
            else:
                await asyncio.create_task(invoke())
        writer.close.assert_called_once()
        self.assertEqual(len(replies), 1)
        return replies[0], probes, deadlines

    async def test_final_operator_managed_and_attributed_reply_checks_once(self):
        worker = 'falcon-worker-one'
        for initial, attribution, expected in (
                ((None, False), None, 'operator'),
                ((worker, True), None, worker),
                ((None, False), worker, worker)):
            with self.subTest(caller=expected, attribution=attribution):
                result, probes, deadlines = await self.reply(initial=initial, attribution=attribution)
                self.assertTrue(result['ok'], result)
                self.assertEqual(result['caller'], expected)
                self.assertEqual(len(probes), 2)
                self.assertEqual(probes[0][1], probes[1][1])
                self.assertNotEqual(probes[1][1], threading.get_ident())
                self.assertEqual(len(deadlines), 2)
                self.assertEqual(deadlines[0], deadlines[1])

    async def test_final_changed_peer_refuses_before_classification(self):
        result, probes, _ = await self.reply(changed_peer=True)
        self.assertFalse(result['ok'], result)
        self.assertEqual(len(probes), 1)

    async def test_final_changed_requested_attribution_refuses(self):
        result, probes, _ = await self.reply(changed_attribution=True,
            attribution='falcon-worker-one')
        self.assertFalse(result['ok'], result)
        self.assertEqual(len(probes), 1)

    async def test_final_changed_process_or_pane_refuses(self):
        for final in ((None, True), ('falcon-worker-other', True),
                      HubError('native process changed')):
            with self.subTest(final=final):
                result, probes, _ = await self.reply(final=final)
                self.assertFalse(result['ok'], result)
                self.assertEqual(len(probes), 2)

    async def test_final_target_generation_change_refuses(self):
        result, probes, _ = await self.reply(changed_target=True)
        self.assertFalse(result['ok'], result)
        self.assertIn('registration changed', result['error'])
        self.assertEqual(len(probes), 2)

    async def test_expiry_during_final_classification_refuses_original_deadline(self):
        result, probes, deadlines = await self.reply(expire=True)
        self.assertFalse(result['ok'], result)
        self.assertIn('authenticated work request changed or expired', result['error'])
        self.assertEqual(len(probes), 2)
        self.assertEqual(len(deadlines), 1)

    async def test_current_permission_failure_still_refuses(self):
        result, _, _ = await self.reply(permission_failure=True)
        self.assertFalse(result['ok'], result)
        self.assertIn('permission revoked', result['error'])
