"""Retained resources can be checked at startup without reopening live access."""
import asyncio
import copy
from datetime import datetime
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from agentmux_contracts import ContractError, canonical_bytes
from hub.fed.board_services import SharedBoardStore
from hub.fed.message_services import LocalMessages, FederationPublisher
from hub.fed.session import FederationSession
from state_owner.ledger import OwnerBinding, StreamIdentity
from . import test_federation_policy_transition as support
from .selected_storage import _PublisherBoardDomain
from .federation_board import FederationBoardResource
from .board_allocation import BoardAllocationResource, BoardAllocationTarget
from .messages import MessageStorageResource, MessageActor
from .messages_host import SelectedMessageDomain
from .policy_bootstrap import PolicyResourceBootstrap


class PolicyBootstrapTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = support.FederationPolicyTransitionTests.asyncSetUp
    make_owner = support.FederationPolicyTransitionTests.make_owner
    request = support.FederationPolicyTransitionTests.request
    selected_storage_host = support.FederationPolicyTransitionTests.selected_storage_host
    final = support.FederationPolicyTransitionTests.final
    project_request = support.FederationPolicyTransitionTests.project_request

    async def run_startup(self, operation, *, knowledge=False):
        selected, second, message = await self.selected_storage_host()
        if knowledge:
            from hub.fed.plugins.knowledge import Knowledge
            from identity.application_service_selection import ApplicationServiceSelection
            from identity.test_authority import ref
            for statement in Knowledge.tables:
                await second.db(second._store.db.execute, statement)
            value = selected._selection.policy
            descriptor = copy.deepcopy(message)
            channel = descriptor['channels'][0]
            channel.pop('peer')
            channel['resourceRef'] = ref('knowledge-one')
            value['storage']['knowledge'] = descriptor
            selected._selection = ApplicationServiceSelection(canonical_bytes(value))
            selected._preconstructed_sources['knowledge'] = second
        selected._preconstructed_sources.update(board=self.source, messages=second)
        raw, desired = await self.final({'verb': 'unshare', 'arguments': {'repo': 'falcon'}})
        await self.transition.apply(raw)
        project = await self.project_request(raw, desired)
        async def startup():
            await self.transition.project(project)
            await operation(selected, second, message)
        task = asyncio.create_task(startup())
        selected._starting = task
        await task

    async def test_suspended_board_keeps_original_card_and_refuses_live_reads(self):
        async def check(selected, second, message):
            permit = await self.source._resource_bootstrap(self.transition, 'board')
            self.addAsyncCleanup(permit.close)
            board = selected._selection.policy['storage']['board']
            pin = board['kvStreamIdentity']
            identity = StreamIdentity(datetime.fromisoformat(pin['created']), pin['minimumSequence'])
            repo = board['repository']
            key = repo['repositoryId'] + '.card.' + board['cardKey']
            raw = canonical_bytes({'rid': repo['repositoryId'], 'key': board['cardKey'], 'unknown': ['preserved']})
            entry = SimpleNamespace(bucket='am_board', key=key, revision=3, value=raw)
            kv = SimpleNamespace(get=AsyncMock(return_value=entry))
            js = SimpleNamespace(_prefix='$JS.'+board['cardPublisher']['connection']['jetstreamDomain']+'.API', key_value=AsyncMock(return_value=kv),
                stream_info=AsyncMock(return_value=SimpleNamespace(created=identity.created,
                    config=SimpleNamespace(name='KV_am_board', subjects=['$KV.am_board.>']),
                    state=SimpleNamespace(last_seq=max(3, identity.minimum_sequence)))))
            session = FederationSession()
            self.addAsyncCleanup(session.close)
            publisher = SimpleNamespace(check=lambda: None)
            domain = SharedBoardStore(_PublisherBoardDomain(self.source, publisher, session, js))
            binding = OwnerBinding('hub-one', 'federation-board', board['resourceRef']['id'],
                'board-card', canonical_bytes(selected._selection.policy['storage']['scope']))
            args = (binding, domain, repo['localName'], repo['repositoryId'], board['cardKey'], identity)
            with self.assertRaises(ContractError):
                FederationBoardResource(*args)
            resource = FederationBoardResource(*args, _bootstrap=permit)
            self.assertIsNone(await permit.validate(resource, 1))
            self.assertEqual(entry.value, raw)
            with self.assertRaises(ContractError):
                await resource.read(3)
            prefix = BoardAllocationResource(OwnerBinding('hub-one', 'federation-board',
                board['allocationPublisher']['ledger']['entityId'], 'board-prefix', binding.scope),
                domain, repo['localName'], BoardAllocationTarget(repo['repositoryId'], repo['counterPrefix'], identity, board['allocationPublisher']['connection']['jetstreamDomain']),
                _bootstrap=permit)
            with self.assertRaises(ContractError):
                prefix._current()
            entry.key = 'substituted'
            with self.assertRaises(ContractError):
                await permit.validate(resource, 1)
            entry.key = key
            self.source._policy_generation += 1
            with self.assertRaises(ContractError):
                permit.check(resource)
            self.source._policy_generation -= 1
            permit.expire()
            with self.assertRaises(ContractError):
                permit.check(resource)
        await self.run_startup(check)

    async def test_actual_message_constructor_preserves_journal_and_rejects_substitution(self):
        async def check(selected, source, message):
            permit = await source._resource_bootstrap(self.transition, 'messages')
            self.addAsyncCleanup(permit.close)
            channel = message['channels'][0]
            session = FederationSession()
            self.addAsyncCleanup(session.close)
            domain = SelectedMessageDomain(source, session, identity=selected._identity,
                scope=selected._selection.policy['storage']['scope'], local_node=message['localNode'])
            binding = OwnerBinding('hub-one', 'federation-messages', channel['resourceRef']['id'],
                'message-channel', canonical_bytes(selected._selection.policy['storage']['scope']))
            kwargs = dict(repository=message['repository']['localName'], peer=channel['peer'],
                actors=tuple(MessageActor(canonical_bytes(a['identityRef']), canonical_bytes(a['transportRef']),
                    a['caller']) for a in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
                instance_id=channel['instanceId'], initial_source=channel['initialSource'])
            resource = MessageStorageResource(binding, LocalMessages(domain), FederationPublisher(domain),
                **kwargs, _bootstrap=permit)
            original = selected._resources[0]
            self.assertEqual(resource._journal.binding, original._journal.binding)
            self.assertEqual(resource._journal._base, original._journal._base)
            await permit.validate(resource, channel['resourceRef']['revision'])
            with self.assertRaises(ContractError):
                MessageStorageResource(binding, LocalMessages(domain), FederationPublisher(domain),
                    **dict(kwargs, instance_id='substituted'), _bootstrap=permit)
            old = source._store
            source._store = object()
            try:
                with self.assertRaises(ContractError):
                    permit.check(resource)
            finally:
                source._store = old
            with self.assertRaises(TypeError):
                PolicyResourceBootstrap()
            with self.assertRaises(ContractError):
                await asyncio.create_task(permit.validate(resource, 1))
        await self.run_startup(check)

    async def test_knowledge_uses_original_store_and_validates_retained_fts_source(self):
        from .knowledge import KnowledgeStorageResource
        from .knowledge_host import SelectedKnowledgeDomain, KnowledgeStoreHost
        async def check(selected, source, message):
            permit = await source._resource_bootstrap(self.transition, 'knowledge')
            self.addAsyncCleanup(permit.close)
            descriptor = selected._selection.policy['storage']['knowledge']
            channel = descriptor['channels'][0]
            session = FederationSession()
            self.addAsyncCleanup(session.close)
            domain = SelectedKnowledgeDomain(source, session, identity=selected._identity,
                scope=selected._selection.policy['storage']['scope'], local_node=descriptor['localNode'])
            await permit.submit(KnowledgeStoreHost.check_knowledge_tables, source._store)
            resource = KnowledgeStorageResource(OwnerBinding('hub-one', 'federation-knowledge',
                channel['resourceRef']['id'], 'knowledge-channel',
                canonical_bytes(selected._selection.policy['storage']['scope'])), domain,
                repository=descriptor['repository']['localName'],
                actors=tuple(MessageActor(canonical_bytes(a['identityRef']), canonical_bytes(a['transportRef']),
                    a['caller']) for a in channel['actors']), plugin_identity_ref=channel['pluginIdentityRef'],
                instance_id=channel['instanceId'], initial_source=None, _bootstrap=permit)
            self.assertIs(resource._store, source._store)
            await permit.validate(resource, 1)
            await permit.submit(source._store.db.execute, 'DROP TRIGGER p_knowledge_ai')
            with self.assertRaisesRegex(ContractError, '^selected_knowledge_store_invalid$'):
                await permit.submit(KnowledgeStoreHost.check_knowledge_tables, source._store)
        await self.run_startup(check, knowledge=True)
