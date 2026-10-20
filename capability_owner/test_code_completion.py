"""Private completion records use a real disposable Hub Store."""
import copy
import tempfile
import unittest

from agentmux_contracts import ContractError, canonical_bytes
from hub.server import Hub
from hub.store import Store
from hub.fed.runtime import Federation
from identity.test_knowledge_client import material
from .code_completion import CodeCompletionStore


class CodeCompletionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = self.directory.name + '/hub.db'
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.db.close())
        self.hub = object.__new__(Hub)
        self.hub.store = self.store
        self.fed = object.__new__(Federation)
        self.fed.hub = self.hub
        public = material()
        self.profile = {k: public[k] for k in ('hubId', 'profileId', 'authorityId')}
        route = public['knowledgeCommands']
        route['grantRefs'] = {'federation-code-' + action: dict(id='code-' + action, ownerHubId='hub-one', revision=1)
            for action in ('publish', 'fetched', 'read', 'inspect', 'outcome')}
        self.binding = {**self.profile, 'scope': public['scope'], 'callerRef': public['callerRef'], 'codeCommands': route}
        self.identity = dict(operation_id='explicit-one', request_digest='a' * 64,
            principal={'authenticatedCaller': 'operator', 'caller': 'operator'})
        self.source = dict(binding=self.binding, contractId='federation-code-publish',
            operationId='original-publish', payloadDigest='sha256:' + 'b' * 64,
            resourceRef=dict(id='task-one', ownerHubId='hub-one', revision=2), result={'id': 'original-share'})
        self.result = {'id': 'original-share', 'ref': 'refs/agentmux/nick/topic_aaaaaaaa',
            'sha': 'a' * 40, 'files': 1, 'stat': 'one.txt | 1 +'}
        self.owner = self.new_owner()

    def new_owner(self, **changes):
        return CodeCompletionStore(self.hub, self.fed, profile=changes.get('profile', self.profile))

    def reserve(self, **changes):
        return self.owner.reserve(**{**self.identity, 'binding': self.binding, **changes})

    def complete(self, **changes):
        with self.store.tx():
            return self.owner.complete(**{**self.identity, 'binding': self.binding,
                'result': self.result, 'code_source': self.source, **changes})

    def test_explicit_result_replays_after_helper_and_database_replacement(self):
        self.reserve()
        original = self.complete()
        self.assertEqual(self.new_owner().lookup(**self.identity), original)
        old_owner = self.owner
        self.store.db.close()
        self.store = Store(self.path)
        self.hub.store = self.store
        self.owner = self.new_owner()
        with self.assertRaisesRegex(ContractError, 'code_completion_binding'):
            old_owner.lookup(**self.identity)
        self.assertEqual(self.owner.lookup(**self.identity), original)
        self.assertEqual(self.reserve(), original)
        self.assertEqual(self.complete(), original)
        self.owner.delivered(original)
        self.assertEqual(self.owner.lookup(**self.identity), original)

    def test_same_explicit_id_refuses_changed_body_binding_result_and_source(self):
        self.reserve()
        with self.assertRaises(ContractError):
            self.reserve(request_digest='c' * 64)
        other = copy.deepcopy(self.binding)
        other['codeCommands']['resourceRef']['revision'] = 2
        with self.assertRaises(ContractError):
            self.reserve(binding=other)
        self.complete()
        for change in ({'result': {**self.result, 'id': 'another'}},
                       {'code_source': {**self.source, 'operationId': 'another'}},
                       {'code_source': {**self.source, 'payloadDigest': 'sha256:' + 'd' * 64}}):
            with self.subTest(change=tuple(change)), self.assertRaises(ContractError):
                self.complete(**change)

    def test_principal_and_profile_do_not_disclose_other_original(self):
        self.reserve()
        original = self.complete()
        changed = {**self.identity, 'principal': {'authenticatedCaller': 'operator', 'caller': 'other'}}
        with self.assertRaises(ContractError):
            self.owner.lookup(**changed)
        with self.assertRaises(ContractError):
            with self.store.tx():
                self.owner.complete(**changed, binding=self.binding, result=self.result, code_source=self.source)
        other = self.new_owner(profile={**self.profile, 'profileId': 'other'})
        self.assertIsNone(other.lookup(**self.identity))
        with self.assertRaises(ContractError):
            other.reserve(**self.identity, binding=self.binding)
        with self.assertRaises(ContractError):
            other.delivered(original)
        self.assertEqual(self.owner.lookup(**self.identity), original)

    def test_explicit_id_rejects_a_different_valid_principal_before_reservation(self):
        self.reserve()
        original = self.complete()
        changed = {**self.identity, 'principal': {'authenticatedCaller': 'another-user', 'caller': 'another-user'}}
        binding = copy.deepcopy(self.binding)
        binding['codeCommands']['authenticatedCaller'] = 'another-user'
        binding['callerRef']['id'] = 'another-human'
        with self.assertRaises(ContractError):
            self.owner.lookup(**changed)
        with self.assertRaises(ContractError):
            self.owner.reserve(**changed, binding=binding)
        self.assertEqual(self.owner.lookup(**self.identity), original)
        self.assertEqual(len(self.store.q('SELECT k FROM fed_state')), 1)

    def test_legacy_requests_keep_separate_principal_keys(self):
        self.identity['operation_id'] = None
        original = self.reserve()
        changed = {**self.identity, 'principal': {'authenticatedCaller': 'another-user', 'caller': 'another-user'}}
        binding = copy.deepcopy(self.binding)
        binding['codeCommands']['authenticatedCaller'] = 'another-user'
        binding['callerRef']['id'] = 'another-human'
        self.assertIsNone(self.owner.lookup(**changed))
        other = self.owner.reserve(**changed, binding=binding)
        self.assertEqual(other['principal'], changed['principal'])
        self.assertEqual(self.owner.lookup(**self.identity), original)
        self.assertEqual(len(self.store.q('SELECT k FROM fed_state')), 2)

    def test_complete_requires_existing_transaction_and_rolls_back_with_group(self):
        pending = self.reserve()
        with self.assertRaisesRegex(ContractError, 'code_completion_transaction_required'):
            self.owner.complete(**self.identity, binding=self.binding, result=self.result, code_source=self.source)
        with self.assertRaisesRegex(RuntimeError, 'group failure'):
            with self.store.tx():
                self.complete()
                self.store.db.execute("INSERT INTO fed_state(k,v) VALUES ('group-companion','kept-together')")
                raise RuntimeError('group failure')
        self.assertEqual(self.owner.lookup(**self.identity), pending)
        self.assertIsNone(self.store.q1("SELECT v FROM fed_state WHERE k='group-companion'"))
        self.assertEqual(self.complete()['state'], 'completed')

    def test_legacy_delivery_removes_only_exact_completed_record(self):
        self.identity['operation_id'] = None
        pending = self.reserve()
        with self.assertRaises(ContractError):
            self.owner.delivered(pending)
        original = self.complete()
        changed = copy.deepcopy(original)
        changed['result']['stat'] = 'changed'
        with self.assertRaises(ContractError):
            self.owner.delivered(changed)
        self.assertEqual(self.owner.lookup(**self.identity), original)
        self.owner.delivered(original)
        self.assertIsNone(self.owner.lookup(**self.identity))
        with self.assertRaises(ContractError):
            self.owner.delivered(original)
        self.assertEqual(self.reserve()['state'], 'pending')

    def test_pending_limit_does_not_count_or_evict_completed_receipts(self):
        original = None
        for index in range(34):
            self.identity['operation_id'] = 'completed-' + str(index)
            self.reserve()
            result = self.complete()
            original = result if index == 0 else original
        for index in range(32):
            self.reserve(operation_id='pending-' + str(index))
        with self.assertRaisesRegex(ContractError, 'code_completion_capacity'):
            self.reserve(operation_id='over-limit')
        self.assertEqual(self.owner.lookup(**{**self.identity, 'operation_id': 'completed-0'}), original)
        self.assertEqual(self.reserve(operation_id='pending-0')['state'], 'pending')

    def test_fetch_result_has_no_outer_id_and_keeps_original_source(self):
        self.reserve()
        source = {**self.source, 'contractId': 'federation-code-fetched'}
        result = {'ref': 'refs/agentmux/alice/topic', 'sha': 'a' * 40,
            'checkout': '/original/checkout', 'verified': True, 'files': ['one.py'], 'next': 'review'}
        completed = self.complete(code_source=source, result=result)
        self.assertEqual(completed['result'], result)
        self.assertEqual(completed['codeSource']['result'], {'id': 'original-share'})

    def test_message_source_matches_profile_scope_principal_and_original(self):
        message_binding = copy.deepcopy(self.binding)
        route = message_binding.pop('codeCommands')
        route['peer'] = 'alice'
        route['grantRefs'] = {'federation-message-' + action:
            dict(id='message-' + action, ownerHubId='hub-one', revision=1)
            for action in ('send', 'inspect', 'outcome')}
        message_binding['messageCommands'] = route
        message = {**self.source, 'binding': message_binding, 'contractId': 'federation-message-send',
            'operationId': 'original-handoff', 'result': {'id': 'handoff-one'}}
        self.reserve()
        for field, value in (('profileId', 'other'), ('scope', {**message_binding['scope'], 'workspaceId': 'other'})):
            changed = copy.deepcopy(message)
            changed['binding'][field] = value
            with self.subTest(field=field), self.assertRaises(ContractError):
                self.complete(message_source=changed)
        completed = self.complete(message_source=message)
        self.assertEqual(completed['messageSource'], message)
        changed = {**message, 'operationId': 'different-handoff'}
        with self.assertRaises(ContractError):
            self.complete(message_source=changed)

    def test_custody_replacement_refuses_all_operations(self):
        self.reserve()
        completed = self.complete()
        self.hub.store = object()
        for action in (lambda: self.owner.lookup(**self.identity), self.reserve, self.complete,
                       lambda: self.owner.delivered(completed)):
            with self.assertRaises(ContractError):
                action()
        self.hub.store = self.store
        connection = self.store.db
        self.store.db = object()
        try:
            with self.assertRaises(ContractError):
                self.owner.lookup(**self.identity)
        finally:
            self.store.db = connection
        self.fed.hub = object()
        with self.assertRaises(ContractError):
            self.owner.lookup(**self.identity)

    def test_invalid_inputs_and_private_binding_are_never_persisted(self):
        for operation_id in ('', 'a.b', 'a' * 129, True):
            with self.subTest(operation_id=operation_id), self.assertRaises(ContractError):
                self.reserve(operation_id=operation_id)
        for digest in ('A' * 64, 'a' * 63, None):
            with self.assertRaises(ContractError):
                self.reserve(request_digest=digest)
        for key in ('token', 'seed', 'privateKey', 'credentials'):
            with self.assertRaises(ContractError):
                self.reserve(binding={**self.binding, key: 'private-value'})
        self.assertEqual(self.store.q('SELECT * FROM fed_state'), [])

    def test_malformed_and_oversized_retained_records_fail_closed(self):
        pending = self.reserve()
        row = self.store.q1('SELECT k,v FROM fed_state')
        bad_records = ['{', ' ' + row['v'], 'x' * 1048577]
        changed = copy.deepcopy(pending)
        changed['formatVersion'] = True
        bad_records.append(canonical_bytes(changed).decode())
        changed = copy.deepcopy(pending)
        changed['binding']['callerRef']['revision'] = True
        bad_records.append(canonical_bytes(changed).decode())
        for raw in bad_records:
            with self.store.tx():
                self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (raw, row['k']))
            with self.subTest(length=len(raw)), self.assertRaises(ContractError):
                self.owner.lookup(**self.identity)
        with self.store.tx():
            self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (row['v'], row['k']))
        with self.assertRaises(ContractError):
            self.complete(result={'stat': 'x' * 1048576})
        self.assertEqual(self.owner.lookup(**self.identity), pending)
        with self.assertRaises(ContractError):
            self.complete(code_source={**self.source,
                'resourceRef': {**self.source['resourceRef'], 'revision': True}})

    def test_completed_record_and_source_shape_cannot_be_relabelled(self):
        self.reserve()
        completed = self.complete()
        row = self.store.q1('SELECT k,v FROM fed_state')
        candidates = []
        for field, value in (('codeSource', None), ('state', 'pending'), ('result', None)):
            candidates.append({**completed, field: value})
        changed = copy.deepcopy(completed)
        changed['codeSource']['binding']['codeCommands']['resourceRef']['id'] = 'other'
        candidates.append(changed)
        changed = copy.deepcopy(completed)
        changed['codeSource']['result']['token'] = 'private-value'
        candidates.append(changed)
        for value in candidates:
            with self.store.tx():
                self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (canonical_bytes(value).decode(), row['k']))
            with self.assertRaises(ContractError):
                self.owner.lookup(**self.identity)
        with self.store.tx():
            self.store.db.execute('UPDATE fed_state SET v=? WHERE k=?', (row['v'], row['k']))
            self.store.db.execute('INSERT INTO fed_state(k,v) VALUES (?,?)',
                (row['k'].replace(':completed:', ':pending:'), row['v']))
        with self.assertRaises(ContractError):
            self.owner.lookup(**self.identity)
