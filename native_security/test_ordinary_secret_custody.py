"""Real owner-reader authorization with native ordinary-secret descriptors.

The existing offline JetStream boundary supplies retained records. Actual broker
and fixed consumer qualification belongs to AMUX-626, not these component tests.
"""
import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import pickle
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, sign_claims, strict_loads
from identity import test_service as service_fixture
from identity.test_authority import ref, SEED
from identity.test_ordinary_secret import resolution_fixture
from identity import test_ordinary_secret_service as ordinary_fixture
from native_security import ordinary_secret_custody as module
from native_security.ordinary_secret_custody import OrdinarySecretCustody, OrdinarySecretUse
from native_security.secret_custody import PrivateSecret, _ImmutableSecretStore
from native_security import test_secret_custody as admin_fixture


class OrdinaryCustodyTests(unittest.IsolatedAsyncioTestCase):
    request = ordinary_fixture.OrdinarySecretServiceTests.request
    store = ordinary_fixture.OrdinarySecretServiceTests.store

    def setUp(self):
        ordinary_fixture.OrdinarySecretServiceTests.setUp(self)
        patch('native_security.ordinary_secret_custody.datetime', service_fixture._Clock).start()
        temporary = tempfile.TemporaryDirectory(prefix='agentmux-ordinary-custody-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.custody = OrdinarySecretCustody(self.root, self.service.reader)
        self.addAsyncCleanup(self.custody.close)
        self.secret = b'SYNTHETIC-ORDINARY-OWNER-ONLY-TOKEN'
        self.outer = canonical_bytes(resolution_fixture()[1])

    async def proposal(self, raw=None):
        request = self.request() if raw is None else raw
        admitted = await self.service.ingress.admit(request, cancellation_ref=ref('custody-cancel'))
        self.assertEqual(admitted.decision.outcome, 'allowed')
        return request, admitted.envelope

    async def enrolled(self):
        request, envelope = await self.proposal()
        self.assertEqual(await self.custody.provision(envelope, secret=self.secret), ref('ordinary-one'))
        await self.service.handle(request)
        return await self.custody.authorize(self.outer)

    @property
    def secret_path(self):
        return self.root / 'ordinary-secrets' / 'hub-one' / 'ordinary-one' / '1.secret'

    def change_current(self, mutate):
        current = strict_loads(self.js.messages[-1].data)
        mutate(current['state'])
        self.js.messages[-1].data = canonical_bytes(current)

    def revoke(self, collection='grants', name='ordinary-use-grant'):
        self.change_current(lambda state: next(row for row in state[collection]
            if row['ref']['id'] == name).update(status='revoked'))

    async def test_stage_is_not_enrollment_and_committed_use_is_private(self):
        request, envelope = await self.proposal()
        before = tuple(message.data for message in self.js.messages)
        await self.custody.provision(envelope, secret=self.secret)
        self.assertEqual(tuple(message.data for message in self.js.messages), before)
        with self.assertRaises(ContractError):
            await self.custody.authorize(self.outer)
        await self.service.handle(request)
        use = await self.custody.authorize(self.outer)
        private = await self.custody._material(use)
        self.assertIs(type(private), PrivateSecret)
        self.assertEqual(private.private_copy(), self.secret)
        self.assertEqual(await self.custody.recover(use), ref('ordinary-one'))
        self.assertEqual((await self.custody.check(use)).claims()['consumerRef'], ref('consumer'))
        for value in (self.custody, use, private):
            self.assertNotIn(self.secret.decode(), repr(value))
            with self.assertRaises(TypeError): json.dumps(value)
        with self.assertRaises(TypeError): pickle.dumps(private)
        with self.assertRaises(TypeError): pickle.dumps(use)
        self.assertEqual(self.secret_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.secret_path.parent.stat().st_mode & 0o777, 0o700)

    async def test_create_or_match_never_rebinds_material(self):
        _, envelope = await self.proposal()
        await self.custody.provision(envelope, secret=self.secret)
        original = self.secret_path.read_bytes()
        await self.custody.provision(envelope, secret=self.secret)
        with self.assertRaisesRegex(ContractError, 'ordinary_secret_custody_recovery_required'):
            await self.custody.provision(envelope, secret=b'SYNTHETIC-SUBSTITUTE')
        self.assertEqual(self.secret_path.read_bytes(), original)

    async def test_stale_or_tampered_set_cannot_write(self):
        _, envelope = await self.proposal()
        for change in (lambda item: item['operation'].update(expectedVersion=0),
                       lambda item: item['payload']['record'].update(profileId='other-profile')):
            value = strict_loads(envelope)
            change(value)
            with self.assertRaises(ContractError):
                await self.custody.provision(canonical_bytes(value), secret=self.secret)
        self.assertFalse(self.secret_path.exists())

    async def test_current_set_revocation_prevents_staging(self):
        _, envelope = await self.proposal()
        self.revoke(name='grant')
        with self.assertRaises(ContractError):
            await self.custody.provision(envelope, secret=self.secret)
        self.assertFalse(self.secret_path.exists())

    async def test_authority_change_after_write_refuses_success_and_retains_bytes(self):
        _, envelope = await self.proposal()
        original = self.custody._store.provision
        def provision(binding, secret):
            result = original(binding, secret)
            self.revoke(name='grant')
            return result
        with patch.object(self.custody._store, 'provision', provision):
            with self.assertRaises(ContractError):
                await self.custody.provision(envelope, secret=self.secret)
        self.assertTrue(self.secret_path.exists())

    async def test_each_current_principal_grant_membership_and_generation_is_required(self):
        use = await self.enrolled()
        original = self.js.messages[-1].data
        for collection, name in (('grants', 'ordinary-use-grant'),
                ('grants', 'ordinary-resolve-grant'), ('identities', 'human'),
                ('identities', 'custody'), ('identities', 'consumer'),
                ('memberships', 'ordinary-caller-member'), ('memberships', 'custody-member'),
                ('memberships', 'consumer-member'), ('transports', 'custody-transport'),
                ('ordinarySecretReferences', 'ordinary-one')):
            self.js.messages[-1].data = original
            self.revoke(collection, name)
            with self.subTest(collection=collection, name=name), self.assertRaises(ContractError):
                await self.custody._material(use)
        self.js.messages[-1].data = original

    async def test_revocation_during_private_read_refuses_disclosure(self):
        use = await self.enrolled()
        original = self.custody._store.read
        def read(binding):
            result = original(binding)
            self.revoke()
            return result
        with patch.object(self.custody._store, 'read', read):
            with self.assertRaises(ContractError):
                await self.custody._material(use)

    async def test_wrong_scope_consumer_purpose_generation_and_profile_refuse(self):
        await self.enrolled()
        original = strict_loads(self.outer)
        for field, value in (('profileId', 'other-profile'), ('consumerRef', ref('custody')),
                ('purposeRef', ref('other-purpose')), ('generationRef', ref('other-generation')),
                ('scope', {**original['payload']['scope'], 'projectId': 'other-project'})):
            outer = copy.deepcopy(original)
            outer['payload'][field] = value
            outer['operation']['payloadDigest'] = payload_digest(outer['payload'])
            outer['ingressAttestation']['claims']['operation'] = copy.deepcopy(outer['operation'])
            outer['ingressAttestation']['signature'] = sign_claims(outer['ingressAttestation']['claims'], SEED)
            with self.subTest(field=field), self.assertRaises(ContractError):
                await self.custody.authorize(canonical_bytes(outer))

    async def test_rotation_keeps_old_file_and_never_serves_its_bytes(self):
        use = await self.enrolled()
        old = self.secret_path.read_bytes()
        payload = {'authorityId': 'authority-one', 'record': copy.deepcopy(
            strict_loads((await self.custody.check(use)).record)), 'previousRef': ref('ordinary-one')}
        payload['record'].update(ref=ref('ordinary-two'), generationRef=ref('ordinary-two'))
        raw = self.request(payload=payload, expected=2, operation='rotate-for-custody')
        _, envelope = await self.proposal(raw)
        await self.custody.provision(envelope, secret=b'SYNTHETIC-NEW-GENERATION')
        await self.service.handle(raw)
        with self.assertRaises(ContractError): await self.custody._material(use)
        self.assertEqual(self.secret_path.read_bytes(), old)
        self.assertTrue((self.secret_path.parent.parent / 'ordinary-two' / '1.secret').is_file())

    async def test_rotation_between_read_and_return_refuses_original(self):
        use = await self.enrolled()
        original = self.custody._store.read
        def read(binding):
            private = original(binding)
            self.change_current(lambda state: next(row for row in state['ordinarySecretReferences']
                if row['ref']['id'] == 'ordinary-one').update(ref={**ref('ordinary-one'), 'revision': 2}, status='revoked'))
            return private
        with patch.object(self.custody._store, 'read', read):
            with self.assertRaises(ContractError): await self.custody._material(use)

    async def test_offline_reader_never_uses_retained_material(self):
        use = await self.enrolled()
        original = self.js.stream_info
        async def unavailable(*args, **kwargs): raise OSError('private-test-error')
        with patch.object(self.js, 'stream_info', unavailable), \
                patch.object(self.custody._store, 'read', side_effect=AssertionError('not reached')):
            with self.assertRaises(ContractError) as failure:
                await self.custody._material(use)
        self.assertNotIn('private-test-error', str(failure.exception))
        self.assertIsNotNone(original)

    async def test_expired_original_never_uses_retained_material(self):
        use = await self.enrolled()
        with patch('identity.ordinary_secret.datetime') as clock, \
                patch.object(self.custody._store, 'read', side_effect=AssertionError('not reached')):
            clock.now.return_value = service_fixture.NOW + timedelta(minutes=11)
            clock.fromisoformat.side_effect = service_fixture.datetime.fromisoformat
            with self.assertRaises(ContractError): await self.custody._material(use)

    async def test_queued_worker_rechecks_authority_before_touching_material(self):
        use = await self.enrolled()
        executor = ThreadPoolExecutor(max_workers=1)
        loop = asyncio.get_running_loop()
        loop.set_default_executor(executor)
        entered, release = threading.Event(), threading.Event()
        def occupied():
            entered.set()
            return release.wait(5)
        holder = loop.run_in_executor(None, occupied)
        caller = None
        try:
            for _ in range(100):
                if entered.is_set(): break
                await asyncio.sleep(0.01)
            self.assertTrue(entered.is_set())
            with patch.object(self.custody._store, 'read', side_effect=AssertionError('not reached')):
                caller = asyncio.create_task(self.custody._material(use))
                await asyncio.sleep(0.01)
                self.revoke()
                release.set()
                with self.assertRaises(ContractError): await caller
        finally:
            release.set()
            await holder
            if caller is not None:
                await asyncio.gather(caller, return_exceptions=True)

    async def test_partial_write_is_retained_and_never_overwritten(self):
        _, envelope = await self.proposal()
        original = module.os.write
        calls = 0
        def failed(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1: return original(fd, data[:20])
            raise OSError('PRIVATE ERROR MUST NOT ESCAPE')
        with patch.object(module.os, 'write', failed):
            with self.assertRaises(ContractError) as failure:
                await self.custody.provision(envelope, secret=self.secret)
        self.assertNotIn('PRIVATE', str(failure.exception))
        partial = self.secret_path.read_bytes()
        self.assertEqual(len(partial), 20)
        with self.assertRaises(ContractError):
            await self.custody.provision(envelope, secret=self.secret)
        self.assertEqual(self.secret_path.read_bytes(), partial)

    async def test_material_size_and_type_are_bounded(self):
        _, envelope = await self.proposal()
        for value in (b'', 'SYNTHETIC-STRING', b'x' * (module.SECRET_LIMIT + 1)):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ContractError):
                await self.custody.provision(envelope, secret=value)
        self.assertFalse(self.secret_path.exists())

    async def test_foreign_and_forged_use_cannot_access_custody(self):
        use = await self.enrolled()
        other = OrdinarySecretCustody(self.root, self.service.reader)
        try:
            for candidate in (use, object.__new__(OrdinarySecretUse), object()):
                with self.assertRaises(ContractError): await other._material(candidate)
            with self.assertRaises(ContractError): OrdinarySecretUse()
        finally:
            await other.close()

    async def test_symlink_hardlink_permissions_and_tampering_refuse(self):
        use = await self.enrolled()
        original = self.secret_path.read_bytes()
        extra = self.root / 'link'
        for mode in ('symlink', 'hardlink', 'permissions', 'changed'):
            with self.subTest(mode=mode):
                if mode == 'symlink':
                    self.secret_path.rename(extra)
                    self.secret_path.symlink_to(extra)
                elif mode == 'hardlink': os.link(self.secret_path, extra)
                elif mode == 'permissions': self.secret_path.chmod(0o644)
                else: self.secret_path.write_bytes(original.replace(b'ordinary-secret-custody', b'changed-secret-custody'))
                with self.assertRaises(ContractError): await self.custody._material(use)
                if mode == 'symlink':
                    self.secret_path.unlink(); extra.rename(self.secret_path)
                elif mode == 'hardlink': extra.unlink()
                elif mode == 'permissions': self.secret_path.chmod(0o600)
                else: self.secret_path.write_bytes(original)

    async def test_root_replacement_is_not_silent_reenrollment(self):
        use = await self.enrolled()
        moved = self.root.with_name(self.root.name + '-moved')
        self.root.rename(moved)
        self.root.mkdir(mode=0o700)
        try:
            with self.assertRaises(ContractError): await self.custody._material(use)
        finally:
            self.root.rmdir(); moved.rename(self.root)

    async def test_administrator_namespace_and_api_remain_separate(self):
        use = await self.enrolled()
        example = admin_fixture.ImmutableSecretStoreTests('test_create_replay_and_private_result')
        example.setUp()
        self.addCleanup(example.doCleanups)
        admin = _ImmutableSecretStore(self.root)
        # Deliberately choose matching hub/ID to prove the ordinary namespace wins.
        binding = copy.deepcopy(example.binding)
        binding['ref'] = ref('ordinary-one')
        admin.provision(binding, b'SYNTHETIC-ADMIN-ONLY')
        self.assertEqual(admin.resolve(binding).private_copy(), b'SYNTHETIC-ADMIN-ONLY')
        self.assertEqual((await self.custody._material(use)).private_copy(), self.secret)
        with self.assertRaises(ContractError): admin.resolve(strict_loads((await self.custody.check(use)).record))

    async def test_cancel_and_close_retain_original_writer_until_join(self):
        _, envelope = await self.proposal()
        entered, release = threading.Event(), threading.Event()
        original = self.custody._store.provision
        def held(binding, secret):
            entered.set()
            if not release.wait(5): raise RuntimeError('test release missing')
            return original(binding, secret)
        with patch.object(self.custody._store, 'provision', held):
            caller = asyncio.create_task(self.custody.provision(envelope, secret=self.secret))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(0.01)
                self.assertTrue(entered.is_set())
                caller.cancel()
                with self.assertRaises(asyncio.CancelledError): await caller
                with self.assertRaisesRegex(ContractError, 'ordinary_secret_custody_cleanup_incomplete'):
                    await self.custody.close(timeout=0.02)
                self.assertIsNotNone(self.custody._store._fd)
                self.assertFalse(self.custody._closing.done())
            finally:
                release.set()
                await self.custody.close()
        self.assertIsNone(self.custody._store._fd)
        self.assertFalse(self.custody._tasks)
        replacement = OrdinarySecretCustody(self.root, self.service.reader)
        try:
            self.assertEqual(await replacement.provision(envelope, secret=self.secret), ref('ordinary-one'))
        finally:
            await replacement.close()

    async def test_repeated_close_cancellation_retains_original_reader(self):
        use = await self.enrolled()
        entered, release = threading.Event(), threading.Event()
        original = self.custody._store.read
        def held(binding):
            entered.set()
            if not release.wait(5): raise RuntimeError('test release missing')
            return original(binding)
        with patch.object(self.custody._store, 'read', held):
            caller = asyncio.create_task(self.custody._material(use))
            try:
                for _ in range(100):
                    if entered.is_set(): break
                    await asyncio.sleep(0.01)
                self.assertTrue(entered.is_set())
                caller.cancel()
                with self.assertRaises(asyncio.CancelledError): await caller
                original_close = None
                for _ in range(2):
                    closing = asyncio.create_task(self.custody.close())
                    await asyncio.sleep(0.01)
                    original_close = original_close or self.custody._closing
                    self.assertIs(self.custody._closing, original_close)
                    closing.cancel()
                    with self.assertRaises(asyncio.CancelledError): await closing
                    self.assertIsNotNone(self.custody._store._fd)
                    self.assertFalse(original_close.done())
            finally:
                release.set()
                await self.custody.close()
        self.assertIsNone(self.custody._store._fd)
        self.assertFalse(self.custody._tasks)

    def test_nonledger_authority_cannot_construct_custody(self):
        with self.assertRaises(ContractError): OrdinarySecretCustody(self.root, object())


if __name__ == '__main__':
    unittest.main()
