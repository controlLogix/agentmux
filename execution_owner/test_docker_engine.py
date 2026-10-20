"""Real bounded subprocess reads and selected immutable image observations."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from agentmux_contracts import ContractError
from .docker_engine import DockerEngine, DockerSelection


class DockerEngineTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name).resolve()/'client'
        self.path.write_text('#!'+sys.executable+'\nimport sys,time\n'+
            "sys.stdout.write('first');sys.stdout.flush();time.sleep(.05);sys.stdout.write('second');sys.stdout.flush()\n")
        self.path.chmod(0o700)
        self.selection=DockerSelection(str(self.path),'desktop-linux','unix:///tmp/selected.sock',
            'selected-engine','29.8.2',str(Path.home()/'.docker'),'sha256:'+'b'*64)
        self.engine=DockerEngine(self.selection)

    async def test_split_output_is_read_completely_through_original_eof(self):
        self.assertEqual(await self.engine._run(('read',)),b'firstsecond')
        self.assertFalse(self.engine._jobs)

    async def test_over_limit_output_joins_original_with_closed_error(self):
        self.path.write_text('#!'+sys.executable+'\nimport sys,time\n'+
            "sys.stdout.write('a'*1024);sys.stdout.flush();time.sleep(.03);sys.stdout.write('b'*2097152);sys.stdout.flush()\n")
        self.engine=DockerEngine(self.selection)
        with self.assertRaisesRegex(ContractError,'^execution_engine_observation_invalid$'):
            await self.engine._run(('read',),limit=4096,timeout=1)
        self.assertFalse(self.engine._jobs)

    async def test_manifest_pin_allows_distinct_content_id_and_refuses_changes(self):
        profile={'image':'python@sha256:'+'a'*64}
        image={'Id':'sha256:'+'b'*64,'Os':'linux','Architecture':'arm64',
            'RepoDigests':[profile['image']],'Config':{}}
        info={'id':'selected-engine','os':'linux','arch':'aarch64','version':'29.8.2'}
        async def read(args):
            if args[0]=='context':return self.selection.endpoint
            if args[0]=='info':return info
            return image
        with patch.object(self.engine,'_json',side_effect=read):
            self.assertEqual((await self.engine.check(profile))['Id'],image['Id'])

            for change in ({'RepoDigests':['python@sha256:'+'c'*64]},
                    {'Architecture':'amd64'}, {'Id':'sha256:'+'c'*64}, {'RepoDigests':{profile['image']:True}}):
                original=image.copy()
                image.update(change)
                with self.subTest(change=change),self.assertRaisesRegex(ContractError,'^execution_image_mismatch$'):
                    await self.engine.check(profile)
                image.clear();image.update(original)

    async def test_commands_use_selected_endpoint_not_mutable_named_context(self):
        self.path.write_text('#!'+sys.executable+'\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
        self.engine=DockerEngine(self.selection)
        got=json.loads(await self.engine._run(('read',)))
        self.assertEqual(got,['--host',self.selection.endpoint,'read'])

    async def test_changed_context_or_daemon_refuses_current_selection(self):
        for endpoint,engine_id in (('unix:///tmp/other.sock','selected-engine'),
                (self.selection.endpoint,'other-engine')):
            async def read(args):
                if args[0]=='context':return endpoint
                return {'id':engine_id,'os':'linux','arch':'aarch64','version':'29.8.2'}
            with patch.object(self.engine,'_json',side_effect=read):
                with self.assertRaisesRegex(ContractError,'^execution_engine_changed$'):
                    await self.engine.check_transport()

    async def test_timeout_joins_same_original_reader_and_process(self):
        self.path.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(5)\n')
        self.engine=DockerEngine(self.selection)
        with self.assertRaisesRegex(ContractError,'^execution_engine_command_unknown$'):
            await self.engine._run(('read',),timeout=.05)
        self.assertFalse(self.engine._jobs)

    async def test_cancellation_joins_same_original_reader_and_process(self):
        import asyncio
        self.path.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(5)\n')
        self.engine=DockerEngine(self.selection)
        original=asyncio.create_task(self.engine._run(('read',)))
        while not self.engine._jobs:await asyncio.sleep(0)
        original.cancel()
        with self.assertRaises(asyncio.CancelledError):await original
        self.assertFalse(self.engine._jobs)
