"""Fixed private Docker commands against one explicitly selected local engine."""
import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import stat

from agentmux_contracts import ContractError, strict_loads


def fail(code='execution_container_refused'):
    raise ContractError(code) from None


def fingerprint(path):
    value = os.stat(path)
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def kill_owned(process):
    if process.returncode is None:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass


@dataclass(frozen=True, slots=True, repr=False)
class DockerSelection:
    executable: str
    context: str
    endpoint: str
    engine_id: str
    server_version: str
    config_directory: str
    image_id: str

    def __repr__(self):
        return '<DockerSelection private>'


class DockerEngine:
    def __init__(self, selection):
        if type(selection) is not DockerSelection:
            fail('execution_engine_selection')
        if (not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', selection.context)
                or not selection.endpoint.startswith('unix:///')
                or not re.fullmatch(r'[A-Za-z0-9:_-]{1,128}', selection.engine_id)
                or not re.fullmatch(r'\d+\.\d+\.\d+', selection.server_version)
                or not re.fullmatch(r'sha256:[a-f0-9]{64}', selection.image_id)):
            fail('execution_engine_selection')
        endpoint = selection.endpoint[7:]
        for path in (selection.executable, selection.config_directory, endpoint):
            if not os.path.isabs(path) or any(c in path for c in '\x00\r\n'):
                fail('execution_engine_selection')
        if str(Path(selection.executable).resolve()) != selection.executable:
            fail('execution_engine_selection')
        if not stat.S_ISREG(os.stat(selection.executable).st_mode):
            fail('execution_engine_selection')
        self.selection = selection
        self._binary = fingerprint(selection.executable)
        self._jobs = set()

    def __repr__(self):
        return '<DockerEngine private selected endpoint>'

    def environment(self):
        selected = self.selection
        for key, expected in (('DOCKER_CONTEXT', selected.context), ('DOCKER_HOST', selected.endpoint),
                ('DOCKER_CONFIG', selected.config_directory)):
            if os.environ.get(key, expected) != expected:
                fail('execution_engine_environment_conflict')
        if fingerprint(selected.executable) != self._binary:
            fail('execution_engine_changed')
        return {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'],
            'DOCKER_CONFIG': selected.config_directory}

    async def _run(self, args, *, data=None, timeout=5, limit=262144):
        process = await asyncio.create_subprocess_exec(self.selection.executable,
            '--host', self.selection.endpoint, *args, env=self.environment(),
            stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
        async def joined():
            try:
                if data is not None:
                    process.stdin.write(data)
                    await process.stdin.drain()
                    process.stdin.close()
                    await process.stdin.wait_closed()
                output = bytearray()
                exceeded = False
                while True:
                    chunk = await process.stdout.read(8192)
                    if not chunk:
                        break
                    if not exceeded:
                        output.extend(chunk[:limit+1-len(output)])
                        if len(output)>limit:
                            exceeded=True
                            if process.returncode is None:
                                kill_owned(process)
                    # After overflow, discard through this same reader's EOF
                    # before wait; a paused full pipe must not block joining.
                code = await process.wait()
                if exceeded:
                    fail('execution_engine_observation_invalid')
                if code:
                    fail('execution_engine_command_unknown')
                return bytes(output)
            except BaseException:
                if process.returncode is None:
                    kill_owned(process)
                while await process.stdout.read(8192):
                    pass
                await process.wait()
                raise
        work = asyncio.create_task(joined(), name='execution-docker-command')
        self._jobs.add(work)
        work.add_done_callback(lambda done: self._jobs.discard(done))
        try:
            async with asyncio.timeout(timeout):
                return await asyncio.shield(work)
        except TimeoutError:
            if process.returncode is None:
                kill_owned(process)
            await asyncio.gather(work, return_exceptions=True)
            fail('execution_engine_command_unknown')
        except asyncio.CancelledError:
            # The caller is an adapter-owned retained request. Its observer is
            # shielded separately; direct cancellation still joins this client.
            if process.returncode is None:
                kill_owned(process)
            await asyncio.gather(work, return_exceptions=True)
            raise

    async def _json(self, args):
        try:
            return strict_loads(await self._run(args))
        except ContractError:
            raise
        except Exception:
            fail('execution_engine_observation_invalid')

    async def check_transport(self):
        endpoint = await self._json(('context','inspect',self.selection.context,'--format','{{json .Endpoints.docker.Host}}'))
        info = await self._json(('info','--format','{"id":{{json .ID}},"os":{{json .OSType}},"arch":{{json .Architecture}},"version":{{json .ServerVersion}}}'))
        if endpoint != self.selection.endpoint or info != {'id': self.selection.engine_id, 'os': 'linux',
                'arch': 'aarch64', 'version': self.selection.server_version}:
            fail('execution_engine_changed')
    async def check(self, profile):
        await self.check_transport()
        image = await self._json(('image','inspect',profile['image'],'--format','{{json .}}'))
        if (type(image) is not dict or type(image.get('Config')) is not dict
                or image.get('Id') != self.selection.image_id or image.get('Os') != 'linux'
                or image.get('Architecture') != 'arm64'
                or type(image.get('RepoDigests')) is not list
                or any(type(item) is not str for item in image['RepoDigests'])
                or profile['image'] not in image['RepoDigests']
                or image.get('Config', {}).get('Volumes') or image.get('Config', {}).get('Entrypoint')):
            fail('execution_image_mismatch')
        return image

    async def find(self, name):
        raw = await self._run(('container','ls','--all','--no-trunc','--filter','name=^/'+name+'$',
            '--format','{{.ID}}'))
        try:found = raw.decode('ascii').splitlines()
        except UnicodeError:fail('execution_engine_observation_invalid')
        if not found:
            return None
        if len(found)!=1 or not re.fullmatch('[a-f0-9]{64}', found[0]):
            fail('execution_engine_observation_invalid')
        return await self.inspect(found[0])

    async def inspect(self, container_id):
        if type(container_id) is not str or not re.fullmatch('[a-f0-9]{64}', container_id):
            fail('execution_container_identity')
        return await self._json(('container','inspect',container_id,'--format','{{json .}}'))

    async def exec_fixed(self, container_id, uid, program, *, data=None):
        return await self._run(('exec','--interactive','--user',str(uid),container_id,
            '/usr/local/bin/python3','-I','-S','-c',program), data=data)

    async def relay(self, container_id, uid, program):
        return await asyncio.create_subprocess_exec(self.selection.executable,
            '--host',self.selection.endpoint,'exec','--interactive','--user',str(uid),container_id,
            '/usr/local/bin/python3','-I','-S','-u','-c',program, env=self.environment(),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=65537)
