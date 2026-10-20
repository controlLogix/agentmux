"""Real fixed relay framing over retained private subprocess pipes."""
import asyncio
from pathlib import Path
import sys
import tempfile
import unittest

from .container_programs import RELAY


class RelayProgramTests(unittest.IsolatedAsyncioTestCase):
    async def test_private_socket_uses_actual_newline_frames(self):
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'network')
            process=await asyncio.create_subprocess_exec(sys.executable,'-I','-S','-u','-c',
                RELAY.replace('/run/agentmux/network',path),stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
            writer=None
            try:
                async with asyncio.timeout(2):
                    while not Path(path).exists():await asyncio.sleep(.01)
                    reader,writer=await asyncio.open_unix_connection(path)
                    request=b'{"destinationRef":{"id":"approved","ownerHubId":"hub-one","revision":1}}\n'
                    writer.write(request);await writer.drain()
                    forwarded=await process.stdout.readline()
                    self.assertEqual(forwarded,request)
                    process.stdin.write(b'{"status":"denied"}\n');await process.stdin.drain()
                    self.assertEqual(await reader.readline(),b'{"status":"denied"}\n')
            finally:
                if writer is not None:writer.close();await writer.wait_closed()
                if process.returncode is None:process.kill()
                while await process.stdout.read(8192):pass
                await process.wait()
