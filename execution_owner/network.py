"""Finite selected HTTPS destinations; task requests carry only references."""
import asyncio
import base64
from dataclasses import dataclass
import ipaddress
import re
import ssl

from agentmux_contracts import canonical_bytes, strict_loads, validate
from .docker_engine import fail


@dataclass(frozen=True, slots=True, repr=False)
class HTTPSDestination:
    reference: bytes
    host: str
    address: str
    port: int
    path: str
    roots_pem: str

    def __post_init__(self):
        validate('execution-plan-read', {'planRef': strict_loads(self.reference)})
        if (not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',self.host)
                or type(self.port) is not int or not 1<=self.port<=65535
                or not re.fullmatch(r'/[A-Za-z0-9/._~-]{0,1023}',self.path)
                or len(self.roots_pem)>16384):
            fail('execution_network_selection')
        ipaddress.ip_address(self.address)
        ssl.create_default_context(cadata=self.roots_pem)

    def __repr__(self):
        return '<HTTPSDestination selected reference>'

    async def read(self):
        writer = None
        try:
            context = ssl.create_default_context(cadata=self.roots_pem)
            async with asyncio.timeout(3):
                reader,writer = await asyncio.open_connection(self.address,self.port,
                    ssl=context,server_hostname=self.host,limit=16385)
                writer.write(('GET '+self.path+' HTTP/1.1\r\nHost: '+self.host+'\r\nConnection: close\r\n\r\n').encode('ascii'))
                await writer.drain()
                headers = await reader.readuntil(b'\r\n\r\n')
                if len(headers)>8192 or not headers.startswith(b'HTTP/1.1 200 '):
                    fail('execution_network_refused')
                fields = {}
                for line in headers.split(b'\r\n')[1:-2]:
                    name,sep,value = line.partition(b':')
                    name=name.strip().lower()
                    if not sep or name in fields:fail('execution_network_refused')
                    fields[name]=value.strip()
                length=fields.get(b'content-length',b'')
                if not length.isdigit() or int(length)>16384 or b'transfer-encoding' in fields:
                    fail('execution_network_refused')
                body=await reader.readexactly(int(length))
                return {'status':'ok','bodyBase64':base64.b64encode(body).decode('ascii')}
        except Exception:
            return {'status':'denied'}
        finally:
            if writer is not None:
                writer.close()
                try:await writer.wait_closed()
                except Exception:pass


class SelectedNetwork:
    def __init__(self, profile_ref, destinations=()):
        validate('execution-plan-read', {'planRef': profile_ref})
        if any(type(item) is not HTTPSDestination for item in destinations) or len(destinations)>8:
            fail('execution_network_selection')
        self.profile_ref=canonical_bytes(profile_ref)
        self.destinations={item.reference:item for item in destinations}
        if len(self.destinations)!=len(destinations):fail('execution_network_selection')

    def check(self, profile):
        selected=profile['network']
        if (canonical_bytes(selected['profileRef'])!=self.profile_ref
                or set(map(canonical_bytes,selected['destinationRefs']))!=set(self.destinations)
                or (selected['mode']=='none') != (not self.destinations)):
            fail('execution_network_selection')

    async def read(self, request):
        if type(request) is not dict or set(request)!={'destinationRef'}:
            return {'status':'denied'}
        try:destination=self.destinations.get(canonical_bytes(request['destinationRef']))
        except Exception:return {'status':'denied'}
        if destination is None:return {'status':'denied'}
        return await destination.read()
