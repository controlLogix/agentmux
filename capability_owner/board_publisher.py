"""Host-owned board publisher and explicit storage-route registration.

This opens only the enrolled publisher connection. It neither rotates legacy
credentials nor proves that other account users are fenced. Broker qualification
and routing every eligible writer remain host deployment requirements.
"""
import asyncio
import base64
import re
import ssl
from urllib.parse import urlsplit
from weakref import WeakKeyDictionary

import nkeys

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed.session import FederationSession
from hub.nats_transport import new_client
from .board_owner import BoardMutationOwner
from .board_allocation_owner import BoardAllocationOwner


_ROUTES = WeakKeyDictionary()
_ALLOCATION_ROUTES = WeakKeyDictionary()
_BOOTSTRAP_ROUTES = WeakKeyDictionary()


class BoardAllocationRoute:
    """Publisher-issued prefix gate and legacy allocation endpoint."""
    __slots__=('__weakref__',)

    def __repr__(self):return '<BoardAllocationRoute private>'

    @property
    def owner(self):
        registered=_ALLOCATION_ROUTES.get(self)
        if registered is None:raise ContractError('board_allocation_route_invalid')
        publisher,owner=registered
        publisher._check_allocation_owner(owner)
        return owner

    def check(self,authority,resource,*,publisher=None,_bootstrap=None):
        from .federation_board import FederationBoardResource
        if _bootstrap is None:
            owner=self.owner
        else:
            registered=_ALLOCATION_ROUTES.get(self)
            if registered is None:raise ContractError('board_allocation_route_invalid')
            issuing,owner=registered
            issuing._check_allocation_owner(owner,_bootstrap=_bootstrap)
        if (type(resource) is not FederationBoardResource
                or owner._journal._authority is not authority or owner._resource.repository_id!=resource.repository_id
                or owner._resource.binding.scope!=resource.binding.scope
                or owner._resource.binding.hub_id!=resource.binding.hub_id
                or owner._resource.target.stream_identity.created!=resource.stream_identity.created
                or getattr(owner._resource._jetstream,'_prefix',None)!=getattr(resource._jetstream,'_prefix',None)):
            raise ContractError('board_allocation_route_invalid')
        prefix=owner._resource.target.counter_prefix+'-'
        suffix=resource.card_key.removeprefix(prefix)
        if (not resource.card_key.startswith(prefix) or re.fullmatch(r'[1-9][0-9]{0,15}',suffix) is None
                or int(suffix)>9_007_199_254_740_991):
            raise ContractError('board_allocation_route_invalid')
        if publisher is not None:
            issuing,_=_ALLOCATION_ROUTES[self]
            if (publisher._server!=issuing._server or publisher._account!=issuing._account
                    or publisher._leaf!=issuing._leaf
                    or publisher._selection['jetstream_domain']!=issuing._selection['jetstream_domain']):
                raise ContractError('board_allocation_route_invalid')
        if publisher is not None and owner._resource.target.domain!=(publisher._selection['jetstream_domain'] or ''):
            raise ContractError('board_allocation_route_invalid')
        if _bootstrap is None:
            owner._resource._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap,owner._resource)
            check_bootstrap(_bootstrap,resource)
        return owner

    async def check_card(self,authority,resource):
        owner=self.check(authority,resource)
        await owner._journal.check_card(resource.card_key)
        self.check(authority,resource)


class BoardStorageRoute:
    """Opaque host registration; only its issuing publisher can bind a backend."""
    __slots__ = ('__weakref__',)

    def __repr__(self):
        return '<BoardStorageRoute private>'

    @property
    def resource(self):
        registered=_ROUTES.get(self)
        if registered is None:
            raise ContractError('board_storage_route_invalid')
        return registered[1]._resource

    def check_registration(self, authority, resource, receiving_connection=None):
        permit=_BOOTSTRAP_ROUTES.get(self)
        if permit is None:
            return self.check(authority,resource,receiving_connection)
        registered=_ROUTES.get(self)
        if registered is None:raise ContractError('board_storage_route_invalid')
        publisher,owner=registered
        publisher._check_owner(owner,_bootstrap=permit)
        if (owner._journal._authority is not authority or owner._resource is not resource
                or receiving_connection is publisher._connection):
            raise ContractError('board_storage_route_invalid')
        from .policy_bootstrap import check_bootstrap
        check_bootstrap(permit,resource)
        return owner

    def check(self, authority, resource, receiving_connection=None):
        registered=_ROUTES.get(self)
        if registered is None:
            raise ContractError('board_storage_route_invalid')
        publisher,owner=registered
        publisher._check_owner(owner)
        if (owner._journal._authority is not authority or owner._resource is not resource
                or receiving_connection is publisher._connection):
            raise ContractError('board_storage_route_invalid')
        resource._current()
        return owner


class BoardPublisher:
    def __init__(self, *, credentials, account_public_key, user_public_key,
                 server_url, tls_context, leaf_certificate_sha256, hub_id, entity_id,
                 scope, stream, reply_prefix, repository_id, card_key=None,counter_prefix=None,jetstream_domain=None,
                 server_name=None, connection_lost=None):
        # Import at construction so the independent credential-policy handoff
        # cannot silently fall back to a generic or broader validator.
        try:
            from native_security.nats_credentials import board_publisher_policy, validate_board_publisher
            url=urlsplit(server_url)
            if (type(server_url) is not str or url.scheme not in ('nats','tls')
                    or not url.hostname or url.port is None or url.username is not None
                    or url.password is not None or url.path or url.query or url.fragment
                    or not isinstance(tls_context,ssl.SSLContext)
                    or tls_context.verify_mode!=ssl.CERT_REQUIRED or not tls_context.check_hostname
                    or type(leaf_certificate_sha256) is not str
                    or re.fullmatch(r'sha256:[a-f0-9]{64}',leaf_certificate_sha256) is None):
                raise ValueError()
            if (server_name is not None and (type(server_name) is not str
                    or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                           for label in server_name.split('.')))
                    or connection_lost is not None and not callable(connection_lost)):
                raise ValueError()
            self._selection=dict(hub_id=hub_id,entity_id=entity_id,
                scope=strict_loads(canonical_bytes(scope)),stream=stream,reply_prefix=reply_prefix,
                repository_id=repository_id,card_key=card_key,counter_prefix=counter_prefix,jetstream_domain=jetstream_domain)
            self._policy=board_publisher_policy(**self._selection)
            self._raw,self._account,self._user=credentials,account_public_key,user_public_key
            self._validate=validate_board_publisher
            self._credential()
            self._connection=new_client(require_tls=True,leaf_certificate_sha256=leaf_certificate_sha256)
            self._session=FederationSession()
            self._connection._agentmux_session=self._session
            self.jetstream=self._connection.jetstream(domain=jetstream_domain)
            self._server,self._tls,self._leaf=server_url,tls_context,leaf_certificate_sha256
            self._server_name, self._connection_lost = server_name, connection_lost
            self._start_task=self._close_task=None
            self._closed=False
            self._owners=set()
        except Exception:
            raise ContractError('board_publisher_configuration') from None

    def __repr__(self):
        return '<BoardPublisher private>'

    def _credential(self):
        credential=self._validate(self._raw,account_public_key=self._account,**self._selection)
        if credential.public_key!=self._user:
            raise ContractError('board_publisher_configuration')
        return credential

    def check(self):
        if (self._closed or self._start_task is None or not self._start_task.done()
                or self._start_task.cancelled() or self._start_task.exception() is not None
                or not self._connection.is_connected):
            raise ContractError('board_publisher_unavailable')
        self._credential()
        self._session.check_open()

    async def start(self):
        if self._closed or self._start_task is not None:
            raise ContractError('board_publisher_unavailable')
        def jwt():
            return self._credential().jwt.encode('ascii')
        def signature(nonce):
            if type(nonce) is not str or not 0<len(nonce)<=4096:
                raise ContractError('board_publisher_unavailable')
            key=nkeys.from_seed(self._credential().seed)
            try:
                return base64.b64encode(key.sign(nonce.encode('ascii')))
            finally:
                key.wipe()
        async def connect():
            async with asyncio.timeout(5):
                options = {}
                if self._server_name is not None:
                    options['tls_hostname'] = self._server_name
                if self._connection_lost is not None:
                    options.update(disconnected_cb=self._connection_lost, reconnected_cb=self._connection_lost,
                        closed_cb=self._connection_lost, error_cb=self._connection_lost)
                await self._connection.connect(servers=[self._server],tls=self._tls,
                    user_jwt_cb=jwt,signature_cb=signature,allow_reconnect=False,
                    connect_timeout=3,tls_handshake_first=True,
                    inbox_prefix=self._selection['reply_prefix'].encode('ascii'), **options)
                await self._connection.flush(timeout=1)
        self._start_task=asyncio.create_task(connect())
        self._start_task.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        try:
            await asyncio.shield(self._start_task)
            self.check()
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('board_publisher_unavailable') from None

    def _check_owner(self, owner, *, _bootstrap=None):
        self.check()
        selected=self._selection
        if (selected['card_key'] is None or type(owner) is not BoardMutationOwner
                or owner._resource._jetstream is not self.jetstream
                or owner._journal._ledger._js is not self.jetstream
                or owner._journal._binding.hub_id!=selected['hub_id']
                or owner._journal._binding.entity_id!=selected['entity_id']
                or owner._journal._binding.scope!=canonical_bytes(selected['scope'])
                or owner._journal._ledger._stream!=selected['stream']
                or owner._journal._ledger._subject!=self._policy.ledger_subject
                or owner._journal._target.domain!=(selected['jetstream_domain'] or '')
                or owner._resource.repository_id!=selected['repository_id']
                or owner._resource.card_key!=selected['card_key']
                or owner._journal._authority._ledger._js is self.jetstream
                or getattr(owner._journal._authority._ledger._js,'_nc',None) is self._connection):
            raise ContractError('board_storage_route_invalid')
        if type(owner._allocation_gate) is not BoardAllocationRoute:
            raise ContractError('board_storage_route_invalid')
        owner._allocation_gate.check(owner._journal._authority,owner._resource,publisher=self,_bootstrap=_bootstrap)

    def bind(self, owner, *, allocation_route, _bootstrap=None):
        if type(owner) is not BoardMutationOwner or type(allocation_route) is not BoardAllocationRoute:
            raise ContractError('board_storage_route_invalid')
        previous=owner._allocation_gate
        owner._allocation_gate=allocation_route
        try:self._check_owner(owner,_bootstrap=_bootstrap)
        except BaseException:
            owner._allocation_gate=previous
            raise
        route=BoardStorageRoute()
        _ROUTES[route]=(self,owner)
        if _bootstrap is not None:_BOOTSTRAP_ROUTES[route]=_bootstrap
        self._owners.add(owner)
        return route

    def _check_allocation_owner(self,owner,*,_bootstrap=None):
        self.check()
        selected=self._selection
        if (selected['counter_prefix'] is None or type(owner) is not BoardAllocationOwner
                or owner._resource._jetstream is not self.jetstream or owner._journal._ledger._js is not self.jetstream
                or owner._journal._binding.hub_id!=selected['hub_id']
                or owner._journal._binding.entity_id!=selected['entity_id']
                or owner._journal._binding.scope!=canonical_bytes(selected['scope'])
                or owner._journal._ledger._stream!=selected['stream']
                or owner._journal._ledger._subject!=self._policy.ledger_subject
                or owner._resource.target.domain!=(selected['jetstream_domain'] or '')
                or owner._resource.target.repository_id!=selected['repository_id']
                or owner._resource.target.counter_prefix!=selected['counter_prefix']
                or owner._journal._authority._ledger._js is self.jetstream
                or getattr(owner._journal._authority._ledger._js,'_nc',None) is self._connection):
            raise ContractError('board_allocation_route_invalid')
        if _bootstrap is None:
            owner._resource._current()
        else:
            from .policy_bootstrap import check_bootstrap
            check_bootstrap(_bootstrap,owner._resource)

    def bind_allocation(self,owner,*,_bootstrap=None):
        self._check_allocation_owner(owner,_bootstrap=_bootstrap)
        route=BoardAllocationRoute()
        _ALLOCATION_ROUTES[route]=(self,owner)
        self._owners.add(owner)
        return route

    async def _close(self):
        # Join business workers before taking away their original transport.
        for owner in tuple(self._owners):
            await owner.close(timeout=None)
        if self._start_task is not None:
            await asyncio.gather(asyncio.shield(self._start_task),return_exceptions=True)
        await self._session.close()
        await self._connection.close()

    async def close(self, *, timeout=5):
        if type(timeout) not in (int,float) or not 0<timeout<=10:
            raise ContractError('board_publisher_cleanup_invalid')
        self._closed=True
        failed=(self._close_task is not None and self._close_task.done()
            and (self._close_task.cancelled() or self._close_task.exception() is not None))
        if self._close_task is None or failed:
            self._close_task=asyncio.create_task(self._close())
        try:
            await asyncio.wait_for(asyncio.shield(self._close_task),timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise ContractError('board_publisher_cleanup_incomplete') from None
