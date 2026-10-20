"""Local lifetime adapter for the pinned nats-py 2.16.0 JetStream client.

Subscription binding and ordered reset follow that client's sequence. This
adapter changes task ownership only; stream, consumer, KV and CAS behavior stay
with the existing NATS implementation. Import it only when federation connects.
"""
# The binding/reset adaptations below derive from nats-py, Copyright 2016-2021
# The NATS Authors, licensed under Apache License 2.0:
# https://www.apache.org/licenses/LICENSE-2.0
# Distributed without warranties or conditions of any kind. See that license
# for permissions and limitations.
from __future__ import annotations

from nats.js import api
from nats.js.client import (
    DEFAULT_JS_SUB_PENDING_BYTES_LIMIT,
    DEFAULT_JS_SUB_PENDING_MSGS_LIMIT,
    JetStreamContext,
)


class OwnedJetStream(JetStreamContext):
    def __init__(self, client, owner):
        super().__init__(client)
        self._owner = owner

    async def subscribe(self, *args, **kwargs):
        return await self._owner.acquire(super().subscribe(*args, **kwargs), self._owner.own_subscription)

    async def pull_subscribe(self, *args, **kwargs):
        return await self._owner.acquire(super().pull_subscribe(*args, **kwargs), self._owner.own_subscription)

    async def subscribe_bind(self, stream, config, consumer, cb=None, manual_ack=False,
                             ordered_consumer=False,
                             pending_msgs_limit=DEFAULT_JS_SUB_PENDING_MSGS_LIMIT,
                             pending_bytes_limit=DEFAULT_JS_SUB_PENDING_BYTES_LIMIT):
        # Upstream hardcodes JetStreamContext._JSI rather than a factory. Keep
        # this small binding seam so its heartbeat/read-loop resets can create
        # owned asynchronous work without blocking the broker read loop.
        if cb and not manual_ack and config.ack_policy not in (api.AckPolicy.NONE, api.AckPolicy.FLOW_CONTROL):
            cb = self._auto_ack_callback(cb)
        if config.deliver_subject is None:
            raise TypeError("config.deliver_subject is required")
        sub = await self._owner.acquire(self._nc.subscribe(
            subject=config.deliver_subject, queue=config.deliver_group or "", cb=cb,
            pending_msgs_limit=pending_msgs_limit, pending_bytes_limit=pending_bytes_limit),
            self._owner.own_subscription)
        psub = JetStreamContext.PushSubscription(self, sub, stream, consumer)
        state = sub._jsi = _OwnedJSI(js=self, conn=self._nc, stream=stream, ordered=ordered_consumer,
                                   psub=psub, sub=sub, ccreq=config)
        self._owner.own_subscription(psub)
        if config.idle_heartbeat:
            state._hbtask = self._owner.start_client_task(state.activity_check(), "heartbeat")
        if ordered_consumer:
            state._fctask = self._owner.start_client_task(state.check_flow_control_response(), "flow-control")
        return psub


class _OwnedJSI(JetStreamContext._JSI):
    async def reset_ordered_consumer(self, sseq):
        owner = self._js._owner
        if owner.closing or self._sub._closed or self._psub._closed:
            return False
        # Preserve the pinned client's local subscription replacement and
        # sequence update order. The recreation request remains asynchronous.
        old_id = self._sub._id
        self._conn._remove_sub(old_id)
        deliver = self._conn.new_inbox()
        self._conn._sid += 1
        new_id = self._conn._sid
        self._conn._subs[new_id] = self._sub
        self._sub._id = self._psub._id = new_id
        await self._conn._send_unsubscribe(old_id)
        self._sub._subject = deliver
        await self._conn._send_subscribe(self._sub)
        # The upstream reset yields here so the protocol commands can be sent.
        import asyncio
        await asyncio.sleep(0)
        if owner.closing or self._sub._closed or self._psub._closed:
            return False
        self._cmeta, self._dseq = None, 1
        self._ccreq.deliver_subject = deliver
        self._ccreq.deliver_policy = api.DeliverPolicy.BY_START_SEQUENCE
        self._ccreq.opt_start_seq = sseq
        owner.start_client_task(self.recreate_consumer())
        return True

    async def recreate_consumer(self):
        try:
            result = await self._js._jsm.add_consumer(self._stream, config=self._ccreq, timeout=self._js._timeout)
            if not self._js._owner.closing and not self._sub._closed and not self._psub._closed:
                self._psub._consumer = result.name
        except Exception as error:
            await self._conn._error_cb(error)
