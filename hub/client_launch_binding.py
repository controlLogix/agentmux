"""Verify client binding replies for one admitted connection lifetime.

The connection owner supplies trusted enrollment and calls invalidate on every
connection loss or reconnect. This module opens no connection, loads no key and
provides no domain-operation authority or application-readiness claim.
"""
from datetime import datetime

from hub.client_launch_imports import use_bundled_sdk
use_bundled_sdk()

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_binding import verify_response


class BindingError(ValueError):
    """Fixed client diagnostics; signed documents and enrollment remain private."""


def _copy(value):
    return strict_loads(canonical_bytes(value))


class ClientBindingState:
    """Own reply admission and expiry on one retained connection.

    Construction must follow production connection admission. Object identity
    alone is insufficient: the owner must invalidate on disconnect/reconnect,
    including an unsuccessful reconnect. This state never makes that decision
    from a request field, callback result, or ambient endpoint.
    """
    def __init__(self, connection, *, public_key, signing_key_ref, caller_ref, scope):
        self._connection = connection
        self._public_key = public_key
        self._signing_key_ref = _copy(signing_key_ref)
        self._caller_ref, self._scope = _copy(caller_ref), _copy(scope)
        self._epoch = object()
        self._attempt = None
        self._latest_attempt = None
        self._request = None
        self._binding = None
        self._closed = False

    def __repr__(self):
        return '<ClientBindingState private>'

    def invalidate(self):
        self._epoch = object()
        self._attempt = self._binding = self._latest_attempt = self._request = None

    def close(self):
        # The actual connection remains with its existing owner.
        self._closed = True
        self.invalidate()

    def begin(self, connection, request_raw):
        if self._closed or connection is not self._connection:
            raise BindingError('application_connection_unavailable')
        self._attempt = self._binding = self._request = None
        self._latest_attempt = object()
        if type(request_raw) is not bytes or len(request_raw) > 65536:
            raise BindingError('application_binding_refused')
        self._request = request_raw
        self._attempt = (self._epoch, self._latest_attempt)
        return self._attempt

    def accept(self, connection, attempt, raw, *, now):
        if (self._closed or connection is not self._connection
                or attempt is not self._attempt or attempt is None
                or attempt[0] is not self._epoch):
            raise BindingError('application_connection_changed')
        # Consume this attempt even if verification fails. Its caller must not
        # restore access with an earlier reply after a failed replacement bind.
        request_raw = self._request
        self._attempt = self._binding = self._request = None
        epoch = self._epoch
        try:
            claims = verify_response(raw, request_raw, public_key=self._public_key,
                                     signing_key_ref=self._signing_key_ref, now=now)
            if claims['callerRef'] != self._caller_ref or claims['scope'] != self._scope:
                raise BindingError('application_caller_mismatch')
        except (ContractError, ValueError, TypeError, KeyError, OverflowError):
            raise BindingError('application_binding_refused') from None
        if (self._closed or epoch is not self._epoch
                or attempt[1] is not self._latest_attempt):
            raise BindingError('application_connection_changed')
        # Retain immutable bytes; a caller cannot mutate the accepted identity,
        # scope or validity interval through a returned dictionary.
        self._binding = canonical_bytes(claims)
        return _copy(claims)

    def current(self, connection, *, now):
        if self._closed or connection is not self._connection or self._binding is None:
            raise BindingError('application_connection_unavailable')
        claims = strict_loads(self._binding)
        try:
            if not (datetime.fromisoformat(claims['issuedAt']) <= now
                    < datetime.fromisoformat(claims['validUntil'])):
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            self.invalidate()
            raise BindingError('application_binding_expired') from None
        return claims
