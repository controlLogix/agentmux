"""Real signed reply checks; these do not qualify connection admission."""
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from nacl.signing import SigningKey
from hub.client_launch_binding import BindingError, ClientBindingState
from agentmux_contracts import canonical_bytes, payload_digest, sign_claims


NOW = datetime(2026, 10, 16, 17, tzinfo=timezone.utc)
SEED = bytes(range(32))


def ref(name):
    return {'id': name, 'ownerHubId': 'hub-one', 'revision': 1}


def signed(claims):
    return canonical_bytes({'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
        'canonicalization': 'RFC8785-JCS-UTF8', 'claims': claims,
        'signature': sign_claims(claims, SEED)})


class ClientLaunchBinding(unittest.TestCase):
    def setUp(self):
        self.connection = object()
        self.scope = {'organizationId': 'org-one', 'projectId': None, 'workspaceId': None}
        self.request = {'purpose': 'agentmux-application-binding-request-v1',
            'requestId': 'request-one', 'nonce': 'b' * 64,
            'hubId': 'hub-one', 'profileId': 'profile-one', 'authorityId': 'authority-one',
            'instanceId': 'instance-one', 'generation': 1, 'lifetimeId': 'a' * 64,
            'releaseDigest': 'sha256:' + 'c' * 64, 'policyRef': ref('policy'),
            'workspaceRef': None, 'transportRef': ref('transport'), 'grantRef': ref('grant'),
            'replySubject': '_INBOX.abcdefghijklmnop', 'issuedAt': NOW.isoformat().replace("+00:00", "Z"),
            'expiresAt': (NOW + timedelta(seconds=4)).isoformat().replace("+00:00", "Z")}
        self.response = {k: v for k, v in self.request.items()
                         if k not in ('purpose', 'replySubject', 'expiresAt')}
        self.response.update(purpose='agentmux-application-binding-response-v1',
            requestDigest=payload_digest(self.request), callerRef=ref('caller'),
            scope=self.scope, signingKeyRef=ref('issuer'), authorityRef=ref('authority-one'),
            authoritySequence=1, validUntil=self.request['expiresAt'])
        import base64
        self.state = ClientBindingState(self.connection,
            public_key=base64.urlsafe_b64encode(bytes(SigningKey(SEED).verify_key)).decode().rstrip('='),
            signing_key_ref=ref('issuer'), caller_ref=ref('caller'), scope=self.scope)

    def accept(self, attempt=None):
        return self.state.accept(self.connection,
            self.state.begin(self.connection, signed(self.request)) if attempt is None else attempt,
            signed(self.response), now=NOW)

    def test_valid_reply_is_private_immutable_and_expires(self):
        accepted = self.accept()
        accepted['callerRef']['id'] = 'substituted'
        self.assertEqual(self.state.current(self.connection, now=NOW)['callerRef'], ref('caller'))
        self.assertNotIn('caller', repr(self.state))
        with self.assertRaises(BindingError):
            self.state.current(self.connection, now=NOW + timedelta(seconds=4))
        with self.assertRaises(BindingError):
            self.state.current(self.connection, now=NOW)

    def test_signed_other_caller_or_scope_is_refused(self):
        for field, value in (('callerRef', ref('other')), ('scope', {**self.scope, 'projectId': 'other'})):
            with self.subTest(field=field):
                original = self.response[field]
                self.response[field] = value
                with self.assertRaisesRegex(BindingError, '^application_binding_refused$'):
                    self.accept()
                with self.assertRaises(BindingError):
                    self.state.current(self.connection, now=NOW)
                self.response[field] = original

    def test_runtime_request_nonce_inbox_and_signature_substitution_refused(self):
        for field, value in (('generation', 2), ('lifetimeId', 'f' * 64),
                             ('nonce', 'e' * 64), ('replySubject', '_INBOX.otherinboxabcdefg')):
            with self.subTest(field=field):
                previous = self.request[field]
                self.request[field] = value
                with self.assertRaises(BindingError):
                    self.accept()
                self.request[field] = previous
        raw = signed(self.response).replace(b'Ed25519', b'Ed25518')
        with self.assertRaises(BindingError):
            self.state.accept(self.connection, self.state.begin(self.connection, signed(self.request)),
                              raw, now=NOW)

    def test_signature_tampering_and_failed_rebind_leave_no_binding(self):
        self.accept()
        attempt = self.state.begin(self.connection, signed(self.request))
        wrapper = {'schemaVersion': '1.0.0', 'algorithm': 'Ed25519',
            'canonicalization': 'RFC8785-JCS-UTF8', 'claims': self.response,
            'signature': sign_claims(self.response, bytes(reversed(SEED)))}
        with self.assertRaisesRegex(BindingError, '^application_binding_refused$'):
            self.state.accept(self.connection, attempt, canonical_bytes(wrapper), now=NOW)
        with self.assertRaises(BindingError):
            self.state.current(self.connection, now=NOW)

    def test_connection_change_during_verification_cannot_restore_binding(self):
        from identity.application_binding import verify_response
        def interrupted(*args, **kwargs):
            claims = verify_response(*args, **kwargs)
            self.state.invalidate()
            return claims
        with patch('hub.client_launch_binding.verify_response', side_effect=interrupted):
            with self.assertRaisesRegex(BindingError, '^application_connection_changed$'):
                self.accept()
        with self.assertRaises(BindingError):
            self.state.current(self.connection, now=NOW)

    def test_replacement_during_verification_cannot_restore_older_binding(self):
        from identity.application_binding import verify_response
        for fail_newer in (False, True):
            with self.subTest(fail_newer=fail_newer):
                def replaced(*args, **kwargs):
                    claims = verify_response(*args, **kwargs)
                    newer = self.state.begin(self.connection, signed(self.request))
                    if fail_newer:
                        with self.assertRaises(BindingError):
                            self.state.accept(self.connection, newer, b'{}', now=NOW)
                    return claims
                with patch('hub.client_launch_binding.verify_response', side_effect=replaced):
                    with self.assertRaisesRegex(BindingError, '^application_connection_changed$'):
                        self.accept()
                with self.assertRaises(BindingError):
                    self.state.current(self.connection, now=NOW)

    def test_exact_request_is_pinned_before_reply_and_invalid_begin_revokes(self):
        attempt = self.state.begin(self.connection, signed(self.request))
        self.request['nonce'] = 'e' * 64
        self.state.accept(self.connection, attempt, signed(self.response), now=NOW)
        self.assertEqual(self.state.current(self.connection, now=NOW)['nonce'], 'b' * 64)
        attempt = self.state.begin(self.connection, signed(self.request))
        with self.assertRaises(BindingError):
            self.state.begin(self.connection, b'x' * 65537)
        with self.assertRaises(BindingError):
            self.accept(attempt)
        with self.assertRaises(BindingError):
            self.state.current(self.connection, now=NOW)

    def test_reconnect_invalidates_pending_and_accepted_reply(self):
        attempt = self.state.begin(self.connection, signed(self.request))
        self.state.invalidate()
        with self.assertRaisesRegex(BindingError, '^application_connection_changed$'):
            self.accept(attempt)
        self.accept()
        self.state.invalidate()
        with self.assertRaises(BindingError):
            self.state.current(self.connection, now=NOW)

    def test_new_attempt_close_and_other_connection_cannot_reuse_binding(self):
        attempt = self.state.begin(self.connection, signed(self.request))
        newer = self.state.begin(self.connection, signed(self.request))
        with self.assertRaises(BindingError):
            self.accept(attempt)
        self.accept(newer)
        with self.assertRaises(BindingError):
            self.accept(newer)
        with self.assertRaises(BindingError):
            self.state.current(object(), now=NOW)
        self.state.close()
        with self.assertRaises(BindingError):
            self.state.begin(self.connection, signed(self.request))
