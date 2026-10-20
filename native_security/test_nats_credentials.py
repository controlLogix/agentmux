"""Offline account signatures and enrolled permission checks."""
import base64
import json
import time
import unittest

import nkeys

from .nats_credentials import CredentialError, MAX_BYTES, validate

PREFIX = '_INBOX.application_000001'


def credential(change=None):
    account = nkeys.from_seed(nkeys.encode_seed(bytes([1]) * 32, nkeys.PREFIX_BYTE_ACCOUNT))
    user = nkeys.from_seed(nkeys.encode_seed(bytes([2]) * 32, nkeys.PREFIX_BYTE_USER))
    try:
        account_public, user_public = account.public_key.decode(), user.public_key.decode()
        claims = {'iss': account_public, 'sub': user_public, 'iat': int(time.time()),
                  'exp': int(time.time()) + 3600, 'nats': {'type': 'user', 'version': 2,
                  'pub': {'allow': ['amx.command']}, 'sub': {'allow': [PREFIX + '.>']}}}
        if change:
            change(claims)
        encode = lambda value: base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
        signed = encode({'typ': 'JWT', 'alg': 'ed25519-nkey'}) + b'.' + encode(claims)
        token = signed + b'.' + base64.urlsafe_b64encode(account.sign(signed)).rstrip(b'=')
        raw = (b'-----BEGIN NATS USER JWT-----\n' + token + b'\n------END NATS USER JWT------\n\n'
               b'-----BEGIN USER NKEY SEED-----\n' + user.seed + b'\n------END USER NKEY SEED------\n')
        return raw, account_public, user_public
    finally:
        account.wipe()
        user.wipe()


class CredentialTests(unittest.TestCase):
    def check(self, raw, account):
        return validate(raw, account_public_key=account, publish_subjects=['amx.command'],
                        subscribe_subjects=[PREFIX + '.>'], private_inbox=True)

    def test_actual_signature_material_and_redaction(self):
        raw, account, user = credential()
        result = self.check(raw, account)
        self.assertEqual(result.public_key, user)
        key = nkeys.from_seed(result.seed)
        try:
            self.assertEqual(key.public_key.decode(), user)
        finally:
            key.wipe()
        for printed in (repr(result), str(result), f'{result!r}'):
            self.assertNotIn(result.jwt, printed)
            self.assertNotIn(result.seed.decode(), printed)
        self.assertEqual(self.check(raw.replace(b'\n', b'\r\n'), account).public_key, user)

    def test_wrong_account_signature_seed_and_bounds(self):
        raw, account, _ = credential()
        token = raw.split(b'\n')[1]
        parts = token.split(b'.')
        signature = bytearray(base64.urlsafe_b64decode(parts[2] + b'=='))
        signature[0] ^= 1
        damaged = b'.'.join(parts[:2] + [base64.urlsafe_b64encode(signature).rstrip(b'=')])
        seed = raw.split(b'BEGIN USER NKEY SEED-----\n')[1].split(b'\n')[0]
        bad_seed = seed[:10] + (b'A' if seed[10:11] != b'A' else b'B') + seed[11:]
        other = nkeys.from_seed(nkeys.encode_seed(bytes([3]) * 32, nkeys.PREFIX_BYTE_ACCOUNT))
        try:
            other_account = other.public_key.decode()
        finally:
            other.wipe()
        for name, candidate, selected in (
                ('account', raw, other_account), ('signature', raw.replace(token, damaged), account),
                ('seed CRC', raw.replace(seed, bad_seed), account), ('duplicate blocks', raw + raw, account),
                ('limit', b'x' * (MAX_BYTES + 1), account), ('empty', b'', account)):
            with self.subTest(name=name), self.assertRaisesRegex(CredentialError, '^nats_credential_invalid$'):
                self.check(candidate, selected)

    def test_closed_claims_time_and_grants(self):
        def permission(direction, values):
            return lambda c: c['nats'].__setitem__(direction, {'allow': values})
        cases = {
            'broad inbox': permission('sub', ['_INBOX.>']),
            'another principal': permission('sub', ['_INBOX.another_principal_0001.>']),
            'extra subscription': permission('sub', [PREFIX + '.>', 'amx.event']),
            'broad publication': permission('pub', ['>']),
            'wrong publication': permission('pub', ['amx.other']),
            'response grant': lambda c: c['nats'].__setitem__('resp', {'max': 1, 'ttl': 1000000000}),
            'bearer': lambda c: c['nats'].__setitem__('bearer_token', True),
            'unknown claim': lambda c: c.__setitem__('future', True),
            'wrong subject': lambda c: c.__setitem__('sub', c['iss']),
            'expired': lambda c: c.__setitem__('exp', int(time.time()) - 60),
            'not before': lambda c: c.__setitem__('nbf', int(time.time()) + 3600),
            'future issue': lambda c: c.__setitem__('iat', int(time.time()) + 3600),
            'boolean time': lambda c: c.__setitem__('exp', True),
            'boolean version': lambda c: c['nats'].__setitem__('version', True),
            'null allow': lambda c: c['nats']['sub'].__setitem__('allow', None),
        }
        for name, change in cases.items():
            raw, account, _ = credential(change)
            with self.subTest(name=name), self.assertRaises(CredentialError):
                self.check(raw, account)

    def test_broad_enrolled_inbox_is_refused(self):
        raw, account, _ = credential(lambda c: c['nats'].__setitem__('sub', {'allow': ['_INBOX.>']}))
        with self.assertRaises(CredentialError):
            validate(raw, account_public_key=account, publish_subjects=['amx.command'],
                     subscribe_subjects=['_INBOX.>'], private_inbox=True)

    def test_literal_mode_and_exact_publication(self):
        raw, account, _ = credential(lambda c: c['nats'].__setitem__('sub', {'allow': ['amx.event']}))
        self.assertTrue(validate(raw, account_public_key=account, publish_subjects=['amx.command'],
                                 subscribe_subjects=['amx.event']).public_key)
        with self.assertRaises(CredentialError):
            validate(raw, account_public_key=account, publish_subjects=['amx.command'],
                     subscribe_subjects=['amx.event'], private_inbox=True)

    def test_application_publish_allows_only_exact_scoped_integration_pattern(self):
        pattern = 'amx.v1.h.hub-one.o.org-one.integrations.*.command'
        raw, account, _ = credential(
            lambda c: c['nats']['pub'].__setitem__('allow', ['amx.command', pattern]))
        self.assertTrue(validate(raw, account_public_key=account,
            publish_subjects=['amx.command', pattern], subscribe_subjects=[PREFIX + '.>'],
            private_inbox=True, application_publish=True).public_key)
        with self.assertRaises(CredentialError):
            validate(raw, account_public_key=account,
                publish_subjects=['amx.command', pattern], subscribe_subjects=[PREFIX + '.>'],
                private_inbox=True)
        for broad in ('amx.v1.h.*.o.org-one.integrations.*.command',
                      'amx.v1.h.hub-one.o.org-one.integrations.>',
                      'amx.v1.h.hub-one.o.*.integrations.*.command'):
            candidate, selected, _ = credential(
                lambda c, value=broad: c['nats']['pub'].__setitem__('allow', ['amx.command', value]))
            with self.subTest(broad=broad), self.assertRaises(CredentialError):
                validate(candidate, account_public_key=selected,
                    publish_subjects=['amx.command', broad], subscribe_subjects=[PREFIX + '.>'],
                    private_inbox=True, application_publish=True)


if __name__ == '__main__':
    unittest.main()
