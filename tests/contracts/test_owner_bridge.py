"""Local owner bridge shapes through both SDKs; no transport authority proof."""
import copy
import json
from pathlib import Path
import unittest

import test_conformance as wire


class OwnerBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clients = [wire.Client('python'), wire.Client('typescript')]
        cls.request = {
            'schemaVersion': '1.0.0', 'kind': 'host-owner-status-request',
            'operation': 'ensure', 'requestId': 'request_' + 'a' * 32,
            'invocationId': 'attempt_' + 'b' * 32,
            'scope': {'hubId': 'fixture_hub', 'instanceId': 'fixture_instance',
                      'profileId': 'fixture_profile', 'assemblyDigest': 'sha256:' + 'c' * 64,
                      'releaseManifestDigest': 'sha256:' + 'd' * 64, 'releaseVersion': '1.0.0'},
            'sentAt': '2026-10-13T20:00:00.123456Z',
        }
        observation = json.loads((Path(__file__).parent / 'vectors/startup-status-examples.json').read_text(encoding='utf-8'))['examples']['reused']
        cls.reply = {key: copy.deepcopy(value) for key, value in cls.request.items() if key != 'operation'}
        cls.reply['kind'] = 'host-owner-status-reply'
        cls.reply['observation'] = observation
        cls.reply['observation']['startupAttemptId'] = cls.request['invocationId']

    def verify(self, cases):
        for client in self.clients:
            replies = client.many([{'op': 'validate', 'schema': schema, 'value': value}
                                   for schema, value, expected in cases])
            for (schema, _, expected), reply in zip(cases, replies):
                with self.subTest(client=client.language, schema=schema, accepted=expected):
                    self.assertIs(reply.get('ok'), expected, reply.get('error'))
                    if expected:
                        self.assertIs(reply.get('result'), True)
                    else:
                        self.assertNotIn('result', reply)

    def test_closed_requests_and_unchanged_l04_reply(self):
        cases = []
        for schema, original in [('host-owner-status-request', self.request),
                                 ('host-owner-status-reply', self.reply)]:
            cases.append((schema, copy.deepcopy(original), True))
            for key in original:
                value = copy.deepcopy(original)
                del value[key]
                cases.append((schema, value, False))
            for path, replacement in [
                (('unexpected',), True), (('schemaVersion',), '2.0.0'),
                (('requestId',), 'request_*'), (('invocationId',), 'attempt_fixture'),
                (('scope', 'hubId'), '*'), (('scope', 'extra'), True),
                (('scope', 'releaseVersion'), '01.0.0'),
                (('sentAt',), '2026-10-13T20:00:00.123456789Z'),
            ]:
                value = copy.deepcopy(original)
                target = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                cases.append((schema, value, False))
        query = copy.deepcopy(self.request)
        query['operation'] = 'status'
        cases.append(('host-owner-status-request', copy.deepcopy(query), True))
        query['operation'] = 'stop-kernel'
        cases.append(('host-owner-status-request', query, False))
        bad_reply = copy.deepcopy(self.reply)
        bad_reply['observation']['startupAttemptId'] = None
        cases.append(('host-owner-status-reply', bad_reply, False))
        self.verify(cases)


if __name__ == '__main__':
    unittest.main()
