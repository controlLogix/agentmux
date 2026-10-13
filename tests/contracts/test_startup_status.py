"""L04 shape admission through both SDKs; no live readiness or authority proof."""
import copy
import json
from pathlib import Path
import unittest

import test_conformance as wire


class StartupStatus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clients = [wire.Client('python'), wire.Client('typescript')]
        cls.examples = json.loads((Path(__file__).parent / 'vectors/startup-status-examples.json').read_text())['examples']

    def cases(self, cases, accepted=False):
        for client in self.clients:
            replies = client.many([{'op': 'validate', 'schema': 'startup-status-observation', 'value': value}
                                   for _, value in cases])
            for (label, _), reply in zip(cases, replies):
                with self.subTest(client=client.language, case=label):
                    self.assertIs(reply.get('ok'), accepted)
                    if accepted:
                        self.assertIs(reply.get('result'), True)
                    else:
                        self.assertIsInstance(reply.get('error'), str)
                        self.assertNotIn('result', reply)

    def changed(self, path, replacement, example='started'):
        value = copy.deepcopy(self.examples[example])
        parent = value
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = replacement
        return value

    def test_all_dispositions_and_honest_observations(self):
        self.assertEqual({v['disposition'] for v in self.examples.values()},
                         {'started', 'reused', 'starting', 'remote', 'unconfigured', 'failed'})
        self.cases(list(self.examples.items()), accepted=True)
        degraded = copy.deepcopy(self.examples['started'])
        degraded['instance'].update(readiness='degraded', runningVersion=None)
        degraded['work'] = copy.deepcopy(self.examples['failed']['work'])
        degraded['persistence'] = copy.deepcopy(self.examples['failed']['persistence'])
        degraded['hubs'] = copy.deepcopy(self.examples['failed']['hubs'])
        failed = copy.deepcopy(self.examples['failed'])
        for field in ('composeProject', 'contextDisplayName', 'contextFingerprint', 'endpoint'):
            failed['instance'][field] = None
        self.cases([('degraded-unknown-services', degraded), ('failed-unknown-context', failed)], accepted=True)
        # A transport observation does not establish application readiness or trust.
        connected = self.examples['link_connected']['hubs']['entries'][0]
        self.assertEqual(connected['applicationAvailability'], 'unavailable')
        self.assertEqual(connected['federationReadiness'], 'unknown')
        self.assertEqual(connected['trustState'], 'unknown')

    def test_required_envelope_and_nested_fields(self):
        cases = []
        original = self.examples['link_connected']
        paths = [(), ('caller',), ('caller', 'scope'), ('caller', 'authenticatedIdentityRef'),
                 ('instance',), ('instance', 'services', 0), ('persistence',),
                 ('persistence', 'storagePressure'), ('persistence', 'replicationHealth'),
                 ('work',), ('hubs',), ('hubs', 'entries', 0),
                 ('hubs', 'entries', 0, 'reservationSummary')]
        for path in paths:
            parent = original
            for key in path:
                parent = parent[key]
            for field in parent:
                value = copy.deepcopy(original)
                target = value
                for key in path:
                    target = target[key]
                del target[field]
                cases.append((f'missing:{path}:{field}', value))
        self.cases(cases)

    def test_identity_timestamp_revision_and_state_refusals(self):
        mutations = [
            (('schemaVersion',), '2.0.0'), (('observationId',), ''),
            (('observedAt',), 'not-a-timestamp'), (('sourceRevision',), -1),
            (('sourceRevision',), True), (('startupAttemptId',), 'bad.scope'),
            (('disposition',), 'healthy'), (('caller', 'principalId'), '*'),
            (('caller', 'kind'), 'operator'),
            (('caller', 'scope', 'organizationId'), 'another.org'),
            (('caller', 'authenticatedIdentityRef', 'revision'), -1),
            (('instance', 'readiness'), 'healthy'),
            (('instance', 'mode'), 'automatic'), (('instance', 'runningVersion'), 'latest'),
            (('persistence', 'storagePressure', 'percentUsed'), 101),
            (('persistence', 'replicationHealth', 'replicas'), 0),
            (('hubs', 'inventoryState'), 'unknown'), (('errors',), None),
        ]
        self.cases([(f'invalid:{path}:{replacement}', self.changed(path, replacement))
                    for path, replacement in mutations])

    def test_zero_requires_an_observation_and_unknown_is_not_zero(self):
        known = copy.deepcopy(self.examples['started'])
        unknown = copy.deepcopy(self.examples['failed'])
        self.assertEqual(known['work']['active'], 0)
        self.assertIsNone(unknown['work']['active'])
        self.cases([('observed-zero', known), ('unknown-null', unknown)], accepted=True)
        cases = []
        for field in ('active', 'projects', 'reserved', 'sourceCursor'):
            cases.append((f'known-null:{field}', self.changed(('work', field), None)))
            cases.append((f'unknown-zero:{field}', self.changed(('work', field), 0, 'failed')))
            cases.append((f'negative:{field}', self.changed(('work', field), -1)))
        cases.append(('known-without-time', self.changed(('work', 'observedAt'), None)))
        cases.append(('unknown-fake-time', self.changed(('work', 'observedAt'), self.examples['started']['observedAt'], 'failed')))
        cases.append(('unknown-storage-zero', self.changed(('persistence', 'storagePressure', 'percentUsed'), 0, 'failed')))
        cases.append(('unknown-replicas-one', self.changed(('persistence', 'replicationHealth', 'replicas'), 1, 'failed')))
        self.cases(cases)

    def test_inventory_visibility_and_future_service_refusals(self):
        cases = []
        entry = copy.deepcopy(self.examples['link_connected']['hubs']['entries'][0])
        for state in ('unavailable', 'forbidden'):
            cases.append((f'hidden-entry:{state}', self.changed(('hubs', 'entries'), [entry], 'inventory_' + state)))
        cases.extend([
            ('hidden-total', self.changed(('hubs', 'totalCount'), 1, 'inventory_forbidden')),
            ('future-service-ready', self.changed(('instance', 'services', 1, 'readiness'), 'ready')),
            ('future-service-no-reason', self.changed(('instance', 'services', 1, 'unavailableReason'), None)),
            ('unavailable-persistence-ready', self.changed(('persistence', 'readiness'), 'ready', 'failed')),
            ('unavailable-domain-leak', self.changed(('persistence', 'domainId'), 'hidden_domain', 'failed')),
            ('future-federation-ready', self.changed(('hubs', 'entries', 0, 'federationReadiness'), 'ready', 'link_connected')),
            ('unknown-reservation-zero', self.changed(('hubs', 'entries', 0, 'reservationSummary', 'count'), 0, 'link_connected')),
            ('negative-age', self.changed(('hubs', 'entries', 0, 'ageSeconds'), -1, 'link_connected')),
        ])
        self.cases(cases)

    def test_failure_errors_and_start_reuse_remote_consistency(self):
        cases = []
        for disposition in ('failed', 'unconfigured'):
            cases.append((disposition + ':empty-errors', self.changed(('errors',), [], disposition)))
            cases.append((disposition + ':false-ready', self.changed(('instance', 'readiness'), 'ready', disposition)))
        for disposition in ('started', 'reused', 'starting'):
            cases.append((disposition + ':no-attempt', self.changed(('startupAttemptId',), None, disposition)))
        for disposition in ('started', 'reused'):
            for field in ('profileId', 'composeProject', 'contextDisplayName', 'contextFingerprint', 'endpoint'):
                cases.append((disposition + ':unknown:' + field, self.changed(('instance', field), None, disposition)))
                degraded = self.changed(('instance', field), None, disposition)
                degraded['instance']['readiness'] = 'degraded'
                cases.append((disposition + ':degraded-unknown:' + field, degraded))
        for state in ('connected', 'disconnected', 'stale'):
            for field in ('observedAt', 'ageSeconds'):
                cases.append((state + ':unknown:' + field,
                              self.changed(('hubs', 'entries', 0, field), None, 'link_' + state)))
            timeless = self.changed(('hubs', 'entries', 0, 'observedAt'), None, 'link_' + state)
            timeless['hubs']['entries'][0]['ageSeconds'] = None
            cases.append((state + ':no-freshness-observation', timeless))
        cases.extend([
            ('starting-false-ready', self.changed(('instance', 'readiness'), 'ready', 'starting')),
            ('remote-local-compose', self.changed(('instance', 'composeProject'), 'local_stack', 'remote')),
            ('remote-local-context', self.changed(('instance', 'contextFingerprint'), 'sha256:' + 'b' * 64, 'remote')),
            ('failed-error-no-code', self.changed(('errors',), [{'component': 'startup', 'message': 'Fixture failure.', 'retryable': False}], 'failed')),
        ])
        self.cases(cases)

    def test_private_fields_and_credential_endpoints_are_refused(self):
        cases = []
        for path in [('credentialPath',), ('token',), ('reasoning',),
                     ('caller', 'token'), ('instance', 'privatePath'),
                     ('instance', 'managementKey'), ('persistence', 'credentials'),
                     ('work', 'privateTasks'), ('hubs', 'hiddenHubIds')]:
            cases.append((f'private-field:{path}', self.changed(path, 'synthetic-private-value')))
        for endpoint in ('file:///private/home', '/private/home',
                         'nats://user:password@localhost:4222',
                         'https://localhost/status?token=synthetic', 'https://localhost/status#secret'):
            cases.append(('credential-endpoint', self.changed(('instance', 'endpoint'), endpoint)))
        self.cases(cases)
