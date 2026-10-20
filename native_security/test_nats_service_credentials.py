"""Separate signed credential policies for existing receiving-service traffic."""
import base64
import json
from types import SimpleNamespace
import unittest

from nats.js.client import JetStreamContext
from nats.nuid import NUID

from .nats_credentials import (CredentialError, service_policy, validate, validate_service,
    authority_switch_receiver_policy, validate_authority_switch_receiver)
from .test_nats_credentials import credential
from state_owner.artifacts import OwnerArtifacts


def options(role='definitions'):
    result = dict(role=role, hub_id='hub-one', entity_id='catalog-one' if role == 'definitions' else 'authority-one',
                  scope={'organizationId': 'org-one', 'projectId': None, 'workspaceId': None},
                  stream='DEFINITIONS' if role == 'definitions' else 'IDENTITY',
                  reply_prefix='_INBOX.' + role + '_service_000001', jetstream_domain='LOCAL')
    if role == 'definitions':
        result.update(artifact_bucket='DEFINITION_ARTIFACTS')
    return result


def signed_service(selected, change=None):
    policy = service_policy(**selected)
    def claims(value):
        value['nats'].update(pub={'allow': list(policy.publish_subjects)},
                             sub={'allow': list(policy.subscribe_subjects)},
                             resp=policy.response_permissions)
        if change:
            change(value['nats'])
    return credential(claims)


def signed_service_policy(policy, change=None):
    def claims(value):
        value['nats'].update(pub={'allow': list(policy.publish_subjects)},
                             sub={'allow': list(policy.subscribe_subjects)},
                             resp=policy.response_permissions)
        if change:
            change(value['nats'])
    return credential(claims)


class ServiceCredentialTests(unittest.TestCase):
    def test_orchestration_service_has_one_scoped_command_and_owner_ledger(self):
        selected = dict(role='orchestration', hub_id='hub-one',
            entity_id='orchestration-one',
            scope={'organizationId': 'org-one', 'projectId': 'project-one',
                   'workspaceId': None}, stream='ORCHESTRATION',
            reply_prefix='_INBOX.orchestration_service_01',
            jetstream_domain='LOCAL')
        policy = service_policy(**selected)
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w._.orchestration.'
            'orchestration-one.command')
        self.assertEqual(policy.ledger_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.'
            'orchestration-operations.orchestration-one')
        self.assertEqual(policy.subscribe_subjects, tuple(sorted((
            policy.command_subject, selected['reply_prefix'] + '.>'))))
        raw, account, user = signed_service(selected)
        self.assertEqual(validate_service(raw, account_public_key=account,
            **selected).public_key, user)
        changed = dict(selected)
        changed['scope'] = dict(selected['scope'], projectId=None)
        with self.assertRaises(CredentialError):
            service_policy(**changed)

    def test_authority_switch_receiver_has_only_exact_command_and_ledger_access(self):
        selected = dict(hub_id='hub-one', entity_id='switch_' + 'a' * 64,
            scope={'organizationId': 'org-one', 'projectId': None, 'workspaceId': None},
            stream='AUTHORITY_SWITCH', reply_prefix='_INBOX.switch_service_0001',
            jetstream_domain='LOCAL')
        policy = authority_switch_receiver_policy(**selected)
        ledger = ('amx.v1.h.hub-one.o.org-one.p._.w._.ledger.authority-switch.'
                  + selected['entity_id'])
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.authority-switch.'
            + selected['entity_id'] + '.command')
        self.assertIn(ledger, policy.publish_subjects)
        self.assertEqual(policy.response_permissions, {'max': 1, 'ttl': 5_000_000_000})
        raw, account, user = signed_service_policy(policy)
        self.assertEqual(validate_authority_switch_receiver(raw,
            account_public_key=account, **selected).public_key, user)
        widened, account, _ = signed_service_policy(policy,
            lambda nats: nats['pub']['allow'].append('$JS.API.>'))
        with self.assertRaises(CredentialError):
            validate_authority_switch_receiver(widened,
                account_public_key=account, **selected)

    def test_exact_signed_roles_and_immutable_policy(self):
        for role in ('identity', 'definitions'):
            selected = options(role)
            policy = service_policy(**selected)
            raw, account, user = signed_service(selected)
            result = validate_service(raw, account_public_key=account, **selected)
            self.assertEqual(result.public_key, user)
            own = ('amx.v1.h.hub-one.o.org-one.p._.w._.ledger.identity.authority-one'
                   if role == 'identity' else
                   'amx.v1.h.hub-one.o.org-one.p._.w._.ledger.definitions.catalog-one')
            expected = [own]
            if role == 'identity':
                expected.extend(('$JS.LOCAL.API.STREAM.INFO.IDENTITY', '$JS.LOCAL.API.STREAM.MSG.GET.IDENTITY'))
            else:
                expected.extend(('$JS.LOCAL.API.STREAM.INFO.DEFINITIONS',
                    '$JS.LOCAL.API.STREAM.MSG.GET.DEFINITIONS',
                    '$JS.LOCAL.API.STREAM.INFO.OBJ_DEFINITION_ARTIFACTS',
                    '$JS.LOCAL.API.STREAM.MSG.GET.OBJ_DEFINITION_ARTIFACTS',
                    '$O.DEFINITION_ARTIFACTS.C.*', '$O.DEFINITION_ARTIFACTS.M.*'))
            expected += [subject.replace('$JS.LOCAL.API.', '$JS.API.') for subject in expected
                         if subject.startswith('$JS.LOCAL.API.')]
            self.assertEqual(policy.publish_subjects, tuple(sorted(expected)))
            self.assertEqual(policy.command_subject, 'amx.v1.h.hub-one.o.org-one.' + role + '.'
                             + selected['entity_id'] + '.command')
            self.assertIn(policy.command_subject, policy.subscribe_subjects)
            self.assertIn(selected['reply_prefix'] + '.>', policy.subscribe_subjects)
            self.assertNotIn('_INBOX.>', policy.publish_subjects)
            response = policy.response_permissions
            response['max'] = 0
            self.assertEqual(policy.response_permissions, {'max': 1, 'ttl': 5_000_000_000})
            with self.assertRaises(CredentialError):
                validate(raw, account_public_key=account, publish_subjects=policy.publish_subjects,
                         subscribe_subjects=policy.subscribe_subjects, private_inbox=True)

    def test_signed_extra_grants_and_response_expansion_are_refused(self):
        selected = options()
        additions = ('_INBOX.>', '$JS.LOCAL.API.>', '$JS.LOCAL.API.STREAM.MSG.GET.OTHER', '$JS.LOCAL.API.STREAM.INFO.IDENTITY',
                     '$JS.API.>', '$JS.API.STREAM.INFO.OTHER', '$JS.API.STREAM.MSG.GET.OTHER',
                     '$JS.API.STREAM.PURGE.DEFINITIONS', '$JS.OTHER.API.STREAM.INFO.DEFINITIONS',
                     '$JS.LOCAL.API.STREAM.MSG.GET.IDENTITY',
                     '$JS.LOCAL.API.STREAM.PURGE.OBJ_DEFINITION_ARTIFACTS',
                     '$JS.LOCAL.API.CONSUMER.CREATE.OBJ_DEFINITION_ARTIFACTS',
                     '$O.OTHER.C.*', '$O.DEFINITION_ARTIFACTS.>',
                     'amx.v1.h.hub-one.o.other-org.p._.w._.ledger.definitions.catalog-one')
        for extra in additions:
            with self.subTest(extra=extra):
                raw, account, _ = signed_service(selected, lambda n: n['pub']['allow'].append(extra))
                with self.assertRaises(CredentialError):
                    validate_service(raw, account_public_key=account, **selected)
        for response in (None, {}, {'max': 0, 'ttl': 5_000_000_000}, {'max': 2, 'ttl': 5_000_000_000},
                         {'max': 1, 'ttl': 0}, {'max': 1, 'ttl': 5_000_000_001},
                         {'max': True, 'ttl': 5_000_000_000}, {'max': 1, 'ttl': 5_000_000_000, 'extra': 1}):
            with self.subTest(response=response):
                raw, account, _ = signed_service(selected, lambda n: n.__setitem__('resp', response))
                with self.assertRaises(CredentialError):
                    validate_service(raw, account_public_key=account, **selected)
        raw, account, _ = signed_service(selected, lambda n: n['sub']['allow'].append('_INBOX.other_principal_00001.>'))
        with self.assertRaises(CredentialError):
            validate_service(raw, account_public_key=account, **selected)

    def test_inputs_cannot_supply_wildcards_or_expand_host_role(self):
        for field, bad in (('role', 'host'), ('role', 'kernel'), ('hub_id', 'hub.*'),
                           ('entity_id', '>'), ('stream', '*'),
                           ('artifact_bucket', 'OTHER.*'), ('jetstream_domain', '>'),
                           ('reply_prefix', '_INBOX')):
            selected = options()
            selected[field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(CredentialError):
                service_policy(**selected)
        selected = options('identity')
        selected['artifact_bucket'] = 'OTHER'
        with self.assertRaises(CredentialError):
            service_policy(**selected)

    def test_mapped_api_requires_both_exact_forms_and_default_domain_has_no_duplicates(self):
        for role in ('identity', 'definitions'):
            selected = options(role)
            for missing in ('$JS.API.STREAM.INFO.', '$JS.API.STREAM.MSG.GET.',
                            '$JS.LOCAL.API.STREAM.INFO.', '$JS.LOCAL.API.STREAM.MSG.GET.'):
                subject = missing + selected['stream']
                raw, account, _ = signed_service(selected, lambda n: n['pub']['allow'].remove(subject))
                with self.subTest(role=role, missing=subject), self.assertRaises(CredentialError):
                    validate_service(raw, account_public_key=account, **selected)
            selected['jetstream_domain'] = None
            policy = service_policy(**selected)
            self.assertEqual(len(policy.publish_subjects), len(set(policy.publish_subjects)))
            self.assertFalse(any(s.startswith('$JS.LOCAL.') for s in policy.publish_subjects))
            raw, account, _ = signed_service(selected)
            validate_service(raw, account_public_key=account, **selected)

    def test_scope_domain_bucket_and_stream_bindings(self):
        selected = options()
        selected['scope'] = {'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': 'workspace-one'}
        raw, account, _ = signed_service(selected)
        self.assertTrue(validate_service(raw, account_public_key=account, **selected).public_key)
        policy = service_policy(**selected)
        self.assertEqual(policy.ledger_subject,
                         'amx.v1.h.hub-one.o.org-one.p.project-one.w.workspace-one.ledger.definitions.catalog-one')
        for field, value in (('entity_id', 'other-catalog'), ('stream', 'OTHER'),
                             ('artifact_bucket', 'OTHER_ARTIFACTS'),
                             ('jetstream_domain', None)):
            changed = {**selected, field: value}
            with self.subTest(field=field), self.assertRaises(CredentialError):
                validate_service(raw, account_public_key=account, **changed)


class _ArtifactConnection:
    """Capture actual pinned nats-py operations without a broker or socket."""
    def __init__(self, policy):
        self.policy = policy
        self._nuid = NUID()
        self.calls = []
        self.messages = {}

    async def request(self, subject, payload=b'', **kwargs):
        self.calls.append(subject)
        def matches(pattern):
            expected, actual = pattern.split('.'), subject.split('.')
            return len(expected) == len(actual) and all(a == b or a == '*' for a, b in zip(expected, actual))
        if not any(matches(pattern) for pattern in self.policy.publish_subjects):
            raise AssertionError('artifact operation outside derived policy')
        if '.STREAM.INFO.' in subject:
            name = subject.rsplit('.', 1)[1]
            body = {'config': {'name': name}, 'state': {'messages': len(self.messages), 'bytes': 0,
                    'first_seq': 1, 'last_seq': len(self.messages), 'consumer_count': 0}}
        elif '.STREAM.MSG.GET.' in subject:
            request = json.loads(payload)
            key = request.get('last_by_subj') or request.get('next_by_subj')
            if key not in self.messages:
                body = {'error': {'code': 404, 'err_code': 10037, 'description': 'no message found'}}
            else:
                sequence, data = self.messages[key]
                body = {'message': {'subject': key, 'seq': sequence, 'time': '2026-10-16T00:00:00Z',
                                    'data': base64.b64encode(data).decode()}}
        else:
            self.messages[subject] = (len(self.messages) + 1, payload)
            body = {'stream': 'OBJ_DEFINITION_ARTIFACTS', 'seq': len(self.messages)}
        return SimpleNamespace(data=json.dumps(body).encode())


class ArtifactTrafficTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_artifact_helper_fits_generated_policy(self):
        selected = options()
        policy = service_policy(**selected)
        connection = _ArtifactConnection(policy)
        jetstream = JetStreamContext(connection, domain=selected['jetstream_domain'])
        store = await jetstream.object_store(selected['artifact_bucket'])
        artifacts = OwnerArtifacts(store, jetstream, bucket=selected['artifact_bucket'],
            owner_hub_id=selected['hub_id'], store_ref={'id': 'artifacts', 'ownerHubId': 'hub-one', 'revision': 1},
            max_bytes=1024)
        data = b'original retained artifact bytes'
        reference = await artifacts.upload(data, media_type='application/octet-stream')
        self.assertEqual(await artifacts.retrieve(reference), data)
        self.assertTrue(any(v.startswith('$O.DEFINITION_ARTIFACTS.C.') for v in connection.calls))
        self.assertTrue(any(v.startswith('$O.DEFINITION_ARTIFACTS.M.') for v in connection.calls))
        self.assertFalse(any('.PURGE.' in v or '.CONSUMER.' in v for v in connection.calls))


class IntegrationCredentialTests(unittest.TestCase):
    def selected(self, bucket=True):
        value = options()
        value.update(role='integration', entity_id='effect-one', stream='INTEGRATION',
            scope={'organizationId': 'org-one', 'projectId': 'project-one', 'workspaceId': None},
            reply_prefix='_INBOX.integration_service_0001')
        if not bucket:
            del value['artifact_bucket']
        return value

    def test_exact_signed_integration_reads_without_artifact_writes(self):
        selected = self.selected()
        policy = service_policy(**selected)
        self.assertEqual(policy.command_subject, 'amx.v1.h.hub-one.o.org-one.integrations.effect-one.command')
        self.assertEqual(policy.ledger_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.integrations.effect-one')
        self.assertEqual(policy.publish_subjects, tuple(sorted((policy.ledger_subject,
            '$JS.LOCAL.API.STREAM.INFO.INTEGRATION', '$JS.LOCAL.API.STREAM.MSG.GET.INTEGRATION',
            '$JS.LOCAL.API.STREAM.INFO.OBJ_DEFINITION_ARTIFACTS',
            '$JS.LOCAL.API.STREAM.MSG.GET.OBJ_DEFINITION_ARTIFACTS',
            '$JS.API.STREAM.INFO.INTEGRATION', '$JS.API.STREAM.MSG.GET.INTEGRATION',
            '$JS.API.STREAM.INFO.OBJ_DEFINITION_ARTIFACTS',
            '$JS.API.STREAM.MSG.GET.OBJ_DEFINITION_ARTIFACTS'))))
        raw, account, user = signed_service(selected)
        self.assertEqual(validate_service(raw, account_public_key=account, **selected).public_key, user)
        for missing in ('$JS.API.STREAM.INFO.INTEGRATION', '$JS.API.STREAM.MSG.GET.INTEGRATION'):
            raw, account, _ = signed_service(selected, lambda n: n['pub']['allow'].remove(missing))
            with self.subTest(missing=missing), self.assertRaises(CredentialError):
                validate_service(raw, account_public_key=account, **selected)
        for extra in ('$O.DEFINITION_ARTIFACTS.C.*', '$O.DEFINITION_ARTIFACTS.M.*',
                      '$JS.API.STREAM.INFO.IDENTITY', '$JS.API.STREAM.MSG.GET.IDENTITY',
                      '$JS.API.STREAM.PURGE.INTEGRATION', '$JS.OTHER.API.STREAM.INFO.INTEGRATION',
                      '$JS.LOCAL.API.STREAM.INFO.IDENTITY', '$JS.LOCAL.API.STREAM.MSG.GET.IDENTITY',
                      '$JS.LOCAL.API.STREAM.PURGE.OBJ_DEFINITION_ARTIFACTS',
                      'amx.v1.h.hub-one.o.org-one.p.other-project.w._.ledger.integrations.effect-one'):
            with self.subTest(extra=extra):
                raw, account, _ = signed_service(selected, lambda n: n['pub']['allow'].append(extra))
                with self.assertRaises(CredentialError):
                    validate_service(raw, account_public_key=account, **selected)

    def test_project_router_wildcards_routes_but_enumerates_stream_apis(self):
        selected = self.selected()
        selected.update(integration_routing=True,
                        additional_streams=('INTEGRATION_TWO',))
        policy = service_policy(**selected)
        self.assertEqual(policy.command_subject,
            'amx.v1.h.hub-one.o.org-one.integrations.*.command')
        self.assertEqual(policy.ledger_subject,
            'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.integrations.*')
        for stream in ('INTEGRATION', 'INTEGRATION_TWO'):
            self.assertIn('$JS.LOCAL.API.STREAM.INFO.' + stream,
                          policy.publish_subjects)
            self.assertIn('$JS.LOCAL.API.STREAM.MSG.GET.' + stream,
                          policy.publish_subjects)
        self.assertNotIn('$JS.LOCAL.API.STREAM.INFO.*', policy.publish_subjects)
        self.assertNotIn('$JS.LOCAL.API.STREAM.MSG.GET.*', policy.publish_subjects)
        raw, account, user = signed_service(selected)
        self.assertEqual(validate_service(raw, account_public_key=account,
            **selected).public_key, user)
        widened, account, _ = signed_service(selected,
            lambda nats: nats['pub']['allow'].append(
                '$JS.LOCAL.API.STREAM.INFO.UNENROLLED'))
        with self.assertRaises(CredentialError):
            validate_service(widened, account_public_key=account, **selected)
        for change in ({'additional_streams': ('INTEGRATION',)},
                       {'additional_streams': ('OBJ_DEFINITION_ARTIFACTS',)},
                       {'additional_streams': ('INTEGRATION_TWO',) * 65},
                       {'role': 'definitions'}):
            with self.subTest(change=change), self.assertRaises(CredentialError):
                service_policy(**{**selected, **change})

    def test_optional_artifacts_and_required_project(self):
        selected = self.selected(bucket=False)
        policy = service_policy(**selected)
        self.assertEqual(len(policy.publish_subjects), 5)
        self.assertFalse(any('OBJ_' in v or '$O.' in v for v in policy.publish_subjects))
        raw, account, _ = signed_service(selected)
        self.assertTrue(validate_service(raw, account_public_key=account, **selected).public_key)
        selected['scope']['projectId'] = None
        with self.assertRaises(CredentialError):
            service_policy(**selected)


class IntegrationArtifactTrafficTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_retrieval_has_only_integration_read_grants(self):
        # Upload through the independently scoped writer, then use the real
        # read helper with the receiving Integration service's derived grants.
        writer_options = options()
        writer = _ArtifactConnection(service_policy(**writer_options))
        writer_js = JetStreamContext(writer, domain=writer_options['jetstream_domain'])
        writer_store = await writer_js.object_store(writer_options['artifact_bucket'])
        store_ref = {'id': 'artifacts', 'ownerHubId': 'hub-one', 'revision': 1}
        writer_artifacts = OwnerArtifacts(writer_store, writer_js, bucket=writer_options['artifact_bucket'],
            owner_hub_id='hub-one', store_ref=store_ref, max_bytes=1024)
        data = b'pre-existing retained integration content'
        reference = await writer_artifacts.upload(data, media_type='application/octet-stream')
        selected = IntegrationCredentialTests().selected()
        reader = _ArtifactConnection(service_policy(**selected))
        reader.messages = dict(writer.messages)
        reader_js = JetStreamContext(reader, domain=selected['jetstream_domain'])
        reader_store = await reader_js.object_store(selected['artifact_bucket'])
        artifacts = OwnerArtifacts(reader_store, reader_js, bucket=selected['artifact_bucket'],
            owner_hub_id='hub-one', store_ref=store_ref, max_bytes=1024)
        self.assertEqual(await artifacts.retrieve(reference), data)
        self.assertTrue(reader.calls)
        self.assertTrue(all(v.startswith('$JS.LOCAL.API.STREAM.') for v in reader.calls))
        self.assertFalse(any(v.startswith('$O.') or '.PURGE.' in v for v in reader.calls))


if __name__ == '__main__':
    unittest.main()
