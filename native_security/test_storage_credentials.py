"""Storage receivers and private publishers have separate exact broker grants."""
import unittest

from .nats_credentials import (CredentialError, storage_receiver_policy,
    private_storage_publisher_policy, validate_storage_receiver, validate_private_storage_publisher)
from .test_nats_credentials import credential


class StorageCredentialTests(unittest.TestCase):
    def inputs(self, receiver=True):
        value = dict(hub_id='hub-one', scope={'organizationId':'org-one',
            'projectId':'project-one','workspaceId':None}, reply_prefix='_INBOX.storage_000000001')
        value.update(dict(service_id='storage-owner') if receiver else
            dict(entity_id='private-one',stream='PRIVATE',jetstream_domain='LOCAL'))
        return value

    def signed(self, policy, change=None):
        def update(claims):
            n = claims['nats']
            n.update(pub={'allow':list(policy.publish_subjects)}, sub={'allow':list(policy.subscribe_subjects)})
            if hasattr(policy, 'response_permissions'):
                n['resp'] = policy.response_permissions
            if change:
                change(n)
        return credential(update)

    def test_exact_receivers_have_no_persistent_write_or_read_permission(self):
        for service in ('storage-owner','outcome-owner'):
            args = self.inputs(); args['service_id'] = service
            policy = storage_receiver_policy(**args)
            self.assertEqual(policy.publish_subjects, ())
            self.assertEqual(policy.command_subject,
                'amx.v1.h.hub-one.o.org-one.p.project-one.w._.capability.'+service+'.command')
            self.assertEqual(policy.response_permissions, {'max':1,'ttl':5_000_000_000})
            raw, account, user = self.signed(policy)
            self.assertEqual(validate_storage_receiver(raw,account_public_key=account,**args).public_key,user)

    def test_finite_selected_scopes_require_the_exact_union_of_receiver_subjects(self):
        args = self.inputs()
        args['additional_scopes'] = ({**args['scope'], 'projectId': 'project-two'},)
        policy = storage_receiver_policy(**args)
        self.assertEqual(len(policy.subscribe_subjects), 3)
        self.assertFalse(any('*' in subject for subject in policy.subscribe_subjects))
        raw, account, _ = self.signed(policy)
        validate_storage_receiver(raw, account_public_key=account, **args)
        for change in (lambda n: n['sub']['allow'].pop(),
                lambda n: n['sub']['allow'].append('amx.v1.h.hub-one.o.org-one.p.extra.w._.capability.storage-owner.command')):
            raw, account, _ = self.signed(policy, change)
            with self.assertRaises(CredentialError):
                validate_storage_receiver(raw, account_public_key=account, **args)
        for scope in (args['scope'], {**args['scope'], 'organizationId': 'other'}):
            with self.assertRaises(CredentialError):
                storage_receiver_policy(**{**args, 'additional_scopes': (scope,)})

    def test_private_publisher_writes_only_own_ledger_and_reads_selected_stream(self):
        args = self.inputs(False)
        policy = private_storage_publisher_policy(**args)
        subject = 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.plugin-private.private-one'
        self.assertEqual(policy.ledger_subject,subject)
        expected = [subject]
        for prefix in ('$JS.API.','$JS.LOCAL.API.'):
            expected.extend((prefix+'STREAM.INFO.PRIVATE',prefix+'STREAM.MSG.GET.PRIVATE'))
        self.assertEqual(policy.publish_subjects,tuple(sorted(expected)))
        self.assertEqual(policy.subscribe_subjects,('_INBOX.storage_000000001.>',))
        raw, account, user = self.signed(policy)
        self.assertEqual(validate_private_storage_publisher(raw,account_public_key=account,**args).public_key,user)

    def test_widened_credential_or_response_permissions_refuse(self):
        for receiver in (True,False):
            args = self.inputs(receiver)
            make = storage_receiver_policy if receiver else private_storage_publisher_policy
            check = validate_storage_receiver if receiver else validate_private_storage_publisher
            policy = make(**args)
            changes = [lambda n: n['pub']['allow'].append('$JS.API.>'),
                lambda n: n['pub']['allow'].append('$KV.am_board.>'),
                lambda n: n['sub']['allow'].append('amx.>'),
                lambda n: n['sub'].update(allow=['_INBOX.>']),
                lambda n: n.update(resp={'max':2,'ttl':5_000_000_000}),
                lambda n: n.update(resp={'max':1,'ttl':5_000_000_001})]
            if not receiver:
                changes.append(lambda n: n.update(resp={'max':1,'ttl':5_000_000_000}))
            for change in changes:
                raw, account, _ = self.signed(policy,change)
                with self.assertRaises(CredentialError):check(raw,account_public_key=account,**args)

    def test_scope_and_token_substitution_refuse(self):
        for receiver in (True,False):
            make = storage_receiver_policy if receiver else private_storage_publisher_policy
            for field, value in [('hub_id','hub-one\n'),('reply_prefix','_INBOX.storage_000000001\n')]:
                args = self.inputs(receiver); args[field] = value
                with self.assertRaises(CredentialError):make(**args)
            args = self.inputs(receiver)
            args['scope'].update(projectId=None,workspaceId='workspace-one')
            with self.assertRaises(CredentialError):make(**args)
