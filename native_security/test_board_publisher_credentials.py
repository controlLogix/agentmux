"""Signed board publisher credentials cannot widen a protected selection."""
import base64
import copy
import unittest

import nkeys

from .nats_credentials import CredentialError, board_publisher_policy, validate_board_publisher, validate
from .test_nats_credentials import credential


def selection(allocation=False):
    return dict(hub_id='hub-one', entity_id='board-journal',
        scope={'organizationId':'org-one','projectId':'project-one','workspaceId':None},
        stream='BOARD_OPERATIONS', reply_prefix='_INBOX.board_publisher_0001',
        repository_id='r0123456789ab', card_key=None if allocation else 'SH-1',
        counter_prefix='SH' if allocation else None, jetstream_domain='LOCAL')


def signed(selected, change=None):
    policy = board_publisher_policy(**selected)
    def update(claims):
        claims['nats'].update(pub={'allow':list(policy.publish_subjects)},
            sub={'allow':list(policy.subscribe_subjects)})
        if change:
            change(claims['nats'])
    return credential(update)


class BoardPublisherCredentialTests(unittest.TestCase):
    def test_exact_card_and_allocation_permissions(self):
        for allocation in (False, True):
            selected = selection(allocation)
            policy = board_publisher_policy(**selected)
            ledger = 'amx.v1.h.hub-one.o.org-one.p.project-one.w._.ledger.federation-board-operations.board-journal'
            expected = [ledger]
            for prefix in ('$JS.API.', '$JS.LOCAL.API.'):
                for stream in ('BOARD_OPERATIONS', 'KV_am_board'):
                    expected.extend((prefix+'STREAM.INFO.'+stream, prefix+'STREAM.MSG.GET.'+stream))
            expected.extend(('$KV.am_board.r0123456789ab.seq.SH', '$KV.am_board.r0123456789ab.card.*')
                if allocation else ('$KV.am_board.r0123456789ab.card.SH-1',))
            self.assertEqual(policy.ledger_subject, ledger)
            self.assertEqual(policy.publish_subjects, tuple(sorted(expected)))
            self.assertEqual(policy.subscribe_subjects, ('_INBOX.board_publisher_0001.>',))
            raw, account, user = signed(selected)
            self.assertEqual(validate_board_publisher(raw, account_public_key=account, **selected).public_key, user)
            if allocation:
                with self.assertRaises(CredentialError):
                    validate(raw, account_public_key=account, publish_subjects=policy.publish_subjects,
                        subscribe_subjects=policy.subscribe_subjects, private_inbox=True)

    def test_added_widened_missing_and_duplicate_permissions_refuse(self):
        for allocation in (False, True):
            selected = selection(allocation)
            additions = ('_INBOX.>', '$JS.API.>', '$JS.OTHER.API.STREAM.INFO.BOARD_OPERATIONS',
                '$JS.API.STREAM.INFO.OTHER', '$JS.API.STREAM.MSG.GET.OTHER',
                '$JS.API.STREAM.CREATE.BOARD_OPERATIONS', '$JS.API.STREAM.PURGE.KV_am_board',
                '$JS.API.CONSUMER.CREATE.KV_am_board', '$KV.am_board.>',
                '$KV.am_board.rffffffffffff.card.*', '$KV.am_board.r0123456789ab.seq.OTHER',
                '$KV.am_board.r0123456789ab.card.>', 'unrelated.subject')
            for extra in additions:
                with self.subTest(allocation=allocation, extra=extra):
                    raw, account, _ = signed(selected, lambda n: n['pub']['allow'].append(extra))
                    with self.assertRaises(CredentialError):
                        validate_board_publisher(raw, account_public_key=account, **selected)
            changes = [lambda n: n['pub']['allow'].pop(),
                lambda n: n['pub']['allow'].append(n['pub']['allow'][0]),
                lambda n: n['pub'].update(allow=['>']),
                lambda n: n['sub']['allow'].append('amx.v1.command'),
                lambda n: n['sub'].update(allow=['_INBOX.>']),
                lambda n: n['sub'].update(allow=['_INBOX.another_publisher_0001.>'])]
            if not allocation:
                changes.append(lambda n: n['pub'].update(allow=[s.replace('.card.SH-1','.card.*') for s in n['pub']['allow']]))
            for change in changes:
                raw, account, _ = signed(selected, change)
                with self.assertRaises(CredentialError):
                    validate_board_publisher(raw, account_public_key=account, **selected)

    def test_response_grants_and_bearer_permissions_refuse(self):
        selected = selection()
        for response in ({}, {'max':1,'ttl':5_000_000_000}, {'max':-1,'ttl':0}):
            raw, account, _ = signed(selected, lambda n: n.update(resp=response))
            with self.assertRaises(CredentialError):
                validate_board_publisher(raw, account_public_key=account, **selected)
        raw, account, _ = signed(selected, lambda n: n.update(bearer_token=True))
        with self.assertRaises(CredentialError):
            validate_board_publisher(raw, account_public_key=account, **selected)

    def test_invalid_scope_tokens_and_ambiguous_modes_refuse(self):
        changes = {'hub_id':['*',None], 'entity_id':['other.entity',True],
            'stream':['*','KV_am_board','with.dot'], 'reply_prefix':['_INBOX','_INBOX.>'],
            'repository_id':['r0123456789ab.*','other','rABCDEF012345'],
            'card_key':['*','SH.1','lowercase','A'*97], 'jetstream_domain':['*','OTHER.DOMAIN',True]}
        for field, values in changes.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(CredentialError):
                    board_publisher_policy(**{**selection(),field:value})
        for scope in ({'organizationId':'org-one','projectId':None,'workspaceId':None},
                      {'organizationId':'org-one','projectId':'*','workspaceId':None},
                      {'organizationId':'org-one','projectId':'project-one'},
                      {'organizationId':'org-one','projectId':'project-one','workspaceId':None,'extra':1}):
            with self.assertRaises(CredentialError):
                board_publisher_policy(**{**selection(),'scope':scope})
        for values in ({'card_key':None,'counter_prefix':None}, {'card_key':'SH-1','counter_prefix':'SH'},
                       {'card_key':None,'counter_prefix':'*'}, {'card_key':None,'counter_prefix':'SH.X'},
                       {'card_key':None,'counter_prefix':'A'*65}):
            with self.assertRaises(CredentialError):
                board_publisher_policy(**{**selection(),**values})

    def test_wrong_account_signature_and_seed_refuse(self):
        selected = selection()
        raw, account, _ = signed(selected)
        token = raw.split(b'\n')[1]
        parts = token.split(b'.')
        signature = bytearray(base64.urlsafe_b64decode(parts[2]+b'=='))
        signature[0] ^= 1
        damaged = b'.'.join(parts[:2]+[base64.urlsafe_b64encode(signature).rstrip(b'=')])
        seed = raw.split(b'BEGIN USER NKEY SEED-----\n')[1].split(b'\n')[0]
        other_account = nkeys.from_seed(nkeys.encode_seed(bytes([3])*32,nkeys.PREFIX_BYTE_ACCOUNT))
        other_user = nkeys.from_seed(nkeys.encode_seed(bytes([4])*32,nkeys.PREFIX_BYTE_USER))
        try:
            candidates = ((raw,other_account.public_key.decode()), (raw.replace(token,damaged),account),
                (raw.replace(seed,other_user.seed),account))
            for candidate, selected_account in candidates:
                with self.assertRaises(CredentialError):
                    validate_board_publisher(candidate, account_public_key=selected_account, **selected)
        finally:
            other_account.wipe()
            other_user.wipe()

    def test_selected_domain_scope_and_resources_are_bound(self):
        selected = selection()
        raw, account, _ = signed(selected)
        for field, value in (('stream','OTHER'),('jetstream_domain','OTHER'),('card_key','SH-2'),
                ('repository_id','rffffffffffff'),('entity_id','another-journal')):
            with self.assertRaises(CredentialError):
                validate_board_publisher(raw, account_public_key=account, **{**selected,field:value})
        changed = copy.deepcopy(selected)
        changed['scope']['projectId'] = 'other-project'
        with self.assertRaises(CredentialError):
            validate_board_publisher(raw, account_public_key=account, **changed)
        selected['jetstream_domain'] = None
        policy = board_publisher_policy(**selected)
        self.assertFalse(any(s.startswith('$JS.LOCAL.') for s in policy.publish_subjects))
        self.assertEqual(len(policy.publish_subjects),len(set(policy.publish_subjects)))
        raw, account, _ = signed(selected)
        validate_board_publisher(raw, account_public_key=account, **selected)
