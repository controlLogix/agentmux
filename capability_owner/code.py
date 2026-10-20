"""Retained code pointers and outbox effects in the original Store transaction."""
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub.fed import envelope, guard
from hub.fed.code_services import CodeShareOwner
from hub.store import now
from .federated_storage import FederatedStorageResource


class CodeStorageResource(FederatedStorageResource):
    domain = 'code'

    def __init__(self, binding, federation, *, legacy_actors=(), **kwargs):
        from .code_legacy import LegacyCodeActor
        from hub.fed.message_storage import MessageStorageJournal
        if (type(legacy_actors) is not tuple
                or any(type(actor) is not LegacyCodeActor for actor in legacy_actors)
                or len({(actor.identity_ref, actor.transport_ref) for actor in legacy_actors}) != len(legacy_actors)):
            raise ContractError('capability_owner_configuration')
        self._legacy_actors = legacy_actors
        self._code = CodeShareOwner(federation)
        super().__init__(binding, federation, **kwargs)
        if legacy_actors:
            descriptor = strict_loads(self._journal.binding)
            descriptor['legacyActors'] = [{'identityRef': strict_loads(actor.identity_ref),
                'transportRef': strict_loads(actor.transport_ref), 'caller': actor.caller,
                'grants': strict_loads(actor.grants)} for actor in legacy_actors]
            self._journal = MessageStorageJournal(self._store, canonical_bytes(descriptor),
                kwargs.get('initial_source'), namespace=self.domain)

    async def authorize_legacy(self, authority, raw):
        from .code_legacy import authorize
        return await authorize(self, authority, raw)

    async def legacy(self, authority, raw):
        from .code_legacy import apply
        return await apply(self, authority, raw)

    def _check_publication_author(self, item, caller):
        sender = self._owner.sender_of(caller)
        author = 'operator' if sender.get('operator') else f"{sender['role']}/{sender['agent']}"
        if item['from'] != self._peer or item['node'] != self._node or item['data']['author'] != author:
            raise ContractError('capability_access_refused')

    def _value(self, original):
        value = original['payload']['input']['value']
        if (type(value) is not dict or type(value.get('formatVersion')) is not int
                or value['formatVersion'] != 1):
            raise ContractError('capability_service_unavailable')
        if value.get('command') == 'fetched':
            if (set(value) != {'formatVersion', 'command', 'id'} or type(value['id']) is not str
                    or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value['id']) is None):
                raise ContractError('capability_service_unavailable')
            self._actor(original)
            return value
        if (set(value) != {'formatVersion', 'command', 'envelope'}
                or value['command'] not in ('publish', 'index')):
            raise ContractError('capability_service_unavailable')
        env = value['envelope']
        self._validate_item(env, incoming=value['command'] == 'index')
        if value['command'] == 'publish':
            self._check_publication_author(env, self._actor(original).caller)
        elif env['from'] == self._peer:
            raise ContractError('capability_access_refused')
        return value

    def _validate_item(self, env, *, incoming=False):
        envelope.validate(env)
        data = env['data']
        if (env['type'] != 'code' or env['rid'] != self.repository_id or env['to'] != '*'
                or type(data.get('sha')) is not str or re.fullmatch(r'[0-9a-f]{40}', data['sha']) is None
                or type(data.get('ref')) is not str
                or not data['ref'].startswith('refs/agentmux/' + env['from'] + '/')
                or len(data['ref']) <= len('refs/agentmux/' + env['from'] + '/')):
            raise ContractError('capability_access_refused')
        fields = {'ref', 'sha', 'base', 'files', 'stat', 'log', 'note', 'slug', 'author', 'remote'}
        if (not incoming and set(data) != fields
                or any(data.get(key) is not None and type(data[key]) is not str
                    for key in fields - {'files'})
                or data.get('files') is not None and (type(data['files']) is not list
                    or any(type(item) is not str for item in data['files']))
                or not incoming and data.get('base') is not None
                    and re.fullmatch(r'[0-9a-f]{40}', data['base']) is None
                or not incoming and type(data.get('author')) is not str):
            raise ContractError('capability_service_unavailable')

    def _effect(self, value, *, approval=None):
        if value['command'] == 'fetched':
            row = self._read_source({'kind': self.domain, 'id': value['id']})
            if row is None:
                raise ContractError('capability_resource_stale')
            peer = row['from_peer']
            if peer != self._peer and (self._owner.policy.trust(peer) == 'deny'
                    or not self._owner.policy.may_receive(self.repository_id, peer)):
                raise ContractError('capability_access_refused')
            fetched = now()
            self._store.db.execute('UPDATE p_code_shares SET fetched=? WHERE id=?', (fetched, row['id']))
            return {'id': row['id'], 'fetched': fetched}, {'kind': self.domain, 'id': row['id']}
        env = value['envelope']
        untrusted = False
        if value['command'] == 'publish':
            clean, kinds = self._owner.stage(env, envelope.subject('code', self._peer, self.repository_id),
                self.repository, '*')
        else:
            subject = envelope.subject('code', env['from'], self.repository_id)
            decision = guard.inbound(self._owner.policy, subject, env)
            if approval is not None:
                from .code_legacy import _Admission, check_approval
                if (type(approval) is not _Admission or approval.resource is not self
                        or strict_loads(approval.original)['contractId'] != 'federation-code-approve'
                        or strict_loads(approval.original)['payload']['input']['envelope'] != env):
                    raise ContractError('capability_access_refused')
                self._journal._deadline(approval.valid_until)
                decision = check_approval(self, strict_loads(approval.original))
            elif decision.action == 'quarantine':
                rows = self._store.q('SELECT envelope FROM fed_quarantine WHERE state=? AND peer=? AND plane=? AND subject=?',
                    ('approved', env['from'], 'code', subject))
                if not any(canonical_bytes(strict_loads(row['envelope'])) == canonical_bytes(env) for row in rows):
                    raise ContractError('capability_access_refused')
                decision = guard.Decision('deliver', 'approved by operator', decision.trust,
                    untrusted=True, local_repo=decision.local_repo, approved=True)
            if decision.action != 'deliver' or decision.local_repo != self.repository:
                raise ContractError('capability_access_refused')
            clean, kinds, untrusted = env, (), decision.untrusted
        self._code._store(clean, self.repository, untrusted)
        row = self._read_source({'kind': self.domain, 'id': clean['id']})
        if row is None:
            raise ContractError('capability_outcome_conflict')
        data = clean['data']
        expected = {'rid': self.repository_id, 'repo': self.repository, 'from_peer': clean['from'],
            'author': data.get('author'), 'ref': data['ref'], 'sha': data['sha'], 'base': data.get('base'),
            'files': '\n'.join(data.get('files') or []), 'stat': data.get('stat'), 'log': data.get('log'),
            'note': data.get('note'), 'untrusted': int(untrusted), 'at': clean.get('at') or row['at']}
        if any(row[key] != item for key, item in expected.items()):
            raise ContractError('capability_outcome_conflict')
        if value['command'] == 'publish':
            staged = self._store.q1('SELECT payload FROM fed_outbox WHERE msg_id=?', (clean['id'],))
            if staged is None or canonical_bytes(strict_loads(staged['payload'])) != canonical_bytes(clean):
                raise ContractError('capability_outcome_conflict')
        return {'id': clean['id'], 'redacted': sorted(set(kinds))}, {'kind': self.domain, 'id': clean['id']}

    def _read_source(self, source):
        if source['kind'] != self.domain:
            raise ContractError('capability_resource_stale')
        row = self._store.q1('SELECT * FROM p_code_shares WHERE id=?', (source['id'],))
        if row is not None and (row['rid'] != self.repository_id or row['repo'] != self.repository):
            raise ContractError('capability_access_refused')
        return row
