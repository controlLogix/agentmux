"""Fixed local Hub work operations over retained, signed owner commands."""
import asyncio
from datetime import datetime, timedelta, timezone
import weakref

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads
from hub.store import HubError
from .legacy_work_client import LegacyWorkCommandClient


class LocalWorkClient:
    """Keep original result evidence until the Hub finishes its follow-on work."""

    def __init__(self, hub, commands):
        if type(commands) is not LegacyWorkCommandClient or commands._hub is not hub:
            raise ContractError('local_work_client_configuration')
        self._hub, self._commands = hub, commands
        self._completions = weakref.WeakKeyDictionary()

    def __repr__(self):
        return '<LocalWorkClient private>'

    def check(self):
        self._commands.check(self._commands._federation)

    def confirm_disclosure(self, value=None):
        self.check()
        return self._commands.confirm_disclosure(value)

    def finish_disclosure(self, value=None):
        self.check()
        if self._completions.get(asyncio.current_task()):
            raise ContractError('local_work_completion_pending')
        return self._commands.finish_disclosure(value)

    async def confirm_completion(self):
        """Call only after the caller's durable capture and notification handoffs."""
        self.confirm_disclosure()
        task = asyncio.current_task()
        pending = self._completions.get(task, [])
        while pending:
            session, enrollment, command, intent, result = pending[0]
            await self._commands.confirm_completion(session, enrollment, command, intent, result)
            pending.pop(0)
            self.confirm_disclosure()
        self._completions.pop(task, None)

    def _expires(self):
        expires = datetime.now(timezone.utc) + timedelta(seconds=5)
        original = self._commands._disclosures.get(asyncio.current_task())
        return min(expires, original[1]) if original is not None else expires

    def _routes(self, caller, command, repository=None):
        return self._commands._select(caller, command, repository)

    @staticmethod
    def _mutation_actor(caller, authenticated_caller, on_behalf_of):
        actor = caller if authenticated_caller is None else authenticated_caller
        if actor != caller:
            if (actor != 'operator' or type(on_behalf_of) is not dict
                    or set(on_behalf_of) != {'session', 'generation'} or on_behalf_of['session'] != caller
                    or type(on_behalf_of['generation']) is not int
                    or not 1 <= on_behalf_of['generation'] <= 9007199254740991):
                raise ContractError('local_work_caller_binding')
        elif on_behalf_of is not None:
            raise ContractError('local_work_caller_binding')
        return actor

    @staticmethod
    def _targeted(value, on_behalf_of):
        return value if on_behalf_of is None else {**value,
            'onBehalfOf': strict_loads(canonical_bytes(on_behalf_of))}

    async def _read(self, caller, query, repository=None):
        routes = self._routes(caller, 'read', repository)
        named = [route for route in routes if route[1]['workCommands']['repository'] is not None]
        if query['kind'] in ('claimable', 'active'):
            if not named:
                raise ContractError('legacy_work_route_unavailable')
            routes = named
        elif named:
            routes = named
        rows = await self._commands._read(routes, query, self._expires())
        return self.confirm_disclosure(rows)

    async def _mutate(self, route, caller, command, value, intent, expires):
        session, enrollment = route
        if asyncio.current_task() in self._commands._disclosures:
            self.confirm_disclosure()
            expires = min(expires, self._expires())
        result = await self._commands._execute(session, enrollment, command, intent, value, caller, expires)
        pending = self._completions.setdefault(asyncio.current_task(), [])
        evidence = (session, enrollment, command, intent, strict_loads(canonical_bytes(result)))
        if evidence not in pending:
            pending.append(evidence)
        return self.confirm_disclosure(result)

    async def _row_route(self, caller, command, work_id, repository=None):
        rows = await self.list(caller, repository=repository)
        found = [row for row in rows if row['id'] == work_id]
        if len(found) != 1:
            raise HubError('work item is unavailable in the authorized repositories')
        self.confirm_disclosure()
        return self._routes(caller, command, found[0]['repo'])[0]

    async def add(self, caller, args, *, intent_digest, authenticated_caller=None, on_behalf_of=None,
                  repository=None):
        if repository is not None and (type(repository) is not str or not repository):
            raise ContractError('legacy_work_route_unavailable')
        actor = self._mutation_actor(caller, authenticated_caller, on_behalf_of)
        target_repository = args.get('repo') or self._hub._repo_of_target(args['to'], caller)
        if repository is not None and target_repository != repository:
            raise ContractError('legacy_work_route_unavailable')
        route = self._routes(actor, 'create', target_repository)[0]
        value = {'target': args['to'], 'title': args['title'], 'body': args.get('body'),
            'taskKey': args.get('task_key'), 'requirements': args.get('requirements'),
            'priority': int(args.get('priority', 100)), 'parentId': args.get('parent'),
            'maxAttempts': int(args.get('max_attempts', 3)), 'federate': bool(args.get('federate'))}
        return await self._mutate(route, actor, 'create', self._targeted(value, on_behalf_of),
            intent_digest, self._expires())

    async def claim(self, caller, args, *, intent_digest, authenticated_caller=None, on_behalf_of=None,
                    repository=None):
        actor = self._mutation_actor(caller, authenticated_caller, on_behalf_of)
        expires = self._expires()
        value = self._targeted({'workId': args.get('work_id'), 'leaseSeconds': args.get('lease_s')}, on_behalf_of)
        original = await self._commands.pending_route(actor, 'claim', intent_digest, repository=repository)
        if original is not None:
            session, enrollment, retained = original
            if retained != value:
                raise ContractError('legacy_work_recovery_invalid')
            return await self._mutate((session, enrollment), actor, 'claim', retained, intent_digest, expires)
        work_id = args.get('work_id')
        if work_id:
            route = await self._row_route(actor, 'claim', work_id, repository)
        else:
            routes = self._routes(actor, 'claim', repository)
            # Claim without an explicit ID retains the Store's global capacity
            # check. Choose a repository from authorized rows, then let its owner
            # make the original atomic first-claim transition.
            rows = await self.list(actor, repository=repository)
            claimable = ((await self.readiness(actor, caller, repository))['claimable']
                if on_behalf_of else await self.claimable(caller, repository))
            eligible = {row['id'] for row in claimable}
            candidates = sorted((row for row in rows if row['id'] in eligible),
                key=lambda row: (row['priority'], row['created']))
            route = (self._routes(actor, 'claim', candidates[0]['repo'])[0] if candidates else routes[0])
        self.confirm_disclosure()
        return await self._mutate(route, actor, 'claim', value, intent_digest, expires)

    async def heartbeat(self, caller, args, *, intent_digest, authenticated_caller=None, on_behalf_of=None,
                        repository=None):
        actor = self._mutation_actor(caller, authenticated_caller, on_behalf_of)
        expires, renewed = self._expires(), 0
        for route in self._routes(actor, 'heartbeat', repository):
            repository = route[1]['workCommands']['repository']
            intent = payload_digest({'intentDigest': intent_digest, 'repository': repository})
            result = await self._mutate(route, actor, 'heartbeat',
                self._targeted({'leaseSeconds': args.get('lease_s')}, on_behalf_of), intent, expires)
            renewed += result['renewed']
        return self.confirm_disclosure({'renewed': renewed})

    async def release(self, caller, args, *, intent_digest, authenticated_caller=None, on_behalf_of=None,
                      repository=None):
        actor = self._mutation_actor(caller, authenticated_caller, on_behalf_of)
        expires = self._expires()
        route = await self._row_route(actor, 'release', args['work_id'], repository)
        return await self._mutate(route, actor, 'release', self._targeted({'workId': args['work_id'],
            'outcome': args['outcome'], 'result': args.get('result')}, on_behalf_of), intent_digest, expires)

    async def cancel(self, caller, args, *, intent_digest, repository=None):
        expires = self._expires()
        route = await self._row_route(caller, 'cancel', args['work_id'], repository)
        return await self._mutate(route, caller, 'cancel', {'workId': args['work_id'],
            'reason': args.get('reason') or 'cancelled by operator'}, intent_digest, expires)

    async def claim_path(self, caller, args, *, intent_digest, authenticated_caller=None, on_behalf_of=None,
                         repository=None):
        if repository is not None and (type(repository) is not str or not repository):
            raise ContractError('legacy_work_route_unavailable')
        actor = self._mutation_actor(caller, authenticated_caller, on_behalf_of)
        target_repository = args.get('repo') or repository or self._hub._repo_of_target('agent:' + caller, caller)
        if repository is not None and target_repository != repository:
            raise ContractError('legacy_work_route_unavailable')
        route = self._routes(actor, 'claim-path', target_repository)[0]
        return await self._mutate(route, actor, 'claim-path', self._targeted({'path': args['path'],
            'workId': args.get('work_id')}, on_behalf_of), intent_digest, self._expires())

    async def show(self, caller, work_id, repository=None):
        rows = [row for row in await self.list(caller, repository=repository) if row['id'] == work_id]
        if not rows:
            return self.confirm_disclosure(None)
        if len(rows) != 1:
            raise ContractError('legacy_work_reply_unconfirmed')
        route = self._routes(caller, 'read', rows[0]['repo'])[0]
        return await self._commands._read([route], {'kind': 'show', 'workId': work_id}, self._expires())

    async def list(self, caller, state=None, repository=None):
        rows = await self._read(caller, {'kind': 'list', 'state': state}, repository)
        return self.confirm_disclosure(sorted(rows, key=lambda row: row['created']))

    async def claimable(self, caller, repository=None):
        rows = await self._read(caller, {'kind': 'claimable'}, repository)
        if rows:
            created = {row['id']: row['created'] for row in await self.list(caller, repository=repository)}
            if any(row['id'] not in created for row in rows):
                raise ContractError('legacy_work_reply_unconfirmed')
            rows = sorted(rows, key=lambda row: (row['priority'], created[row['id']]))
        return self.confirm_disclosure(rows)

    async def active(self, caller, repository=None):
        return await self._read(caller, {'kind': 'active'}, repository)

    async def claims(self, caller, repository=None):
        return await self._read(caller, {'kind': 'claims'}, repository)

    async def readiness(self, caller, target=None, repository=None):
        """Read an exact target using the caller's own named repository grants."""
        target = caller if target is None else target
        if (type(target) is not str or not target
                or repository is not None and (type(repository) is not str or not repository)):
            raise ContractError('legacy_work_route_unavailable')
        routes = [route for route in self._routes(caller, 'read', repository)
            if route[1]['workCommands']['repository'] is not None]
        if not routes:
            raise ContractError('legacy_work_route_unavailable')
        claimable, active, capacities, created = [], [], [], {}
        for route in routes:
            if asyncio.current_task() in self._commands._disclosures:
                self.confirm_disclosure()
            value = await self._commands._read([route],
                {'kind': 'readiness', 'session': target}, self._expires())
            self.confirm_disclosure()
            claimable.extend(value['claimable'])
            active.extend(value['active'])
            capacities.append(value['capacity']['available'])
            if len(routes) > 1 and value['claimable']:
                # Sort with authorized rows only; keep the readiness projection
                # unchanged and never look up another repository's work.
                rows = await self._commands._read([route],
                    {'kind': 'list', 'state': None}, self._expires())
                self.confirm_disclosure()
                created.update((row['id'], row['created']) for row in rows)
        if len({row['id'] for row in claimable}) != len(claimable) or len(
                {row['id'] for row in active}) != len(active):
            raise ContractError('legacy_work_reply_unconfirmed')
        if len(routes) > 1:
            if any(row['id'] not in created for row in claimable):
                raise ContractError('legacy_work_reply_unconfirmed')
            claimable.sort(key=lambda row: (row['priority'], created[row['id']]))
        # Each owner counts all claims without exposing their rows. Concurrent
        # snapshots may narrow capacity; an aggregate must never add the slots.
        available = min(capacities)
        result = {'claimable': claimable, 'active': active,
            'capacity': {'atCapacity': available == 0, 'available': available}}
        if len(canonical_bytes(result)) > 1_000_000:
            raise ContractError('legacy_work_reply_unconfirmed')
        return self.confirm_disclosure(result)
