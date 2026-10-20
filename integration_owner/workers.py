"""Host-private ownership of fixed Atlassian I/O after durable admission.

This is an I/O primitive, not authority or durable deduplication. Only a receiving
owner that has freshly committed a unique dispatch claim may call _start. That
owner must reauthorize first and persist the resulting observation separately.
The receiver starts the worker only after that claim and another authority read.
At most eight tasks and observations remain owned until the receiver retains
their completion. No production subscription or credential enrollment is installed.
"""
import asyncio
from dataclasses import dataclass

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from taskmgmt import atlassian
from .atlassian_requests import prepare_atlassian_request, PreparedAtlassianRequest
from .credentials import AtlassianCredentialResolver, PrivateAtlassianConfig
from .intent import ID, DIGEST, intent
from .observations import atlassian_ack, observation


@dataclass(frozen=True, slots=True, repr=False)
class PreparedAtlassianDispatch:
    original_id: str
    original_digest: str
    attempt_id: str
    prepared: PreparedAtlassianRequest
    _config: PrivateAtlassianConfig

    def __repr__(self):
        return '<PreparedAtlassianDispatch private; not authority>'


class AtlassianWorker:
    def __init__(self, resolver):
        if type(resolver) is not AtlassianCredentialResolver:
            raise ContractError('integration_worker_configuration')
        self._resolver = resolver
        self._tasks = {}
        self._prepared = {}
        self._closed = False

    def __repr__(self):
        return '<AtlassianWorker private>'

    def prepare(self, original_id, original_digest, attempt_id, proposal, content):
        """Host-private preflight after admission; no request or thread starts."""
        if (self._closed or not isinstance(original_id, str) or not ID.fullmatch(original_id)
                or not isinstance(attempt_id, str) or not ID.fullmatch(attempt_id) or attempt_id == original_id
                or not isinstance(original_digest, str) or not DIGEST.fullmatch(original_digest)):
            raise ContractError('integration_worker_refused')
        body = intent(proposal)
        from agentmux_contracts import payload_digest
        if payload_digest(body) != original_digest:
            raise ContractError('integration_original_identity_conflict')
        provider = body['action'].split('-', 1)[0]
        private_config = self._resolver.resolve(body['credentialRef'], provider=provider,
                                               config_version=body['credentialRef']['revision'])
        prepared = prepare_atlassian_request(body, content, private_config.private_copy())
        return PreparedAtlassianDispatch(original_id, original_digest, attempt_id, prepared, private_config)

    def _perform(self, job):
        """Fixed blocking transport. Only the owned task below invokes it."""
        try:
            # The executor may have queued this task after the claim check.
            # Recheck the same enrolled pin at the actual transport boundary.
            cfg = self._current_config(job).private_copy()
        except ContractError:
            return observation(job.original_id, job.original_digest, job.attempt_id, kind='not-dispatched')
        request = strict_loads(job.prepared.request)
        url = request['url']
        base = cfg['base_url']
        if not url.startswith(base + '/'):
            return observation(job.original_id, job.original_digest, job.attempt_id, kind='not-dispatched')
        path = url[len(base):]
        try:
            response = atlassian.request(cfg, request['method'], path, request['body'])
            result = atlassian_ack(job.original_id, job.original_digest, job.attempt_id, job.prepared, response)
            # Even a syntactically valid receipt cannot disclose a known secret.
            encoded = result._encoded
            header = atlassian._auth_header(cfg)
            if any(secret.encode() in encoded for secret in (cfg['api_token'], header, header.partition(' ')[2])):
                raise ContractError('integration_provider_receipt_invalid')
            return result
        except Exception:
            return observation(job.original_id, job.original_digest, job.attempt_id, kind='uncertain')

    def _start(self, job):
        """Called only after the owner commits and rechecks a fresh dispatch claim."""
        if self._closed or type(job) is not PreparedAtlassianDispatch:
            raise ContractError('integration_worker_refused')
        existing = self._tasks.get(job.attempt_id)
        if existing is not None:
            if self._prepared[job.attempt_id] is not job:
                raise ContractError('integration_attempt_conflict')
            return existing
        if len(self._tasks) >= 8:
            raise ContractError('integration_worker_capacity')
        # Preparing the request precedes an awaited durable claim. A credential
        # rotation or file replacement during that wait must not dispatch the
        # previously captured configuration under the old enrollment revision.
        self._current_config(job)
        task = asyncio.create_task(asyncio.to_thread(self._perform, job))
        self._prepared[job.attempt_id] = job
        self._tasks[job.attempt_id] = task
        return task

    def _current_config(self, job):
        current = self._resolver.resolve(strict_loads(self._resolver._binding[0]),
            provider=self._resolver._binding[1], config_version=self._resolver._binding[4])
        if current != job._config:
            raise ContractError('integration_credential_changed')
        return current

    async def wait(self, attempt_id):
        """Cancellation keeps the original I/O task and its result owned."""
        task = self._tasks.get(attempt_id)
        if task is None:
            raise ContractError('integration_attempt_unavailable')
        return await asyncio.shield(task)

    def _release(self, attempt_id, observed):
        """Only the receiver calls this after retaining the exact completion."""
        task = self._tasks.get(attempt_id)
        if task is None:
            return
        if not task.done() or task.cancelled() or task.result()._encoded != observed._encoded:
            raise ContractError('integration_cleanup_incomplete')
        del self._tasks[attempt_id]
        del self._prepared[attempt_id]

    def _start_read(self, operation_id, original_id, original_digest, attempt_id, proposal):
        """Owned fixed reads only. Their observations cannot authorize a retry."""
        if self._closed:
            raise ContractError('integration_worker_refused')
        body = intent(proposal)
        identity = (original_id, original_digest, attempt_id, canonical_bytes(body))
        if operation_id in self._tasks:
            if self._prepared[operation_id] != identity:
                raise ContractError('integration_attempt_conflict')
            return self._tasks[operation_id]
        if len(self._tasks) >= 8:
            raise ContractError('integration_worker_capacity')
        provider = body['action'].split('-', 1)[0]
        config = self._resolver.resolve(body['credentialRef'], provider=provider,
                                       config_version=body['credentialRef']['revision'])
        task = asyncio.create_task(asyncio.to_thread(self._read, original_id,
            original_digest, attempt_id, body, config))
        self._prepared[operation_id] = identity
        self._tasks[operation_id] = task
        return task

    def _read(self, original_id, original_digest, attempt_id, proposal, private_config):
        target = proposal['target']
        action = proposal['action']
        resource = target.get('issueKey') or target.get('pageId') or target.get('projectKey') or target['spaceKey']
        presence = 'unavailable'
        try:
            current = self._resolver.resolve(proposal['credentialRef'], provider=action.split('-', 1)[0],
                config_version=proposal['credentialRef']['revision'])
            if current != private_config:
                raise ContractError('integration_credential_changed')
            cfg = current.private_copy()
        except ContractError:
            return observation(original_id, original_digest, attempt_id, kind='read-only',
                               identity={'presence': presence, 'resourceId': resource})
        if 'issueKey' in target:
            path = atlassian._jira_api(cfg) + '/issue/' + target['issueKey'] + '?fields=status'
            expected_key = 'key'
        elif action == 'confluence-update':
            path = atlassian._conf_api(cfg) + '/content/' + target['pageId'] + '?expand=version'
            expected_key = 'id'
        else:
            path = None  # A lost create receipt supplies no exact remote object ID.
        if path is not None:
            try:
                result = atlassian.request(cfg, 'GET', path)
                if result.get(expected_key) == resource:
                    presence = 'present'
            except Exception:
                pass
        return observation(original_id, original_digest, attempt_id, kind='read-only',
                           identity={'presence': presence, 'resourceId': resource})

    async def close(self, *, timeout=5.0):
        if type(timeout) not in (int, float) or not 0 < timeout <= 10:
            raise ContractError('integration_cleanup_invalid')
        self._closed = True
        if self._tasks:
            done, pending = await asyncio.wait(tuple(self._tasks.values()), timeout=timeout)
            for task in done:
                if not task.cancelled():
                    task.exception()
            if pending:
                # Do not cancel a Python thread or infer that provider work stopped.
                raise ContractError('integration_cleanup_incomplete')
