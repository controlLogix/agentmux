"""Closed owner observations; requests cannot submit these as effect receipts."""
from dataclasses import dataclass
from datetime import datetime, timezone
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate
from .intent import ID, DIGEST

MAX_OBSERVATION_BYTES = 4096


@dataclass(frozen=True, slots=True, repr=False)
class ProviderObservation:
    _encoded: bytes

    def __repr__(self):
        return '<ProviderObservation private>'

    def private_copy(self):
        return strict_loads(self._encoded)


def observation(original_id, original_digest, attempt_id, *, kind, identity=None):
    if (not isinstance(original_id, str) or not ID.fullmatch(original_id)
            or not isinstance(attempt_id, str) or not ID.fullmatch(attempt_id) or original_id == attempt_id
            or not isinstance(original_digest, str) or not DIGEST.fullmatch(original_digest)
            or kind not in ('acknowledged', 'uncertain', 'not-dispatched', 'read-only')):
        raise ContractError('integration_observation_invalid')
    value = {'format': 'amx-integration-observation-v1', 'originalOperationId': original_id,
        'originalPayloadDigest': original_digest, 'attemptOperationId': attempt_id,
        'kind': kind, 'observedAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'identity': identity, 'retryAllowed': False}
    raw = canonical_bytes(value)
    if len(raw) > MAX_OBSERVATION_BYTES:
        raise ContractError('integration_observation_limit')
    validate('integration-provider-observation', value)
    return ProviderObservation(raw)


def atlassian_ack(original_id, original_digest, attempt_id, prepared, response):
    """Called only on the fixed worker's actual completed transport result."""
    target, request = strict_loads(prepared.target), strict_loads(prepared.request)
    if not isinstance(response, dict):
        raise ContractError('integration_provider_receipt_invalid')
    action = prepared.action
    identity = dict(target)
    def number(value):
        if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]{0,29}', value):
            raise ContractError('integration_provider_receipt_invalid')
        return value
    if action == 'jira-create':
        key = response.get('key')
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]*-[0-9]+', key)
                or not key.startswith(target['projectKey'] + '-')):
            raise ContractError('integration_provider_receipt_invalid')
        identity = {'issueKey': key}
    elif action == 'jira-comment':
        identity = {'issueKey': target['issueKey'], 'commentId': number(response.get('id'))}
    elif action == 'jira-transition':
        pass  # A completed successful transition request can legitimately return 204.
    elif action in ('confluence-create', 'confluence-update'):
        page_id = number(response.get('id'))
        version = response.get('version')
        space = response.get('space')
        expected = 1 if action == 'confluence-create' else target['expectedVersion'] + 1
        if (response.get('type') != 'page' or response.get('title') != request['body']['title']
                or not isinstance(space, dict) or space.get('key') != target['spaceKey']
                or not isinstance(version, dict) or type(version.get('number')) is not int
                or version['number'] != expected
                or (action == 'confluence-update' and page_id != target['pageId'])):
            raise ContractError('integration_provider_receipt_invalid')
        identity = {'spaceKey': target['spaceKey'], 'pageId': page_id, 'version': expected}
    else:
        raise ContractError('integration_action_unsupported')
    return observation(original_id, original_digest, attempt_id, kind='acknowledged', identity=identity)


def github_ack(original_id, original_digest, attempt_id, prepared, output):
    """Accept only the exact github.com URL emitted for the prepared write."""
    if type(output) is not bytes or len(output) > 4096 or b'\x00' in output:
        raise ContractError('integration_provider_receipt_invalid')
    try:
        value = output.decode('utf-8').strip()
    except UnicodeDecodeError:
        raise ContractError('integration_provider_receipt_invalid') from None
    target = strict_loads(prepared.target)
    if prepared.action == 'github-repo-create':
        repository = target['owner'] + '/' + target['name']
        match = re.fullmatch(r'https://github\.com/([^/]+/[^/]+)/?', value)
        if match is None or match.group(1).casefold() != repository.casefold():
            raise ContractError('integration_provider_receipt_invalid')
        identity = {'repository': repository}
    elif prepared.action == 'github-issue-create':
        repository = target['repository']
        match = re.fullmatch(r'https://github\.com/([^/]+/[^/]+)/issues/([1-9][0-9]*)/?', value)
        if (match is None or match.group(1).casefold() != repository.casefold()
                or int(match.group(2)) > 9007199254740991):
            raise ContractError('integration_provider_receipt_invalid')
        identity = {'repository': repository, 'issueNumber': int(match.group(2))}
    else:
        raise ContractError('integration_action_unsupported')
    return observation(original_id, original_digest, attempt_id, kind='acknowledged', identity=identity)
