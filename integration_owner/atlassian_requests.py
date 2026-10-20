"""Prepare exact legacy Atlassian requests without making external calls.

The eventual enrolled worker resolves config and retrieves content only after
current admission and a durable dispatch claim. These preparations alone grant
no permission and contain no credential headers. No dashboard module is imported.
"""
from dataclasses import dataclass

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from taskmgmt import atlassian
from .intent import closed, intent


@dataclass(frozen=True, repr=False)
class PreparedAtlassianRequest:
    action: str
    target: bytes
    request: bytes

    def __repr__(self):
        return '<PreparedAtlassianRequest private; no external dispatch>'


def bounded_text(value, maximum, *, empty=False):
    if (not isinstance(value, str) or len(value) > maximum
            or (not empty and not value.strip()) or '\x00' in value):
        raise ContractError('integration_content_invalid')


def prepare_atlassian_request(proposal, content, config):
    body = intent(proposal)
    action, target = body['action'], body['target']
    if action.split('-', 1)[0] not in ('jira', 'confluence'):
        raise ContractError('integration_action_unsupported')
    cfg = atlassian.validate_config(config)
    if action == 'jira-transition':
        if content is not None:
            raise ContractError('integration_content_unsupported')
        request = atlassian.jira_transition(cfg, target['issueKey'], target['transitionId'], dry_run=True)
    else:
        if type(content) is not bytes or not 0 < len(content) <= 60000:
            raise ContractError('integration_content_invalid')
        from hashlib import sha256
        reference = body['contentRef']
        if reference['bytes'] != len(content) or reference['digest'] != 'sha256:' + sha256(content).hexdigest():
            raise ContractError('integration_content_digest_mismatch')
        data = strict_loads(content)
        if action == 'jira-create':
            closed(data, ('summary', 'description', 'labels'))
            bounded_text(data['summary'], 255)
            bounded_text(data['description'], 50000, empty=True)
            if not isinstance(data['labels'], list) or len(data['labels']) > 64:
                raise ContractError('integration_content_invalid')
            for label in data['labels']:
                bounded_text(label, 255)
            if cfg.get('jira_project') != target['projectKey']:
                raise ContractError('integration_config_target_changed')
            request = atlassian.jira_create(cfg, data['summary'], data['description'],
                target['issueType'], data['labels'], dry_run=True)
        elif action == 'jira-comment':
            closed(data, ('text',))
            bounded_text(data['text'], 8000)
            request = atlassian.jira_comment(cfg, target['issueKey'], data['text'], dry_run=True)
        else:
            closed(data, ('title', 'html'))
            bounded_text(data['title'], 255)
            bounded_text(data['html'], 59000)
            if cfg.get('confluence_space') != target['spaceKey']:
                raise ContractError('integration_config_target_changed')
            payload = {'type': 'page', 'title': data['title'], 'space': {'key': target['spaceKey']},
                'body': {'storage': {'value': data['html'], 'representation': 'storage'}}}
            if action == 'confluence-create':
                if target['parentId'] is not None:
                    payload['ancestors'] = [{'id': target['parentId']}]
                method, path = 'POST', atlassian._conf_api(cfg) + '/content'
            else:
                payload['version'] = {'number': target['expectedVersion'] + 1}
                method, path = 'PUT', atlassian._conf_api(cfg) + '/content/' + target['pageId']
            request = atlassian.request(cfg, method, path, payload, dry_run=True)
    return PreparedAtlassianRequest(action, canonical_bytes(target), canonical_bytes(request))
