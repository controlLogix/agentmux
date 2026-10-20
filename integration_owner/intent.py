"""Closed integration intent data, with no credentials or external I/O.

These local domain checks supplement the canonical shared contracts. They grant
no authority. The receiving owner also requires SDK validation and current
AuthorityReader admission for the complete signed operation.
"""
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, payload_digest, strict_loads, validate

ID = re.compile(r'[a-z][a-z0-9_-]{0,95}\Z')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
MAX_REVISION = 9007199254740991


def effect_id(scope, operation_id):
    """One aggregate for the same original operation within its exact scope."""
    if not isinstance(operation_id, str) or not ID.fullmatch(operation_id):
        raise ContractError('integration_original_identity_invalid')
    return 'effect-' + hashlib.sha256(canonical_bytes({
        'scope': scope, 'operationId': operation_id})).hexdigest()


def closed(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ContractError('integration_shape_invalid')


def text(value, pattern, maximum=300):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not re.fullmatch(pattern, value):
        raise ContractError('integration_target_invalid')


def reference(value):
    closed(value, ('id', 'ownerHubId', 'revision'))
    if (not isinstance(value['id'], str) or not ID.fullmatch(value['id'])
            or not isinstance(value['ownerHubId'], str) or not ID.fullmatch(value['ownerHubId'])
            or type(value['revision']) is not int or not 0 <= value['revision'] <= MAX_REVISION):
        raise ContractError('integration_reference_invalid')


def intent(payload):
    """Copy and validate a proposal; this function cannot admit or retain it."""
    body = strict_loads(canonical_bytes(payload))
    closed(body, ('effectRef', 'credentialRef', 'action', 'target', 'contentRef'))
    reference(body['effectRef'])
    reference(body['credentialRef'])
    action, target = body['action'], body['target']
    shapes = {
        'github-repo-create': ('owner', 'name', 'visibility'),
        'github-issue-create': ('repository',),
        'jira-create': ('projectKey', 'issueType'),
        'jira-comment': ('issueKey',),
        'jira-transition': ('issueKey', 'transitionId'),
        'confluence-create': ('spaceKey', 'parentId'),
        'confluence-update': ('spaceKey', 'pageId', 'expectedVersion'),
    }
    if not isinstance(action, str) or action not in shapes:
        raise ContractError('integration_action_unsupported')
    closed(target, shapes[action])
    for key, value in target.items():
        if key == 'expectedVersion':
            if type(value) is not int or not 1 <= value < MAX_REVISION:
                raise ContractError('integration_target_invalid')
        elif key in ('pageId', 'parentId', 'transitionId'):
            if key != 'parentId' or value is not None:
                text(value, r'[1-9][0-9]{0,29}')
        elif key == 'visibility':
            if value not in ('private', 'public', 'internal'):
                raise ContractError('integration_target_invalid')
        elif key == 'owner':
            text(value, r'[A-Za-z0-9][A-Za-z0-9-]{0,38}')
        elif key == 'name':
            text(value, r'[A-Za-z0-9_][A-Za-z0-9._-]{0,99}')
        elif key == 'repository':
            text(value, r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}')
        elif key == 'issueKey':
            text(value, r'[A-Z][A-Z0-9_]*-[0-9]+')
        elif key == 'projectKey':
            text(value, r'[A-Z][A-Z0-9_]*')
        elif key == 'spaceKey':
            text(value, r'[A-Za-z0-9_~.-]+')
        else:
            text(value, r'[^\x00-\x1f\x7f-\x9f]+', 100)
    content = body['contentRef']
    if action == 'jira-transition' and content is not None:
        raise ContractError('integration_content_unsupported')
    required_content = action not in ('jira-transition', 'github-repo-create')
    if content is None:
        if required_content:
            raise ContractError('integration_content_required')
    else:
        # Accept only immutable artifact metadata, never a path or external URL.
        closed(content, ('artifactId', 'ownerHubId', 'storeRef', 'version', 'digest', 'bytes', 'mediaType'))
        reference(content['storeRef'])
        for key in ('artifactId', 'ownerHubId', 'version'):
            if not isinstance(content[key], str) or not ID.fullmatch(content[key]):
                raise ContractError('integration_reference_invalid')
        if (not isinstance(content['digest'], str) or not DIGEST.fullmatch(content['digest'])
                or type(content['bytes']) is not int or not 0 < content['bytes'] <= 60000
                or content['mediaType'] != 'application/vnd.agentmux.integration-content+json'):
            raise ContractError('integration_content_invalid')
    if len(canonical_bytes(body)) > 12000:
        raise ContractError('integration_body_limit')
    return body


def query(payload):
    body = strict_loads(canonical_bytes(payload))
    closed(body, ('effectRef', 'originalOperationId', 'originalPayloadDigest'))
    reference(body['effectRef'])
    if (not isinstance(body['originalOperationId'], str) or not ID.fullmatch(body['originalOperationId'])
            or not isinstance(body['originalPayloadDigest'], str)
            or not DIGEST.fullmatch(body['originalPayloadDigest'])):
        raise ContractError('integration_original_identity_invalid')
    return body


def retained_state(record):
    """Verify original intent provenance before using any retained projection."""
    state = record['state']
    closed(state, ('format', 'originalOperationId', 'originalPayloadDigest', 'phase', 'intent'))
    operation = record['operation']
    expected_audit = {'operationId': operation['operationId'], 'decision': 'allowed',
        'reason': 'authorized', 'actorRef': operation['effectiveActorRef'], 'contractId': 'integration-intent'}
    if (state['format'] != 'amx-integration-effect-v1' or state['phase'] != 'intent-committed'
            or not operation['approvalRefs']
            or operation['expectedVersion'] != 0
            or state['originalOperationId'] != operation['operationId']
            or state['originalPayloadDigest'] != operation['payloadDigest']
            or record.get('authorizationDecision') != expected_audit or record['outcome'] != 'committed'
            or record['entityVersion'] != 1 or record['previousRevision'] != 0
            or record['repository'] is not None or len(record['effects']) != 1):
        raise ContractError('integration_retained_intent_invalid')
    body = intent(state['intent'])
    if payload_digest(body) != operation['payloadDigest']:
        raise ContractError('integration_retained_intent_invalid')
    effect = record['effects'][0]
    if effect != {'effectId': record['entityId'], 'contractId': 'integration-intent',
            'payloadDigest': operation['payloadDigest'], 'grantRef': operation['grantRef'],
            'recovery': 'query-before-retry', 'payload': body}:
        raise ContractError('integration_retained_intent_invalid')
    expected_artifacts = [] if body['contentRef'] is None else [body['contentRef']]
    if record['artifacts'] != expected_artifacts:
        raise ContractError('integration_retained_intent_invalid')
    validate('owner-record', record)
    return state
