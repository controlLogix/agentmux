"""Prepare fixed GitHub arguments without credentials or external calls.

Preparation grants no permission. An enrolled worker must recheck current
authority, retrieve content within its scope, and hold a durable dispatch claim
before using these arguments with its trusted gh executable. This module does
not resolve credentials, inspect local repositories, or start that executable.
"""
from dataclasses import dataclass
from hashlib import sha256
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads

from .intent import closed, intent


@dataclass(frozen=True, slots=True, repr=False)
class PreparedGithubRequest:
    """Target is canonical JSON; argv excludes the worker's executable path."""

    action: str
    target: bytes
    argv: tuple[str, ...]
    stdin: bytes

    def __repr__(self):
        return '<PreparedGithubRequest private; no external dispatch>'


def _text(value, maximum, *, empty=False, multiline=False):
    if (not isinstance(value, str) or len(value) > maximum
            or (not empty and not value.strip()) or '\x00' in value):
        raise ContractError('integration_content_invalid')
    if not multiline and re.search(r'[\x00-\x1f\x7f-\x9f]', value):
        raise ContractError('integration_content_invalid')


def _content(reference, content):
    if reference is None:
        if content is not None:
            raise ContractError('integration_content_unsupported')
        return {}
    if type(content) is not bytes or not 0 < len(content) <= 60000:
        raise ContractError('integration_content_invalid')
    if (reference['bytes'] != len(content)
            or reference['digest'] != 'sha256:' + sha256(content).hexdigest()):
        raise ContractError('integration_content_digest_mismatch')
    return strict_loads(content)


def prepare_github_request(proposal: dict, content: bytes | None = None) -> PreparedGithubRequest:
    """Compile validated intent and exact artifact bytes into a fixed request.

    Repository content may contain description, gitignore, and license. Issue
    content must contain title, body, and labels. Unknown fields are refused.
    No field supplies an actor, command, executable, flag, or credential.
    """
    body = intent(proposal)
    action, target = body['action'], body['target']
    if action not in ('github-repo-create', 'github-issue-create'):
        raise ContractError('integration_action_unsupported')
    data = _content(body['contentRef'], content)
    stdin = b''
    if action == 'github-repo-create':
        if not isinstance(data, dict) or set(data) - {'description', 'gitignore', 'license'}:
            raise ContractError('integration_shape_invalid')
        repository = 'github.com/' + target['owner'] + '/' + target['name']
        argv = ['repo', 'create', repository, '--' + target['visibility']]
        description = data.get('description', '')
        _text(description, 350, empty=True)
        if description:
            argv.append('--description=' + description)
        for field, pattern in (('gitignore', r'[A-Za-z0-9][A-Za-z0-9+#.-]{0,39}'),
                               ('license', r'[A-Za-z0-9][A-Za-z0-9.-]{0,39}')):
            value = data.get(field, '')
            if not isinstance(value, str) or (value and not re.fullmatch(pattern, value)):
                raise ContractError('integration_content_invalid')
            if value:
                argv.append('--' + field + '=' + value)
    else:
        closed(data, ('title', 'body', 'labels'))
        _text(data['title'], 250)
        _text(data['body'], 8000, empty=True, multiline=True)
        labels = data['labels']
        if not isinstance(labels, list) or len(labels) > 10:
            raise ContractError('integration_content_invalid')
        for label in labels:
            if not isinstance(label, str) or not re.fullmatch(r'[A-Za-z0-9 :._-]{1,50}', label):
                raise ContractError('integration_content_invalid')
        argv = ['issue', 'create', '--repo=github.com/' + target['repository'],
                '--title=' + data['title'], '--body-file', '-']
        argv.extend('--label=' + label for label in labels)
        stdin = data['body'].encode('utf-8')
    return PreparedGithubRequest(action, canonical_bytes(target), tuple(argv), stdin)
