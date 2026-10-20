"""Closed orchestration commands prepared under an enrolled policy binding.

This module validates and freezes domain input. It does not authenticate a caller,
grant authority, or dispatch an effect. The receiving owner must do those things
from current retained authority before and after its durable dispatch claim.
"""
from dataclasses import dataclass, field
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads

_ID = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_RUN = re.compile(r"[a-f0-9]{6}\Z")
_TASK = re.compile(r"[A-Z][A-Z0-9]{1,15}-[0-9]{1,12}\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9_./-]{1,200}\Z")


def _ref(value):
    return (type(value) is dict and set(value) == {'id', 'ownerHubId', 'revision'}
            and all(type(value[k]) is str and _ID.fullmatch(value[k])
                    for k in ('id', 'ownerHubId'))
            and type(value['revision']) is int
            and 0 <= value['revision'] <= 9_007_199_254_740_991)


def _scope(value):
    return (type(value) is dict
            and set(value) == {'organizationId', 'projectId', 'workspaceId'}
            and type(value['organizationId']) is str
            and _ID.fullmatch(value['organizationId']) is not None
            and type(value['projectId']) is str
            and _ID.fullmatch(value['projectId']) is not None
            and (value['workspaceId'] is None
                 or type(value['workspaceId']) is str
                 and _ID.fullmatch(value['workspaceId']) is not None))


@dataclass(frozen=True, repr=False)
class OrchestrationPolicyBinding:
    """Private selected resource and optional environment for one project."""
    resource_ref: bytes = field(repr=False)
    scope: bytes = field(repr=False)
    repository: str
    orchestrator_agent: str
    environment_ref: bytes | None = field(default=None, repr=False)

    def __post_init__(self):
        resource = strict_loads(self.resource_ref) if type(self.resource_ref) is bytes else self.resource_ref
        scope = strict_loads(self.scope) if type(self.scope) is bytes else self.scope
        environment = (strict_loads(self.environment_ref)
                       if type(self.environment_ref) is bytes else self.environment_ref)
        if (not _ref(resource) or not _scope(scope)
                or environment is not None and not _ref(environment)
                or environment is not None and environment['ownerHubId'] != resource['ownerHubId']
                or resource['ownerHubId'] == ''
                or type(self.repository) is not str or not self.repository.startswith('/')
                or '\x00' in self.repository or not _NAME.fullmatch(self.orchestrator_agent)):
            raise ContractError('orchestration_policy_invalid')
        object.__setattr__(self, 'resource_ref', canonical_bytes(resource))
        object.__setattr__(self, 'scope', canonical_bytes(scope))
        object.__setattr__(self, 'environment_ref',
                           None if environment is None else canonical_bytes(environment))

    def __repr__(self):
        return '<OrchestrationPolicyBinding private>'


@dataclass(frozen=True, repr=False)
class PreparedOrchestrationEffect:
    command: str
    candidate: bytes = field(repr=False)
    candidate_digest: str

    def __repr__(self):
        return f'<PreparedOrchestrationEffect {self.command}>'

    def private_input(self):
        return strict_loads(self.candidate)['input']


def _text(value, maximum, *, empty=False):
    return type(value) is str and len(value) <= maximum and (empty or bool(value.strip()))


def _command(value):
    if type(value) is not dict or type(value.get('command')) is not str:
        raise ContractError('orchestration_command_invalid')
    name = value['command']
    fields = {
        'orchestrator-start': {'command', 'request'},
        'orchestrator-stop': {'command'},
        'run-start': {'command', 'request'},
        'run-assign': {'command', 'runId', 'worker', 'reviewer', 'task', 'brief'},
        'run-complete': {'command', 'runId'},
        'run-teardown': {'command', 'runId'},
        'claim-for': {'command', 'resource', 'holder', 'ttl', 'note', 'task', 'dependsOn'},
        'release-for': {'command', 'resource', 'holder'},
    }
    if name not in fields or set(value) != fields[name]:
        raise ContractError('orchestration_command_invalid')
    if name in ('orchestrator-start', 'run-start') and not _text(value['request'], 8192):
        raise ContractError('orchestration_command_invalid')
    if name in ('run-assign', 'run-complete', 'run-teardown') and not _RUN.fullmatch(value['runId']):
        raise ContractError('orchestration_command_invalid')
    if name == 'run-assign':
        if (not _NAME.fullmatch(value['worker']) or not _NAME.fullmatch(value['reviewer'])
                or value['worker'] == value['reviewer']
                or value['task'] is not None and not _TASK.fullmatch(value['task'])
                or value['brief'] is not None and not _text(value['brief'], 32768, empty=True)):
            raise ContractError('orchestration_command_invalid')
    if name in ('claim-for', 'release-for'):
        if (not _RESOURCE.fullmatch(value['resource']) or '..' in value['resource']
                or not _NAME.fullmatch(value['holder'])):
            raise ContractError('orchestration_command_invalid')
    if name == 'claim-for':
        depends = value['dependsOn']
        if (type(value['ttl']) is not int or not 60 <= value['ttl'] <= 86400
                or not _text(value['note'], 500, empty=True)
                or value['task'] is not None and not _text(value['task'], 64)
                or type(depends) is not list or len(depends) > 64
                or len(set(depends)) != len(depends)
                or any(not isinstance(item, str) or not _RESOURCE.fullmatch(item) or '..' in item
                       for item in depends)):
            raise ContractError('orchestration_command_invalid')
    return canonical_bytes(value)


def prepare_command(payload, binding):
    """Bind exact command bytes to the selected resource, project and environment."""
    if type(binding) is not OrchestrationPolicyBinding or type(payload) is not dict:
        raise ContractError('orchestration_command_invalid')
    if set(payload) != {'resourceRef', 'environmentRef', 'input'}:
        raise ContractError('orchestration_command_invalid')
    resource = strict_loads(binding.resource_ref)
    environment = None if binding.environment_ref is None else strict_loads(binding.environment_ref)
    if (payload['resourceRef'] != resource or payload['environmentRef'] != environment):
        raise ContractError('orchestration_scope_mismatch')
    frozen = canonical_bytes({'resourceRef': resource, 'environmentRef': environment,
                              'input': strict_loads(_command(payload['input']))})
    return PreparedOrchestrationEffect(payload['input']['command'], frozen,
        'sha256:' + hashlib.sha256(frozen).hexdigest())
