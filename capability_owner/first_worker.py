"""Activate one initial declaration from the original completed Hub spawn."""
import hashlib
import re

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from hub import names


def declaration(value, repository, actors):
    if (type(value) is not dict or set(value) != {'caller', 'generation', 'spawnOperationId'}
            or type(value['generation']) is not int or value['generation'] != 1
            or type(value['spawnOperationId']) is not str
            or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value['spawnOperationId']) is None
            or type(value['caller']) is not str or value['caller'] in ('operator', 'federation')
            or repository is None):
        raise ContractError('capability_owner_configuration')
    try:
        repo, role, agent = names.split_session(value['caller'])
    except Exception:
        raise ContractError('capability_owner_configuration') from None
    if (repo != repository or names.session_name(repo, role, agent) != value['caller']
            or sum(actor.caller == value['caller'] for actor in actors) != 1):
        raise ContractError('capability_owner_configuration')
    return canonical_bytes(value)


def source_inspection(resource, actor, original):
    """Pending declarations permit only the existing signed source proof."""
    raw = resource._first_worker
    return (raw is not None and strict_loads(raw)['caller'] == actor.caller
        and type(original) is dict and original['contractId'] == 'federation-work-inspect'
        and set(original['payload']['input']) == {'sourceBinding'})


def check_active(resource, caller):
    raw = resource._first_worker
    if raw is None or strict_loads(raw)['caller'] != caller:
        return
    resource._current()
    declared = strict_loads(raw)
    authority = resource._legacy_authority
    profile = {'hubId': authority._hub, 'profileId': authority._profile, 'authorityId': authority._entity}
    prefix = 'hub-work-maintenance:' + hashlib.sha256(canonical_bytes(profile)).hexdigest() + ':'
    operation = declared['spawnOperationId']

    def refuse():
        raise ContractError('first_worker_inactive')

    def read(key):
        row = resource._store.q1('SELECT v FROM fed_state WHERE k=?', (prefix + key,))
        if row is None:
            refuse()
        value = strict_loads(row['v'])
        if type(value) is not dict or canonical_bytes(value).decode() != row['v']:
            refuse()
        return value

    request = read('request:' + hashlib.sha256(operation.encode()).hexdigest())
    if (set(request) != {'operationId', 'requestDigest', 'verb', 'authenticatedCaller', 'caller'}
            or request['operationId'] != operation or request['verb'] != 'spawn'
            or request['authenticatedCaller'] != 'operator' or request['caller'] != 'operator'
            or type(request['requestDigest']) is not str
            or re.fullmatch(r'[a-f0-9]{64}', request['requestDigest']) is None):
        refuse()

    def phase(name):
        key = hashlib.sha256(canonical_bytes({'operationId': operation, 'phase': name})).hexdigest()
        value = read(key)
        if value.get('identity') != {**request, 'phase': name}:
            refuse()
        return value

    registered = phase('register')
    if (set(registered) != {'formatVersion', 'identity', 'command', 'intent', 'arguments', 'operationId', 'completed'}
            or type(registered['formatVersion']) is not int or registered['formatVersion'] != 1
            or registered['command'] != 'register' or registered['completed'] is not True
            or type(registered['intent']) is not dict or type(registered['arguments']) is not dict
            or registered['arguments'] != {**registered['intent'], 'generation': None}):
        refuse()
    args = registered['arguments']
    if (set(args) != {'repo', 'role', 'agent', 'cli', 'roleSnapshot', 'transport', 'handle',
            'panePid', 'legacy', 'tokenSha', 'generation'}
            or names.session_name(args['repo'], args['role'], args['agent']) != caller
            or args['repo'] != resource.repository or args['transport'] != 'tmux'
            or args['handle'] is not None or args['panePid'] is not None or args['legacy'] is not None):
        refuse()
    process, completed = phase('spawn-process'), phase('spawn-result')
    for value in (process, completed):
        if set(value) != {'identity', 'state', 'result'} or value['state'] != 'completed' or type(value['result']) is not dict:
            refuse()
    result = completed['result']
    if (set(process['result']) != {'returncode', 'stdout', 'stderr'}
            or type(process['result']['returncode']) is not int or process['result']['returncode'] != 0
            or set(result) != {'session', 'handle', 'pane_pid', 'cwd', 'spawn_out'}
            or result['session'] != caller or type(result['handle']) is not str
            or re.fullmatch(r'%[0-9]+', result['handle']) is None
            or type(result['pane_pid']) is not int or result['pane_pid'] <= 0):
        refuse()
    row = resource._agent(caller)
    if (row['generation'] != 1 or row['repo'] != resource.repository
            or row['role'] != args['role'] or row['agent'] != args['agent']
            or row['cli'] != args['cli'] or row['transport'] != args['transport']
            or row['token_sha'] != args['tokenSha']
            or row['handle'] != result['handle'] or row['pane_pid'] != result['pane_pid']):
        refuse()
