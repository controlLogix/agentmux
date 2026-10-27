"""Explicit application-service enrollment and constructor inputs.

The admitted host resolves connections, histories, artifacts and checkpoint commit
handlers, then owns start and close. No executable, environment or grant is inferred.
"""
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import secrets
import ssl
import stat

from nacl.signing import SigningKey
from agentmux_contracts import ContractError, canonical_bytes, strict_loads, validate, sign_claims
from state_owner.ledger import OwnerBinding, StreamIdentity
from state_owner.retention import Retention
from state_owner.history import OwnerHistory
from state_owner.backup_host import BackupHost, _native_guard
from state_owner.artifacts import OwnerArtifacts
from .authority import LedgerAuthorityReader
from .application_enrollment import _read_material, _write_material
from .application_host_selection import ApplicationHostSelectionReceipt, _path, _nkey


def _fail():
    raise ContractError('application_service_selection_invalid')


def validate_protected_host_account(value):
    """Check the native admission description, not establish its provenance.

    Only the admitted launcher's private start packet supplies this value after
    comparing the complete local broker factory and matching OwnerBridge scope.
    HOST names this local password account, not accounts on other brokers.
    """
    if (type(value) is not dict or set(value) != {'kind', 'account', 'broker'}
            or value['kind'] != 'named-password' or value['account'] != 'HOST'):
        _fail()
    broker = value['broker']
    if (type(broker) is not dict or set(broker) != {'endpoint', 'serverName', 'configSha256'}
            or any(type(v) is not str for v in broker.values())):
        _fail()
    endpoint = re.fullmatch(r'tls://127\.0\.0\.1:([1-9][0-9]{0,4})', broker['endpoint'])
    if (endpoint is None or int(endpoint[1]) > 65535
            or not re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', broker['serverName'])
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', broker['configSha256'])):
        _fail()


def _digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _outside(path, workspaces):
    if not _path(path):
        _fail()
    if any(Path(os.path.realpath(path)).is_relative_to(os.path.realpath(root)) for root in workspaces):
        _fail()


def authority_switch_custody_directory(host_policy):
    """Return the custody directory fixed by the admitted host-policy root."""
    if not _path(host_policy):
        _fail()
    return os.path.join(os.path.dirname(os.path.realpath(host_policy)), 'authority-switch')


def retained_authority_switch_exists(directory=None):
    """Check the fixed private custody root for any retained switch record."""
    if directory is None:
        _fail()
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            _fail()
        _native_guard(fd, directory=True)
        with os.scandir(fd) as entries:
            return any(entry.name.startswith('authority-switch-') for entry in entries)
    except FileNotFoundError:
        return False
    except ContractError:
        raise
    except OSError:
        _fail()
    finally:
        if fd is not None:
            os.close(fd)


def _schema_name(name, *, max_length=1024):
    return (type(name) is str and bool(name) and len(name) <= max_length
            and all(re.fullmatch(r'[A-Za-z0-9_.-]+', part) and part not in ('.', '..')
                    for part in name.split('/')))


def _oidc(value):
    selected = value.get('oidcBrowser')
    if selected is None:
        return None
    from .oidc_adapter import OIDCProvider
    from .oidc_authorization_code import OIDCAuthorizationCodeProvider
    from .oidc_device_authorization import OIDCDeviceAuthorizationProvider
    provider = OIDCProvider(selected['issuer'], selected['audience'],
        selected['keyId'], selected['publicKey'], selected['maxTokenSeconds'],
        selected.get('rootsPEM'))
    OIDCAuthorizationCodeProvider(provider, selected['authorizationEndpoint'],
        selected['tokenEndpoint'], 'http://127.0.0.1:1024/oidc/callback')
    OIDCDeviceAuthorizationProvider(provider,
        selected['deviceAuthorizationEndpoint'], selected['tokenEndpoint'])
    return (provider, selected['authorizationEndpoint'],
            selected['deviceAuthorizationEndpoint'], selected['tokenEndpoint'])


def _oidc_browser(value):
    selected = _oidc(value)
    if selected is None:
        return None
    return selected[0], selected[1], selected[3]


def _oidc_device(value):
    selected = _oidc(value)
    if selected is None:
        return None
    return selected[0], selected[2], selected[3]


def _check_fields(value):
    validate('application-service-selection', value)
    if len(canonical_bytes(value)) > 65536 or value['ownerUid'] != os.getuid():
        _fail()
    hub = value['kernelScope']['hubId']
    workspaces = value['workspaces']
    _oidc_browser(value)
    if not all(_path(p) for p in [value['hostPolicy'], *workspaces]):
        _fail()
    roles = ('identity', 'definitions') + tuple(r for r in (
        'integration', 'configuration', 'task', 'orchestration', 'policy') if value.get(r) is not None)
    for role in roles:
        service = value[role]
        ledger, credentials, issuer = (service[k] for k in ('ledger', 'credentials', 'issuer'))
        for path in (credentials['path'], issuer['keyFile']['path'], ledger['history']['path'], ledger['checkpoint']['path']):
            _outside(path, workspaces)
        scope = ledger['scope']
        if (scope['organizationId'] != value['organizationId']
                or scope['workspaceId'] is not None and scope['projectId'] is None
                or any(r['ownerHubId'] != hub for r in (issuer['issuerRef'], ledger['checkpoint']['commitRef']))):
            _fail()
        Retention(ledger['retention']['maxBytes'], ledger['retention']['reserveBytes'], ledger['retention']['replicas'])
        StreamIdentity(datetime.fromisoformat(ledger['streamIdentity']['created']), ledger['streamIdentity']['minimumSequence'])
        if not _nkey(credentials['accountPublicKey'], 0) or not _nkey(credentials['userPublicKey'], 160):
            _fail()
        key = base64.urlsafe_b64decode(issuer['publicKey'] + '=')
        if len(key) != 32 or base64.urlsafe_b64encode(key).decode().rstrip('=') != issuer['publicKey']:
            _fail()
        connection = service['connection']
        if int(connection['endpoint'].rsplit(':', 1)[1]) > 65535:
            _fail()
        labels = connection['serverName'].split('.')
        if (all(label.isdigit() for label in labels)
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels)):
            _fail()
        roots = connection['rootsPEM']
        if len(roots.encode()) > 16384 or roots.count('-----BEGIN CERTIFICATE-----') != 1 or roots.count('-----END CERTIFICATE-----') != 1:
            _fail()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=roots)
    if len({value[role]['credentials']['userPublicKey'] for role in roles}) != len(roles):
        _fail()
    if len({value[role]['issuer']['publicKey'] for role in roles}) != len(roles):
        _fail()
    if len({value[role]['ledger']['history']['path'] for role in roles}) != len(roles):
        _fail()
    if value.get('integration') is not None:
        from integration_owner.intent import effect_id
        integration = value['integration']
        ledger = integration['ledger']
        if (ledger['scope']['projectId'] is None
                or ledger['entityId'] != effect_id(ledger['scope'], integration['originalOperationId'])
                or integration['credentialRef']['ownerHubId'] != hub
                or integration['artifacts']['storeRef']['ownerHubId'] != hub):
            _fail()
        if integration['credentialEnrollment'] is not None:
            _outside(integration['credentialEnrollment']['path'], workspaces)
        routing = integration.get('routing')
        if routing is not None:
            roots = [routing[k] for k in ('resourceDirectory',
                'inventoryDirectory', 'credentialDirectory',
                'backupKeyDirectory')]
            for path in roots:
                _outside(path, workspaces)
            if any(Path(os.path.realpath(a)).is_relative_to(os.path.realpath(b))
                    or Path(os.path.realpath(b)).is_relative_to(os.path.realpath(a))
                    for i, a in enumerate(roots) for b in roots[i + 1:]):
                _fail()
            fixed = [integration['credentials']['path'],
                integration['issuer']['keyFile']['path'],
                integration['ledger']['history']['path'],
                integration['ledger']['checkpoint']['path']]
            if integration['credentialEnrollment'] is not None:
                fixed.append(integration['credentialEnrollment']['path'])
            if any(Path(os.path.realpath(a)).is_relative_to(os.path.realpath(b))
                    or Path(os.path.realpath(b)).is_relative_to(os.path.realpath(a))
                    for a in roots for b in fixed):
                _fail()
    if value.get('configuration') is not None:
        configuration = value['configuration']
        producer = configuration['producer']
        _outside(producer['keyFile']['path'], workspaces)
        public = base64.urlsafe_b64decode(producer['publicKey'] + '=')
        if (len(public) != 32 or base64.urlsafe_b64encode(public).decode().rstrip('=') != producer['publicKey']
                or producer['publicKey'] == configuration['issuer']['publicKey']
                or any(producer[k]['ownerHubId'] != hub for k in ('identityRef','transportRef','grantRef'))):
            _fail()
        if (not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}', configuration['requesterReplyPrefix'])
                or configuration['requesterReplyPrefix'] == configuration['credentials']['replyPrefix']
                or not _schema_name(configuration['schemaRef'])
                or configuration['schemaRef'] not in configuration['schemaResources']):
            _fail()
        for name, pin in configuration['schemaResources'].items():
            if not _schema_name(name):
                _fail()
            _outside(pin['path'], workspaces)
    if value.get('task') is not None:
        task = value['task']
        if (task['serviceIdentityRef']['ownerHubId'] != hub
                or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}', task['requesterReplyPrefix'])
                or task['requesterReplyPrefix'] == task['credentials']['replyPrefix']):
            _fail()
        if 'artifacts' in task:
            artifacts = task['artifacts']
            reader = artifacts['reader']
            if (not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', artifacts['bucket'])
                    or any(not re.fullmatch(r'artifact_backup_[a-f0-9]{64}', operation)
                           for operation in reader.get('approvalsByOperation', {}))):
                _fail()
            references = [reader['transportRef'], reader['grantRef']]
            references.extend(ref for refs in reader.get('approvalsByOperation', {}).values() for ref in refs)
            if (artifacts['storeRef']['ownerHubId'] != hub
                    or any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in references)
                    or task['ledger']['stream'] == 'OBJ_' + artifacts['bucket']):
                _fail()
    identity, definitions = value['identity'], value['definitions']
    if (identity['ledger']['entityId'] != value['authorityId']
            or identity['ledger']['scope']['projectId'] is not None
            or identity['ledger']['scope']['workspaceId'] is not None
            or definitions['ledger']['scope']['projectId'] is None
            or identity['credentials']['userPublicKey'] == definitions['credentials']['userPublicKey']
            or identity['issuer']['issuerRef'] == definitions['issuer']['issuerRef']
            or identity['issuer']['publicKey'] == definitions['issuer']['publicKey']):
        _fail()
    if identity['ledger']['history']['path'] == definitions['ledger']['history']['path']:
        _fail()
    project_scope = definitions['ledger']['scope']
    dashboard = value.get('dashboard')
    if dashboard is not None:
        if (dashboard['scope'] != project_scope
                or dashboard['resourceRef']['ownerHubId'] != hub):
            _fail()
        _outside(dashboard['databasePath'], workspaces)
    orchestration = value.get('orchestration')
    if orchestration is not None:
        environment = orchestration['environmentRef']
        phase = orchestration['phaseAuthority']
        _outside(phase['keyFile']['path'], workspaces)
        public = base64.urlsafe_b64decode(phase['publicKey'] + '=')
        if (orchestration['scope'] != project_scope
                or orchestration['resourceRef']['ownerHubId'] != hub
                or orchestration['repository'] not in workspaces
                or orchestration['ledger']['entityId'] != orchestration['resourceRef']['id']
                or orchestration['ledger']['scope'] != project_scope
                or orchestration['serviceIdentityRef']['ownerHubId'] != hub
                or any(ref['ownerHubId'] != hub
                       for ref in (phase['transportRef'], *phase['grants'].values()))
                or environment is not None and environment['ownerHubId'] != hub
                or len(public) != 32
                or base64.urlsafe_b64encode(public).decode().rstrip('=') != phase['publicKey']
                or phase['publicKey'] == orchestration['issuer']['publicKey']):
            _fail()
    for role in ('identity', 'configuration', 'task', 'policy'):
        if value.get(role) is None:
            continue
        backup = value[role]['backup']
        roots = [backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory')]
        for path in roots:
            _outside(path, workspaces)
        if any(Path(os.path.realpath(a)).is_relative_to(os.path.realpath(b)) for i, a in enumerate(roots)
               for j, b in enumerate(roots) if i != j):
            _fail()
    if definitions['artifacts']['storeRef']['ownerHubId'] != hub:
        _fail()
    if not all(_path(p) for p in definitions['directories'].values()):
        _fail()
    if definitions['directories']['projectRoot'] not in workspaces:
        _fail()
    if 'storage' in value:
        try:
            _check_storage(value)
        except Exception:
            _fail()
    if value.get('policy') is not None:
        _check_policy(value)
    if value.get('workspace') is not None:
        from .workspace_selection import check_workspace_selection
        check_workspace_selection(value)
    if value.get('artifact') is not None:
        from .artifact_selection import check_artifact_selection
        check_artifact_selection(value)
    if value.get('ordinarySecret') is not None:
        from .secret_selection import check_secret_selection
        check_secret_selection(value)
    if value.get('process') is not None:
        from .process_selection import check_process_selection
        check_process_selection(value)
    if value.get('coreWorkTransport') is not None:
        from .core_work_transport import check_core_work_selection
        check_core_work_selection(value)
    if value.get('peerControl') is not None:
        from .peer_control import check_peer_control_selection
        check_peer_control_selection(value)
    if value.get('federationPolicy') is not None:
        from .federation_policy_selection import check_federation_policy_selection
        check_federation_policy_selection(value)
    try:
        _check_authority_switch(value)
    except Exception:
        _fail()


def _check_policy(value):
    policy, hub = value['policy'], value['kernelScope']['hubId']
    references = [policy[key] for key in ('policyRef', 'pluginIdentityRef', 'serviceIdentityRef', 'requestSigningKeyRef')]
    if (any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in references)
            or policy['policyRef']['id'] != policy['ledger']['entityId']
            or policy['requestSigningKeyRef'] != value['identity']['issuer']['issuerRef']):
        _fail()
    entries = [value[key] for key in ('identity', 'definitions', 'integration', 'configuration',
        'task', 'orchestration') if value.get(key)]
    storage = value.get('storage')
    if storage is not None:
        entries.extend(_storage_entries(value).values())
    prefixes = [entry['credentials']['replyPrefix'] for entry in entries]
    prefixes.extend(entry['requesterReplyPrefix'] for entry in entries if 'requesterReplyPrefix' in entry)
    if (policy['credentials']['replyPrefix'] in prefixes
            or policy['credentials']['userPublicKey'] in {entry['credentials']['userPublicKey'] for entry in entries}):
        _fail()
    def paths(entry):
        selected = [entry['credentials']['path']]
        if 'issuer' in entry:
            selected.append(entry['issuer']['keyFile']['path'])
        if 'ledger' in entry:
            selected.extend(entry['ledger'][key]['path'] for key in ('history', 'checkpoint'))
        if 'backup' in entry:
            selected.extend(entry['backup'][key] for key in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'))
        return [Path(os.path.realpath(path)) for path in selected]
    existing = [path for entry in entries for path in paths(entry)]
    if storage is not None and 'privateStorage' in storage:
        private = storage['privateStorage']
        existing.extend(paths(dict(private['publisher'], ledger=private['ledger'], backup=private['backup'])))
    if storage is not None and 'board' in storage:
        board = storage['board']
        existing.extend(Path(os.path.realpath(pin['path'])) for pin in board['auditMirror'].values())
        existing.append(Path(os.path.realpath(board['phaseAuthority']['keyFile']['path'])))
    if storage is not None and 'messages' in storage:
        existing.extend(Path(os.path.realpath(pin['path'])) for pin in storage['messages']['source'].values())
    if storage is not None and 'knowledge' in storage:
        existing.extend(Path(os.path.realpath(pin['path'])) for pin in storage['knowledge']['source'].values())
    if storage is not None and 'code' in storage:
        existing.extend(Path(os.path.realpath(pin['path'])) for pin in storage['code']['source'].values())
    if storage is not None and 'work' in storage:
        existing.extend(Path(os.path.realpath(pin['path'])) for pin in storage['work']['source'].values())
    selected = paths(policy)
    if any(a.is_relative_to(b) or b.is_relative_to(a) for index, a in enumerate(selected)
           for b in [*existing, *selected[index + 1:]]):
        _fail()


def _storage_entries(value):
    storage = value['storage']
    result = dict(storage['receivers'])
    if 'privateStorage' in storage:
        result['private'] = storage['privateStorage']['publisher']
    if 'board' in storage:
        result.update(card=storage['board']['cardPublisher'], allocation=storage['board']['allocationPublisher'])
    return result


def _check_storage_messages(value, ids):
    from hub import names
    from hub.fed.policy import normalize_remote, rid_for_remote
    storage, hub = value['storage'], value['kernelScope']['hubId']
    messages = storage['messages']
    repository = messages['repository']
    if (repository is None) != (storage['scope']['projectId'] is None):
        _fail()
    if repository is not None and (normalize_remote(repository['normalizedRemote']) != repository['normalizedRemote']
            or rid_for_remote(repository['normalizedRemote']) != repository['repositoryId']):
        _fail()
    for pin in messages['source'].values():
        _outside(pin['path'], value['workspaces'])
    board = storage.get('board')
    if board is not None:
        source, audit = messages['source'], board['auditMirror']
        message_database = os.path.realpath(source['database']['path'])
        board_database = os.path.realpath(audit['database']['path'])
        if (message_database == os.path.realpath(audit['policy']['path'])
                or os.path.realpath(source['policy']['path']) == board_database):
            _fail()
        if message_database == board_database and (source != audit or repository is None
                or any(repository[k] != board['repository'][k] for k in repository)
                or messages['localPeer'] != board['localPeer']):
            _fail()
    for channel in messages['channels']:
        if (channel['resourceRef']['ownerHubId'] != hub or channel['resourceRef']['revision'] < 1
                or channel['pluginIdentityRef']['ownerHubId'] != hub or channel['pluginIdentityRef']['revision'] < 1
                or channel['peer'] == messages['localPeer']):
            _fail()
        ids.append(channel['resourceRef']['id'])
        seen = set()
        for actor in channel['actors']:
            key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
            if key in seen or any(actor[k]['ownerHubId'] != hub or actor[k]['revision'] < 1
                    for k in ('identityRef', 'transportRef')):
                _fail()
            seen.add(key)
            if actor['caller'] not in ('operator', 'virtual:operator'):
                caller = actor['caller'].removeprefix('agent:')
                repo, _, _ = names.split_session(caller)
                if repository is None or repo != repository['localName']:
                    _fail()
        seen = set()
        for actor in channel.get('legacyActors', ()):
            key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
            if key in seen or any(ref['ownerHubId'] != hub or ref['revision'] < 1
                    for ref in (actor['identityRef'], actor['transportRef'], *actor['grants'].values())):
                _fail()
            seen.add(key)
            contracts = set(actor['grants'])
            if actor['caller'] == 'federation':
                if contracts - {'federation-message-deliver', 'federation-message-inspect', 'federation-message-outcome'}:
                    _fail()
            else:
                if 'federation-message-deliver' in contracts:
                    _fail()
                if 'federation-message-approve' in contracts and actor['caller'] != 'operator':
                    _fail()
                if actor['caller'] not in ('operator', 'virtual:operator'):
                    repo, _, _ = names.split_session(actor['caller'].removeprefix('agent:'))
                    if repository is None or repo != repository['localName']:
                        _fail()


def _check_storage_knowledge(value, ids):
    from hub import names
    from hub.fed.policy import normalize_remote, rid_for_remote
    storage, hub = value['storage'], value['kernelScope']['hubId']
    selected = storage['knowledge']
    repository = selected['repository']
    if (storage['scope']['projectId'] is None
            or normalize_remote(repository['normalizedRemote']) != repository['normalizedRemote']
            or rid_for_remote(repository['normalizedRemote']) != repository['repositoryId']):
        _fail()
    if os.path.realpath(selected['source']['database']['path']) == os.path.realpath(selected['source']['policy']['path']):
        _fail()
    for pin in selected['source'].values():
        _outside(pin['path'], value['workspaces'])
    others = [(storage[name], key) for name, key in (('messages', 'source'), ('board', 'auditMirror'))
        if name in storage]
    if 'workspace' in value:
        others.append((value['workspace'], 'source'))
    for other, key in others:
        pins = other[key]
        if any(os.path.realpath(selected['source'][a]['path']) == os.path.realpath(pins[b]['path'])
                for a, b in (('database', 'policy'), ('policy', 'database'))):
            _fail()
        if os.path.realpath(selected['source']['database']['path']) == os.path.realpath(pins['database']['path']):
            if (selected['source'] != pins or other['repository'] is None
                    or any(other['repository'][k] != repository[k] for k in repository)
                    or other['localPeer'] != selected['localPeer']):
                _fail()
    for channel in selected['channels']:
        if any(channel[k]['ownerHubId'] != hub or channel[k]['revision'] < 1
                for k in ('resourceRef', 'pluginIdentityRef')):
            _fail()
        ids.append(channel['resourceRef']['id'])
        seen = set()
        for actor in channel['actors']:
            key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
            if key in seen or any(actor[k]['ownerHubId'] != hub or actor[k]['revision'] < 1
                    for k in ('identityRef', 'transportRef')):
                _fail()
            seen.add(key)
            if actor['caller'] not in ('operator', 'virtual:operator'):
                repo, _, _ = names.split_session(actor['caller'].removeprefix('agent:'))
                if repo != repository['localName']:
                    _fail()
        seen = set()
        for actor in channel.get('legacyActors', ()):
            key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
            if key in seen or any(ref['ownerHubId'] != hub or ref['revision'] < 1
                    for ref in (actor['identityRef'], actor['transportRef'], *actor['grants'].values())):
                _fail()
            seen.add(key)
            contracts = set(actor['grants'])
            service_actions = {'federation-knowledge-' + action for action in ('index', 'capture', 'withdraw')}
            if actor['caller'] == 'federation':
                if contracts - (service_actions | {'federation-knowledge-read',
                        'federation-knowledge-inspect', 'federation-knowledge-outcome'}):
                    _fail()
            else:
                if contracts & service_actions or ('federation-knowledge-approve' in contracts
                        and actor['caller'] != 'operator'):
                    _fail()
                if actor['caller'] not in ('operator', 'virtual:operator'):
                    repo, _, _ = names.split_session(actor['caller'].removeprefix('agent:'))
                    if repo != repository['localName']:
                        _fail()
        sources = channel.get('messageSources', ())
        messages = storage.get('messages')
        if sources and (not channel.get('legacyActors') or messages is None
                or any(messages[key] != selected[key]
                    for key in ('source', 'repository', 'localPeer', 'localNode'))):
            _fail()
        source_ids = set()
        for reference in sources:
            if (reference['ownerHubId'] != hub or reference['revision'] < 1
                    or reference['id'] in source_ids
                    or not any(item['resourceRef']['id'] == reference['id']
                        and item['resourceRef']['ownerHubId'] == hub
                        and item['resourceRef']['revision'] <= reference['revision']
                        for item in messages['channels'])):
                _fail()
            source_ids.add(reference['id'])

        work_sources = channel.get('workSources', ())
        work = storage.get('work')
        if work_sources and (not channel.get('legacyActors') or work is None
                or any(work[key] != selected[key] for key in ('source', 'localPeer', 'localNode'))):
            _fail()
        work_ids = set()
        for reference in work_sources:
            matches = [item for item in work['channels'] if item['resourceRef']['id'] == reference['id']
                and item['resourceRef']['ownerHubId'] == hub
                and item['resourceRef']['revision'] <= reference['revision']]
            if (reference['ownerHubId'] != hub or reference['revision'] < 1
                    or reference['id'] in work_ids or len(matches) != 1):
                _fail()
            work_repo, work_scope = _work_channel_projection(storage, work, matches[0])
            if work_repo != repository or work_scope != storage['scope']:
                _fail()
            work_ids.add(reference['id'])



def _check_storage_code(value, ids):
    from hub import names
    from hub.fed.policy import normalize_remote, rid_for_remote
    storage, hub = value['storage'], value['kernelScope']['hubId']
    selected = storage['code']
    repository = selected['repository']
    if (storage['scope']['projectId'] is None
            or normalize_remote(repository['normalizedRemote']) != repository['normalizedRemote']
            or rid_for_remote(repository['normalizedRemote']) != repository['repositoryId']):
        _fail()
    if os.path.realpath(selected['source']['database']['path']) == os.path.realpath(selected['source']['policy']['path']):
        _fail()
    for pin in selected['source'].values():
        _outside(pin['path'], value['workspaces'])
    others = [(storage[name], key) for name, key in (('messages', 'source'), ('knowledge', 'source'), ('board', 'auditMirror'))
        if name in storage]
    if 'workspace' in value:
        others.append((value['workspace'], 'source'))
    for other, key in others:
        pins = other[key]
        if any(os.path.realpath(selected['source'][a]['path']) == os.path.realpath(pins[b]['path'])
                for a, b in (('database', 'policy'), ('policy', 'database'))):
            _fail()
        if os.path.realpath(selected['source']['database']['path']) == os.path.realpath(pins['database']['path']):
            if (selected['source'] != pins or other['repository'] is None
                    or any(other['repository'][k] != repository[k] for k in repository)
                    or other['localPeer'] != selected['localPeer']):
                _fail()
    for channel in selected['channels']:
        if any(channel[k]['ownerHubId'] != hub or channel[k]['revision'] < 1
                for k in ('resourceRef', 'pluginIdentityRef')):
            _fail()
        ids.append(channel['resourceRef']['id'])
        seen = set()
        for actor in channel['actors']:
            key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
            if key in seen or any(actor[k]['ownerHubId'] != hub or actor[k]['revision'] < 1
                    for k in ('identityRef', 'transportRef')):
                _fail()
            seen.add(key)
            if actor['caller'] not in ('operator', 'virtual:operator'):
                repo, _, _ = names.split_session(actor['caller'].removeprefix('agent:'))
                if repo != repository['localName']:
                    _fail()
        seen = set()
        for actor in channel.get('legacyActors', ()):
            key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
            if key in seen or any(ref['ownerHubId'] != hub or ref['revision'] < 1
                    for ref in (actor['identityRef'], actor['transportRef'], *actor['grants'].values())):
                _fail()
            seen.add(key)
            contracts = set(actor['grants'])
            service_actions = {'federation-code-index'}
            if actor['caller'] == 'federation':
                if contracts - (service_actions | {'federation-code-read',
                        'federation-code-inspect', 'federation-code-outcome'}):
                    _fail()
            else:
                if contracts & service_actions or ('federation-code-approve' in contracts
                        and actor['caller'] != 'operator'):
                    _fail()
                if actor['caller'] not in ('operator', 'virtual:operator'):
                    repo, _, _ = names.split_session(actor['caller'].removeprefix('agent:'))
                    if repo != repository['localName']:
                        _fail()

def _work_channel_projection(storage, selected, channel):
    """Resolve only an explicitly selected work channel, preserving old defaults."""
    if ('repository' in channel) != ('scope' in channel):
        _fail()
    repository = channel.get('repository', selected['repository'])
    scope = channel.get('scope', storage['scope'])
    if (repository is None) != (scope['projectId'] is None):
        _fail()
    return repository, scope


def _check_storage_work(value, ids):
    from hub import names
    from hub.fed.policy import normalize_remote, rid_for_remote
    from .authority import WORK_COMMANDS, WORK_SERVICE_COMMANDS, WORK_OPERATOR_COMMANDS
    storage, hub = value['storage'], value['kernelScope']['hubId']
    selected = storage['work']
    if sum('firstWorker' in channel for channel in selected['channels']) > 1:
        _fail()
    repository, source = selected['repository'], selected['source']
    shared = 'policy' in source
    reads = {'federation-work-' + action for action in ('read', 'inspect', 'outcome')}
    federation_only = {'federation-work-' + action for action in (
        'offer', 'ingest', 'claim-envelope', 'grant-envelope', 'result-envelope',
        'stage-result', 'revoke', 'approve', 'approve-privileged')}
    if ((repository is None) != (storage['scope']['projectId'] is None)
            or shared != (selected['localPeer'] is not None)):
        _fail()
    if repository is not None:
        names.check_part(repository['localName'], 'repo')
        if shared and (normalize_remote(repository['normalizedRemote']) != repository['normalizedRemote']
                or rid_for_remote(repository['normalizedRemote']) != repository['repositoryId']):
            _fail()
    paths = [os.path.realpath(pin['path']) for pin in source.values()]
    if len(set(paths)) != len(paths):
        _fail()
    for pin in source.values():
        _outside(pin['path'], value['workspaces'])
    others = [(storage[name], key) for name, key in (
        ('messages', 'source'), ('knowledge', 'source'), ('code', 'source'), ('board', 'auditMirror'))
        if name in storage]
    if 'workspace' in value:
        others.append((value['workspace'], 'source'))
    for other, key in others:
        pins = other[key]
        if any(a != b and os.path.realpath(left['path']) == os.path.realpath(right['path'])
                for a, left in source.items() for b, right in pins.items()):
            _fail()
        if os.path.realpath(source['database']['path']) == os.path.realpath(pins['database']['path']):
            other_repo = other['repository']
            if (source != pins or selected['localPeer'] != other['localPeer']
                    or (repository is None) != (other_repo is None)
                    or repository is not None and any(other_repo.get(k) != v for k, v in repository.items())):
                _fail()
    for channel in selected['channels']:
        if any(channel[k]['ownerHubId'] != hub or channel[k]['revision'] < 1
                for k in ('resourceRef', 'pluginIdentityRef')):
            _fail()
        channel_repository, channel_scope = _work_channel_projection(storage, selected, channel)
        if 'firstWorker' in channel:
            declared = channel['firstWorker']
            caller = declared['caller']
            if (channel_repository is None or caller in ('operator', 'federation')
                    or names.split_session(caller)[0] != channel_repository['localName']
                    or names.session_name(*names.split_session(caller)) != caller
                    or sum(actor['caller'] == caller for actor in channel.get('legacyActors', ())) != 1
                    or any(actor['caller'] == caller for actor in channel['actors'])):
                _fail()
        if channel_repository is None and channel['initialSource'] is not None:
            _fail()
        if channel_scope['organizationId'] != storage['scope']['organizationId']:
            _fail()
        if channel_repository is not None:
            names.check_part(channel_repository['localName'], 'repo')
            if set(channel_repository) != {'localName'}:
                if (not shared or normalize_remote(channel_repository['normalizedRemote']) != channel_repository['normalizedRemote']
                        or rid_for_remote(channel_repository['normalizedRemote']) != channel_repository['repositoryId']):
                    _fail()
        ids.append(channel['resourceRef']['id'])
        for family in ('actors', 'legacyActors'):
            seen = set()
            for actor in channel.get(family, ()):
                key = (canonical_bytes(actor['identityRef']), canonical_bytes(actor['transportRef']))
                refs = (actor['identityRef'], actor['transportRef'], *actor.get('grants', {}).values())
                if key in seen or any(ref['ownerHubId'] != hub or ref['revision'] < 1 for ref in refs):
                    _fail()
                seen.add(key)
                caller = actor['caller']
                contracts = set(actor.get('grants', {}))
                if family == 'actors' and caller == 'federation':
                    _fail()
                if caller not in ('operator', 'federation'):
                    # Registration names provide syntax, not project authority.
                    names.split_session(caller)
                if (contracts - WORK_COMMANDS or channel_repository is None and contracts - reads
                        or not shared and contracts & federation_only
                        or caller == 'federation' and contracts - (WORK_SERVICE_COMMANDS | reads)
                        or caller != 'federation' and contracts & WORK_SERVICE_COMMANDS
                        or caller != 'operator' and contracts & WORK_OPERATOR_COMMANDS):
                    _fail()


def _check_storage(value):
    """Validate protected provider inputs without granting a native generation."""
    from capability_owner.private_storage import private_storage_binding_digest
    from hub.fed.policy import normalize_remote, rid_for_remote
    from hub.fed.plugins.messages import parse_peer_address
    storage, hub = value['storage'], value['kernelScope']['hubId']
    scope, workspaces = storage['scope'], value['workspaces']
    if (scope['organizationId'] != value['organizationId']
            or scope['workspaceId'] is not None and scope['projectId'] is None):
        _fail()
    entries = _storage_entries(value)
    existing = [value[k] for k in ('identity','definitions','integration','configuration',
        'task','orchestration','policy') if value.get(k)]
    users = [e['credentials']['userPublicKey'] for e in (*existing, *entries.values())]
    inboxes = [e['credentials']['replyPrefix'] for e in entries.values()]
    existing_inboxes = {e['credentials']['replyPrefix'] for e in existing}
    existing_inboxes.update(e['requesterReplyPrefix'] for e in existing if 'requesterReplyPrefix' in e)
    if (len(set(users)) != len(users) or len(set(inboxes)) != len(inboxes)
            or existing_inboxes.intersection(inboxes)):
        _fail()
    for entry in entries.values():
        connection, credentials = entry['connection'], entry['credentials']
        _outside(credentials['path'], workspaces)
        if (not _nkey(credentials['accountPublicKey'], 0) or not _nkey(credentials['userPublicKey'], 160)
                or not re.fullmatch(r'_INBOX\.[A-Za-z0-9_-]{16,64}',credentials['replyPrefix'])
                or not re.fullmatch(r'tls://127\.0\.0\.1:[1-9][0-9]{0,4}',connection['endpoint'])
                or int(connection['endpoint'].rsplit(':',1)[1]) > 65535
                or connection['jetstreamDomain'] is not None and
                    not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',connection['jetstreamDomain'])):
            _fail()
        labels = connection['serverName'].split('.')
        if (all(label.isdigit() for label in labels)
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels)):
            _fail()
        roots = connection['rootsPEM']
        if (len(roots.encode()) > 16384 or roots.count('-----BEGIN CERTIFICATE-----') != 1
                or roots.count('-----END CERTIFICATE-----') != 1):
            _fail()
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=roots)
    receivers = storage['receivers']
    issuers = [entry['issuer'] for entry in (*existing, *receivers.values())]
    if len({i['publicKey'] for i in issuers}) != len(issuers):
        _fail()
    for entry in receivers.values():
        issuer = entry['issuer']
        _outside(issuer['keyFile']['path'],workspaces)
        public = base64.urlsafe_b64decode(issuer['publicKey']+'=')
        if (len(public) != 32 or base64.urlsafe_b64encode(public).decode().rstrip('=') != issuer['publicKey']
                or any(r['ownerHubId'] != hub for r in
                    (issuer['issuerRef'],entry['serviceIdentityRef'],entry['requestSigningKeyRef']))
                or entry['requestSigningKeyRef'] != value['identity']['issuer']['issuerRef']):
            _fail()
    resources = []
    if 'privateStorage' in storage:
        private = storage['privateStorage']
        ledger = private['ledger']
        binding = OwnerBinding(hub,'plugin-private',ledger['entityId'],'plugin-storage',canonical_bytes(scope))
        stream = ledger['streamIdentity']; retention = ledger['retention']
        digest = private_storage_binding_digest(binding=binding,plugin_identity_ref=private['pluginIdentityRef'],
            instance_id=private['instanceId'],package_id=private['packageId'],stream=ledger['stream'],
            stream_identity=StreamIdentity(datetime.fromisoformat(stream['created']),stream['minimumSequence']),
            retention=Retention(retention['maxBytes'],retention['reserveBytes'],retention['replicas']),
            domain=private['publisher']['connection']['jetstreamDomain'] or '')
        if digest != private['bindingDigest']:
            _fail()
        resources.append(private)
    if 'board' in storage:
        board, repo = storage['board'], storage['board']['repository']
        if (scope['projectId'] is None or board['resourceRef']['ownerHubId'] != hub
                or normalize_remote(repo['normalizedRemote']) != repo['normalizedRemote']
                or rid_for_remote(repo['normalizedRemote']) != repo['repositoryId']
                or not re.fullmatch(r'[A-Z0-9_-]{1,64}',repo['counterPrefix'])
                or not re.fullmatch(re.escape(repo['counterPrefix'])+r'-[1-9][0-9]{0,15}',board['cardKey'])
                or int(board['cardKey'].rsplit('-',1)[1]) > 9_007_199_254_740_991
                or board['cardPublisher']['ledger']['entityId'] != board['resourceRef']['id']):
            _fail()
        # Both publishers must address the same board, while retaining separate users.
        card, allocation = board['cardPublisher'], board['allocationPublisher']
        if (card['connection'] != allocation['connection']
                or card['credentials']['accountPublicKey'] != allocation['credentials']['accountPublicKey']
                or card['ledger']['entityId'] == allocation['ledger']['entityId']):
            _fail()
        phase = board['phaseAuthority']
        _outside(phase['keyFile']['path'],workspaces)
        references = [phase['serviceIdentityRef'],phase['transportRef'],
            *phase['cardGrants'].values(),*phase['allocationGrants'].values()]
        if any(r['ownerHubId'] != hub or r['revision'] < 1 for r in references):
            _fail()
        if len({canonical_bytes(r) for r in references[2:]}) != 4:
            _fail()
        if len({(canonical_bytes(a['identityRef']),canonical_bytes(a['transportRef'])) for a in board['actors']}) != len(board['actors']):
            _fail()
        for actor in board['actors']:
            parse_peer_address(actor['address'])
            if any(actor[k]['ownerHubId'] != hub for k in ('identityRef','transportRef')):
                _fail()
        for pin in board['auditMirror'].values():
            _outside(pin['path'],workspaces)
        resources.extend((card,allocation))
    paths, streams, ids = [], [], []
    if 'messages' in storage:
        _check_storage_messages(value, ids)
        paths.extend(os.path.realpath(pin['path']) for pin in storage['messages']['source'].values())
    if 'knowledge' in storage:
        _check_storage_knowledge(value, ids)
        paths.extend(path for pin in storage['knowledge']['source'].values()
            if (path := os.path.realpath(pin['path'])) not in paths)
    if 'code' in storage:
        _check_storage_code(value, ids)
        paths.extend(path for pin in storage['code']['source'].values()
            if (path := os.path.realpath(pin['path'])) not in paths)
    if 'work' in storage:
        _check_storage_work(value, ids)
        paths.extend(path for pin in storage['work']['source'].values()
            if (path := os.path.realpath(pin['path'])) not in paths)
    existing_paths = []
    for entry in existing:
        existing_paths.extend(os.path.realpath(entry['ledger'][key]['path']) for key in ('history','checkpoint'))
        if 'backup' in entry:
            existing_paths.extend(os.path.realpath(entry['backup'][key]) for key in
                ('backupDirectory','inventoryDirectory','keyDirectory'))
    for resource in resources:
        ledger = resource['ledger']
        if ledger['scope'] != scope or ledger['checkpoint']['commitRef']['ownerHubId'] != hub:
            _fail()
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',ledger['stream']) or ledger['stream'] == 'KV_am_board':
            _fail()
        retention, source = ledger['retention'], ledger['streamIdentity']
        Retention(retention['maxBytes'],retention['reserveBytes'],retention['replicas'])
        StreamIdentity(datetime.fromisoformat(source['created']),source['minimumSequence'])
        ids.append(ledger['entityId']); streams.append(ledger['stream'])
        for pin in (ledger['history'],ledger['checkpoint']):
            _outside(pin['path'],workspaces); paths.append(os.path.realpath(pin['path']))
        backup = resource['backup']
        for name in ('backupDirectory','inventoryDirectory','keyDirectory'):
            _outside(backup[name],workspaces); paths.append(os.path.realpath(backup[name]))
    if len(set(ids)) != len(ids) or len(set(streams)) != len(streams):
        _fail()
    if any(Path(a).is_relative_to(b) for i,a in enumerate(paths) for j,b in enumerate(paths) if i != j):
        _fail()
    if any(Path(a).is_relative_to(b) or Path(b).is_relative_to(a) for a in paths for b in existing_paths):
        _fail()


def _check_authority_switch(value):
    """Validate the retained cutover owner selected by the protected host."""
    from state_owner.authority_switch import authority_switch_id
    selected = value['authoritySwitch']
    workspaces = value['workspaces']
    _outside(selected['custodyDirectory'], workspaces)
    if selected['custodyDirectory'] != authority_switch_custody_directory(value['hostPolicy']):
        _fail()
    binding = selected['binding']
    if binding is None:
        return
    source, receiver, ledger = (binding[key] for key in ('source', 'receiver', 'ledger'))
    hub = value['kernelScope']['hubId']
    validate('authority-switch', {'action': 'record-source-fence',
        'switchId': binding['switchId'], 'source': source})
    scope = ledger['scope']
    if (authority_switch_id(source) != binding['switchId']
            or ledger['entityId'] != binding['switchId']
            or scope != {'organizationId': value['organizationId'],
                         'projectId': None, 'workspaceId': None}
            or source['sourceRef']['ownerHubId'] != hub):
        _fail()
    for path in (receiver['credentials']['path'], receiver['issuer']['keyFile']['path'],
                 ledger['history']['path'], ledger['checkpoint']['path']):
        _outside(path, workspaces)
    connection, credentials, issuer = (receiver[key]
        for key in ('connection', 'credentials', 'issuer'))
    if (not _nkey(credentials['accountPublicKey'], 0)
            or not _nkey(credentials['userPublicKey'], 160)
            or receiver['requestSigningKeyRef'] != value['identity']['issuer']['issuerRef']
            or any(ref['ownerHubId'] != hub for ref in
                (receiver['serviceIdentityRef'], receiver['requestSigningKeyRef'],
                 issuer['issuerRef'], ledger['checkpoint']['commitRef']))):
        _fail()
    if (not re.fullmatch(r'tls://127\.0\.0\.1:[1-9][0-9]{0,4}', connection['endpoint'])
            or int(connection['endpoint'].rsplit(':', 1)[1]) > 65535):
        _fail()
    labels = connection['serverName'].split('.')
    roots = connection['rootsPEM']
    public = base64.urlsafe_b64decode(issuer['publicKey'] + '=')
    if (all(label.isdigit() for label in labels)
            or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in labels)
            or len(roots.encode()) > 16384
            or roots.count('-----BEGIN CERTIFICATE-----') != 1
            or roots.count('-----END CERTIFICATE-----') != 1
            or len(public) != 32
            or base64.urlsafe_b64encode(public).decode().rstrip('=') != issuer['publicKey']):
        _fail()
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=roots)
    stream, retention = ledger['streamIdentity'], ledger['retention']
    StreamIdentity(datetime.fromisoformat(stream['created']), stream['minimumSequence'])
    Retention(retention['maxBytes'], retention['reserveBytes'], retention['replicas'])
    occupied = [value[key] for key in ('identity', 'definitions', 'integration',
        'configuration', 'task', 'orchestration', 'policy') if value.get(key)]
    if value.get('storage') is not None:
        occupied.extend(_storage_entries(value).values())
    if (credentials['userPublicKey'] in {entry['credentials']['userPublicKey'] for entry in occupied}
            or credentials['replyPrefix'] in
                {entry['credentials']['replyPrefix'] for entry in occupied}
            or issuer['publicKey'] in {entry['issuer']['publicKey'] for entry in occupied
                                      if 'issuer' in entry}):
        _fail()


def _check(value):
    try:
        _check_fields(value)
    except ContractError:
        raise
    except (ValueError, TypeError, KeyError, ssl.SSLError):
        _fail()


@dataclass(frozen=True, repr=False)
class ApplicationServiceSelection:
    document: bytes

    def __post_init__(self):
        if type(self.document) is not bytes or len(self.document) > 65536:
            _fail()
        value = strict_loads(self.document)
        _check(value)
        object.__setattr__(self, 'document', canonical_bytes(value))

    def __repr__(self):
        return '<ApplicationServiceSelection private>'

    @property
    def policy(self):
        return strict_loads(self.document)

    def work_channel_projection(self, resource_ref):
        """Return the exact protected work channel and its repository scope."""
        value = self.policy
        selected = value.get('storage', {}).get('work')
        if selected is None:
            _fail()
        matches = [channel for channel in selected['channels'] if channel['resourceRef'] == resource_ref]
        if len(matches) != 1:
            _fail()
        channel = matches[0]
        repository, scope = _work_channel_projection(value['storage'], selected, channel)
        return selected, channel, repository, scope

    def service(self, role):
        if role not in ('identity', 'definitions', 'integration', 'configuration', 'task',
                        'orchestration', 'policy') or self.policy.get(role) is None:
            _fail()
        return self.policy[role]

    def dashboard_policy(self):
        """Return the protected dashboard resource, or keep writes disabled."""
        return self.policy.get('dashboard')

    def local_browser_port(self):
        """Return the selected private loopback port, or None when none was selected."""
        selected = self.policy.get('localBrowser')
        return None if selected is None else selected['port']

    def orchestration_policy(self):
        """Return the protected orchestration resource and local routing inputs."""
        return self.policy.get('orchestration')

    def orchestration_policy_binding(self):
        """Freeze the selected project, repository and optional environment."""
        selected = self.service('orchestration')
        from orchestration_owner.commands import OrchestrationPolicyBinding
        return OrchestrationPolicyBinding(selected['resourceRef'], selected['scope'],
            selected['repository'], selected['orchestratorAgent'],
            selected['environmentRef'])

    def oidc_browser_configuration(self):
        """Return only the protected provider pins admitted with this selection."""
        return _oidc_browser(self.policy)

    def oidc_device_configuration(self):
        """Return the same provider pins for a supported terminal owner."""
        return _oidc_device(self.policy)

    def authority_switch_configuration(self):
        """Return the closed public cutover binding and a fail-closed guard.

        Owner credentials remain in this protected selection. The returned
        guard can close the legacy writer but cannot authorize recovery.
        """
        selected = self.policy['authoritySwitch']
        binding = selected['binding']
        if binding is None:
            if retained_authority_switch_exists(selected['custodyDirectory']):
                _fail()
            return None
        from hub.migration_recovery import LegacyWriterRecoveryGuard
        from state_owner.authority_switch import AuthoritySwitchHost
        ledger = binding['ledger']
        stream = ledger['streamIdentity']
        owner_binding = OwnerBinding(self.policy['kernelScope']['hubId'],
            'authority-switch', binding['switchId'], 'authority-switch',
            canonical_bytes(ledger['scope']))
        identity = StreamIdentity(datetime.fromisoformat(stream['created']),
                                  stream['minimumSequence'])
        host = AuthoritySwitchHost(selected['custodyDirectory'], binding=owner_binding,
                                   stream_identity=identity)
        guard = LegacyWriterRecoveryGuard.closed(source=binding['source'],
            switch_id=binding['switchId'], stream_identity=identity, host=host)
        public = {'switchId': binding['switchId'], 'source': binding['source'],
            'streamIdentity': stream, 'custodyDirectory': selected['custodyDirectory']}
        return strict_loads(canonical_bytes(public)), guard

    def authority_switch_policy_inputs(self):
        """Derive the exact receiver and ledger permissions from protected pins."""
        from native_security.nats_credentials import authority_switch_receiver_policy
        binding = self.policy['authoritySwitch']['binding']
        if binding is None:
            _fail()
        receiver, ledger = binding['receiver'], binding['ledger']
        inputs = dict(hub_id=self.policy['kernelScope']['hubId'],
            entity_id=binding['switchId'], scope=ledger['scope'],
            stream=ledger['stream'], reply_prefix=receiver['credentials']['replyPrefix'],
            jetstream_domain=receiver['connection']['jetstreamDomain'])
        try:
            authority_switch_receiver_policy(**inputs)
        except Exception:
            _fail()
        return inputs

    def read_authority_switch_credentials(self):
        binding = self.policy['authoritySwitch']['binding']
        if binding is None:
            _fail()
        pin = binding['receiver']['credentials']
        raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
        if not raw or _digest(raw) != pin['sha256']:
            _fail()
        return raw

    def authority_switch_tls_options(self):
        binding = self.policy['authoritySwitch']['binding']
        if binding is None:
            _fail()
        connection = binding['receiver']['connection']
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=connection['rootsPEM'])
        return {'servers': [connection['endpoint']], 'tls': context,
                'tls_hostname': connection['serverName'], 'tls_handshake_first': True}

    def load_authority_switch_signing_seed(self):
        value = self.policy
        binding = value['authoritySwitch']['binding']
        if binding is None:
            _fail()
        receiver, issuer = binding['receiver'], binding['receiver']['issuer']
        pin = issuer['keyFile']
        raw = _read_material(pin['path'], return_bytes=True)
        if _digest(raw) != pin['sha256']:
            _fail()
        key = strict_loads(raw)
        validate('application-service-key', key)
        expected = {'serviceId': 'authority-switch-owner',
            'hubId': value['kernelScope']['hubId'],
            'profileId': value['kernelScope']['profileId'],
            'authorityId': value['authorityId'], 'issuerRef': issuer['issuerRef']}
        if any(key.get(name) != selected for name, selected in expected.items()):
            _fail()
        seed = base64.b64decode(key['seed'], validate=True)
        public = base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
        if len(seed) != 32 or public != issuer['publicKey']:
            _fail()
        return seed

    def storage_descriptor(self, name):
        """Return one selected connection; absence never creates a default."""
        try:
            return _storage_entries(self.policy)[name]
        except (KeyError, TypeError):
            _fail()

    def storage_policy_inputs(self, name):
        value = self.policy
        selected = self.storage_descriptor(name)
        result = dict(hub_id=value['kernelScope']['hubId'],scope=value['storage']['scope'],
            reply_prefix=selected['credentials']['replyPrefix'])
        if name in ('storage','outcome'):
            scopes = {}
            work = value['storage'].get('work')
            if work is not None:
                for channel in work['channels']:
                    scope = _work_channel_projection(value['storage'], work, channel)[1]
                    if scope != value['storage']['scope']:
                        scopes[canonical_bytes(scope)] = scope
            if scopes:
                result['additional_scopes'] = tuple(scopes[key] for key in sorted(scopes))
            return dict(result,service_id=name+'-owner')
        resource = value['storage']['privateStorage'] if name == 'private' else selected
        result.update(entity_id=resource['ledger']['entityId'],stream=resource['ledger']['stream'],
            jetstream_domain=selected['connection']['jetstreamDomain'])
        if name in ('card','allocation'):
            board = value['storage']['board']
            result.update(repository_id=board['repository']['repositoryId'])
            result.update({'card_key':board['cardKey']} if name == 'card' else
                {'counter_prefix':board['repository']['counterPrefix']})
        return result

    def read_storage_credentials(self, name):
        pin = self.storage_descriptor(name)['credentials']
        raw = _read_material(pin['path'],max_bytes=65536,return_bytes=True)
        if not raw or _digest(raw) != pin['sha256']:
            _fail()
        return raw

    def load_storage_credentials(self, name):
        from native_security.nats_credentials import (validate_storage_receiver,
            validate_private_storage_publisher, validate_board_publisher)
        selected = self.storage_descriptor(name)['credentials']
        validator = (validate_storage_receiver if name in ('storage','outcome') else
            validate_private_storage_publisher if name == 'private' else validate_board_publisher)
        try:
            credential = validator(self.read_storage_credentials(name),
                account_public_key=selected['accountPublicKey'],**self.storage_policy_inputs(name))
            if credential.public_key != selected['userPublicKey']:
                _fail()
            return credential
        except (ValueError, TypeError):
            raise ContractError('application_service_credentials_unavailable') from None

    def storage_tls_options(self, name):
        connection = self.storage_descriptor(name)['connection']
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=connection['rootsPEM'])
        return {'servers':[connection['endpoint']],'tls':context,
            'tls_hostname':connection['serverName'],'tls_handshake_first':True}

    def load_storage_signing_seed(self, name):
        """Read a pinned receiver issuer key or the raw board transport seed."""
        value = self.policy
        selected = (self.storage_descriptor(name)['issuer'] if name in ('storage','outcome')
            else value['storage']['board']['phaseAuthority'] if name == 'phase' else None)
        if selected is None:
            _fail()
        pin = selected['keyFile']
        raw = _read_material(pin['path'],return_bytes=True)
        if _digest(raw) != pin['sha256']:
            _fail()
        if name == 'phase':
            seed = raw
        else:
            key = strict_loads(raw)
            validate('application-service-key',key)
            expected = {'serviceId':name+'-owner','hubId':value['kernelScope']['hubId'],
                'profileId':value['kernelScope']['profileId'],'authorityId':value['authorityId'],
                'issuerRef':selected['issuerRef']}
            if any(key[k] != v for k,v in expected.items()):
                _fail()
            seed = base64.b64decode(key['seed'],validate=True)
        if (len(seed) != 32 or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
                != selected['publicKey']):
            _fail()
        return seed

    def check_storage_identity_source(self, identity):
        """Use the selected service's exact retained source and ingress signer."""
        from .service import IdentityService
        if not isinstance(identity,IdentityService):
            _fail()
        authority, ingress = identity.reader, identity.ingress
        value = self.policy
        if (not isinstance(authority,LedgerAuthorityReader) or ingress._reader is not authority
                or (authority._hub,authority._profile,authority._entity,authority._organization) !=
                    (value['kernelScope']['hubId'],value['kernelScope']['profileId'],
                     value['authorityId'],value['organizationId'])):
            _fail()
        self._task_identity_source(authority,ingress)
        return authority, ingress

    async def check_storage_authority(self, identity):
        """Check current startup authority without creating a business operation.

        Native generation and namespace admission remain per-call requirements;
        starting the owner services does not activate a future plugin generation.
        """
        from .authority import _active, _indexes, _key
        authority, _ = self.check_storage_identity_source(identity)
        snapshot = await authority.current()
        self.check_storage_identity_source(identity)
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'],record['ownerHubId'])
        now = datetime.now(timezone.utc)
        storage = self.policy['storage']

        def current(collection, reference):
            item = index[collection].get(_key(reference))
            if item is None or not _active(item,now):
                _fail()
            return item

        ingress_ref = self.service('identity')['issuer']['issuerRef']
        ingress_issuer = current('issuers',ingress_ref)
        if current('identities',ingress_issuer['identityRef'])['kind'] != 'service':
            _fail()
        for entry in storage['receivers'].values():
            signer = current('issuers',entry['issuer']['issuerRef'])
            principal = current('identities',entry['serviceIdentityRef'])
            if (principal['kind'] != 'service' or signer['identityRef'] != principal['ref']
                    or signer['instanceId'] != entry['serviceInstanceId']
                    or signer['publicKey'] != entry['issuer']['publicKey']
                    or entry['requestSigningKeyRef'] != ingress_ref):
                _fail()
        for name in ('messages', 'knowledge', 'code', 'work'):
            if name not in storage:
                continue
            for channel in storage[name]['channels']:
                channel_scope = (_work_channel_projection(storage, storage[name], channel)[1]
                    if name == 'work' else storage['scope'])
                if current('identities', channel['pluginIdentityRef'])['kind'] != 'plugin':
                    _fail()
                for actor in channel['actors']:
                    principal = current('identities', actor['identityRef'])
                    transport = current('transports', actor['transportRef'])
                    if transport['identityRef'] != actor['identityRef']:
                        _fail()
                    if name == 'work' and (principal['kind'] not in ('human', 'device')
                            or transport['issuerRef'] != ingress_ref
                            or not any(_active(m, now) and m['identityRef'] == principal['ref']
                                and m['scope'] == channel_scope for m in index['memberships'].values())):
                        _fail()
                for actor in channel.get('legacyActors', ()):
                    principal = current('identities', actor['identityRef'])
                    transport = current('transports', actor['transportRef'])
                    if (transport['identityRef'] != actor['identityRef'] or transport['issuerRef'] != ingress_ref
                            or transport['method'] != 'nats-credential-mapping'
                            or (actor['caller'] == 'federation') != (principal['kind'] == 'service')
                            or principal['kind'] not in ('human', 'device', 'service')
                            or not any(_active(m, now) and m['identityRef'] == principal['ref']
                                and m['scope'] == channel_scope for m in index['memberships'].values())):
                        _fail()
                    for contract, reference in actor['grants'].items():
                        grant = current('grants', reference)
                        matching = [g for g in index['grants'].values() if _active(g, now)
                            and g['callerRef'] == principal['ref'] and g['actorRef'] == principal['ref']
                            and g['scope'] == channel_scope and g['contractId'] == contract
                            and g['resourceId'] == channel['resourceRef']['id']]
                        if (grant not in matching or grant['decision'] != 'allowed'
                                or grant['delegationRef'] is not None or any(g['decision'] == 'denied' for g in matching)
                                or contract in ('federation-message-approve', 'federation-knowledge-approve', 'federation-code-approve')
                                    and principal['kind'] != 'human'):
                            _fail()
                        if name == 'work':
                            from .authority import WORK_OPERATOR_COMMANDS
                            if contract in WORK_OPERATOR_COMMANDS and principal['kind'] != 'human':
                                _fail()
        if self.policy.get('coreWorkTransport') is not None:
            from .core_work_transport import check_authority
            for route in self.policy['coreWorkTransport']['routes']:
                for contract in route['peer']['grantRefs']:
                    await check_authority(self, identity, route_id=route['routeId'],
                        contract=contract, snapshot=snapshot)
                if 'publisher' in route:
                    for contract in route['publisher']['grantRefs']:
                        await check_authority(self, identity, route_id=route['routeId'],
                            contract=contract, publisher=True, snapshot=snapshot)
        if 'board' in storage:
            board = storage['board']; selected = board['phaseAuthority']
            actor = current('identities',selected['serviceIdentityRef'])
            transport = current('transports',selected['transportRef'])
            scope = storage['scope']
            if (actor['kind'] != 'service' or transport['identityRef'] != actor['ref']
                    or transport['issuerRef'] != ingress_ref or transport['publicKey'] != selected['publicKey']
                    or not any(_active(m,now) and m['identityRef'] == actor['ref'] and m['scope'] == scope
                        for m in index['memberships'].values())):
                _fail()
            for name, publisher in (('cardGrants','cardPublisher'),('allocationGrants','allocationPublisher')):
                for contract, reference in selected[name].items():
                    grant = current('grants',reference)
                    matching = [g for g in index['grants'].values() if _active(g,now)
                        and g['callerRef'] == actor['ref'] and g['actorRef'] == actor['ref']
                        and g['scope'] == scope and g['contractId'] == contract
                        and g['resourceId'] == board[publisher]['ledger']['entityId']]
                    if (grant not in matching or grant['decision'] != 'allowed'
                            or grant['delegationRef'] is not None or any(g['decision'] == 'denied' for g in matching)):
                        _fail()
        return snapshot

    def read_credential_bytes(self, role):
        """Read the exact selected bytes; the host still verifies JWT permissions."""
        pin = self.service(role)['credentials']
        raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
        if not raw or _digest(raw) != pin['sha256']:
            _fail()
        return raw

    def service_policy_inputs(self, role):
        """Derive receiving-service permissions from the protected selection only."""
        from native_security.nats_credentials import service_policy, CredentialError
        service, value = self.service(role), self.policy
        ledger = service['ledger']
        inputs = dict(role=role, hub_id=value['kernelScope']['hubId'], entity_id=ledger['entityId'],
            scope=ledger['scope'], stream=ledger['stream'], reply_prefix=service['credentials']['replyPrefix'],
            jetstream_domain=service['connection']['jetstreamDomain'])
        if role in ('definitions', 'integration'):
            inputs['artifact_bucket'] = service['artifacts']['bucket']
        if role == 'task' and 'artifacts' in service:
            inputs['artifact_bucket'] = service['artifacts']['bucket']
        try:
            service_policy(**inputs)
        except CredentialError:
            raise ContractError('application_service_credentials_unavailable') from None
        return inputs

    def integration_routing_policy_inputs(self, *, additional_streams=()):
        """Derive the broker route for dynamic effects from enrolled stream names.

        This changes transport reach only. Each command still needs its current
        product grant and approval, and each effect needs a separately enrolled
        exact owner service supplied to the router.
        """
        if type(additional_streams) not in (tuple, list):
            _fail()
        inputs = self.service_policy_inputs('integration')
        inputs.update(integration_routing=True,
                      additional_streams=tuple(additional_streams))
        from native_security.nats_credentials import service_policy, CredentialError
        try:
            service_policy(**inputs)
        except CredentialError:
            raise ContractError('application_service_credentials_unavailable') from None
        return inputs

    def load_service_credentials(self, role, *, protected_host_account):
        """Require JWT-only service credentials, distinct from named-password HOST."""
        from native_security.nats_credentials import validate_service, CredentialError
        selected = self.service(role)['credentials']
        try:
            validate_protected_host_account(protected_host_account)
            credential = validate_service(self.read_credential_bytes(role),
                account_public_key=selected['accountPublicKey'], **self.service_policy_inputs(role))
            if credential.public_key != selected['userPublicKey']:
                _fail()
            return credential
        except (CredentialError, ValueError, TypeError):
            raise ContractError('application_service_credentials_unavailable') from None

    def load_integration_router_credentials(self, *, protected_host_account,
                                            additional_streams=()):
        """Validate an enrolled project router credential with exact stream API access."""
        from native_security.nats_credentials import validate_service, CredentialError
        selected = self.service('integration')['credentials']
        try:
            validate_protected_host_account(protected_host_account)
            credential = validate_service(self.read_credential_bytes('integration'),
                account_public_key=selected['accountPublicKey'],
                **self.integration_routing_policy_inputs(
                    additional_streams=additional_streams))
            if credential.public_key != selected['userPublicKey']:
                _fail()
            return credential
        except (CredentialError, ValueError, TypeError):
            raise ContractError('application_service_credentials_unavailable') from None

    def tls_options(self, role):
        """Explicit TLS inputs; the host factory must also enforce the leaf pin."""
        connection = self.service(role)['connection']
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=connection['rootsPEM'])
        return {'servers': [connection['endpoint']], 'tls': context,
                'tls_hostname': connection['serverName'], 'tls_handshake_first': True}

    def binding(self, role):
        value, ledger = self.policy, self.service(role)['ledger']
        domain, kind = {'identity': ('identity', 'identity-authority'),
                        'definitions': ('definitions', 'definition-catalog'),
                        'integration': ('integrations', 'effect'),
                        'configuration': ('configuration', 'configuration'), 'task': ('task', 'task'),
                        'orchestration': ('orchestration-operations', 'attempt'),
                        'policy': ('policy-evaluations', 'policy-evaluation')}[role]
        return OwnerBinding(value['kernelScope']['hubId'], domain, ledger['entityId'], kind,
                            canonical_bytes(ledger['scope']))

    def stream_identity(self, role):
        value = self.service(role)['ledger']['streamIdentity']
        return StreamIdentity(datetime.fromisoformat(value['created']), value['minimumSequence'])

    def retention(self, role):
        value = self.service(role)['ledger']['retention']
        return Retention(value['maxBytes'], value['reserveBytes'], value['replicas'])

    def load_signing_seed(self, role):
        value, service = self.policy, self.service(role)
        pin = service['issuer']['keyFile']
        raw = _read_material(pin['path'], return_bytes=True)
        if _digest(raw) != pin['sha256']:
            _fail()
        key = strict_loads(raw)
        validate('application-service-key', key)
        service_id = {'identity': 'identity-owner', 'definitions': 'definition-owner',
                      'integration': 'integration-owner', 'configuration': 'configuration-owner',
                      'task': 'task-owner', 'orchestration': 'orchestration-owner', 'policy': 'policy-owner'}[role]
        if any(key[k] != expected for k, expected in {
                'serviceId': service_id, 'hubId': value['kernelScope']['hubId'],
                'profileId': value['kernelScope']['profileId'], 'authorityId': value['authorityId'],
                'issuerRef': service['issuer']['issuerRef']}.items()):
            _fail()
        seed = base64.b64decode(key['seed'], validate=True)
        self._check_seed(role, seed)
        return seed

    def _check_seed(self, role, seed):
        if type(seed) is not bytes or len(seed) != 32:
            _fail()
        public = base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
        if public != self.service(role)['issuer']['publicKey']:
            _fail()

    def load_orchestration_phase_seed(self):
        """Load the separate service transport key used only for owner phases."""
        selected = self.service('orchestration')['phaseAuthority']
        raw = _read_material(selected['keyFile']['path'], return_bytes=True)
        if (_digest(raw) != selected['keyFile']['sha256'] or len(raw) != 32
                or base64.urlsafe_b64encode(bytes(SigningKey(raw).verify_key)).decode().rstrip('=')
                    != selected['publicKey']):
            _fail()
        return raw

    def check_orchestration_identity_source(self, identity):
        """Use the selected identity reader and ingress for orchestration."""
        from .service import IdentityService
        if not isinstance(identity, IdentityService):
            _fail()
        authority, ingress = identity.reader, identity.ingress
        value = self.policy
        if (not isinstance(authority, LedgerAuthorityReader) or ingress._reader is not authority
                or (authority._hub, authority._profile, authority._entity,
                    authority._organization) !=
                    (value['kernelScope']['hubId'], value['kernelScope']['profileId'],
                     value['authorityId'], value['organizationId'])):
            _fail()
        self._task_identity_source(authority, ingress)
        return authority, ingress

    async def check_orchestration_authority(self, identity):
        """Require the current service identity, transport and exact phase grants."""
        from .authority import _active, _indexes, _key
        authority, _ = self.check_orchestration_identity_source(identity)
        snapshot = await authority.current()
        self.check_orchestration_identity_source(identity)
        record = strict_loads(snapshot.record)
        index = _indexes(record['state'], record['ownerHubId'])
        now = datetime.now(timezone.utc)
        selected = self.service('orchestration')
        phase = selected['phaseAuthority']

        def current(collection, reference):
            item = index[collection].get(_key(reference))
            if item is None or not _active(item, now):
                _fail()
            return item

        actor = current('identities', selected['serviceIdentityRef'])
        issuer = current('issuers', selected['issuer']['issuerRef'])
        transport = current('transports', phase['transportRef'])
        ingress_ref = self.service('identity')['issuer']['issuerRef']
        if (actor['kind'] != 'service' or issuer['identityRef'] != actor['ref']
                or issuer['publicKey'] != selected['issuer']['publicKey']
                or transport['identityRef'] != actor['ref']
                or transport['issuerRef'] != ingress_ref
                or transport['publicKey'] != phase['publicKey']
                or not any(_active(m, now) and m['identityRef'] == actor['ref']
                           and m['scope'] == selected['scope']
                           for m in index['memberships'].values())):
            _fail()
        for contract, reference in phase['grants'].items():
            grant = current('grants', reference)
            matching = [candidate for candidate in index['grants'].values()
                if _active(candidate, now) and candidate['callerRef'] == actor['ref']
                and candidate['actorRef'] == actor['ref']
                and candidate['scope'] == selected['scope']
                and candidate['contractId'] == contract
                and candidate['resourceId'] == selected['resourceRef']['id']]
            if (grant not in matching or grant['decision'] != 'allowed'
                    or grant['delegationRef'] is not None
                    or any(candidate['decision'] == 'denied' for candidate in matching)):
                _fail()
        return snapshot

    def load_configuration_schemas(self):
        resources, total = {}, 0
        for name, pin in self.service('configuration')['schemaResources'].items():
            raw = _read_material(pin['path'], max_bytes=262144, return_bytes=True)
            total += len(raw)
            if not raw or total > 262144 or _digest(raw) != pin['sha256']:
                _fail()
            resources[name] = raw
        return resources

    def configuration_event_producer(self, *, authority, signing_seed):
        from .configuration_events import ConfigurationEventProducer
        self._check_seed('configuration', signing_seed)
        value, service = self.policy, self.service('configuration')
        selected = service['producer']
        seed = _read_material(selected['keyFile']['path'], max_bytes=32, return_bytes=True)
        if (len(seed) != 32 or _digest(seed) != selected['keyFile']['sha256']
                or base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=') != selected['publicKey']):
            _fail()
        return ConfigurationEventProducer(authority,hub_id=value['kernelScope']['hubId'],
            profile_id=value['kernelScope']['profileId'],authority_id=value['authorityId'],
            configuration_id=service['ledger']['entityId'],scope=service['ledger']['scope'],
            identity_ref=selected['identityRef'],transport_ref=selected['transportRef'],grant_ref=selected['grantRef'],
            transport_seed=seed,issuer_ref=service['issuer']['issuerRef'],signing_seed=signing_seed)

    def configuration_kwargs(self, *, authority, history, signing_seed, checkpoint_host, backup_host):
        """Resolve pinned schema bytes and validate the host's borrowed resources."""
        from state_owner.checkpoint_host import CheckpointHost
        value, service = self.policy, self.service('configuration')
        ledger, backup = service['ledger'], service['backup']
        result = self._kwargs('configuration', history=history,
            checkpoint_committed=checkpoint_host.committed if isinstance(checkpoint_host, CheckpointHost) else None,
            signing_seed=signing_seed)
        if (not isinstance(authority, LedgerAuthorityReader)
                or (authority._hub, authority._entity, authority._profile, authority._organization) !=
                   (value['kernelScope']['hubId'], value['authorityId'], value['kernelScope']['profileId'], value['organizationId'])
                or not isinstance(checkpoint_host, CheckpointHost)
                or checkpoint_host.binding != self.binding('configuration')
                or checkpoint_host.stream != ledger['stream']
                or checkpoint_host.stream_identity != self.stream_identity('configuration')
                or str(checkpoint_host.checkpoint_prefix) != ledger['checkpoint']['path']
                or checkpoint_host.commit_ref != ledger['checkpoint']['commitRef']
                or not isinstance(backup_host, BackupHost)
                or backup_host.binding != self.binding('configuration')
                or backup_host.stream_identity != self.stream_identity('configuration')
                or tuple(map(str, backup_host._roots)) != tuple(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'))
                or backup_host._destination_id != backup['destinationId']):
            _fail()
        result.pop('checkpoint_path')
        result.pop('checkpoint_committed')
        return dict(result, authority=authority, binding=self.binding('configuration'), owner=service['owner'],
            schema_ref=service['schemaRef'], schema_resources=self.load_configuration_schemas(),
            reply_prefix=service['requesterReplyPrefix'], checkpoint_host=checkpoint_host,
            event_producer=self.configuration_event_producer(authority=authority, signing_seed=signing_seed),
            event_account_public_key=service['credentials']['accountPublicKey'],
            event_jetstream_domain=service['connection']['jetstreamDomain'],
            backup_host=backup_host, backup_key_id=backup['keyId'])

    def task_kwargs(self, *, authority, ingress, history, signing_seed, checkpoint_host, backup_host, artifacts=None):
        """Bind the task host to shared identity and selected durable resources."""
        from state_owner.checkpoint_host import CheckpointHost
        from .ingress import EnrolledIngress
        value, service = self.policy, self.service('task')
        ledger, backup = service['ledger'], service['backup']
        result = self._kwargs('task', history=history,
            checkpoint_committed=checkpoint_host.committed if isinstance(checkpoint_host, CheckpointHost) else None,
            signing_seed=signing_seed)
        if (type(authority) is not LedgerAuthorityReader
                or type(ingress) is not EnrolledIngress or ingress._reader is not authority
                or (authority._hub, authority._entity, authority._profile, authority._organization) !=
                   (value['kernelScope']['hubId'], value['authorityId'], value['kernelScope']['profileId'], value['organizationId'])
                or not isinstance(checkpoint_host, CheckpointHost)
                or checkpoint_host.binding != self.binding('task')
                or checkpoint_host.stream != ledger['stream']
                or checkpoint_host.stream_identity != self.stream_identity('task')
                or str(checkpoint_host.checkpoint_prefix) != ledger['checkpoint']['path']
                or checkpoint_host.commit_ref != ledger['checkpoint']['commitRef']
                or not isinstance(backup_host, BackupHost)
                or backup_host.binding != self.binding('task')
                or backup_host.stream_identity != self.stream_identity('task')
                or tuple(map(str, backup_host._roots)) != tuple(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'))
                or backup_host._destination_id != backup['destinationId']):
            _fail()
        self._task_identity_source(authority, ingress)
        result.pop('checkpoint_path')
        result.pop('checkpoint_committed')
        selected_artifacts = service.get('artifacts')
        if selected_artifacts is None:
            if artifacts is not None:
                _fail()
        else:
            if (type(artifacts) is not OwnerArtifacts
                    or artifacts._bucket != selected_artifacts['bucket']
                    or artifacts._owner != value['kernelScope']['hubId']
                    or artifacts._ref != selected_artifacts['storeRef']
                    or artifacts._max_bytes != selected_artifacts['maxBytes']
                    or getattr(artifacts._store, '_name', None) != selected_artifacts['bucket']):
                _fail()
            reader = selected_artifacts['reader']
            result.update(artifacts=artifacts, artifact_reader={
                'transport_ref': reader['transportRef'], 'grant_ref': reader['grantRef'],
                'approvals_by_operation': reader.get('approvalsByOperation', {})})
        return dict(result, authority=authority, ingress=ingress, binding=self.binding('task'),
            service_identity_ref=service['serviceIdentityRef'], service_instance_id=service['serviceInstanceId'],
            requester_reply_prefix=service['requesterReplyPrefix'],
            account_public_key=service['credentials']['accountPublicKey'],
            checkpoint_host=checkpoint_host, backup_host=backup_host, backup_key_id=backup['keyId'])

    def _task_identity_source(self, authority, ingress):
        """Match the borrowed reader's durable source and ingress signer to enrollment."""
        from state_owner.ledger import OwnerLedger, owner_subject
        selected = self.service('identity')
        ledger = authority._ledger
        source = self.stream_identity('identity')
        binding = self.binding('identity')
        if (type(ledger) is not OwnerLedger or ledger._binding != binding
                or ledger._stream != selected['ledger']['stream']
                or ledger._subject != owner_subject(binding)
                or ledger._identity.created != source.created
                or ledger._identity.minimum_sequence < source.minimum_sequence
                or not isinstance(ledger._history, OwnerHistory)):
            _fail()
        history = ledger._history
        pin = selected['ledger']['history']
        if (history.binding != binding or history.source_identity.created != source.created
                or history.source_identity.minimum_sequence < source.minimum_sequence
                or ledger._minimum_sequence < max(source.minimum_sequence,
                    ledger._identity.minimum_sequence, history.source_identity.minimum_sequence)
                or str(history._path) != pin['path']
                or history._max_records != pin['maxRecords'] or history._max_bytes != pin['maxBytes']
                or ingress._issuer_ref != canonical_bytes(selected['issuer']['issuerRef'])):
            _fail()
        self._check_seed('identity', ingress._seed)

    def _kwargs(self, role, *, history, checkpoint_committed, signing_seed):
        self._check_seed(role, signing_seed)
        service = self.service(role)
        ledger = service['ledger']
        if (not isinstance(history, OwnerHistory) or history.binding != self.binding(role) or history.source_identity != self.stream_identity(role)
                or str(history._path) != ledger['history']['path']
                or history._max_records != ledger['history']['maxRecords']
                or history._max_bytes != ledger['history']['maxBytes']
                or not callable(checkpoint_committed)):
            _fail()
        return dict(stream=ledger['stream'], stream_identity=self.stream_identity(role),
            retention=self.retention(role), history=history, issuer_ref=service['issuer']['issuerRef'],
            signing_seed=signing_seed, checkpoint_path=Path(ledger['checkpoint']['path']),
            checkpoint_committed=checkpoint_committed, jetstream_domain=service['connection']['jetstreamDomain'])

    def identity_kwargs(self, *, history, checkpoint_committed, signing_seed, backup_host):
        """Inputs to IdentityService after the host resolves the selected resources."""
        result = self._kwargs('identity', history=history, checkpoint_committed=checkpoint_committed, signing_seed=signing_seed)
        value, backup = self.policy, self.service('identity')['backup']
        if (not isinstance(backup_host, BackupHost) or backup_host.binding != self.binding('identity') or backup_host.stream_identity != self.stream_identity('identity')
                or tuple(map(str, backup_host._roots)) != tuple(backup[k] for k in ('backupDirectory', 'inventoryDirectory', 'keyDirectory'))
                or backup_host._destination_id != backup['destinationId']):
            _fail()
        return dict(result, hub_id=value['kernelScope']['hubId'], entity_id=value['authorityId'],
            profile_id=value['kernelScope']['profileId'], organization_id=value['organizationId'],
            backup_host=backup_host, backup_key_id=backup['keyId'])

    def definition_kwargs(self, *, history, checkpoint_committed, signing_seed, authority, artifacts, scope):
        """Inputs to DefinitionCommandService.from_enrolled_host; no resources are opened."""
        result = self._kwargs('definitions', history=history, checkpoint_committed=checkpoint_committed, signing_seed=signing_seed)
        value, service = self.policy, self.service('definitions')
        if (not isinstance(authority, LedgerAuthorityReader) or (authority._hub, authority._entity, authority._profile, authority._organization) !=
                (value['kernelScope']['hubId'], value['authorityId'], value['kernelScope']['profileId'], value['organizationId'])):
            _fail()
        selected = service['artifacts']
        if (not isinstance(artifacts, OwnerArtifacts) or artifacts._bucket != selected['bucket'] or artifacts._ref != selected['storeRef']
                or artifacts._max_bytes != selected['maxBytes'] or artifacts._owner != value['kernelScope']['hubId']
                or str(scope.project_root) != service['directories']['projectRoot']
                or str(scope.home) != service['directories']['home'] or str(scope.global_root) != service['directories']['globalRoot']
                or scope.project_id != service['ledger']['scope']['projectId']):
            _fail()
        return dict(result, binding=self.binding('definitions'), authority=authority, artifacts=artifacts, scope=scope)

    def orchestration_kwargs(self, *, authority, ingress, history, signing_seed,
                             phase_signing_seed):
        """Bind the orchestration service to one selected retained aggregate."""
        from .ingress import EnrolledIngress
        selected, value = self.service('orchestration'), self.policy
        ledger = selected['ledger']
        self._check_seed('orchestration', signing_seed)
        phase = selected['phaseAuthority']
        if type(phase_signing_seed) is not bytes or len(phase_signing_seed) != 32:
            _fail()
        phase_public = base64.urlsafe_b64encode(
            bytes(SigningKey(phase_signing_seed).verify_key)).decode().rstrip('=')
        if (not isinstance(authority, LedgerAuthorityReader)
                or not isinstance(ingress, EnrolledIngress)
                or ingress._reader is not authority
                or (authority._hub, authority._entity, authority._profile,
                    authority._organization) !=
                    (value['kernelScope']['hubId'], value['authorityId'],
                     value['kernelScope']['profileId'], value['organizationId'])
                or not isinstance(history, OwnerHistory)
                or history.binding != self.binding('orchestration')
                or history.source_identity != self.stream_identity('orchestration')
                or str(history._path) != ledger['history']['path']
                or history._max_records != ledger['history']['maxRecords']
                or history._max_bytes != ledger['history']['maxBytes']
                or phase_public != phase['publicKey']):
            _fail()
        self._task_identity_source(authority, ingress)
        return {'policy_binding': self.orchestration_policy_binding(),
            'authority': authority, 'ingress': ingress,
            'binding': self.binding('orchestration'),
            'stream': ledger['stream'],
            'stream_identity': self.stream_identity('orchestration'),
            'retention': self.retention('orchestration'), 'history': history,
            'issuer_ref': selected['issuer']['issuerRef'],
            'signing_seed': signing_seed,
            'owner_service_identity_ref': selected['serviceIdentityRef'],
            'owner_transport_ref': phase['transportRef'],
            'phase_grants': phase['grants'],
            'phase_signing_seed': phase_signing_seed,
            'jetstream_domain': selected['connection']['jetstreamDomain']}


    def integration_kwargs(self, *, authority, history, artifacts, credentials,
                           signing_seed, checkpoint_committed):
        """Inputs to IntegrationService.from_enrolled_host after resource admission."""
        from integration_owner.credentials import AtlassianCredentialResolver
        from integration_owner.github_worker import GithubCredentialResolver
        result = self._kwargs('integration', history=history,
            checkpoint_committed=checkpoint_committed, signing_seed=signing_seed)
        selected, value = self.service('integration'), self.policy
        if (not isinstance(authority, LedgerAuthorityReader)
                or (authority._hub, authority._entity, authority._profile, authority._organization) !=
                   (value['kernelScope']['hubId'], value['authorityId'], value['kernelScope']['profileId'], value['organizationId'])
                or not isinstance(artifacts, OwnerArtifacts)
                or artifacts._owner != value['kernelScope']['hubId']
                or artifacts._ref != selected['artifacts']['storeRef']
                or artifacts._bucket != selected['artifacts']['bucket']
                or artifacts._max_bytes != selected['artifacts']['maxBytes']):
            _fail()
        if selected['provider'] in ('jira', 'confluence'):
            if (type(credentials) is not AtlassianCredentialResolver
                    or credentials._binding[0] != canonical_bytes(selected['credentialRef'])
                    or credentials._binding[1] != selected['provider']):
                _fail()
        elif selected['provider'] == 'github' and selected['credentialEnrollment'] is not None:
            if (type(credentials) is not GithubCredentialResolver
                    or credentials._binding[0] != canonical_bytes(selected['credentialRef'])):
                _fail()
        elif credentials is not None:
            _fail()
        return dict(result, authority=authority, binding=self.binding('integration'),
                    provider=selected['provider'], credential_ref=selected['credentialRef'],
                    artifacts=artifacts, credentials=credentials)

    def integration_router_kwargs(self, *, authority, signing_seed,
                                  service_factory, artifacts, credentials):
        """Inputs for a dynamic project router; the factory supplies exact owners.

        The factory receives ``(binding, original_operation_id)`` and may be
        asynchronous so an admitted operation can run the explicit provisioner.
        """
        from integration_owner.credentials import AtlassianCredentialResolver
        from integration_owner.github_worker import GithubCredentialResolver
        selected, value = self.service('integration'), self.policy
        self._check_seed('integration', signing_seed)
        if (not isinstance(authority, LedgerAuthorityReader)
                or (authority._hub, authority._entity, authority._profile,
                    authority._organization) !=
                   (value['kernelScope']['hubId'], value['authorityId'],
                    value['kernelScope']['profileId'], value['organizationId'])
                or not callable(service_factory)
                or not isinstance(artifacts, OwnerArtifacts)
                or artifacts._owner != value['kernelScope']['hubId']
                or artifacts._ref != selected['artifacts']['storeRef']
                or artifacts._bucket != selected['artifacts']['bucket']
                or artifacts._max_bytes != selected['artifacts']['maxBytes']):
            _fail()
        if selected['provider'] in ('jira', 'confluence'):
            if (type(credentials) is not AtlassianCredentialResolver
                    or credentials._binding[0] != canonical_bytes(selected['credentialRef'])
                    or credentials._binding[1] != selected['provider']):
                _fail()
        elif selected['provider'] == 'github' and selected['credentialEnrollment'] is not None:
            if (type(credentials) is not GithubCredentialResolver
                    or credentials._binding[0] != canonical_bytes(selected['credentialRef'])):
                _fail()
        elif credentials is not None:
            _fail()
        return {'authority': authority, 'scope': selected['ledger']['scope'],
                'provider': selected['provider'],
                'credential_ref': selected['credentialRef'],
                'issuer_ref': selected['issuer']['issuerRef'],
                'signing_seed': signing_seed,
                'service_factory': service_factory, 'artifacts': artifacts,
                'credentials': credentials}

    def integration_effect_provisioner(self, jetstream, *, resource_directory,
            inventory_directory, credential_directory, backup_key_directory,
            backup_key_id, backup_destination_id, commit_ref, credential_issuer):
        """Build the explicit operator owner for new exact effect resources.

        The supplied JetStream handle and credential issuer are administrator
        dependencies.  This selection does not expose an account signing key or
        turn resource provisioning into a product grant.
        """
        from integration_owner.provisioning import IntegrationEffectProvisioner
        selected, value = self.service('integration'), self.policy
        for path in (resource_directory, inventory_directory,
                     credential_directory, backup_key_directory):
            _outside(str(path), value['workspaces'])
        routing = selected.get('routing')
        supplied = {'resourceDirectory': str(resource_directory),
            'inventoryDirectory': str(inventory_directory),
            'credentialDirectory': str(credential_directory),
            'backupKeyDirectory': str(backup_key_directory),
            'backupKeyId': backup_key_id,
            'backupDestinationId': backup_destination_id}
        if routing is not None and supplied != routing:
            _fail()
        return IntegrationEffectProvisioner(jetstream,
            hub_id=value['kernelScope']['hubId'], scope=selected['ledger']['scope'],
            base_stream=selected['ledger']['stream'],
            artifact_bucket=selected['artifacts']['bucket'],
            reply_prefix=selected['credentials']['replyPrefix'],
            jetstream_domain=selected['connection']['jetstreamDomain'],
            account_public_key=selected['credentials']['accountPublicKey'],
            retention=self.retention('integration'),
            max_history_records=selected['ledger']['history']['maxRecords'],
            max_history_bytes=selected['ledger']['history']['maxBytes'],
            resource_directory=resource_directory,
            inventory_directory=inventory_directory,
            credential_directory=credential_directory,
            backup_key_directory=backup_key_directory,
            backup_key_id=backup_key_id,
            backup_destination_id=backup_destination_id,
            commit_ref=commit_ref, credential_issuer=credential_issuer)

    def integration_effect_inventory(self):
        """Open the operator-preprovisioned routed effect inventory read only."""
        from integration_owner.provisioning import IntegrationEffectInventory
        selected, value = self.service('integration'), self.policy
        routing = selected.get('routing')
        if routing is None:
            _fail()
        return IntegrationEffectInventory(
            hub_id=value['kernelScope']['hubId'], scope=selected['ledger']['scope'],
            base_stream=selected['ledger']['stream'],
            artifact_bucket=selected['artifacts']['bucket'],
            reply_prefix=selected['credentials']['replyPrefix'],
            jetstream_domain=selected['connection']['jetstreamDomain'],
            account_public_key=selected['credentials']['accountPublicKey'],
            retention=self.retention('integration'),
            max_history_records=selected['ledger']['history']['maxRecords'],
            max_history_bytes=selected['ledger']['history']['maxBytes'],
            resource_directory=routing['resourceDirectory'],
            inventory_directory=routing['inventoryDirectory'],
            credential_directory=routing['credentialDirectory'],
            backup_key_directory=routing['backupKeyDirectory'],
            backup_key_id=routing['backupKeyId'],
            backup_destination_id=routing['backupDestinationId'],
            commit_ref=selected['ledger']['checkpoint']['commitRef'])

    def read_integration_enrollment(self):
        """Return pinned enrollment bytes for AMUX-66's durable loader, never repin."""
        pin = self.service('integration')['credentialEnrollment']
        if pin is None:
            _fail()
        raw = _read_material(pin['path'], max_bytes=65536, return_bytes=True)
        if not raw or _digest(raw) != pin['sha256']:
            _fail()
        return raw


def write_application_service_selection(path, selection):
    _check(selection)
    _outside(str(path), selection['workspaces'])
    raw = canonical_bytes(selection)
    _write_material(path, selection, max_bytes=65536)
    return ApplicationHostSelectionReceipt(str(path), _digest(raw))


def load_application_service_selection(path, *, expected_digest, host_policy, owner_uid,
                                       workspaces, kernel_scope, protected_host_account):
    """Match host pins and require the native-admitted password HOST model."""
    validate_protected_host_account(protected_host_account)
    _outside(str(path), workspaces)
    raw = _read_material(path, max_bytes=65536, return_bytes=True)
    if _digest(raw) != expected_digest:
        _fail()
    value = strict_loads(raw)
    _check(value)
    if any(value[k] != expected for k, expected in {'hostPolicy': host_policy, 'ownerUid': owner_uid,
            'workspaces': list(workspaces), 'kernelScope': kernel_scope}.items()):
        _fail()
    return ApplicationServiceSelection(canonical_bytes(value))


def provision_application_service_issuer(path, *, service_id, profile_id, authority_id,
        instance_id, identity, issuer_ref, issued_at, expires_at):
    """Create a separate issuer key and return its proof-bearing enrollment payload.

    Setup must submit the payload through the authorized identity owner. This
    creates no broker credentials, membership, business grants or owner streams.
    """
    if identity.get('kind') != 'service' or identity.get('status') != 'active':
        _fail()
    seed = secrets.token_bytes(32)
    key = {'schemaVersion': '1.0.0', 'purpose': 'agentmux-application-service-key-v1',
        'serviceId': service_id, 'hubId': identity['ref']['ownerHubId'], 'profileId': profile_id,
        'authorityId': authority_id, 'issuerRef': issuer_ref, 'seed': base64.b64encode(seed).decode()}
    validate('application-service-key', key)
    if (issuer_ref['ownerHubId'] != key['hubId'] or issuer_ref['revision'] != 1
            or identity['ref']['revision'] != 1
            or datetime.fromisoformat(issued_at) >= datetime.fromisoformat(expires_at)):
        _fail()
    public = base64.urlsafe_b64encode(bytes(SigningKey(seed).verify_key)).decode().rstrip('=')
    record = {'ref': issuer_ref, 'identityRef': identity['ref'], 'status': 'active',
        'instanceId': instance_id, 'publicKey': public, 'issuedAt': issued_at, 'expiresAt': expires_at}
    claims = {'purpose': 'agentmux-enrollment-possession-v1', 'profileId': profile_id,
        'authorityId': authority_id, 'credential': record}
    payload = {'authorityId': authority_id, 'identity': identity,
        'issuers': [{'record': record, 'proof': sign_claims(claims, seed)}], 'transports': []}
    validate('identity-enroll', payload)
    _write_material(path, key)
    return payload, ApplicationHostSelectionReceipt(str(path), _digest(canonical_bytes(key)))
