"""Write a new profile's private owner and setup requests (AMUX-728).

Installed entry: ``application-requests --client-installation ID
--foundation-selection PATH --foundation-selection-sha256 DIGEST
--repository-root PATH --principal NAME --local-node NAME --message-peer NAME
--organization ID --output DIR``.

It replaces the hand-written step before ``prepare-owner-profile`` and
``application-enroll``. Everything else in the two requests is derived:

* fresh profile, instance and owner Hub IDs and the broker names;
* the release and runtime of the client's installed foundation, checked
  against the selection the installer used (the release public key is only
  in that selection);
* the Docker context, engine and versions as Docker reports them now
  (``prepare-owner-profile --apply`` checks them again);
* a free private broker port that no other profile or runtime here keeps.

``DIR`` is created here and must not exist, so a rerun never changes requests
that were already reviewed. Both files are owner-private and written once.
Only paths, digests and the generated IDs reach stdout.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from identity.application_enrollment import _read_material
from identity.local_enrollment import (AGENTMUX, LEGACY_BROWSER_PORT, PRIVATE_PORTS, SCHEMA_VERSION, _DIGEST, _ID,
                                       _PEER, _REMOTE, _private_bytes, digest)

PROTECTED = Path('/Library/Application Support/Agentmux/Protected')
# Docker Desktop's own client first; the others are the usual links to it.
DOCKER_CANDIDATES = ('/Applications/Docker.app/Contents/Resources/bin/docker', '/opt/homebrew/bin/docker',
                     '/usr/local/bin/docker')
VALIDITY_DAYS = 365
BROKER_MEMORY_BYTES = 268435456
BROKER_FILE_BYTES = 1073741824
LIMITS = {'startupMilliseconds': 60000, 'probeMilliseconds': 5000, 'roleStartMilliseconds': 30000,
          'stopGraceMilliseconds': 10000, 'reapMilliseconds': 10000}
_INSTALLATION = re.compile(r'[0-9a-f]{64}')
_VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')
_CONTEXT = re.compile(r'[a-z0-9][a-z0-9_-]{0,62}')
_ENGINE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}')
_ARGUMENTS = ('--client-installation', '--foundation-selection', '--foundation-selection-sha256', '--repository-root',
              '--principal', '--local-node', '--message-peer', '--organization', '--output')


def _sha256(path):
    with open(path, 'rb') as file:
        return 'sha256:' + hashlib.sha256(file.read()).hexdigest()


def _installed_json(path):
    """Read protected public metadata: root-owned and not writable by others."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0, os.getuid()) or meta.st_mode & 0o022:
            raise ContractError('application_requests_installation_invalid')
        return strict_loads(os.read(fd, min(meta.st_size, 1 << 20) + 1))
    finally:
        os.close(fd)


def installed_release(protected, client_installation, selection):
    """The installed foundation's release, matched to the installer's selection."""
    try:
        manifest = _installed_json(protected / 'clients' / client_installation / 'client-manifest.json')
        foundation = manifest['foundationInstallationId']
        if not _INSTALLATION.fullmatch(str(foundation)):
            raise ValueError()
        directory = protected / 'releases' / foundation
        release, runtime = dict(selection['release']), selection['runtime']
        if (_sha256(directory / 'release-manifest.json') != release['releaseManifestDigest']
                or _sha256(directory / 'agentmux-runtime') != runtime['digest']
                or manifest['frontendDigest'] != runtime['digest']):
            raise ContractError('application_requests_release_mismatch')
    except ContractError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise ContractError('application_requests_installation_invalid') from None
    release['packageDirectory'] = str(directory)
    return release, {'path': str(directory / 'agentmux-runtime'), 'digest': runtime['digest']}


def _docker(executable, *arguments):
    environment = {key: value for key, value in os.environ.items() if not key.startswith('DOCKER_')}
    completed = subprocess.run([executable, *arguments], env=environment, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=10, check=True)
    return completed.stdout.decode('utf-8').strip()


def observe_docker(candidates=DOCKER_CANDIDATES):
    """The local Docker engine as it is now; nothing here grants authority."""
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            executable = candidate
            break
    else:
        raise ContractError('application_requests_docker_unavailable')
    try:
        context = _docker(executable, 'context', 'show')
        endpoint = _docker(executable, 'context', 'inspect', context, '--format', '{{.Endpoints.docker.Host}}')
        engine = json.loads(_docker(executable, '--context', context, 'info', '--format', '{{json .}}'))
        client = _docker(executable, '--context', context, 'version', '--format', '{{.Client.Version}}')
        compose = _docker(executable, '--context', context, 'compose', 'version', '--short').removeprefix('v')
    except (OSError, ValueError, subprocess.SubprocessError, UnicodeDecodeError):
        raise ContractError('application_requests_docker_unavailable') from None
    path = endpoint.removeprefix('unix://')
    if (not _CONTEXT.fullmatch(context) or not endpoint.startswith('unix:///') or os.path.normpath(path) != path
            or not isinstance(engine, dict) or not _ENGINE.fullmatch(str(engine.get('ID'))) or engine.get('OSType') != 'linux'
            or not all(_VERSION.fullmatch(str(v)) for v in (client, engine.get('ServerVersion'), compose))):
        raise ContractError('application_requests_docker_unsupported')
    return {'backend': 'native-unix', 'executable': executable, 'context': context, 'endpoint': endpoint,
            'engineId': engine['ID'], 'clientVersion': client, 'serverVersion': engine['ServerVersion'],
            'composeVersion': compose}


def retained_ports(agentmux):
    """Ports this user's runtime, enrolled services and prepared profiles keep."""
    ports = {LEGACY_BROWSER_PORT}
    try:
        ports.add(_read_material(agentmux / 'application-runtime' / 'inputs.json', max_bytes=65536)['port'])
    except (ContractError, OSError, KeyError, TypeError):
        pass
    for selection in agentmux.glob('application-enrollment/*/service-selection.json'):
        try:
            ports.add(_read_material(selection, max_bytes=1048576)['localBrowser']['port'])
        except (ContractError, OSError, KeyError, TypeError):
            continue
    for profile in agentmux.glob('profiles/*/profile.json'):
        try:
            ports.add(int(json.loads(profile.read_bytes())['natsEndpoint'].rsplit(':', 1)[1]))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    return ports


def broker_port(agentmux):
    reserved = retained_ports(agentmux)
    for _ in range(64):
        port = PRIVATE_PORTS[secrets.randbelow(len(PRIVATE_PORTS))]
        if port in reserved:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(('127.0.0.1', port))
            except OSError:
                continue
        return port
    raise ContractError('application_requests_port_unavailable')


def repository(root):
    """The repository's local name and normalized origin remote from .git/config."""
    try:
        config = (Path(root) / '.git' / 'config').read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        raise ContractError('application_requests_repository_invalid') from None
    section, url = None, None
    for line in config.splitlines():
        line = line.strip()
        if line.startswith('['):
            section = line
        elif section == '[remote "origin"]' and line.startswith('url') and '=' in line:
            url = line.split('=', 1)[1].strip()
    if url is None:
        raise ContractError('application_requests_repository_invalid')
    remote = re.sub(r'^(?:[a-z+]+://)?(?:[^@/]+@)?', '', url.lower()).replace(':', '/', 1)
    remote = remote.removesuffix('/').removesuffix('.git')
    local = re.sub(r'[^a-z0-9_]', '_', Path(root).name.lower())[:32]
    if not _REMOTE.fullmatch(remote) or not local:
        raise ContractError('application_requests_repository_invalid')
    return {'root': root, 'localName': local, 'normalizedRemote': remote}


def write_requests(*, client_installation, foundation_selection, foundation_sha256, repository_root, principal,
                   local_node, message_peer, organization, output, protected=PROTECTED, agentmux=AGENTMUX,
                   docker_candidates=DOCKER_CANDIDATES):
    output = Path(output)
    if (not _INSTALLATION.fullmatch(client_installation) or not _DIGEST.fullmatch(foundation_sha256)
            or not all(_PEER.fullmatch(v) for v in (principal, local_node, message_peer)) or principal == message_peer
            or not principal[0].isalpha() or not _ID.fullmatch(organization)
            or not all(os.path.isabs(p) and os.path.normpath(p) == p
                       for p in (foundation_selection, repository_root, str(output)))):
        raise ContractError('application_requests_arguments_invalid')
    if output.exists() or output.is_symlink():
        raise ContractError('application_requests_output_exists')
    raw = _read_material(foundation_selection, max_bytes=65536, return_bytes=True)
    if digest(raw) != foundation_sha256:
        raise ContractError('application_requests_selection_changed')
    release, runtime = installed_release(Path(protected), client_installation, strict_loads(raw))
    checkout = repository(repository_root)
    docker = observe_docker(docker_candidates)
    port = broker_port(Path(agentmux))
    profile = 'profile_' + secrets.token_hex(16)
    hub = 'hub_' + principal + '_' + secrets.token_hex(4)
    names = profile.removeprefix('profile_')[:12]
    owner = {'schemaVersion': SCHEMA_VERSION,
        'owner': {'schemaVersion': SCHEMA_VERSION, 'ownerUid': os.getuid(), 'principalId': principal,
            'authenticatedIdentityRef': {'id': principal, 'ownerHubId': hub, 'revision': 1},
            'scope': {'organizationId': organization, 'projectId': None, 'workspaceId': None},
            'instanceId': 'instance_' + secrets.token_hex(16), 'profileId': profile,
            'releaseFingerprint': release['releaseManifestDigest']},
        'context': {'environment': 'Local Development', 'project': checkout['localName']},
        'clientInstallationId': client_installation, 'approvedWorkspaceRoots': [repository_root],
        'release': release, 'runtimeExecutable': runtime, 'docker': docker, 'hostPort': port,
        'composeProject': 'agentmux-' + names, 'serverName': 'infra-' + names, 'domain': 'infra_' + names,
        'maxMemoryBytes': BROKER_MEMORY_BYTES, 'maxFileBytes': BROKER_FILE_BYTES, 'limits': dict(LIMITS)}
    output.mkdir(mode=0o700)
    owner_path, owner_raw = output / 'owner-request.json', canonical_bytes(owner)
    _private_bytes(owner_path, owner_raw)
    setup = {'schemaVersion': SCHEMA_VERSION, 'ownerRequest': {'path': str(owner_path), 'sha256': digest(owner_raw)},
             'projectId': checkout['localName'], 'repositories': [checkout], 'localPeer': principal,
             'localNode': local_node, 'messagePeer': message_peer, 'validityDays': VALIDITY_DAYS}
    setup_path, setup_raw = output / 'setup-request.json', canonical_bytes(setup)
    _private_bytes(setup_path, setup_raw)
    return {'profileId': profile, 'hubId': hub,
            'ownerRequest': {'path': str(owner_path), 'sha256': digest(owner_raw)},
            'setupRequest': {'path': str(setup_path), 'sha256': digest(setup_raw)}}


def _diagnostic(code):
    import sys
    sys.stderr.write(json.dumps({'schemaVersion': SCHEMA_VERSION, 'kind': 'application-requests-diagnostic',
                                 'code': code}) + '\n')
    return 1


def main(arguments):
    """Installed entry; see the module docstring. Only closed codes leave on failure."""
    import sys
    if len(arguments) != 2 * len(_ARGUMENTS) or tuple(arguments[0::2]) != _ARGUMENTS:
        return _diagnostic('application_requests_arguments_invalid')
    values = dict(zip(arguments[0::2], arguments[1::2]))
    try:
        result = write_requests(client_installation=values['--client-installation'],
            foundation_selection=values['--foundation-selection'],
            foundation_sha256=values['--foundation-selection-sha256'], repository_root=values['--repository-root'],
            principal=values['--principal'], local_node=values['--local-node'],
            message_peer=values['--message-peer'], organization=values['--organization'], output=values['--output'])
    except ContractError as error:
        code = str(error) if re.fullmatch(r'[a-z_]{1,96}', str(error)) else 'application_requests_failed'
        return _diagnostic(code)
    except Exception:
        return _diagnostic('application_requests_failed')
    sys.stdout.buffer.write(canonical_bytes({'schemaVersion': SCHEMA_VERSION, 'kind': 'application-requests-result',
                                             **result}) + b'\n')
    sys.stdout.buffer.flush()
    return 0
