"""Read-only standalone WSL transport diagnostic; no production deadline change."""
import hashlib
import http.client
import io
import json
import os
import selectors
import signal
import subprocess
import time

DOCKER = '/mnt/c/Users/RyanHelms/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe'
CONTEXT = 'desktop-linux'
ENDPOINT = 'npipe:////./pipe/dockerDesktopLinuxEngine'
ENGINE = 'e0f1f93d-abf1-44f2-b62a-5bfee21d2b5c'
VERSION = '29.8.0'
LIMIT = 1024 * 1024 + 16 * 1024
REQUEST = b'GET /info HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n'


def environment():
    for key, expected in [('DOCKER_HOST', ENDPOINT), ('DOCKER_CONTEXT', CONTEXT)]:
        if os.environ.get(key) not in (None, '', expected):
            raise ValueError('endpoint_selection_conflict')
    # Match the reviewed adapter's sanitation; do not print the inherited values.
    selected = {key: value for key, value in os.environ.items()
                if not key.upper().startswith('COMPOSE_')
                and key.upper() not in ('DOCKER_HOST', 'DOCKER_CONTEXT')}
    selected.update(COMPOSE_REMOVE_ORPHANS='0', COMPOSE_DISABLE_ENV_FILE='1')
    return selected


def query(arguments, request=None):
    start = time.monotonic()
    deadline = start + 12
    data = bytearray()
    process = subprocess.Popen([DOCKER, '--context', CONTEXT, *arguments],
        stdin=subprocess.PIPE if request else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=environment(), start_new_session=True)
    try:
        if request:
            process.stdin.write(request)
            # Keep stdin open until the response closes. A Windows named pipe
            # need not support the tunnel's half-close operation on stdin EOF.
            process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('standalone_transport_timeout')
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(data) + len(chunk) > LIMIT:
                        raise ValueError('bounded_response_exceeded')
                    else:
                        data.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('standalone_transport_timeout')
        code = process.wait(timeout=remaining)
        elapsed = round(time.monotonic() - start, 6)
        if code != 0:
            raise ValueError('owned_process_failed')
        return bytes(data), {'exitCode': code, 'seconds': elapsed,
                             'stdoutSha256': hashlib.sha256(data).hexdigest(),
                             'ownedProcessReaped': True}
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        if process.stdin is not None:
            process.stdin.close()
        process.stdout.close()
        data.clear()


class MemorySocket:
    def __init__(self, data):
        self.data = data

    def makefile(self, *_args):
        return io.BytesIO(self.data)


def main():
    stage = 'client-version'
    report = {'recordKind': 'read-only-wsl-docker-stdio-diagnostic',
              'phaseAccepted': False, 'productionDeadlineSeconds': 4,
              'standaloneDeadlineSeconds': 12, 'trials': [],
              'resourceMutations': False, 'fullInfoRetained': False,
              'stderrRetained': False}
    try:
        raw, metadata = query(['--version'])
        if not raw.decode('utf-8').startswith('Docker version ' + VERSION + ','):
            raise ValueError('client_version_mismatch')
        report['client'] = metadata | {'version': VERSION}
        for index in range(3):
            stage = 'context-endpoint'
            trial = {'trial': index + 1, 'status': 'failed'}
            report['trials'].append(trial)
            raw, metadata = query(['context', 'inspect', CONTEXT, '--format', '{{json .Endpoints.docker.Host}}'])
            if json.loads(raw) != ENDPOINT:
                raise ValueError('context_endpoint_mismatch')
            trial['context'] = metadata | {'expectedEndpointVerified': True}
            stage = 'dial-stdio'
            raw, metadata = query(['system', 'dial-stdio'], REQUEST)
            trial['transport'] = metadata
            stage = 'http-response'
            response = http.client.HTTPResponse(MemorySocket(raw))
            response.begin()
            if response.status != 200:
                raise ValueError('http_status_not_successful')
            body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise ValueError('bounded_body_exceeded')
            info = json.loads(body)
            stage = 'engine-identity'
            if info.get('ID') != ENGINE or info.get('OSType') != 'linux' or info.get('ServerVersion') != VERSION:
                raise ValueError('expected_engine_identity_mismatch')
            trial.update(status='passed', transport=metadata,
                         engineID=ENGINE, osType='linux', serverVersion=VERSION,
                         httpStatus=200, bodySha256=hashlib.sha256(body).hexdigest(),
                         withinProductionReadBudget=metadata['seconds'] <= 4,
                         verifiedContextAndQuerySeconds=round(trial['context']['seconds'] + metadata['seconds'], 6))
            del raw, body, info, response
        report['status'] = 'passed'
    except Exception as error:
        # Never print Docker output, stderr, headers, auth or exception messages.
        report['status'] = 'failed'
        report['failureType'] = type(error).__name__
        report['failureStage'] = stage
        if type(error) is ValueError and str(error) in {
            'endpoint_selection_conflict', 'client_version_mismatch', 'context_endpoint_mismatch',
            'owned_process_failed', 'bounded_response_exceeded', 'http_status_not_successful',
            'bounded_body_exceeded', 'expected_engine_identity_mismatch'}:
            report['failureCode'] = str(error)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
