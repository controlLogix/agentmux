"""Collect native P02 foundation evidence without changing the checkout."""
import argparse
import atexit
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import threading
import unittest
from unittest import mock
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
GO_VERSION = '1.27.2'
MODULE = 'github.com/controlLogix/agentmux/platform'
COLLECTION_BUDGET_SECONDS = 35 * 60
RESEARCH_BUDGET_SECONDS = 12 * 60
DARWIN_INSTALL_NAMES = ('TestDarwinProtectedInstalledExecutable', 'TestDarwinProtectedPathPolicy',
                        'TestDarwinMachODependencyPolicy', 'TestDarwinProductRemainsFailClosed')
DARWIN_INSTALL_PATTERN = '^TestDarwin(ProtectedInstalledExecutable|ProtectedPathPolicy|MachODependencyPolicy|ProductRemainsFailClosed)$'
DARWIN_HOST_NAMES = ('TestDarwinInstalledHostSurvivesFrontendExit', 'TestDarwinInstalledHostReplacementRefusal',
                     'TestDarwinInstalledHostOwnedStopAndWait')
DARWIN_HOST_PATTERN = '^TestDarwinInstalledHost(SurvivesFrontendExit|ReplacementRefusal|OwnedStopAndWait)$'
DARWIN_INSTALL_SCOPES = (('darwin-protected-install', './runtime'), ('darwin-installed-host-lifecycle', './runtime'))
DARWIN_INSTALL_SELECTIONS = {
    'darwin-protected-install': (DARWIN_INSTALL_NAMES, DARWIN_INSTALL_PATTERN),
    'darwin-installed-host-lifecycle': (DARWIN_HOST_NAMES, DARWIN_HOST_PATTERN),
}
DARWIN_CGO0_PRIVATE_TEST = 'TestDarwinWithoutCGORefusesDescriptorAccessQualification'
DARWIN_CGO0_PRIVATE_PATTERN = '^' + DARWIN_CGO0_PRIVATE_TEST + '$'
DARWIN_CGO0_DEPLOYMENT_TEST = 'TestDarwinTeamPrivateCredentialWithoutCGORefuses'
DARWIN_CGO0_DEPLOYMENT_PATTERN = '^' + DARWIN_CGO0_DEPLOYMENT_TEST + '$'
DARWIN_CGO0_SCOPES = (('darwin-cgo0-private-refusal', './privatefs'),
                      ('darwin-cgo0-deployment-refusal', './deployment'))
FOUNDATION_SCOPES = (
    ('assembly', './kernel/assembly'), ('accounts', './kernel/communication'),
    ('deployment', './deployment'), ('protocol', './kernel/protocol'),
    ('boot', './kernel/boot'), ('launcher', './launcher'),
    ('runtime-command', './cmd/agentmux-runtime'), ('local-tls', './localtls'),
    ('private-files', './privatefs'), ('runtime', './runtime'),
)
# Explicit opt-in cohorts. New owner tests enter only after their names freeze.
DARWIN_COHORTS = {
    'darwin-frontend-budget': ('./cmd/agentmux-runtime', '', 180, (
        'TestFrontendBudgetReservesResponseAndCleanup', 'TestFrontendCleanupNeverExtendsTotal',
        'TestFrontendStatusUsesOriginalFiveSecondTotal', 'TestFrontendEarlierCancelledCallerDoesNotGainTime')),
    'darwin-frontend-receipt': ('./cmd/agentmux-runtime', 'agentmux_darwin_install', 180, (
        'TestOwnedBootstrapProgressChecksActualChildAndCaller',
        'TestFrontendNearExpiryOwnedReceiptRetainsUnknownFactsAndCleanup')),
    'darwin-signed-role-lifecycle': ('./launcher', 'agentmux_bootstrap_docker', 900, (
        'TestSessionLifecycleActualSingleChildExit', 'TestSessionLifecycleActualRetirementAndReusedSeparation',
        'TestSessionLifecycleActualFailedStopRetainsCleanup', 'TestSessionLifecycleConcurrentCloseAndObservation',
        'TestRuntimeCleanupRetainsExactSessionLeaseAndHonorsCancellation',
        'TestRuntimeCleanupExistingReaperReleasesIgnoredError')),
    'darwin-installed-cli': ('./launcher', 'agentmux_bootstrap_docker', 1200, (
        'TestInstalledCLIDarwinRealComposeColdWarmAndRefresh', 'TestInstalledCLIDarwinRealComposeConcurrentCold',
        'TestInstalledCLIDarwinRealComposeAuthenticatedPending', 'TestInstalledCLIDarwinRealComposeAbruptHostRestart',
        'TestInstalledCLIDarwinRealComposeDifferentWorkingDirectoryReuse',
        'TestInstalledCLIDarwinRealComposeConflictingChildSelection')),
    'darwin-installed-cli-port': ('./launcher', 'agentmux_bootstrap_docker', 1200, (
        'TestInstalledCLIDarwinRealComposeOccupiedSelectedPort',)),
    'darwin-creator-history': ('./launcher', 'agentmux_darwin_install', 180, (
        'TestBootstrapHistoryActualCreatorTerminalWhileLeaseHeldAndAfterExit',
        'TestHostHistoryPolicyActualSealedCreatorAndDrift')),
    'darwin-startup-owner': ('./launcher', 'agentmux_bootstrap_docker', 1200, (
        'TestInstalledCLIDarwinRealComposeStartupOwnerDeathBeforeRoles',)),
    'darwin-runtime-rollback': ('./runtime', 'agentmux_bootstrap_docker,agentmux_darwin_runtime_fixture', 180, (
        'TestDarwinPartialStartFailureReapsEarlierChild',
        'TestDarwinCancellationDuringPartialStartupReapsOwnedChildren',
        'TestDarwinStartValidationRejectsNextImageAndReapsEarlierChildren')),
    'darwin-normal-self': ('./internal/darwinfixtureidentity',
        'agentmux_bootstrap_docker,agentmux_darwin_identity_normal_probe', 180, (
        'TestNormalAdmissionSelfSDK265',)),
    'darwin-normal-identity': ('./internal/darwinfixtureidentity',
        'agentmux_bootstrap_docker,agentmux_darwin_identity_protected_normal', 180, (
        'TestProtectedNormalLoaderAdmission', 'TestProtectedNormalFastCompletion',
        'TestProtectedNormalWrongDigest', 'TestProtectedNormalInvalidArguments',
        'TestProtectedNormalReparentedRoles', 'TestProtectedNormalHostRefusals',
        'TestProtectedNormalRoleRosterRefusals')),
    'darwin-normal-parent': ('./internal/darwinfixtureidentity',
        'agentmux_bootstrap_docker,agentmux_darwin_identity_protected_normal,agentmux_darwin_runtime_fixture', 180, (
        'TestRuntimeNormalParentEOFStopsActualChild',
        'TestRuntimeNormalParentInheritedLeasesLastUntilOwnedReap')),
    'darwin-live-role-recovery': ('./launcher', 'agentmux_bootstrap_docker', 900, (
        'TestSignedDarwinLiveRolesLateSnapshotDegradationAndWholeGroupRecovery',
        'TestSignedDarwinLiveTLSBrokerRecoveryPreservesOwnedRoles',
        'TestSignedDarwinLiveTLSBrokerReconnectExhaustionIsBounded')),
    'darwin-installed-cli-slow-consumer': ('./launcher', 'agentmux_bootstrap_docker', 1200, (
        'TestInstalledCLIDarwinRealComposeSlowConsumerIsolationAndRecovery',)),
}


def cohort_pattern(names):
    if not names or len(names) != len(set(names)) or any(not re.fullmatch(r'Test[A-Za-z0-9_]+', n) for n in names):
        raise ValueError('cohort_names_invalid')
    return '^(' + '|'.join(re.escape(n) for n in names) + ')$'


def validate_cohort_inventory(raw, source, cohort):
    package, tags, budget, names = DARWIN_COHORTS[cohort]
    record = json.loads(raw)
    if (record.get('ImportPath') != MODULE + '/' + package[2:] or record.get('Error')
            or record.get('Incomplete') or record.get('DepsErrors')):
        raise ValueError('cohort_inventory_invalid')
    files = record.get('TestGoFiles', []) + record.get('XTestGoFiles', [])
    declarations = []
    for name in files:
        if not isinstance(name, str) or Path(name).name != name or '\\' in name:
            raise ValueError('cohort_inventory_path_invalid')
        declarations.extend(re.findall(r'^func\s+(Test\w+)\s*\(t \*testing\.T\)',
                            (source / package[2:] / name).read_text(), re.M))
    if any(declarations.count(n) != 1 for n in names):
        raise ValueError('cohort_declaration_missing_or_duplicate')
    return {'package': record['ImportPath'], 'testFiles': files, 'requiredTests': list(names),
            'tags': tags, 'selector': cohort_pattern(names)}


def admit_cohort_events(raw, stderr, code, package, names):
    events = []
    try:
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value: raise ValueError('duplicate_event_field')
                value[key] = item
            return value
        events = [json.loads(line, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite_event_value')))
                  for line in raw.splitlines() if line.strip()]
        if any(not isinstance(e, dict) or e.get('Package') != package or
               ('Test' in e and not isinstance(e['Test'], str)) for e in events):
            raise ValueError('cohort_event_invalid')
        result = admit_required_events(raw, code, package, names)
        starts = [e for e in events if e.get('Action') == 'start' and not e.get('Test')]
        actual = {e['Test'] for e in events if e.get('Action') == 'run' and e.get('Test') and '/' not in e['Test']}
        unexpected = sorted(actual - set(names))
        race = 'WARNING: DATA RACE' in raw or 'WARNING: DATA RACE' in stderr
        complete = len(starts) == 1 and events[0] == starts[0] and not any(e.get('Action') == 'bench' for e in events)
        ended = False
        active = set()
        ownership = True
        for event in events:
            name, action = event.get('Test'), event.get('Action')
            if ended or (name and name.split('/')[0] not in names):
                complete = False
            if (name and '/' in name and action in ('run', 'pause', 'cont', 'pass', 'fail', 'skip')
                    and name.split('/', 1)[0] not in active):
                ownership = False
            if name and action == 'run':
                # Go JSON provides no parent identity. T.Run suffixes are
                # opaque names, including slashes, not a nested ancestry proof.
                active.add(name)
            elif name and action in ('pass', 'fail', 'skip'):
                if '/' not in name and any(child.startswith(name + '/') for child in active):
                    ownership = False
                active.discard(name)
            elif name and action in ('pause', 'cont') and name not in active:
                ownership = False
            if not name and action in ('pass', 'fail', 'skip'):
                if active:
                    ownership = False
                ended = True
    except (ValueError, TypeError, KeyError, IndexError):
        events = []
        result = {'status': 'failed', 'malformedOutput': True, 'allRequiredTestsPassed': False}
        actual = set()
        unexpected, race, complete = [], False, False
        ownership = False
    result.update(unexpectedTopLevelTests=unexpected, missingTopLevelTests=sorted(set(names) - actual),
                  completePackageStart=complete, topLevelOwnershipAndJoinOrderVerified=ownership, raceWarningObserved=race,
                  parentageScope='top-level-ownership', nestedParentageVerified=False,
                  parentageLimits=['Subtest suffixes are opaque; nested T.Run correctness relies on the pinned Go harness and joined successful process, not name-prefix inference.'])
    if unexpected or race or not complete or not ownership:
        result['status'] = 'failed'
    result['namedResults'] = [{k: e[k] for k in ('Test', 'Action', 'Elapsed') if k in e}
                              for e in events if e.get('Test') and e.get('Action') in ('run', 'pass', 'fail', 'skip')]
    return result
# Official go.dev release metadata, checked October 13, 2026.
GO_SHA256 = {
    'linux-amd64': 'ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5',
    'linux-arm64': '94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8',
    'darwin-amd64': '587b59182488b23aa6e5fc25110405a3e0e5b38ed2f5b2f46ed13c32aee356fe',
    'darwin-arm64': '76812b213b1b2302c978d28fa52fa92d541704b9e7d9d5db8002c50e4018c4c5',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_report(path, report):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                dir=path.parent, prefix='.report-', delete=False) as output:
            temporary = Path(output.name)
            json.dump(report, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def remaining_timeout(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Collection budget exhausted')
    return min(maximum, remaining)


# Owners hold only exact Popen/session handles minted by this collector.
_RETAINED_REAPS = set()
_REAP_LOCK = threading.Lock()


class OwnedCleanupError(RuntimeError):
    """Cleanup is incomplete or failed; no exit result has been admitted."""
    def __init__(self, owner, cause=None):
        super().__init__('owned_process_cleanup_incomplete')
        self.owner = owner
        self._cause = cause
        self._cleanup_cause = owner.wait_failure or owner.failure

    def __repr__(self):
        return 'OwnedCleanupError(owned_process_cleanup_incomplete)'


class _OwnedReap:
    def __init__(self, process):
        self.process = process
        self.gate = threading.Lock()
        self.code = None
        self.failure = None
        self.wait_failure = None
        self.stop_attempted = False
        self.shutdown_started = False
        with _REAP_LOCK:
            _RETAINED_REAPS.add(self)

    def _stop(self):
        if self.stop_attempted or self.process.returncode is not None:
            return
        self.stop_attempted = True
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            self.failure = exc

    def stop_until(self, deadline, cause=None):
        try:
            acquired = self.gate.acquire(timeout=max(0, deadline - time.monotonic()))
        except BaseException as exc:
            failure = OwnedCleanupError(self, cause)
            failure._gate_cause = exc
            raise failure from None
        if not acquired:
            raise OwnedCleanupError(self, cause) from None
        try:
            if self.code is not None:
                if self.failure is not None:
                    raise OwnedCleanupError(self, cause) from None
                return self.code
            self._stop()
            try:
                # Builtin Popen uses a bounded wait; no background waiter exists.
                self.code = self.process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException as exc:
                self.wait_failure = exc
                raise OwnedCleanupError(self, cause) from None
            self.wait_failure = None
            with _REAP_LOCK:
                _RETAINED_REAPS.discard(self)
            if self.failure is not None:
                raise OwnedCleanupError(self, cause) from None
            return self.code
        finally:
            self.gate.release()

    def shutdown(self):
        # Interpreter shutdown has no hard wall-time bound. Only this exact owner
        # may wait, after the earlier bounded waiter has returned and released gate.
        while True:
            try:
                self.gate.acquire()
                break
            except BaseException:
                pass
        try:
            if self.code is not None or self.shutdown_started:
                return
            self.shutdown_started = True
            self._stop()
            while self.code is None:
                try:
                    self.code = self.process.wait()
                except BaseException as exc:
                    self.wait_failure = exc
                    try:
                        time.sleep(.1)
                    except BaseException:
                        pass
            with _REAP_LOCK:
                _RETAINED_REAPS.discard(self)
        finally:
            self.gate.release()


def _shutdown_retained_reaps():
    with _REAP_LOCK:
        owners = tuple(_RETAINED_REAPS)
    for owner in owners:
        owner.shutdown()


atexit.register(_shutdown_retained_reaps)


def stop_owned(process, deadline):
    """Use the original remaining budget; retain incomplete cleanup for shutdown."""
    return _OwnedReap(process).stop_until(deadline)


def wait_owned(process, timeout, *, deadline=None):
    # Real collection passes its original deadline and reserves five seconds.
    # Standalone controls receive a one-second cleanup allowance inside their end.
    end = time.monotonic() + timeout + 1 if deadline is None else deadline
    wait = timeout if deadline is None else min(timeout, max(0, end - time.monotonic() - 5))
    try:
        return process.wait(timeout=wait), False
    except subprocess.TimeoutExpired as exc:
        return _OwnedReap(process).stop_until(end, exc), True
    except BaseException as exc:
        _OwnedReap(process).stop_until(end, exc)
        raise


def admit_preparation_workspace(workspace):
    if not workspace.is_dir() or workspace == ROOT or ROOT in workspace.parents:
        raise ValueError('Preparation workspace must be outside the checkout')
    entries = list(workspace.iterdir())
    if len(entries) > 1:
        raise ValueError('Preparation markers are mutually exclusive')
    for entry in entries:
        if (entry.name not in ('research-only', 'install-only') or entry.is_symlink()
                or not entry.is_file() or entry.stat().st_size != 0):
            raise ValueError('Preparation requires a fresh workspace with one empty mode marker at most')


def prepare_tools(workspace):
    """Runs only in the parent's owned preparation process, never an agent/provider."""
    admit_preparation_workspace(workspace)
    report = {'status': 'failed'}
    try:
        system = {'Linux': 'linux', 'Darwin': 'darwin'}[platform.system()]
        arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]
        toolchain(workspace, system + '-' + arch, report)
        if not any((workspace / marker).exists() for marker in ('research-only', 'install-only')):
            broker_downloader()(workspace, report)
        report['status'] = 'prepared'
    except Exception as exc:
        report['failureType'] = type(exc).__name__
    atomic_report(workspace / 'preparation.json', report)
    return 0 if report['status'] == 'prepared' else 1


def source_hashes():
    paths = []
    for directory in ('platform', 'contracts/v1'):
        paths.extend(p for p in (ROOT / directory).rglob('*') if p.is_file()
                     and not set(p.parts) & {'__pycache__', 'node_modules', '.git'})
    paths.extend(ROOT / p for p in ('tests/platform/native_go.py',
                 'tests/contracts/ci.py', '.github/workflows/platform-foundation.yml'))
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted(paths)}


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def broker_downloader():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / 'tests' / 'contracts'))
    from ci import broker
    return broker


def toolchain(workspace, target, report):
    asset = f'go{GO_VERSION}.{target}.tar.gz'
    releases = json.loads(download('https://go.dev/dl/?mode=json&include=all'))
    matches = [f for release in releases if release['version'] == 'go' + GO_VERSION
               for f in release['files'] if f['filename'] == asset]
    if len(matches) != 1 or matches[0]['sha256'] != GO_SHA256[target]:
        raise ValueError('Official Go checksum is missing or differs from the reviewed pin')
    archive = workspace / asset
    archive.write_bytes(download('https://go.dev/dl/' + asset))
    if digest(archive) != GO_SHA256[target]:
        raise ValueError('Go archive checksum differs')
    with tarfile.open(archive, 'r:gz') as package:
        package.extractall(workspace, filter='data')
    report['toolchain'] = {'version': GO_VERSION, 'archiveSha256': digest(archive),
                           'checksumUrl': 'https://go.dev/dl/?mode=json&include=all',
                           'archiveUrl': 'https://go.dev/dl/' + asset}
    return workspace / 'go' / 'bin' / 'go'


def validate_module(record):
    required = [r for r in record.get('Require', []) if r.get('Path') == 'github.com/nats-io/nats.go']
    if (record.get('Go') != GO_VERSION or len(required) != 1
            or required[0].get('Version') != 'v1.54.0' or record.get('Replace')):
        raise ValueError('Module pins or replacements differ from the approved foundation')


def validate_package_matrix(raw):
    """Fail on unreviewed test-bearing package drift; do not silently omit tests."""
    decoder = json.JSONDecoder()
    records = []
    text = raw.strip()
    while text:
        record, end = decoder.raw_decode(text)
        if not isinstance(record, dict) or not isinstance(record.get('ImportPath'), str):
            raise ValueError('Invalid Go package inventory')
        records.append(record)
        text = text[end:].lstrip()
    paths = [record['ImportPath'] for record in records]
    if not paths or len(paths) != len(set(paths)) or any(
            not p.startswith(MODULE + '/') for p in paths):
        raise ValueError('Missing, repeated or foreign package inventory')
    for record in records:
        if record.get('Error') or record.get('Incomplete') or record.get('DepsErrors'):
            raise ValueError('Incomplete Go package inventory')
        for key in ('TestGoFiles', 'XTestGoFiles'):
            if not isinstance(record.get(key, []), list) or any(
                    not isinstance(name, str) for name in record.get(key, [])):
                raise ValueError('Malformed Go test file inventory')
    bearing = {record['ImportPath'] for record in records
               if record.get('TestGoFiles') or record.get('XTestGoFiles')}
    selected = {MODULE + '/' + package[2:] for _, package in FOUNDATION_SCOPES}
    if bearing != selected:
        raise ValueError('Test-bearing packages differ from the reviewed P02 matrix')
    return [{'package': record['ImportPath'], 'testFiles': record.get('TestGoFiles', []),
             'externalTestFiles': record.get('XTestGoFiles', []),
             'selected': record['ImportPath'] in selected} for record in records]


def validate_install_selection(raw, source):
    record = json.loads(raw)
    if (record.get('ImportPath') != MODULE + '/runtime' or record.get('Error')
            or record.get('Incomplete') or record.get('DepsErrors') or not record.get('CgoFiles')):
        raise ValueError('Native cgo runtime inventory is incomplete')
    files = record.get('TestGoFiles', [])
    cgo = record.get('CgoFiles', [])
    if (not isinstance(files, list) or not isinstance(cgo, list)
            or any(not isinstance(name, str) or Path(name).name != name for name in files + cgo)):
        raise ValueError('Invalid tagged test file inventory')
    observed = []
    for name in files:
        observed.extend(re.findall(r'^func (TestDarwin\w+)\(t \*testing\.T\)',
                        (source / 'runtime' / name).read_text(encoding='utf-8'), re.MULTILINE))
    selected = DARWIN_INSTALL_NAMES + DARWIN_HOST_NAMES
    if any(observed.count(name) != 1 for name in selected):
        raise ValueError('Reviewed install test names are missing or repeated')
    return {'package': record['ImportPath'], 'testFiles': files, 'cgoFiles': record['CgoFiles'],
            'selectedTests': list(selected)}


def admit_install_events(raw, exit_code, selected=DARWIN_INSTALL_NAMES):
    result = admit_required_events(raw, exit_code, MODULE + '/runtime', selected)
    result['allReviewedInstallTestsPassed'] = result['allRequiredTestsPassed']
    return result


def admit_required_events(raw, exit_code, expected_package, selected):
    result = admit_events(raw, exit_code, expected_package)
    passed = set()
    if not result['malformedOutput']:
        passed = {event.get('Test') for event in (json.loads(line) for line in raw.splitlines())
                  if event.get('Action') == 'pass' and event.get('Test') in selected}
    result['selectedTests'] = list(selected)
    result['allRequiredTestsPassed'] = passed == set(selected)
    if not result['allRequiredTestsPassed']:
        result['status'] = 'failed'
    return result


def validate_cgo0_private_selection(raw, source):
    record = json.loads(raw)
    if (not isinstance(record, dict) or record.get('ImportPath') != MODULE + '/privatefs'
            or record.get('Error') or record.get('Incomplete') or record.get('DepsErrors')
            or not isinstance(record.get('CgoFiles', []), list) or record.get('CgoFiles')):
        raise ValueError('Native CGO0 private-file inventory is invalid')
    files = record.get('TestGoFiles', [])
    if (not isinstance(files, list) or not files or any(not isinstance(name, str)
            or Path(name).name != name or '/' in name or '\\' in name for name in files)):
        raise ValueError('Invalid CGO0 test file inventory')
    observed = []
    for name in files:
        observed.extend(re.findall(r'^func (Test\w+)\(t \*testing\.T\)',
                        (source / 'privatefs' / name).read_text(encoding='utf-8'), re.MULTILINE))
    if observed.count(DARWIN_CGO0_PRIVATE_TEST) != 1:
        raise ValueError('Exact reviewed CGO0 refusal test is missing or repeated')
    return {'package': record['ImportPath'], 'testFiles': files,
            'selectedTests': [DARWIN_CGO0_PRIVATE_TEST], 'cgoEnabled': False}


def validate_cgo0_deployment_selection(raw, source):
    record = json.loads(raw)
    if (not isinstance(record, dict) or record.get('ImportPath') != MODULE + '/deployment'
            or record.get('Error') or record.get('Incomplete') or record.get('DepsErrors')
            or not isinstance(record.get('CgoFiles', []), list) or record.get('CgoFiles')):
        raise ValueError('Native CGO0 team-credential inventory is invalid')
    files = record.get('TestGoFiles', [])
    if (not isinstance(files, list) or not files or any(not isinstance(name, str)
            or Path(name).name != name or '/' in name or '\\' in name for name in files)):
        raise ValueError('Invalid CGO0 test file inventory')
    observed = []
    for name in files:
        observed.extend(re.findall(r'^func (Test\w+)\(t \*testing\.T\)',
                        (source / 'deployment' / name).read_text(encoding='utf-8'), re.MULTILINE))
    if observed.count(DARWIN_CGO0_DEPLOYMENT_TEST) != 1:
        raise ValueError('Exact reviewed CGO0 refusal test is missing or repeated')
    return {'package': record['ImportPath'], 'testFiles': files,
            'selectedTests': [DARWIN_CGO0_DEPLOYMENT_TEST], 'cgoEnabled': False}


def admit_events(text, exit_code, expected_package='fixture'):
    """Require real terminal package/test events, no skips and no hidden failures."""
    events = []
    malformed = False
    for line in text.splitlines():
        try:
            event = json.loads(line)
            if (not isinstance(event, dict) or event.get('Package') != expected_package
                    or event.get('Action') not in ('start', 'run', 'pause', 'cont', 'pass', 'fail', 'skip', 'output', 'bench')):
                raise ValueError('Not a Go test event')
            events.append(event)
        except (ValueError, TypeError):
            malformed = True
    tests = [e for e in events if e.get('Test') and e['Action'] in ('pass', 'fail', 'skip')]
    packages = [e for e in events if not e.get('Test') and e['Action'] in ('pass', 'fail', 'skip')]
    skipped = sum(e['Action'] == 'skip' for e in events)
    failed = sum(e['Action'] == 'fail' for e in events)
    passed = sum(e['Action'] == 'pass' for e in tests)
    started = [e['Test'] for e in events if e.get('Test') and e['Action'] == 'run']
    finished = [e['Test'] for e in tests]
    completed = (len(started) == len(set(started)) and len(finished) == len(set(finished))
                 and set(started) == set(finished))
    active = set()
    ended = set()
    package_ended = False
    ordered = True
    for event in events:
        name, action = event.get('Test'), event['Action']
        if name and action == 'run':
            if package_ended or name in active or name in ended:
                ordered = False
            active.add(name)
        elif name and action in ('pass', 'fail', 'skip'):
            if package_ended or name not in active or name in ended:
                ordered = False
            active.discard(name)
            ended.add(name)
        elif not name and action in ('pass', 'fail', 'skip'):
            if package_ended or active or not ended:
                ordered = False
            package_ended = True
    ok = (exit_code == 0 and not malformed and passed > 0 and bool(packages)
          and completed and ordered and not skipped and not failed and len(packages) == 1
          and all(e['Action'] == 'pass' for e in packages))
    return {'status': 'passed' if ok else 'failed', 'passedTestEvents': passed,
            'skipEvents': skipped, 'failureEvents': failed, 'malformedOutput': malformed,
            'allStartedTestsCompleted': completed, 'lifecycleOrderValid': ordered}


class AdmissionTests(unittest.TestCase):
    def test_completion_order_requires_run_then_test_end_then_package_end(self):
        run = {'Action': 'run', 'Test': 'TestReal', 'Package': 'fixture'}
        end = dict(run, Action='pass')
        package = {'Action': 'pass', 'Package': 'fixture'}
        encode = lambda rows: '\n'.join(json.dumps(event) for event in rows)
        for rows in ([end, run, package], [run, package, end], [package, run, end]):
            self.assertEqual(admit_events(encode(rows), 0)['status'], 'failed')
        # Parallel tests may overlap and pause; each still completes before its package.
        other = dict(run, Test='TestOther')
        rows = [run, dict(run, Action='pause'), other, dict(other, Action='pass'),
                dict(run, Action='cont'), end, package]
        self.assertEqual(admit_events(encode(rows), 0)['status'], 'passed')

    def test_interrupted_checkpoint_publication_preserves_prior_report(self):
        with tempfile.TemporaryDirectory(prefix='agentmux-checkpoint-control-') as directory:
            target = Path(directory) / 'result.json'
            atomic_report(target, {'status': 'failed', 'prior': True})
            before = target.read_bytes()
            with mock.patch.object(os, 'replace', side_effect=OSError('synthetic interruption')):
                with self.assertRaises(OSError):
                    atomic_report(target, {'status': 'passed'})
            self.assertEqual(before, target.read_bytes())
            self.assertEqual([p.name for p in target.parent.iterdir()], ['result.json'])
    def test_actual_pass(self):
        events = '\n'.join(json.dumps(e) for e in (
            {'Action': 'run', 'Test': 'TestReal', 'Package': 'fixture'},
            {'Action': 'pass', 'Test': 'TestReal', 'Package': 'fixture'},
            {'Action': 'pass', 'Package': 'fixture'}))
        self.assertEqual(admit_events(events, 0)['status'], 'passed')

    def test_empty_skip_failure_and_malformed_are_not_passes(self):
        for action in ('skip', 'fail'):
            events = json.dumps({'Action': action, 'Test': 'TestReal'})
            self.assertEqual(admit_events(events, 0)['status'], 'failed')
        for text in ('', 'not-json', '{}', '[]'):
            self.assertEqual(admit_events(text, 0)['status'], 'failed')

    def test_nonzero_exit_and_package_only_are_not_passes(self):
        text = json.dumps({'Action': 'pass', 'Package': 'fixture'})
        self.assertEqual(admit_events(text, 0)['status'], 'failed')
        self.assertEqual(admit_events(text, 1)['status'], 'failed')

    def test_a_pass_cannot_hide_skip_failure_or_missing_package_end(self):
        success = [{'Action': 'run', 'Test': 'TestReal', 'Package': 'fixture'},
                   {'Action': 'pass', 'Test': 'TestReal', 'Package': 'fixture'},
                   {'Action': 'pass', 'Package': 'fixture'}]
        for action in ('skip', 'fail'):
            extra = [{'Action': 'run', 'Test': 'TestNegative', 'Package': 'fixture'},
                     {'Action': action, 'Test': 'TestNegative', 'Package': 'fixture'}]
            text = '\n'.join(json.dumps(e) for e in success + extra)
            self.assertEqual(admit_events(text, 0)['status'], 'failed')
        package_failure = success[:-1] + [{'Action': 'fail', 'Package': 'fixture'}]
        self.assertEqual(admit_events('\n'.join(json.dumps(e) for e in package_failure), 0)['status'], 'failed')
        self.assertEqual(admit_events(json.dumps(success[0]), 0)['status'], 'failed')
        self.assertEqual(admit_events('\n'.join(json.dumps(e) for e in success), 1)['status'], 'failed')

    def test_missing_mismatched_and_incomplete_package_events_fail(self):
        success = [{'Action': 'run', 'Test': 'TestReal', 'Package': 'fixture'},
                   {'Action': 'pass', 'Test': 'TestReal', 'Package': 'fixture'},
                   {'Action': 'pass', 'Package': 'fixture'}]
        for extra in ({'Action': 'run', 'Test': 'TestUnfinished', 'Package': 'fixture'},
                      {'Action': 'pass', 'Package': 'unrelated'},
                      {'Action': 'pass', 'Test': 'TestMissingPackage'}):
            self.assertEqual(admit_events('\n'.join(json.dumps(e) for e in success + [extra]), 0)['status'], 'failed')

    def test_module_pins_are_structured_and_replacements_refused(self):
        valid = {'Go': GO_VERSION, 'Require': [{'Path': 'github.com/nats-io/nats.go', 'Version': 'v1.54.0'}]}
        validate_module(valid)
        for altered in ({**valid, 'Go': '1.26'}, {**valid, 'Require': []},
                        {**valid, 'Replace': [{'Old': {'Path': 'github.com/nats-io/nats.go'}, 'New': {'Path': './fake'}}]},
                        {'Comment': 'go 1.27.2 github.com/nats-io/nats.go v1.54.0'}):
            with self.assertRaises(ValueError):
                validate_module(altered)

    def test_downloader_import_does_not_write_checkout_bytecode(self):
        cache = ROOT / 'tests/contracts/__pycache__'
        def observed():
            return {p.name: (digest(p), p.stat().st_mtime_ns) for p in cache.glob('*') if p.is_file()}
        before = observed()
        self.assertTrue(callable(broker_downloader()))
        self.assertTrue(sys.dont_write_bytecode)
        self.assertEqual(before, observed())

    def test_package_matrix_cannot_hide_missing_new_or_incomplete_tests(self):
        records = [{'ImportPath': MODULE + '/' + package[2:], 'TestGoFiles': ['fixture_test.go']}
                   for _, package in FOUNDATION_SCOPES]
        raw = lambda items: '\n'.join(json.dumps(item) for item in items)
        self.assertEqual(len(validate_package_matrix(raw(records))), len(FOUNDATION_SCOPES))
        bad = (records[:-1], records + [records[0]], records + [
            {'ImportPath': MODULE + '/new-package', 'TestGoFiles': ['new_test.go']}],
            [dict(records[0], Incomplete=True)] + records[1:],
            [dict(records[0], TestGoFiles='not-a-list')] + records[1:])
        for items in bad:
            with self.assertRaises(ValueError):
                validate_package_matrix(raw(items))
        records.append({'ImportPath': MODULE + '/cmd/agentmux-kernel'})
        self.assertFalse(validate_package_matrix(raw(records))[-1]['selected'])

    def test_runtime_command_package_cannot_be_omitted_or_declared_without_tests(self):
        records = [{'ImportPath': MODULE + '/' + package[2:], 'TestGoFiles': ['fixture_test.go']}
                   for _, package in FOUNDATION_SCOPES]
        target = MODULE + '/cmd/agentmux-runtime'
        self.assertEqual(len([record for record in records if record['ImportPath'] == target]), 1)
        for altered in ([record for record in records if record['ImportPath'] != target],
                        [dict(record, TestGoFiles=[]) if record['ImportPath'] == target else record for record in records]):
            with self.assertRaises(ValueError):
                validate_package_matrix('\n'.join(json.dumps(record) for record in altered))

    def test_local_tls_package_cannot_be_omitted_or_declared_without_tests(self):
        records = [{'ImportPath': MODULE + '/' + package[2:], 'TestGoFiles': ['fixture_test.go']}
                   for _, package in FOUNDATION_SCOPES]
        target = MODULE + '/localtls'
        self.assertEqual(len([record for record in records if record['ImportPath'] == target]), 1)
        for altered in ([record for record in records if record['ImportPath'] != target],
                        [dict(record, TestGoFiles=[]) if record['ImportPath'] == target else record for record in records]):
            with self.assertRaises(ValueError):
                validate_package_matrix('\n'.join(json.dumps(record) for record in altered))

    def test_private_files_package_cannot_be_omitted_or_declared_without_tests(self):
        records = [{'ImportPath': MODULE + '/' + package[2:], 'TestGoFiles': ['fixture_test.go']}
                   for _, package in FOUNDATION_SCOPES]
        target = MODULE + '/privatefs'
        self.assertEqual(len([record for record in records if record['ImportPath'] == target]), 1)
        for altered in ([record for record in records if record['ImportPath'] != target],
                        [dict(record, TestGoFiles=[]) if record['ImportPath'] == target else record for record in records]):
            with self.assertRaises(ValueError):
                validate_package_matrix('\n'.join(json.dumps(record) for record in altered))


class RunnerTests(unittest.TestCase):
    """Synthetic runner controls; never native runtime qualification."""

    def test_interrupted_owned_wait_stops_and_reaps_before_propagation(self):
        for failure in (KeyboardInterrupt(), RuntimeError('synthetic wait failure')):
            process = mock.Mock(pid=12345, returncode=None)
            process.wait.side_effect = [failure, -9]
            with mock.patch.object(os, 'killpg', create=True) as kill, \
                    mock.patch.object(signal, 'SIGKILL', 9, create=True):
                with self.assertRaises(type(failure)):
                    wait_owned(process, 1)
                kill.assert_called_once_with(12345, 9)
                self.assertEqual(process.wait.call_args_list, [mock.call(timeout=1), mock.call(timeout=mock.ANY)])

    def test_interruption_after_reaping_never_signals_saved_identity(self):
        process = mock.Mock(pid=12345, returncode=None)

        def interrupted_wait(*, timeout):
            process.returncode = 0
            process.wait.side_effect = None
            process.wait.return_value = 0
            raise KeyboardInterrupt()

        process.wait.side_effect = interrupted_wait
        with mock.patch.object(os, 'killpg', create=True) as kill:
            with self.assertRaises(KeyboardInterrupt):
                wait_owned(process, 1)
            kill.assert_not_called()
            self.assertEqual(process.wait.call_args_list, [mock.call(timeout=1), mock.call(timeout=mock.ANY)])

    def test_owned_builtin_timeout_reaps_actual_child(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'],
                                   start_new_session=True)
        try:
            start = time.monotonic()
            code, timed_out = wait_owned(process, .01, deadline=start + .5)
            self.assertTrue(timed_out)
            self.assertEqual(code, -signal.SIGKILL)
            self.assertEqual(process.returncode, code)
            self.assertLess(time.monotonic() - start, .5)
        finally:
            if process.returncode is None:
                stop_owned(process, time.monotonic() + 2)

    def test_owned_cleanup_timeout_retains_owner_and_retry_resolves(self):
        first = subprocess.TimeoutExpired('fixed', 1)
        cleanup = subprocess.TimeoutExpired('fixed', .05)
        process = mock.Mock(pid=12345, returncode=None)
        process.wait.side_effect = [first, cleanup, -9]
        deadline = time.monotonic() + .05
        with mock.patch.object(os, 'killpg', create=True) as kill:
            with self.assertRaises(OwnedCleanupError) as result:
                wait_owned(process, .01, deadline=deadline)
            owner = result.exception.owner
            self.assertIs(owner.process, process)
            self.assertIn(owner, _RETAINED_REAPS)
            self.assertIsNone(owner.code)
            self.assertIs(result.exception._cleanup_cause, cleanup)
            self.assertIs(result.exception._cause, first)
            for call in process.wait.call_args_list:
                self.assertIn('timeout', call.kwargs)
                self.assertLessEqual(call.kwargs['timeout'], .05)
            self.assertEqual(owner.stop_until(time.monotonic() + 1), -9)
            self.assertNotIn(owner, _RETAINED_REAPS)
            self.assertIs(result.exception._cleanup_cause, cleanup)
            kill.assert_called_once_with(12345, signal.SIGKILL)

    def test_owned_cleanup_interruption_retains_owner(self):
        process = mock.Mock(pid=12345, returncode=None)
        interruption = KeyboardInterrupt()
        process.wait.side_effect = [subprocess.TimeoutExpired('fixed', 1), interruption, -9]
        with mock.patch.object(os, 'killpg', create=True):
            with self.assertRaises(OwnedCleanupError) as result:
                wait_owned(process, .01, deadline=time.monotonic() + .05)
            owner = result.exception.owner
            self.assertIs(owner.process, process)
            self.assertIs(result.exception._cleanup_cause, interruption)
            self.assertEqual(owner.stop_until(time.monotonic() + 1), -9)
            self.assertNotIn(owner, _RETAINED_REAPS)

    def test_owned_cleanup_stop_failure_never_disappears_after_reap(self):
        process = mock.Mock(pid=12345, returncode=None)
        process.wait.return_value = 0
        private = PermissionError('private synthetic cause')
        with mock.patch.object(os, 'killpg', side_effect=private, create=True):
            with self.assertRaises(OwnedCleanupError) as result:
                stop_owned(process, time.monotonic() + .05)
            owner = result.exception.owner
            self.assertEqual(owner.code, 0)
            self.assertIs(result.exception._cleanup_cause, private)
            with self.assertRaises(OwnedCleanupError) as repeated:
                owner.stop_until(time.monotonic() + .05)
            self.assertIs(repeated.exception.owner, owner)
            self.assertEqual(process.wait.call_count, 1)
            self.assertNotIn('private', str(result.exception))
            self.assertNotIn('private', repr(result.exception))

    def test_owned_cleanup_shutdown_reaps_exact_retained_child(self):
        # The controlled timeout obeys the wait contract. Its exact builtin
        # process.wait performs the real reap during interpreter shutdown.
        program = r"""
import atexit, json, os, runpy, subprocess, sys, time
child = None
@atexit.register
def verify():
    joined = child is not None and child.returncode == -9
    print(json.dumps({'exactChildReaped': joined}), flush=True)
    if not joined: os._exit(3)
collector = runpy.run_path(sys.argv[1])
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'], start_new_session=True)
actual_wait = child.wait
def controlled_wait(timeout=None):
    if timeout is not None: raise subprocess.TimeoutExpired('fixed', timeout)
    return actual_wait()
child.wait = controlled_wait
try:
    collector['stop_owned'](child, time.monotonic() + .01)
except collector['OwnedCleanupError'] as failure:
    assert failure.owner.process is child and failure.owner.code is None
else:
    raise AssertionError('missing retained exact owner')
"""
        process = subprocess.Popen([sys.executable, '-c', program, str(Path(__file__).resolve())],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(json.loads(out), {'exactChildReaped': True})
            self.assertEqual(err, b'')
        finally:
            if process.returncode is None:
                stop_owned(process, time.monotonic() + 2)

    def test_hidden_preparation_refuses_populated_workspace_before_writes(self):
        with tempfile.TemporaryDirectory(prefix='agentmux-preparation-admission-') as directory:
            work = Path(directory)
            preserved = work / 'preparation.json'
            preserved.write_text('existing notes', encoding='utf-8')
            with mock.patch(__name__ + '.toolchain') as setup:
                with self.assertRaises(SystemExit):
                    main(['--prepare-tools', '--workspace', str(work)])
                setup.assert_not_called()
            self.assertEqual(preserved.read_text(encoding='utf-8'), 'existing notes')
            self.assertEqual(list(work.iterdir()), [preserved])

    def test_preparation_accepts_only_empty_regular_marker(self):
        with tempfile.TemporaryDirectory(prefix='agentmux-preparation-marker-') as directory:
            work = Path(directory)
            admit_preparation_workspace(work)
            marker = work / 'research-only'
            marker.touch()
            admit_preparation_workspace(work)
            marker.write_text('unrelated data', encoding='utf-8')
            with self.assertRaises(ValueError):
                admit_preparation_workspace(work)

    def exercise(self, *, host='Linux', research=False, install=False, authorized=True, uid=501, compiler_output='Apple clang version 17.0.0\nSynthetic control only', broker_failure=False,
                 test_failure=False, fail_host_scope=False, fail_cgo0_scope=False, fail_cgo0_deployment=False, mutate_copy=False, mutate_original=False, timeout_first=False, exhausted=False, timeout_exit= -9):
        with tempfile.TemporaryDirectory(prefix='agentmux-native-runner-unit-') as directory:
            base = Path(directory)
            root = base / 'checkout'
            for name, content in {
                'platform/go.mod': 'module github.com/controlLogix/agentmux/platform\ngo 1.27.2\n',
                'platform/go.sum': '', 'contracts/v1/fixture.json': '{}',
                'tests/platform/native_go.py': 'synthetic runner source',
                'tests/contracts/ci.py': 'synthetic downloader source',
                '.github/workflows/platform-foundation.yml': 'synthetic workflow source',
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding='utf-8', newline='\n')
            work, evidence = base / 'work', base / 'evidence'
            sdk = base / 'synthetic-sdk'
            sdk.mkdir()
            if install:
                fixture = root / 'platform/runtime/install_test.go'
                fixture.parent.mkdir(parents=True)
                fixture.write_text('\n'.join('func ' + name + '(t *testing.T) {}' for name in DARWIN_INSTALL_NAMES + DARWIN_HOST_NAMES), encoding='utf-8')
            if host == 'Darwin' and not research and not install:
                fixture = root / 'platform/privatefs/refusal_test.go'
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_text('func ' + DARWIN_CGO0_PRIVATE_TEST + '(t *testing.T) {}', encoding='utf-8')
                fixture = root / 'platform/deployment/refusal_test.go'
                fixture.parent.mkdir(parents=True, exist_ok=True)
                fixture.write_text('func ' + DARWIN_CGO0_DEPLOYMENT_TEST + '(t *testing.T) {}', encoding='utf-8')
            calls = []
            os_name = 'darwin' if host == 'Darwin' else 'linux'

            def prepared(workspace, target, report):
                report['toolchain'] = {'synthetic': True}
                return workspace / 'go/bin/go'

            def query(command, **kwargs):
                if command[0] == '/usr/bin/clang':
                    return compiler_output
                if command[0] == '/usr/bin/xcrun':
                    return '15.0' if command[-1] == '--show-sdk-version' else str(sdk)
                if command[0] == 'git':
                    return 'a' * 40
                if command[1:] == ['version']:
                    return f'go version go{GO_VERSION} {os_name}/amd64'
                if command[1:3] == ['mod', 'edit']:
                    return json.dumps({'Go': GO_VERSION, 'Require': [
                        {'Path': 'github.com/nats-io/nats.go', 'Version': 'v1.54.0'}]})
                if command[1:] == ['list', '-mod=readonly', '-json', './...']:
                    return '\n'.join(json.dumps({'ImportPath': MODULE + '/' + package[2:],
                                                'TestGoFiles': ['synthetic_test.go']})
                                     for _, package in FOUNDATION_SCOPES)
                if 'agentmux_darwin_install' in command:
                    return json.dumps({'ImportPath': MODULE + '/runtime', 'CgoFiles': ['acl_darwin.go'],
                                       'TestGoFiles': ['install_test.go']})
                if command[1:] == ['list', '-mod=readonly', '-json', './deployment']:
                    if kwargs['env'].get('CGO_ENABLED') != '0':
                        raise ValueError('Synthetic deployment refusal query requires CGO0')
                    return json.dumps({'ImportPath': MODULE + '/deployment', 'CgoFiles': [], 'TestGoFiles': ['refusal_test.go']})
                if command[1:] == ['list', '-mod=readonly', '-json', './privatefs']:
                    if kwargs['env'].get('CGO_ENABLED') != '0':
                        raise ValueError('Synthetic CGO0 query did not select its separate environment')
                    return json.dumps({'ImportPath': MODULE + '/privatefs', 'CgoFiles': [], 'TestGoFiles': ['refusal_test.go']})
                return json.dumps({'Path': 'github.com/nats-io/nats.go', 'Version': 'v1.54.0'})

            def spawn(command, **kwargs):
                if '--prepare-tools' in command:
                    prepare_report = {'status': 'prepared', 'toolchain': {'synthetic': True}}
                    if broker_failure:
                        prepare_report = {'status': 'failed', 'failureType': 'RuntimeError'}
                    atomic_report(work / 'preparation.json', prepare_report)
                    process = mock.Mock()
                    process.wait.return_value = 1 if broker_failure else 0
                    return process
                calls.append((command, kwargs))
                package = next(arg for arg in command if arg.startswith('./'))
                qualified = 'github.com/controlLogix/agentmux/platform/' + package[2:]
                failed = (test_failure or (fail_host_scope and DARWIN_HOST_PATTERN in command)
                          or (fail_cgo0_scope and DARWIN_CGO0_PRIVATE_PATTERN in command)
                          or (fail_cgo0_deployment and DARWIN_CGO0_DEPLOYMENT_PATTERN in command))
                action = 'fail' if failed else 'pass'
                events = [{'Action': 'run', 'Test': 'TestSynthetic', 'Package': qualified},
                          {'Action': action, 'Test': 'TestSynthetic', 'Package': qualified},
                          {'Action': action, 'Package': qualified}]
                if install:
                    pattern = command[command.index('-run') + 1]
                    names = next(names for names, expected in DARWIN_INSTALL_SELECTIONS.values() if pattern == expected)
                    events = [event for name in names for event in (
                        {'Action': 'run', 'Test': name, 'Package': qualified},
                        {'Action': action, 'Test': name, 'Package': qualified})]
                    events.append({'Action': action, 'Package': qualified})
                if research:
                    selected_name = command[command.index('-run') + 1][1:-1]
                    events = [{'Action': 'run', 'Test': selected_name, 'Package': qualified},
                              {'Action': action, 'Test': selected_name, 'Package': qualified},
                              {'Action': action, 'Package': qualified}]
                if DARWIN_CGO0_PRIVATE_PATTERN in command:
                    events = [{'Action': 'run', 'Test': DARWIN_CGO0_PRIVATE_TEST, 'Package': qualified},
                              {'Action': action, 'Test': DARWIN_CGO0_PRIVATE_TEST, 'Package': qualified},
                              {'Action': action, 'Package': qualified}]
                if DARWIN_CGO0_DEPLOYMENT_PATTERN in command:
                    events = [{'Action': 'run', 'Test': DARWIN_CGO0_DEPLOYMENT_TEST, 'Package': qualified},
                              {'Action': action, 'Test': DARWIN_CGO0_DEPLOYMENT_TEST, 'Package': qualified},
                              {'Action': action, 'Package': qualified}]
                kwargs['stdout'].write(('\n'.join(json.dumps(e) for e in events) + '\n').encode())
                if mutate_copy:
                    (work / 'source/platform/go.mod').write_text('changed synthetic source', encoding='utf-8')
                if mutate_original:
                    (root / 'platform/go.mod').write_text('changed synthetic original', encoding='utf-8')
                process = mock.Mock()
                process.pid = 12345
                if timeout_first and len(calls) == 1:
                    process.wait.side_effect = [subprocess.TimeoutExpired(command, 1), timeout_exit]
                    def timed_wait(*, timeout):
                        process.wait.side_effect = None
                        process.wait.return_value = timeout_exit
                        raise subprocess.TimeoutExpired(command, timeout)
                    process.wait.side_effect = timed_wait
                    process.returncode = None
                else:
                    process.wait.return_value = 1 if failed else 0
                return process

            downloader = mock.Mock(return_value=work / 'nats-server')
            if broker_failure:
                downloader.side_effect = RuntimeError('private transport text must not enter evidence')
            argv = ['--workspace', str(work), '--evidence', str(evidence)]
            if research:
                argv.append('--darwin-research')
            if install:
                argv.append('--darwin-install')
            with mock.patch.dict(os.environ, {'UNRELATED_SECRET': 'unit-sentinel',
                    'AMX_DARWIN_INSTALL_AUTHORIZED': '1' if authorized else '0'}), \
                    mock.patch(__name__ + '.ROOT', root), \
                    mock.patch.object(platform, 'system', return_value=host), \
                    mock.patch.object(platform, 'machine', return_value='x86_64'), \
                    mock.patch.object(platform, 'release', return_value='synthetic-native'), \
                    mock.patch.object(platform, 'platform', return_value='synthetic-native-runner-control'), \
                    mock.patch.object(os, 'geteuid', return_value=uid, create=True), \
                    mock.patch(__name__ + '.toolchain', side_effect=prepared) as go_setup, \
                    mock.patch(__name__ + '.broker_downloader', return_value=downloader) as broker_setup, \
                    mock.patch.object(subprocess, 'check_output', side_effect=query), \
                    mock.patch.object(os, 'killpg', create=True), \
                    mock.patch.object(signal, 'SIGKILL', 9, create=True), \
                    mock.patch(__name__ + '.COLLECTION_BUDGET_SECONDS', 0 if exhausted else COLLECTION_BUDGET_SECONDS), \
                    mock.patch.object(subprocess, 'Popen', side_effect=spawn):
                code = main(argv)
                record = json.loads((evidence / 'result.json').read_text(encoding='utf-8'))
                return code, record, calls, go_setup.call_count, broker_setup.call_count

    def test_synthetic_darwin_metadata_never_uses_process_fake(self):
        # Exercise Darwin's real stdlib metadata branch while the collector's
        # owned-process boundary is mocked. This is a fixture, not native proof.
        uname = platform.uname_result('Darwin', 'synthetic', '25.0', 'synthetic', 'arm64')
        with mock.patch.object(platform, 'uname', return_value=uname), \
                mock.patch.dict(platform._platform_cache, {}, clear=True), \
                mock.patch.object(platform, '_syscmd_file', wraps=platform._syscmd_file) as metadata_query:
            code, record, _, _, _ = self.exercise(host='Darwin')
        self.assertEqual(code, 0)
        self.assertEqual(record['host'], 'synthetic-native-runner-control')
        self.assertFalse(record['nativeProtectedBootQualified'])
        metadata_query.assert_not_called()

    def test_install_requires_native_host_authorization_and_nonroot_before_effects(self):
        for controls in ({'host': 'Linux'}, {'host': 'Darwin', 'authorized': False}, {'host': 'Darwin', 'uid': 0}):
            code, record, calls, _, _ = self.exercise(install=True, **controls)
            self.assertEqual(code, 1)
            self.assertFalse(calls)
            self.assertNotIn('toolchain', record)
            self.assertFalse(record['protectedInstallEvidence'])

    def test_install_selection_is_separate_and_never_qualifies_full_boot(self):
        code, record, calls, _, broker_calls = self.exercise(host='Darwin', install=True)
        self.assertEqual(code, 0)
        self.assertEqual(broker_calls, 0)
        self.assertEqual(len(calls), 2)
        command, options = calls[0]
        self.assertIn('-race', command)
        self.assertIn('-timeout=180s', command)
        self.assertIn('agentmux_darwin_install', command)
        self.assertEqual(command[-2:], [DARWIN_INSTALL_PATTERN, './runtime'])
        self.assertEqual(calls[1][0][-2:], [DARWIN_HOST_PATTERN, './runtime'])
        self.assertEqual(options['env']['CGO_ENABLED'], '1')
        self.assertEqual(options['env']['CC'], '/usr/bin/clang')
        self.assertEqual(options['env']['AMX_DARWIN_INSTALL_AUTHORIZED'], '1')
        self.assertNotIn('UNRELATED_SECRET', options['env'])
        self.assertTrue(record['protectedInstallEvidence'])
        self.assertTrue(record['installedHostLifecycleEvidence'])
        self.assertFalse(record['fourRoleBootQualified'])
        self.assertFalse(record['composeQualified'])
        self.assertFalse(record['phaseAccepted'])
        self.assertEqual(record['runtimeQualification'], 'unqualified')
        code, record, _, _, _ = self.exercise(host='Darwin', install=True, test_failure=True)
        self.assertEqual(code, 1)
        self.assertFalse(record['protectedInstallEvidence'])
        self.assertFalse(record['installedHostLifecycleEvidence'])

    def test_install_admission_requires_every_reviewed_top_level_test(self):
        package = MODULE + '/runtime'
        events = [event for name in DARWIN_INSTALL_NAMES for event in (
            {'Action': 'run', 'Test': name, 'Package': package},
            {'Action': 'pass', 'Test': name, 'Package': package})]
        events.append({'Action': 'pass', 'Package': package})
        encode = lambda rows: '\n'.join(json.dumps(e) for e in rows)
        self.assertEqual(admit_install_events(encode(events), 0)['status'], 'passed')
        missing = [e for e in events if e.get('Test') != DARWIN_INSTALL_NAMES[0]]
        self.assertEqual(admit_install_events(encode(missing), 0)['status'], 'failed')
        self.assertEqual(admit_install_events(encode(events), 1)['status'], 'failed')

    def test_install_inventory_refuses_missing_tests_or_cgo(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'runtime').mkdir()
            fixture = source / 'runtime/install_test.go'
            fixture.write_text('\n'.join('func ' + name + '(t *testing.T) {}' for name in DARWIN_INSTALL_NAMES + DARWIN_HOST_NAMES), encoding='utf-8')
            record = {'ImportPath': MODULE + '/runtime', 'CgoFiles': ['acl_darwin.go'], 'TestGoFiles': ['install_test.go']}
            self.assertEqual(validate_install_selection(json.dumps(record), source)['selectedTests'], list(DARWIN_INSTALL_NAMES + DARWIN_HOST_NAMES))
            for change in ({'CgoFiles': []}, {'CgoFiles': 'wrong'}, {'TestGoFiles': ['../install_test.go']}, {'Incomplete': True}, {'ImportPath': 'wrong'}):
                with self.assertRaises(ValueError):
                    validate_install_selection(json.dumps(record | change), source)
            fixture.write_text('func ' + DARWIN_INSTALL_NAMES[0] + '(t *testing.T) {}', encoding='utf-8')
            with self.assertRaises(ValueError):
                validate_install_selection(json.dumps(record), source)

    def test_host_scope_cannot_borrow_protected_image_passes(self):
        package = MODULE + '/runtime'
        encode = lambda names: '\n'.join(json.dumps(event) for name in names for event in (
            {'Action': 'run', 'Test': name, 'Package': package},
            {'Action': 'pass', 'Test': name, 'Package': package})) + '\n' + json.dumps({'Action': 'pass', 'Package': package})
        self.assertEqual(admit_install_events(encode(DARWIN_HOST_NAMES), 0, DARWIN_HOST_NAMES)['status'], 'passed')
        variants = [DARWIN_INSTALL_NAMES]
        variants.extend(tuple(name for name in DARWIN_HOST_NAMES if name != missing) for missing in DARWIN_HOST_NAMES)
        for names in variants:
            self.assertEqual(admit_install_events(encode(names), 0, DARWIN_HOST_NAMES)['status'], 'failed')
        self.assertEqual(admit_install_events(encode(DARWIN_HOST_NAMES), 1, DARWIN_HOST_NAMES)['status'], 'failed')
        self.assertEqual(admit_install_events(encode(DARWIN_HOST_NAMES), 0)['status'], 'failed')

    def test_host_selection_failure_or_source_drift_never_qualifies_collection(self):
        for controls in ({'test_failure': True}, {'mutate_copy': True}, {'timeout_first': True}):
            code, record, _, _, _ = self.exercise(host='Darwin', install=True, **controls)
            self.assertEqual(code, 1)
            self.assertFalse(record['protectedInstallEvidence'])
            self.assertFalse(record['installedHostLifecycleEvidence'])
            self.assertFalse(record['phaseAccepted'])

    def test_protected_image_pass_cannot_hide_failed_host_scope(self):
        code, record, calls, _, _ = self.exercise(host='Darwin', install=True, fail_host_scope=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual([check['status'] for check in record['checks']], ['passed', 'failed'])
        self.assertFalse(record['protectedInstallEvidence'])
        self.assertFalse(record['installedHostLifecycleEvidence'])
        self.assertFalse(record['phaseAccepted'])

    def test_install_inventory_requires_all_host_declarations_exactly_once(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'runtime').mkdir()
            fixture = source / 'runtime/install_test.go'
            record = {'ImportPath': MODULE + '/runtime', 'CgoFiles': ['acl_darwin.go'], 'TestGoFiles': ['install_test.go']}
            variants = [DARWIN_INSTALL_NAMES, DARWIN_INSTALL_NAMES + DARWIN_HOST_NAMES + DARWIN_HOST_NAMES[:1]]
            variants.extend(DARWIN_INSTALL_NAMES + tuple(name for name in DARWIN_HOST_NAMES if name != missing)
                            for missing in DARWIN_HOST_NAMES)
            for names in variants:
                fixture.write_text('\n'.join('func ' + name + '(t *testing.T) {}' for name in names), encoding='utf-8')
                with self.assertRaises(ValueError):
                    validate_install_selection(json.dumps(record), source)

    def test_install_refuses_malformed_apple_compiler_version_before_tests(self):
        for compiler in ('', 'clang version 17.0.0', 'Apple clang version nonsense', 'Apple clang version 17.0.evil'):
            code, record, calls, _, _ = self.exercise(host='Darwin', install=True, compiler_output=compiler)
            self.assertEqual(code, 1)
            self.assertEqual(record['failureType'], 'ValueError')
            self.assertFalse(calls)
            self.assertFalse(record['protectedInstallEvidence'])
            self.assertNotIn('nativeBuild', record)

    def test_install_and_research_flags_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            main(['--darwin-install', '--darwin-research'])

    def test_preparation_rejects_combined_install_and_research_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'install-only').touch()
            admit_preparation_workspace(work)
            (work / 'research-only').touch()
            with self.assertRaises(ValueError):
                admit_preparation_workspace(work)

    def test_synthetic_normal_runner_records_every_scope_and_isolates_environment(self):
        code, record, calls, _, _ = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual([c['name'] for c in record['checks']], [name for name, _ in FOUNDATION_SCOPES])
        self.assertEqual(len(record['packageMatrix']), len(FOUNDATION_SCOPES))
        self.assertFalse(record['phaseAccepted'])
        self.assertTrue(record['sourceUnchangedDuringRun'])
        self.assertTrue(record['executedSourceUnchangedDuringRun'])
        for _, options in calls:
            self.assertNotIn('UNRELATED_SECRET', options['env'])
            self.assertEqual(options['env']['GOTOOLCHAIN'], 'local')
            self.assertEqual(options['env']['GOENV'], 'off')
            self.assertEqual(options['env']['GOWORK'], 'off')

    def test_unsupported_host_refuses_before_tools_or_tests(self):
        code, record, calls, go_calls, broker_calls = self.exercise(host='Windows')
        self.assertEqual(code, 1)
        self.assertEqual(record['status'], 'failed')
        self.assertEqual((calls, go_calls, broker_calls), ([], 0, 0))

    def test_normal_native_selection_executes_runtime_command_on_both_hosts(self):
        for host in ('Linux', 'Darwin'):
            code, record, calls, _, _ = self.exercise(host=host)
            self.assertEqual(code, 0)
            command_calls = [command for command, _ in calls if './cmd/agentmux-runtime' in command]
            self.assertEqual(len(command_calls), 1)
            self.assertNotIn('-run', command_calls[0])
            command_checks = [check for check in record['checks'] if check['name'] == 'runtime-command']
            self.assertEqual(len(command_checks), 1)
            self.assertEqual(command_checks[0]['status'], 'passed')
            self.assertFalse(record['phaseAccepted'])

    def test_normal_native_selection_executes_local_tls_on_both_hosts(self):
        for host in ('Linux', 'Darwin'):
            code, record, calls, _, _ = self.exercise(host=host)
            self.assertEqual(code, 0)
            selected = [command for command, _ in calls if './localtls' in command]
            self.assertEqual(len(selected), 1)
            self.assertNotIn('-run', selected[0])
            checks = [check for check in record['checks'] if check['name'] == 'local-tls']
            self.assertEqual(len(checks), 1)
            self.assertEqual(checks[0]['status'], 'passed')
            self.assertFalse(record['phaseAccepted'])

    def test_darwin_normal_matrix_requires_actual_cgo_compiler_sdk_for_private_files(self):
        code, record, calls, _, _ = self.exercise(host='Darwin')
        self.assertEqual(code, 0)
        selected = [(command, options) for command, options in calls if './privatefs' in command and DARWIN_CGO0_PRIVATE_PATTERN not in command]
        self.assertEqual(len(selected), 1)
        command, options = selected[0]
        self.assertNotIn('-run', command)
        self.assertEqual(options['env']['CGO_ENABLED'], '1')
        self.assertEqual(options['env']['CC'], '/usr/bin/clang')
        self.assertTrue(Path(options['env']['SDKROOT']).is_absolute())
        self.assertNotIn('AMX_DARWIN_INSTALL_AUTHORIZED', options['env'])
        self.assertTrue(record['nativeBuild']['cgoEnabled'])
        self.assertEqual(record['runtimeQualification'], 'unqualified')
        for compiler in ('', 'clang version 17.0.0', 'Apple clang version nonsense'):
            code, record, calls, _, _ = self.exercise(host='Darwin', compiler_output=compiler)
            self.assertEqual(code, 1)
            self.assertFalse(calls)
            self.assertNotIn('nativeBuild', record)

    def test_darwin_cgo0_refusal_is_exact_separate_and_not_product_qualification(self):
        code, record, calls, _, _ = self.exercise(host='Darwin', authorized=False)
        self.assertEqual(code, 0)
        selected = [(command, options) for command, options in calls if DARWIN_CGO0_PRIVATE_PATTERN in command]
        self.assertEqual(len(selected), 1)
        command, options = selected[0]
        self.assertEqual(options['env']['CGO_ENABLED'], '0')
        self.assertEqual(command[-2:], ['-run', DARWIN_CGO0_PRIVATE_PATTERN])
        self.assertTrue(record['cgo0PrivateAccessRefusalObserved'])
        self.assertEqual(record['runtimeQualification'], 'unqualified')
        self.assertFalse(record['nativeProtectedBootQualified'])
        code, record, _, _, _ = self.exercise(host='Darwin', fail_cgo0_scope=True)
        self.assertEqual(code, 1)
        self.assertFalse(record['cgo0PrivateAccessRefusalObserved'])
        self.assertFalse(record['phaseAccepted'])

    def test_cgo0_inventory_and_named_events_cannot_hide_missing_or_wrong_test(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'privatefs').mkdir()
            fixture = source / 'privatefs/refusal_test.go'
            fixture.write_text('func ' + DARWIN_CGO0_PRIVATE_TEST + '(t *testing.T) {}', encoding='utf-8')
            record = {'ImportPath': MODULE + '/privatefs', 'TestGoFiles': ['refusal_test.go']}
            self.assertFalse(validate_cgo0_private_selection(json.dumps(record), source)['cgoEnabled'])
            for change in ({'CgoFiles': ['access_darwin.go']}, {'CgoFiles': 'wrong'}, {'TestGoFiles': []},
                           {'TestGoFiles': ['../refusal_test.go']}, {'Incomplete': True}):
                with self.assertRaises(ValueError):
                    validate_cgo0_private_selection(json.dumps(record | change), source)
            fixture.write_text('func TestOther(t *testing.T) {}', encoding='utf-8')
            with self.assertRaises(ValueError):
                validate_cgo0_private_selection(json.dumps(record), source)
        package = MODULE + '/privatefs'
        events = [{'Action': 'run', 'Package': package, 'Test': DARWIN_CGO0_PRIVATE_TEST},
                  {'Action': 'pass', 'Package': package, 'Test': DARWIN_CGO0_PRIVATE_TEST},
                  {'Action': 'pass', 'Package': package}]
        encode = lambda rows: '\n'.join(json.dumps(event) for event in rows)
        selected = (DARWIN_CGO0_PRIVATE_TEST,)
        self.assertEqual(admit_required_events(encode(events), 0, package, selected)['status'], 'passed')
        for action in ('skip', 'fail'):
            altered = [events[0], dict(events[1], Action=action), events[2]]
            self.assertEqual(admit_required_events(encode(altered), 0, package, selected)['status'], 'failed')
        self.assertEqual(admit_required_events(encode(events[:1]+events[2:]), 0, package, selected)['status'], 'failed')

    def test_darwin_cgo0_deployment_refusal_has_separate_command_and_report(self):
        code, record, calls, _, _ = self.exercise(host='Darwin')
        self.assertEqual(code, 0)
        selected = [(command, options) for command, options in calls if DARWIN_CGO0_DEPLOYMENT_PATTERN in command]
        self.assertEqual(len(selected), 1)
        command, options = selected[0]
        self.assertEqual(command[-3:], ['./deployment', '-run', DARWIN_CGO0_DEPLOYMENT_PATTERN])
        self.assertEqual(options['env']['CGO_ENABLED'], '0')
        self.assertEqual(record['cgo0DeploymentSelection']['selectedTests'], [DARWIN_CGO0_DEPLOYMENT_TEST])
        self.assertTrue(record['cgo0DeploymentRefusalObserved'])
        self.assertFalse(record['nativeProtectedBootQualified'])
        self.assertEqual(record['runtimeQualification'], 'unqualified')
        code, record, _, _, _ = self.exercise(host='Darwin', fail_cgo0_deployment=True)
        self.assertEqual(code, 1)
        self.assertFalse(record['cgo0DeploymentRefusalObserved'])
        private = next(check for check in record['checks'] if check['name'] == 'darwin-cgo0-private-refusal')
        self.assertEqual(private['status'], 'passed')
        self.assertFalse(record['phaseAccepted'])
        _, linux, calls, _, _ = self.exercise(host='Linux')
        self.assertNotIn('cgo0DeploymentSelection', linux)
        self.assertFalse(any(DARWIN_CGO0_DEPLOYMENT_PATTERN in command for command, _ in calls))

    def test_deployment_refusal_claim_requires_stable_original_and_executed_source(self):
        for controls in ({'mutate_copy': True}, {'mutate_original': True}):
            code, record, _, _, _ = self.exercise(host='Darwin', **controls)
            self.assertEqual(code, 1)
            check = next(check for check in record['checks'] if check['name'] == 'darwin-cgo0-deployment-refusal')
            self.assertEqual(check['status'], 'passed')
            self.assertFalse(record['cgo0DeploymentRefusalObserved'])

    def test_cgo0_deployment_inventory_rejects_wrong_missing_and_repeated_test(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / 'deployment').mkdir()
            fixture = source / 'deployment/refusal_test.go'
            text = 'func ' + DARWIN_CGO0_DEPLOYMENT_TEST + '(t *testing.T) {}'
            fixture.write_text(text, encoding='utf-8')
            record = {'ImportPath': MODULE + '/deployment', 'TestGoFiles': ['refusal_test.go']}
            self.assertFalse(validate_cgo0_deployment_selection(json.dumps(record), source)['cgoEnabled'])
            for change in ({'ImportPath': MODULE + '/privatefs'}, {'CgoFiles': ['unsafe.go']},
                           {'CgoFiles': 'wrong'}, {'TestGoFiles': []}, {'TestGoFiles': ['../refusal_test.go']},
                           {'Error': {'Err': 'fixture'}}, {'Incomplete': True}):
                with self.assertRaises(ValueError):
                    validate_cgo0_deployment_selection(json.dumps(record | change), source)
            for text in ('func TestOther(t *testing.T) {}', text + '\n' + text):
                fixture.write_text(text, encoding='utf-8')
                with self.assertRaises(ValueError):
                    validate_cgo0_deployment_selection(json.dumps(record), source)

    def test_cgo0_deployment_events_require_exact_actual_named_completion(self):
        package = MODULE + '/deployment'
        selected = (DARWIN_CGO0_DEPLOYMENT_TEST,)
        events = [{'Action': 'run', 'Package': package, 'Test': selected[0]},
                  {'Action': 'pass', 'Package': package, 'Test': selected[0]},
                  {'Action': 'pass', 'Package': package}]
        encode = lambda rows: '\n'.join(json.dumps(event) for event in rows)
        self.assertEqual(admit_required_events(encode(events), 0, package, selected)['status'], 'passed')
        for rows, code in ((events, 1), ([events[0], events[2]], 0),
                           ([events[0], dict(events[1], Action='skip'), events[2]], 0),
                           ([events[0], dict(events[1], Action='fail'), events[2]], 0),
                           ([dict(event, Package=MODULE + '/privatefs') for event in events], 0)):
            self.assertEqual(admit_required_events(encode(rows), code, package, selected)['status'], 'failed')

    def test_setup_failure_retains_failed_report_without_private_error_text(self):
        code, record, calls, _, _ = self.exercise(broker_failure=True)
        self.assertEqual(code, 1)
        self.assertEqual(record['failureType'], 'RuntimeError')
        self.assertNotIn('private transport text', json.dumps(record))
        self.assertFalse(calls)

    def test_synthetic_test_failure_and_changed_execution_source_cannot_pass(self):
        for controls in ({'test_failure': True}, {'mutate_copy': True}):
            code, record, _, _, _ = self.exercise(**controls)
            self.assertEqual(code, 1)
            self.assertEqual(record['status'], 'failed')

    def test_research_has_separate_results_and_actual_fail_closed_control(self):
        code, record, calls, _, broker_calls = self.exercise(host='Darwin', research=True)
        self.assertEqual(code, 0)
        self.assertEqual(broker_calls, 0)
        self.assertTrue(record['researchOnly'])
        self.assertTrue(record['unprotectedImageRefusalObserved'])
        self.assertEqual(record['runtimeQualification'], 'unqualified')
        self.assertEqual([c[0][-1] for c in calls], [
            '^TestDarwinUnlinkedDescriptorResearch$', '^TestDarwinProductRemainsFailClosed$'])
        self.assertEqual(calls[0][0][calls[0][0].index('-tags') + 1], 'agentmux_darwin_descriptor_research')
        self.assertNotIn('-tags', calls[1][0])
        code, record, _, _, _ = self.exercise(host='Darwin', research=True, test_failure=True)
        self.assertEqual(code, 1)
        self.assertFalse(record['unprotectedImageRefusalObserved'])

    def test_research_refusal_claim_requires_stable_original_and_executed_source(self):
        for controls in ({'mutate_copy': True}, {'mutate_original': True}):
            code, record, _, _, _ = self.exercise(host='Darwin', research=True, **controls)
            self.assertEqual(code, 1)
            refusal = next(check for check in record['checks'] if check['name'] == 'darwin-fail-closed-control')
            self.assertEqual(refusal['status'], 'passed')
            self.assertFalse(record['unprotectedImageRefusalObserved'])
    def test_darwin_normal_matrix_never_claims_native_protected_boot(self):
        code, record, calls, _, _ = self.exercise(host='Darwin')
        self.assertEqual(code, 0)
        self.assertEqual(record['runtimeQualification'], 'unqualified')
        self.assertFalse(record['nativeProtectedBootQualified'])
        self.assertEqual(len([command for command, _ in calls if '^TestDarwinProductRemainsFailClosed$' in command]), 1)
        self.assertIn('actual native macOS protected-process boot remains unqualified', record['checks'][4]['scope'])

    def test_timeout_is_checkpointed_and_exhausted_scopes_are_unexecuted(self):
        code, record, _, _, _ = self.exercise(timeout_first=True)
        self.assertEqual(code, 1)
        self.assertTrue(record['checks'][0]['timedOut'])
        self.assertEqual(record['checks'][0]['exitCode'], -9)
        code, record, _, _, _ = self.exercise(timeout_first=True, timeout_exit=0)
        self.assertEqual(code, 1)
        self.assertEqual(record['checks'][0]['status'], 'failed')
        code, record, calls, _, _ = self.exercise(exhausted=True)
        self.assertEqual(code, 1)
        self.assertFalse(calls)
        self.assertEqual(record['failureType'], 'TimeoutError')
        self.assertEqual(len(record['checks']), len(FOUNDATION_SCOPES))
        self.assertTrue(all(check['status'] == 'unexecuted' for check in record['checks']))
        self.assertFalse(record['collectionComplete'])


def main(argv=None):
    # New cohorts reuse the enrolled, clean-candidate path, never tool download
    # or privileged preparation. Existing foundation/research/install CLI stays intact.
    arguments = list(sys.argv[1:] if argv is None else argv)
    if '--darwin-cohort' in arguments or any(a.startswith('--darwin-cohort=') for a in arguments):
        import importlib.util
        spec = importlib.util.spec_from_file_location('agentmux_cohort_collector', ROOT / 'tests/platform/native_compose.py')
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        return collector.main(arguments)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--self-test', action='store_true')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--darwin-research', action='store_true',
                        help='Run only the separate native Darwin descriptor research probe')
    modes.add_argument('--darwin-install', action='store_true',
                       help='Run separately authorized native protected-install fixture checks only')
    parser.add_argument('--prepare-tools', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.prepare_tools:
        if args.workspace is None:
            parser.error('Preparation needs its owned workspace')
        workspace = args.workspace.resolve()
        try:
            admit_preparation_workspace(workspace)
        except ValueError as exc:
            parser.error(str(exc))
        return prepare_tools(workspace)
    if args.self_test:
        suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                                   for case in (AdmissionTests, RunnerTests))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    if args.workspace is None or args.evidence is None:
        parser.error('--workspace and --evidence are required')
    workspace, evidence = args.workspace.resolve(), args.evidence.resolve()
    for path in (workspace, evidence):
        if path == ROOT or ROOT in path.parents:
            parser.error('Use disposable directories outside the checkout')
    if workspace == evidence or workspace in evidence.parents or evidence in workspace.parents:
        parser.error('Workspace and evidence must be separate directories')
    for path in (workspace, evidence):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(path.iterdir()):
            parser.error('Workspace and evidence must be empty; old results are not reusable')
    report = {'recordedAt': datetime.now(timezone.utc).isoformat(), 'checks': [],
              'host': platform.platform(), 'sourceHashes': source_hashes(), 'status': 'failed',
              'phaseAccepted': False, 'limits': [
                  'Foundation tests only; Compose, real boot and full phase acceptance remain required.',
                  'Native Linux does not qualify WSL. No cross-compilation is accepted as native execution.',
                  'Darwin runtime remains unqualified. Its research probe is not enabled here.']}
    if args.darwin_research:
        report.update(researchOnly=True, unprotectedImageRefusalObserved=False,
                      runtimeQualification='unqualified')
        report['limits'][-1] = 'Descriptor research only; successful execution does not prove same-UID immutability or native product boot.'
    if args.darwin_install:
        report.update(installFixtureOnly=True, protectedInstallEvidence=False, installedHostLifecycleEvidence=False,
                      fourRoleBootQualified=False, composeQualified=False, runtimeQualification='unqualified')
        report['limits'][-1] = 'Separate protected-image and installed-host lifetime/replacement fixtures only; native NATS, four-role boot, Compose, EOF and a production signed installer remain unqualified.'
    budget = RESEARCH_BUDGET_SECONDS if (args.darwin_research or args.darwin_install) else COLLECTION_BUDGET_SECONDS
    collection_deadline = time.monotonic() + budget
    report['collectionBudgetSeconds'] = budget
    report['collectionComplete'] = False

    def checkpoint():
        atomic_report(evidence / 'result.json', report)

    checkpoint()
    normal_darwin = False
    try:
        system = {'Linux': 'linux', 'Darwin': 'darwin'}.get(platform.system())
        arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine())
        if system is None or arch is None:
            raise ValueError('This runner requires a native Linux or macOS amd64/arm64 host')
        normal_darwin = system == 'darwin' and not args.darwin_research and not args.darwin_install
        if normal_darwin:
            report['cgo0PrivateAccessRefusalObserved'] = False
        if system == 'linux' and 'microsoft' in platform.release().lower():
            raise ValueError('WSL needs its own qualification; this runner is native-host only')
        if args.darwin_research and system != 'darwin':
            raise ValueError('Darwin research requires a native macOS host')
        if args.darwin_install:
            if system != 'darwin' or os.environ.get('AMX_DARWIN_INSTALL_AUTHORIZED') != '1':
                raise ValueError('Native Darwin install fixtures require explicit authorization')
            uid = os.geteuid()
            if uid == 0:
                raise ValueError('Fixture runtime and adversary must not run as root')
            report['executionUID'] = uid
            report['privilegeScope'] = 'Non-elevated runtime/adversary; fixed installer fixture uses sudo -n. This does not establish a non-admin account.'
        report['sourceCommit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
                                                        timeout=remaining_timeout(collection_deadline, 15)).strip()
        if args.darwin_research:
            (workspace / 'research-only').touch()
        if args.darwin_install:
            (workspace / 'install-only').touch()
        # Bound even a slow HTTP body in one owned, reapable process. No inherited
        # provider credentials or arbitrary URL/command is passed to this child.
        preparation_wait = remaining_timeout(collection_deadline, budget)
        child_env = {'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
        preparation = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--prepare-tools',
                      '--workspace', str(workspace)], env=child_env, start_new_session=True,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        preparation_code, preparation_timed_out = wait_owned(preparation, preparation_wait, deadline=collection_deadline)
        if preparation_timed_out:
            raise TimeoutError('Owned preparation exceeded collection budget')
        prepared = json.loads((workspace / 'preparation.json').read_text(encoding='utf-8'))
        if preparation_code != 0 or prepared.get('status') != 'prepared':
            raise RuntimeError('Owned tool preparation failed')
        report['toolchain'] = prepared['toolchain']
        tools_only = args.darwin_research or args.darwin_install
        if not tools_only:
            report['broker'] = prepared.get('broker', {})
        go = workspace / 'go/bin/go'
        server = None if tools_only else workspace / 'nats-server'
        source = workspace / 'source'
        shutil.copytree(ROOT / 'platform', source / 'platform')
        shutil.copytree(ROOT / 'contracts' / 'v1', source / 'contracts' / 'v1')
        copied = {p.relative_to(source).as_posix(): digest(p) for p in source.rglob('*') if p.is_file()}
        expected = {p: value for p, value in report['sourceHashes'].items()
                    if p.startswith(('platform/', 'contracts/v1/'))}
        if copied != expected:
            raise ValueError('Isolated source copy differs from the recorded candidate bytes')
        report['executedSourceHashes'] = copied
        home = workspace / 'home'
        home.mkdir(mode=0o700)
        env = {key: os.environ[key] for key in ('LANG', 'LC_ALL', 'LC_CTYPE', 'TZ') if key in os.environ}
        env.update(HOME=str(home), PATH=str(go.parent) + os.pathsep + os.defpath,
                   GOTOOLCHAIN='local', GOENV='off', GOWORK='off', GOPROXY='https://proxy.golang.org',
                   GOSUMDB='sum.golang.org', GOCACHE=str(workspace / 'go-cache'),
                   GOPATH=str(workspace / 'go-path'), TMPDIR=str(home))
        if server is not None:
            env['AGENTMUX_TEST_NATS'] = str(server)
        if system == 'darwin' and not args.darwin_research:
            def native_query(command):
                return subprocess.check_output(command, env=env, text=True,
                        timeout=remaining_timeout(collection_deadline, 15)).strip()
            compiler = native_query(['/usr/bin/clang', '--version'])
            sdk_version = native_query(['/usr/bin/xcrun', '--show-sdk-version'])
            sdk_path = native_query(['/usr/bin/xcrun', '--show-sdk-path'])
            if (not re.match(r'^Apple clang version [0-9]+(?:\.[0-9]+){1,2}(?:\s|$)', compiler)
                    or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,2}', sdk_version)
                    or not Path(sdk_path).is_absolute() or not Path(sdk_path).is_dir()
                    or any(c in sdk_path for c in '\r\n\x00')):
                raise ValueError('Actual Apple compiler/SDK selection is unavailable')
            env.update(CGO_ENABLED='1', CC='/usr/bin/clang', SDKROOT=sdk_path)
            if args.darwin_install:
                env['AMX_DARWIN_INSTALL_AUTHORIZED'] = '1'
            report['nativeBuild'] = {'compilerVersion': compiler, 'compiler': '/usr/bin/clang',
                                    'sdkVersion': sdk_version, 'sdkPath': sdk_path, 'cgoEnabled': True}
        version = subprocess.check_output([str(go), 'version'], env=env, text=True, timeout=remaining_timeout(collection_deadline, 15)).strip()
        if version != f'go version go{GO_VERSION} {system}/{arch}':
            raise ValueError('Prepared Go executable does not match the native host')
        report['toolchain']['observedVersion'] = version
        module = json.loads(subprocess.check_output([str(go), 'mod', 'edit', '-json'],
                            cwd=source / 'platform', env=env, text=True, timeout=remaining_timeout(collection_deadline, 30)))
        validate_module(module)
        resolved = json.loads(subprocess.check_output([str(go), 'list', '-mod=readonly', '-m', '-json',
                              'github.com/nats-io/nats.go'], cwd=source / 'platform', env=env, text=True, timeout=remaining_timeout(collection_deadline, 120)))
        if resolved.get('Version') != 'v1.54.0' or resolved.get('Replace'):
            raise ValueError('Resolved NATS module differs from the reviewed pin')
        report['natsModule'] = {'path': resolved['Path'], 'version': resolved['Version']}
        scopes = FOUNDATION_SCOPES
        report['nativeProtectedBootQualified'] = False
        if not tools_only:
            inventory = subprocess.check_output([str(go), 'list', '-mod=readonly', '-json', './...'],
                        cwd=source / 'platform', env=env, text=True, timeout=remaining_timeout(collection_deadline, 120))
            report['packageMatrix'] = validate_package_matrix(inventory)
        if normal_darwin:
            scopes += DARWIN_CGO0_SCOPES
            refusal_env = dict(env, CGO_ENABLED='0')
            refusal_inventory = subprocess.check_output([str(go), 'list', '-mod=readonly', '-json', './privatefs'],
                                cwd=source / 'platform', env=refusal_env, text=True,
                                timeout=remaining_timeout(collection_deadline, 120))
            report['cgo0PrivateSelection'] = validate_cgo0_private_selection(refusal_inventory, source / 'platform')
            deployment_inventory = subprocess.check_output([str(go), 'list', '-mod=readonly', '-json', './deployment'],
                                   cwd=source / 'platform', env=refusal_env, text=True,
                                   timeout=remaining_timeout(collection_deadline, 120))
            report['cgo0DeploymentSelection'] = validate_cgo0_deployment_selection(deployment_inventory, source / 'platform')
        if args.darwin_research:
            scopes = (('darwin-descriptor-research', './runtime'), ('darwin-fail-closed-control', './runtime'))
        if args.darwin_install:
            scopes = DARWIN_INSTALL_SCOPES
            tagged = subprocess.check_output([str(go), 'list', '-mod=readonly', '-tags',
                     'agentmux_darwin_install', '-json', './runtime'], cwd=source / 'platform',
                     env=env, text=True, timeout=remaining_timeout(collection_deadline, 120))
            report['installSelection'] = validate_install_selection(tagged, source / 'platform')
        for name, package in scopes:
            test_env = env
            command = [str(go), 'test', '-mod=readonly', '-count=1', '-timeout=5m', '-json', package]
            if system == 'darwin' and name == 'runtime':
                command += ['-run', '^TestDarwinProductRemainsFailClosed$']
            if name == 'darwin-descriptor-research':
                command += ['-tags', 'agentmux_darwin_descriptor_research', '-run', '^TestDarwinUnlinkedDescriptorResearch$']
            if name == 'darwin-fail-closed-control':
                command += ['-run', '^TestDarwinProductRemainsFailClosed$']
            if name == 'darwin-cgo0-private-refusal':
                command += ['-run', DARWIN_CGO0_PRIVATE_PATTERN]
                test_env = refusal_env
            if name == 'darwin-cgo0-deployment-refusal':
                command += ['-run', DARWIN_CGO0_DEPLOYMENT_PATTERN]
                test_env = refusal_env
            if args.darwin_install:
                selected, pattern = DARWIN_INSTALL_SELECTIONS[name]
                command = [str(go), 'test', '-mod=readonly', '-tags', 'agentmux_darwin_install',
                           '-race', '-count=1', '-json', '-timeout=180s', '-run', pattern, package]
            remaining = collection_deadline - time.monotonic()
            if remaining <= 10:
                report['checks'].append({'name': name, 'command': command, 'status': 'unexecuted',
                                         'exitCode': None, 'reason': 'collection_budget_exhausted'})
                checkpoint()
                continue
            started = time.monotonic()
            raw = evidence / (name + '.jsonl')
            errors = evidence / (name + '.stderr.log')
            code = 1
            timed_out = False
            with raw.open('wb') as out, errors.open('wb') as err:
                process = subprocess.Popen(command, cwd=source / 'platform', env=test_env,
                                           stdout=out, stderr=err, start_new_session=True)
                try:
                    code, timed_out = wait_owned(process, min(360, remaining - 5), deadline=collection_deadline)
                except OwnedCleanupError:
                    report['checks'].append({'name': name, 'command': command, 'status': 'failed',
                        'exitCode': None, 'reason': 'owned_process_cleanup_incomplete',
                        'cleanupJoined': False, 'raw': raw.name, 'stderr': errors.name})
                    raise
            item = admit_events(raw.read_text(encoding='utf-8'), code,
                                'github.com/controlLogix/agentmux/platform/' + package[2:])
            if args.darwin_research:
                required = ('TestDarwinUnlinkedDescriptorResearch' if name == 'darwin-descriptor-research'
                            else 'TestDarwinProductRemainsFailClosed')
                item = admit_required_events(raw.read_text(encoding='utf-8'), code, MODULE + '/runtime', (required,))
            if name == 'darwin-cgo0-private-refusal':
                item = admit_required_events(raw.read_text(encoding='utf-8'), code, MODULE + '/privatefs', (DARWIN_CGO0_PRIVATE_TEST,))
                item['scope'] = 'Native CGO0 platform refusal only; not usable private-store or product qualification'
                item['cgoEnabled'] = False
            if name == 'darwin-cgo0-deployment-refusal':
                item = admit_required_events(raw.read_text(encoding='utf-8'), code, MODULE + '/deployment', (DARWIN_CGO0_DEPLOYMENT_TEST,))
                item['scope'] = 'Native CGO0 team-credential refusal only; not private credential usability or native boot qualification'
                item['cgoEnabled'] = False
            if args.darwin_install:
                item = admit_install_events(raw.read_text(encoding='utf-8'), code, selected)
                item['scope'] = ('Protected install/adversary/marker-process fixtures only' if name == 'darwin-protected-install'
                    else 'Installed-host frontend-exit/replacement/owned-stop-and-wait fixtures only') + '; not four-role, NATS, EOF, Compose or phase qualification'
            if timed_out:
                item['status'] = 'failed'
            item.update(name=name, command=command, exitCode=code,
                        timedOut=timed_out,
                        seconds=round(time.monotonic() - started, 3),
                        raw=raw.name, rawSha256=digest(raw), stderr=errors.name, stderrSha256=digest(errors))
            if system == 'darwin' and name == 'runtime':
                item['scope'] = 'Fail-closed refusal only; not runtime boot or research qualification'
            if name == 'boot':
                item['scope'] = ('Real NATS actors and Linux sealed protected-process fixtures; not full Compose/phase acceptance'
                    if system == 'linux' else
                    'Real NATS actor fixtures only; actual native macOS protected-process boot remains unqualified')
            if args.darwin_research:
                item['scope'] = 'Native descriptor research only; actual failure remains failed evidence'
            report['checks'].append(item)
            checkpoint()
        report['sourceUnchangedDuringRun'] = report['sourceHashes'] == source_hashes()
        report['executedSourceUnchangedDuringRun'] = copied == {
            p.relative_to(source).as_posix(): digest(p) for p in source.rglob('*') if p.is_file()}
        report['status'] = 'passed' if (report['sourceUnchangedDuringRun']
            and report['executedSourceUnchangedDuringRun']
            and all(c['status'] == 'passed' for c in report['checks'])) else 'failed'
        report['runtimeQualification'] = 'unqualified' if system == 'darwin' else 'foundation-tests-only'
        if args.darwin_research:
            report['unprotectedImageRefusalObserved'] = (report['status'] == 'passed'
                and report['sourceUnchangedDuringRun'] and report['executedSourceUnchangedDuringRun']
                and any(check['name'] == 'darwin-fail-closed-control'
                    and check['status'] == 'passed' and check['exitCode'] == 0
                    and not check['timedOut'] for check in report['checks']))
        report['collectionComplete'] = all(check['status'] != 'unexecuted' for check in report['checks'])
        if normal_darwin:
            report['cgo0PrivateAccessRefusalObserved'] = report['status'] == 'passed'
            report['cgo0DeploymentRefusalObserved'] = (report['status'] == 'passed'
                and report['sourceUnchangedDuringRun'] and report['executedSourceUnchangedDuringRun']
                and any(check['name'] == 'darwin-cgo0-deployment-refusal'
                    and check['status'] == 'passed' and check['exitCode'] == 0
                    and not check['timedOut'] for check in report['checks']))
        if args.darwin_install:
            report['protectedInstallEvidence'] = report['status'] == 'passed'
            report['installedHostLifecycleEvidence'] = report['status'] == 'passed'
    except Exception as exc:
        # Do not retain network transport text, arbitrary environment values or credentials.
        report['failureType'] = type(exc).__name__
        if isinstance(exc, OwnedCleanupError):
            report['cleanupJoined'] = False
            report['collectionComplete'] = False
            report['ownedProcessExitCode'] = None
            report['cleanupOwnership'] = 'retained exact process; collector exit waits for owned shutdown cleanup'
            report['limits'].append('Cleanup observation is bounded; physical reaping and collector exit are not hard bounded.')
        if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
            planned = (('darwin-descriptor-research', './runtime'), ('darwin-fail-closed-control', './runtime')) if args.darwin_research else FOUNDATION_SCOPES
            if normal_darwin:
                planned += DARWIN_CGO0_SCOPES
            if args.darwin_install:
                planned = DARWIN_INSTALL_SCOPES
            existing = {check['name'] for check in report['checks']}
            for name, package in planned:
                if name not in existing:
                    report['checks'].append({'name': name, 'package': package, 'status': 'unexecuted',
                                             'exitCode': None, 'reason': 'preparation_or_query_timeout'})
        print('Foundation collection failed; inspect the source-bound report and scoped logs.', file=sys.stderr)
    finally:
        checkpoint()
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
