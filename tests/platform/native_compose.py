"""Collect separately enrolled native Compose evidence; never provision an engine."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {'linux-amd64': ('linux', 'amd64'), 'linux-arm64': ('linux', 'arm64'),
           'darwin-amd64': ('darwin', 'amd64'), 'darwin-arm64': ('darwin', 'arm64')}
NAMES = ('TestBootstrapRealDockerIdentityPreflight',
         'TestBootstrapRealDockerConcurrentAbsentInspection',
         'TestBootstrapRealDockerBatchedPreservationInventory',
         'TestBootstrapRealComposeConcurrentColdWarmAndOwnerRecovery')
PATTERN = '^(' + '|'.join(NAMES) + ')$'
PACKAGE = 'github.com/controlLogix/agentmux/platform/launcher'
DOCKER_COHORTS = ('darwin-installed-cli', 'darwin-installed-cli-port', 'darwin-startup-owner',
                  'darwin-installed-cli-slow-consumer')
RUNTIME_FIXTURE_PURPOSE = 'native_runtime_five_member_test_artifact_only'
BUDGET = 40 * 60
HEX = re.compile(r'^[a-f0-9]{64}$')
PRIVATE_MATERIAL = re.compile(rb'-----BEGIN |(?<![A-Za-z0-9_])(?:password|seed|privateKey)\s*[":=]', re.I)
SAFE_FILES = {'fixture.json', 'baseline.json', 'cold-owner-status.json',
              'concurrent-warm.json', 'concurrent-reuse-status.json', 'warm-reuse-status.json', 'recovered-owner-status.json',
              'recovery.json', 'cleanup.json', 'bootstrap-call-results.json',
              'warm-failure.json', 'recovery-failure.json', 'baseline-difference.json',
              'cleanup-unverified.json', 'incomplete-bootstrap-cleanup.json'}
FAILURE_FILES = {'warm-failure.json', 'recovery-failure.json', 'baseline-difference.json',
                 'cleanup-unverified.json', 'incomplete-bootstrap-cleanup.json'}
ROLES = {'boot', 'kernel-lifecycle', 'internal-communication', 'exported-status'}
PRIVATE_GATE_SOURCE = '''package main
import (
 "fmt"
 "os"
 "strconv"
 "strings"
 "syscall"
 "github.com/controlLogix/agentmux/platform/privatefs"
)
func main() {
 args := os.Args[1:]
 if len(args) < 3 { os.Exit(2) }
 for index, arg := range args {
  kind, number, ok := strings.Cut(arg, "=")
  fd, err := strconv.Atoi(number)
  if !ok || err != nil || fd < 3 { os.Exit(2) }
  expectedKind := "ancestor"
  if index >= len(args)-2 { expectedKind = "private" }
  if kind != expectedKind { os.Exit(2) }
  access := privatefs.PublicAncestor
  if kind == "private" { access = privatefs.PrivateObject } else if kind != "ancestor" { os.Exit(2) }
  file := os.NewFile(uintptr(fd), "held-qualification-descriptor")
  if file == nil { os.Exit(3) }
  info, err := file.Stat()
  if err != nil { os.Exit(3) }
  held, ok := info.Sys().(*syscall.Stat_t)
  if !ok || info.Mode() & (os.ModeSetuid | os.ModeSetgid) != 0 { os.Exit(3) }
  if index == len(args)-1 {
   if !info.Mode().IsRegular() || held.Nlink != 1 { os.Exit(3) }
  } else if !info.IsDir() { os.Exit(3) }
  if kind == "private" {
   if held.Uid != uint32(os.Geteuid()) || info.Mode().Perm() & 0077 != 0 { os.Exit(3) }
  } else if (held.Uid != 0 && held.Uid != uint32(os.Geteuid())) || info.Mode().Perm() & 0022 != 0 { os.Exit(3) }
  if privatefs.CheckDescriptor(file, access) != nil { os.Exit(3) }
 }
 fmt.Println("held_private_access_admitted")
}
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def closed_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_json_field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json_constant')))


def absolute(value):
    return isinstance(value, str) and value != '/' and Path(value).is_absolute() and '..' not in Path(value).parts and str(Path(value)) == value and not any(c in value for c in '\x00\r\n')


def read_stable_file(path, maximum):
    if not absolute(str(path)):
        raise ValueError('bounded_file_path_invalid')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError('enrollment_not_bounded_regular_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        held = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if not stat.S_ISREG(held.st_mode) or identity(before) != identity(held) or identity(held) != identity(after) or identity(after) != identity(final) or len(raw) > maximum:
        raise ValueError('enrollment_bytes_or_identity_changed')
    return raw


def read_pinned(path, pin, maximum=32768):
    if not HEX.fullmatch(pin or ''):
        raise ValueError('enrollment_pin_invalid')
    raw = read_stable_file(path, maximum)
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('enrollment_bytes_differ_from_separate_pin')
    return closed_json(raw)


def cohort_groups(cohort):
    if cohort in ('darwin-frontend-budget', 'darwin-normal-self'): return ()
    if cohort in ('darwin-frontend-receipt', 'darwin-creator-history'): return ('frontendReceiptChild',)
    if cohort in ('darwin-runtime-rollback', 'darwin-normal-parent'): return ('runtimeFixture',)
    if cohort == 'darwin-normal-identity': return ('cooperativeIdentity',)
    return ('signedRelease',)


def cohort_tuple(report, selected, prereq):
    return {'sourceCommit': report['sourceCommit'], 'sourceHashes': report['sourceHashes'],
            'selection': selected, 'goSHA256': prereq['goSHA256'], 'natsSHA256': prereq['natsSHA256'],
            'compilerSHA256': prereq['compilerSHA256'], 'compilerVersion': report['compilerVersion'],
            'nativeSDK': report['nativeSDK']}


def json_pin(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def pinned_reference(value):
    if not isinstance(value, dict) or set(value) != {'path', 'sha256'} or not absolute(value['path']):
        raise ValueError('cohort_reference_invalid')
    path = Path(value['path'])
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('cohort_reference_not_private')
    return read_pinned(path, value['sha256'], 128 * 1024)


def validate_cohort_bundle(bundle, cohort, tuple_pin):
    required = cohort_groups(cohort)
    if (not isinstance(bundle, dict) or set(bundle) != {'schemaVersion', 'target', 'currentTupleSHA256', 'groups'}
            or bundle['schemaVersion'] != '2.0.0' or bundle['target'] != 'darwin-arm64'
            or bundle['currentTupleSHA256'] != tuple_pin or not isinstance(bundle['groups'], dict)
            or not set(required) <= set(bundle['groups'])
            or not set(bundle['groups']) <= {'signedRelease', 'frontendReceiptChild', 'cooperativeIdentity', 'runtimeFixture'}):
        raise ValueError('cohort_bundle_scope_or_tuple_invalid')
    admitted = {}
    for name in bundle['groups']:
        group = bundle['groups'][name]
        purpose = RUNTIME_FIXTURE_PURPOSE if name == 'runtimeFixture' else name
        if not isinstance(group, dict) or set(group) != {'purpose', 'plan', 'installationReceipt', 'candidateMatch', 'members', 'policy', 'cliInstallPlan'} or group['purpose'] != purpose:
            raise ValueError('cohort_group_purpose_invalid')
        plan = pinned_reference(group['plan'])
        receipt = pinned_reference(group['installationReceipt'])
        match = pinned_reference(group['candidateMatch'])
        # Separate reviewed attestations bind original installer evidence and
        # current rebuild comparison; neither historical source nor signatures
        # alone establish current-candidate equivalence.
        for record, kind in ((receipt, 'installation'), (match, 'candidateMatch')):
            if (not isinstance(record, dict) or set(record) != {'schemaVersion', 'kind', 'purpose', 'status', 'currentTupleSHA256', 'members', 'evidence'}
                    or record['schemaVersion'] != '1.0.0' or record['kind'] != kind or record['purpose'] != purpose
                    or record['status'] != 'passed' or record['currentTupleSHA256'] != tuple_pin
                    or record['members'] != group['members']):
                raise ValueError('cohort_artifact_attestation_invalid')
            pinned_reference(record['evidence'])
        expected = ({'runtime-fixture', 'bin/boot', 'bin/kernel-lifecycle', 'bin/internal-communication', 'bin/exported-status'} if name == 'runtimeFixture' else
                    {'fixture', 'bin/boot', 'bin/kernel-lifecycle', 'bin/internal-communication', 'bin/exported-status'} if name == 'cooperativeIdentity' else
                    {'agentmux-frontend-receipt-fixture'} if name == 'frontendReceiptChild' else
                    {'release-manifest.json', 'protected-assembly.json', 'release-authorization.json',
                     'release-authorization.sig', 'bin/boot', 'bin/kernel-lifecycle',
                     'bin/internal-communication', 'bin/exported-status', 'agentmux-runtime'})
        if not isinstance(group['members'], dict) or set(group['members']) != expected:
            raise ValueError('cohort_artifact_member_roster_invalid')
        directories = set()
        for relative, member in group['members'].items():
            if not isinstance(member, dict) or set(member) != {'path', 'sha256', 'bytes'} or not absolute(member['path']) or not HEX.fullmatch(member['sha256'] or '') or type(member['bytes']) is not int or not 0 < member['bytes'] <= 128 * 1024 * 1024:
                raise ValueError('cohort_artifact_member_invalid')
            path = Path(member['path'])
            root = path
            for _ in Path(relative).parts: root = root.parent
            if str(root.parent) != '/Library/Application Support/Agentmux/Protected/releases' or not HEX.fullmatch(root.name) or path != root / relative:
                raise ValueError('cohort_artifact_path_invalid')
            directories.add(str(root))
            for ancestor in (root, *root.parents, path.parent):
                info = ancestor.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('cohort_artifact_ancestor_unsafe')
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o222:
                raise ValueError('cohort_artifact_member_unsafe')
            raw = read_stable_file(path, 128 * 1024 * 1024)
            if len(raw) != member['bytes'] or hashlib.sha256(raw).hexdigest() != member['sha256']:
                raise ValueError('cohort_installed_artifact_changed')
        if len(directories) != 1:
            raise ValueError('cohort_artifact_mixed_release')
        if name == 'runtimeFixture' and (plan.get('purpose') != RUNTIME_FIXTURE_PURPOSE
                or plan.get('releaseDirectory') != next(iter(directories))
                or len({(member['sha256'], member['bytes']) for member in group['members'].values()}) != 1):
            raise ValueError('cohort_runtime_fixture_plan_or_image_mismatch')
        if name == 'signedRelease':
            policy = pinned_reference(group['policy'])
            if plan.get('releaseDirectory') != next(iter(directories)) or policy != plan.get('publicTrust'):
                raise ValueError('cohort_signed_policy_plan_mismatch')
            cli = pinned_reference(group['cliInstallPlan'])
            member = group['members']['agentmux-runtime']
            if cli.get('destination') != member['path'] or cli.get('digest') != 'sha256:' + member['sha256'] or cli.get('bytes') != member['bytes']:
                raise ValueError('cohort_cli_plan_mismatch')
        elif group['policy'] is not None or group['cliInstallPlan'] is not None:
            raise ValueError('receipt_child_cannot_supply_release_policy')
        admitted[name] = group
    return admitted


def cohort_environment(base, cohort, groups, output, nats_pin):
    # base is the collector-created whitelist, never ambient os.environ.
    allowed = {'HOME', 'TMPDIR', 'PATH', 'GOTOOLCHAIN', 'GOENV', 'GOWORK', 'GOFLAGS', 'GOPROXY', 'GOSUMDB',
               'GOCACHE', 'GOPATH', 'GOMODCACHE', 'CGO_ENABLED', 'CC', 'SDKROOT', 'CGO_CFLAGS', 'CGO_LDFLAGS',
               'AGENTMUX_TEST_NATS', 'GORACE', 'PYTHONDONTWRITEBYTECODE'}
    env = {k: v for k, v in base.items() if k in allowed}
    if cohort in DOCKER_COHORTS:
        for key in ('DOCKER_CONFIG', 'AMX_BOOTSTRAP_DOCKER_AUTHORIZED', 'AMX_BOOTSTRAP_SELECTION_FILE', 'AMX_BOOTSTRAP_SELECTION_SHA256'):
            env[key] = base[key]
    if 'signedRelease' in cohort_groups(cohort):
        g = groups['signedRelease']
        for suffix, ref in (('PLAN', g['plan']), ('POLICY', g['policy'])):
            env['AMX_DARWIN_ROLE_RELEASE_' + suffix] = ref['path']
            env['AMX_DARWIN_REVIEWED_ROLE_RELEASE_' + suffix] = 'sha256:' + ref['sha256']
        if cohort in ('darwin-signed-role-lifecycle', 'darwin-live-role-recovery'):
            env['AMX_DARWIN_LIFECYCLE_NATS_SHA256'] = 'sha256:' + nats_pin
            env['AGENTMUX_TEST_LIFECYCLE_OUTPUT'] = str(output)
        else:
            env['AMX_DARWIN_CLI_INSTALL_PLAN'] = g['cliInstallPlan']['path']
            env['AMX_DARWIN_CLI_REVIEWED_INSTALL_PLAN'] = 'sha256:' + g['cliInstallPlan']['sha256']
    if 'frontendReceiptChild' in cohort_groups(cohort):
        m = groups['frontendReceiptChild']['members']['agentmux-frontend-receipt-fixture']
        env.update(AMX_DARWIN_FRONTEND_RECEIPT_AUTHORIZED='1', AMX_DARWIN_FRONTEND_RECEIPT_FIXTURE=m['path'],
                   AMX_DARWIN_FRONTEND_RECEIPT_SHA256='sha256:' + m['sha256'])
    if 'runtimeFixture' in cohort_groups(cohort):
        m = groups['runtimeFixture']['members']['runtime-fixture']
        env.update(AGENTMUX_RUNTIME_FIXTURE_AUTHORIZED='1', AGENTMUX_RUNTIME_FIXTURE_PATH=m['path'],
                   AGENTMUX_RUNTIME_FIXTURE_DIGEST='sha256:' + m['sha256'])
    if 'cooperativeIdentity' in cohort_groups(cohort):
        m = groups['cooperativeIdentity']['members']['fixture']
        env.update(AGENTMUX_IDENTITY_FIXTURE_PATH=m['path'], AGENTMUX_IDENTITY_FIXTURE_DIGEST='sha256:' + m['sha256'])
    return env


def collect_cohort_cleanup(home):
    # Do not export arbitrary fixture output or widen the legacy SAFE_FILES.
    directories = sorted((home / '.cache/agentmux-governance').glob('p02-bootstrap-private-*'))
    if not directories:
        raise ValueError('cohort_fixture_cleanup_records_missing')
    records = []
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir() or any((directory / n).exists() for n in FAILURE_FILES):
            raise ValueError('cohort_fixture_cleanup_unknown')
        fixture = clean_safe_json(read_stable_file(directory / 'fixture.json', 512 * 1024))
        cleanup = clean_safe_json(read_stable_file(directory / 'cleanup.json', 512 * 1024))
        container = cleanup.get('containerId', '')
        labels = {'agentmux.instance.id': fixture.get('instanceId'), 'agentmux.profile.id': fixture.get('profileId'),
                  'agentmux.release.digest': fixture.get('releaseDigest'), 'com.docker.compose.project': fixture.get('project')}
        volume = cleanup.get('volume', {})
        if (not HEX.fullmatch(container) or cleanup.get('ownedIDs') != {container: True} or cleanup.get('state') != 'stopped'
                or cleanup.get('volumeRetained') is not True or not timestamp(cleanup.get('at'))
                or volume.get('Name') != fixture.get('project', '') + '_data' or volume.get('Labels') != labels
                or not timestamp(volume.get('CreatedAt'))):
            raise ValueError('cohort_exact_owned_cleanup_invalid')
        network = clean_safe_json(read_stable_file(directory / 'network-cleanup.json', 512 * 1024))
        if (network.get('containerId') != container or network.get('networkRemoved') is not True
                or network.get('emptyBeforeRemoval') is not True or network.get('unrelatedNetworkBaselineUnchanged') is not True
                or network.get('stoppedContainerRetained') is not True):
            raise ValueError('cohort_network_cleanup_invalid')
        records.append({'directory': str(directory), 'files': {n: digest(directory / n) for n in ('fixture.json', 'cleanup.json', 'network-cleanup.json')}})
    return {'status': 'passed', 'cleanupVerified': True, 'privateRecords': records,
            'limits': ['Exact fixture cleanup records plus completed test cleanup; no authority to signal or adopt processes.']}


def run_darwin_cohort(args, report, helpers, selected, prereq, source, home, env, invoke, executed, post_access=None, deadline=None):
    cohort = args.darwin_cohort
    package, tags, budget, names = helpers.DARWIN_COHORTS[cohort]
    report.update(requestedCohorts=[cohort], omittedCohorts=sorted(set(helpers.DARWIN_COHORTS) - {cohort}),
                  cohort={'id': cohort, 'testStatus': 'unexecuted', 'artifactValidationStatus': 'failed', 'status': 'failed'},
                  phaseAccepted=False, separatePrequalification={'runtimeCandidateParent': {
                      'status': 'unqualified', 'historical': True, 'sdkProfile': 'SDK27-candidate',
                      'reason': 'Historical candidate-parent diagnostics only; never credited to normal SDK cohorts.',
                      'tests': ['TestRuntimeCandidateParentEOFStopsActualChild',
                                'TestRuntimeCandidateParentInheritedLeasesLastUntilOwnedReap']}})
    item = report['cohort']
    report['limits'] = ['Explicit native macOS ARM64 named cohort only; not full P02 acceptance.',
                        'Consumes separately installed prerequisites; never builds an installer, elevates or enables a diagnostic ABI.',
                        'Historical evidence and omitted cohorts remain separate and unqualified.',
                        'Event parentage checks prove top-level ownership only; nested T.Run parentage is not inferred from slash-containing names.']
    tuple_pin = json_pin(cohort_tuple(report, selected, prereq))
    report['currentTupleSHA256'] = tuple_pin
    groups = {}
    bundle = None
    if args.cohort_prerequisites is not None:
        bundle = pinned_reference({'path': str(args.cohort_prerequisites), 'sha256': args.cohort_prerequisites_sha256})
        groups = validate_cohort_bundle(bundle, cohort, tuple_pin)
    elif cohort_groups(cohort):
        raise ValueError('cohort_installed_prerequisites_required')
    item.update(prerequisiteGroups=list(groups), prerequisiteBundleSHA256=args.cohort_prerequisites_sha256,
                artifactValidationStatus='passed', currentTupleSHA256=tuple_pin)
    output = args.workspace / 'lifecycle-output'; output.mkdir(mode=0o700)
    test_env = cohort_environment(env, cohort, groups, output, prereq['natsSHA256'])
    env.clear(); env.update(test_env)
    inventory_command = [prereq['goExecutable'], 'list', '-mod=readonly']
    if tags: inventory_command += ['-tags', tags]
    raw = successful(invoke(inventory_command + ['-json', package], 'cohort-inventory', 60))
    item['selectionInventory'] = helpers.validate_cohort_inventory(raw, source / 'platform', cohort)
    if cohort in DOCKER_COHORTS:
        private = invoke([prereq['goExecutable'], 'test', '-race', '-mod=readonly', '-count=1', '-timeout=5m', '-json', './privatefs'], 'cohort-privatefs', 360)
        report['privateFilesystem'] = admit_native_events(private['stdout'].read_text(), private['exitCode'], helpers.MODULE + '/privatefs')
        if private['timedOut'] or report['privateFilesystem']['status'] != 'passed':
            raise ValueError('native_private_filesystem_checks_failed')
    command = [prereq['goExecutable'], 'test', '-race', '-failfast', '-mod=readonly', '-count=1', '-json', '-timeout=' + str(budget) + 's']
    if tags: command += ['-tags', tags]
    command += ['-run', helpers.cohort_pattern(names), package]
    item['command'] = command
    if deadline is not None and deadline - time.monotonic() <= budget + 30:
        raise ValueError('cohort_full_package_budget_unavailable_before_effects')
    # Checkpoint and retain the existing engine owner before any fixture effect.
    if cohort in DOCKER_COHORTS:
        args.engine_lease.mark_started(args.candidate_commit)
    report['effectsMayBeLive'] = True
    helpers.atomic_report(args.evidence / 'result.json', report)
    result = invoke(command, 'cohort-tests', budget + 30)
    for key in ('stdout', 'stderr'): result[key].chmod(0o600)
    raw, stderr = result['stdout'].read_text(), result['stderr'].read_text()
    admission = helpers.admit_cohort_events(raw, stderr, result['exitCode'], helpers.MODULE + '/' + package[2:], names)
    if result['timedOut']: admission['status'] = 'failed'
    item.update(testStatus=admission['status'], admission=admission, timedOut=result['timedOut'], exitCode=result['exitCode'],
                rawOutputs={k: {'path': str(result[k]), 'sha256': digest(result[k]), 'bytes': result[k].stat().st_size} for k in ('stdout', 'stderr')})
    if cohort in DOCKER_COHORTS:
        report['installedCLI'] = {'status': admission['status'], 'cohort': cohort, 'scope': 'Named tests only; artifact and cleanup admission remain separate.'}
    helpers.atomic_report(args.evidence / 'result.json', report)
    if admission['status'] != 'passed':
        raise ValueError('cohort_tests_failed_no_retry')
    if cohort in DOCKER_COHORTS:
        item['cleanup'] = collect_cohort_cleanup(home)
    else:
        item['cleanup'] = {'status': 'passed', 'basis': 'All selected tests and registered cleanups completed without failure; no separate process census.'}
    item['artifactValidationStatus'] = 'failed'
    if bundle is not None and (pinned_reference({'path': str(args.cohort_prerequisites), 'sha256': args.cohort_prerequisites_sha256}) != bundle
                               or validate_cohort_bundle(bundle, cohort, tuple_pin) != groups):
        item['artifactValidationStatus'] = 'failed'
        raise ValueError('cohort_artifacts_changed')
    if post_access is not None: post_access('cohort-held-access-after-effects')
    verify_files(prereq, selected)
    if (source_hashes() != report['sourceHashes'] or executed != {p.relative_to(source).as_posix(): digest(p) for p in source.rglob('*') if p.is_file()}
            or read_pinned(args.selection, args.selection_sha256, 16384) != selected
            or read_pinned(args.prerequisites, args.prerequisites_sha256) != prereq):
        raise ValueError('cohort_source_or_enrollment_changed')
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() != args.candidate_commit or subprocess.check_output(['git', 'status', '--porcelain', '--', 'platform', 'contracts/v1', 'sdk/python', 'tests/platform', '.github/workflows/platform-compose.yml'], cwd=ROOT):
        raise ValueError('cohort_committed_candidate_changed')
    if args.engine_lease is not None:
        args.engine_lease.verified_cleanup()
    item.update(status='passed', artifactValidationStatus='passed')
    report.update(status='passed', effectsMayBeLive=False, sourceUnchangedDuringRun=True, executedSourceUnchangedDuringRun=True,
                  enrollmentUnchangedDuringRun=True, preparedToolsUnchangedDuringRun=True)
    report['limits'].append('Only the named cohort passed; omitted cohorts and full P02 remain unqualified. Private raw outputs remain in the owned workspace.')


def native_host():
    system = {'Linux': 'linux', 'Darwin': 'darwin'}.get(platform.system())
    arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
    if system is None or arch is None or 'microsoft' in platform.release().lower():
        raise ValueError('actual_host_not_supported_native_target')
    if os.geteuid() == 0:
        raise ValueError('runtime_must_not_run_as_root')
    return system, arch


def validate_selection(selected, target, host, workspace):
    expected = {'schemaVersion', 'target', 'goos', 'goarch', 'workspaceRoot', 'docker', 'image', 'natsVersion', 'compiler', 'sdkRoot'}
    docker_keys = {'backend', 'executable', 'context', 'endpoint', 'engineId', 'clientVersion', 'serverVersion', 'composeVersion'}
    if target not in TARGETS or TARGETS[target] != host or not isinstance(selected, dict) or set(selected) != expected:
        raise ValueError('selection_target_or_fields_invalid')
    d = selected['docker']
    if not isinstance(d, dict) or set(d) != docker_keys or any(not isinstance(v, str) for v in d.values()) or any(not isinstance(v, str) for k, v in selected.items() if k != 'docker'):
        raise ValueError('selection_field_types_invalid')
    system, arch = host
    endpoint = d['endpoint']
    if selected['schemaVersion'] != '1.0.0' or selected['target'] != 'native-' + system or selected['goos'] != system or selected['goarch'] != arch or selected['workspaceRoot'] != str(workspace / 'source') or not absolute(selected['workspaceRoot']):
        raise ValueError('selection_workspace_or_native_target_invalid')
    if d['backend'] != 'native-unix' or not absolute(d['executable']) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', d['context']) or d['context'] == 'default' or not endpoint.startswith('unix:///') or not absolute(endpoint[7:]) or any(c in endpoint for c in '%?#'):
        raise ValueError('selection_local_engine_invalid')
    if not re.fullmatch(r'[^\s\x00]{1,128}', d['engineId']) or any(not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', d[k]) for k in ('clientVersion', 'serverVersion', 'composeVersion')) or d['composeVersion'] != '5.5.1' or selected['natsVersion'] != '2.15.0' or not re.fullmatch(r'docker.io/library/nats@sha256:[a-f0-9]{64}', selected['image']):
        raise ValueError('selection_versions_or_image_invalid')
    if system == 'linux' and (selected['compiler'] or selected['sdkRoot']):
        raise ValueError('linux_kernel_build_selection_invalid')
    if system == 'darwin' and (selected['compiler'] != '/usr/bin/clang' or not absolute(selected['sdkRoot']) or not selected['sdkRoot'].endswith('.sdk') or any(c in selected['sdkRoot'] for c in '"\\')):
        raise ValueError('darwin_kernel_build_selection_invalid')
    return selected


def validate_prerequisites(record, target):
    keys = {'schemaVersion', 'target', 'goExecutable', 'goSHA256', 'natsExecutable', 'natsSHA256',
            'dockerExecutableSHA256', 'compilerExecutable', 'compilerSHA256', 'dockerConfig',
            'dockerConfigHashes', 'darwinProtectedInstallAuthorized', 'moduleCache', 'qualificationLockDirectory'}
    if not isinstance(record, dict) or set(record) != keys or record['schemaVersion'] != '1.0.0' or record['target'] != target or type(record['darwinProtectedInstallAuthorized']) is not bool:
        raise ValueError('prerequisites_fields_or_target_invalid')
    for key in ('goExecutable', 'natsExecutable', 'compilerExecutable', 'dockerConfig', 'moduleCache', 'qualificationLockDirectory'):
        if not absolute(record[key]):
            raise ValueError('prerequisites_path_invalid')
    for key in ('goSHA256', 'natsSHA256', 'dockerExecutableSHA256', 'compilerSHA256'):
        if not isinstance(record[key], str) or not HEX.fullmatch(record[key]):
            raise ValueError('prerequisites_executable_pin_invalid')
    files = record['dockerConfigHashes']
    if not isinstance(files, dict) or not files or 'config.json' not in files:
        raise ValueError('minimal_docker_config_inventory_missing')
    for name, pin in files.items():
        if not isinstance(name, str) or not (name == 'config.json' or re.fullmatch(r'contexts/meta/[a-f0-9]{64}/meta.json', name) or name == 'cli-plugins/docker-compose') or not isinstance(pin, str) or not HEX.fullmatch(pin):
            raise ValueError('minimal_docker_config_inventory_invalid')
    return record


class EngineLease:
    """Serialize an enrolled engine and retain uncertainty across collector death."""
    def __init__(self, directory, engine_id):
        import fcntl
        self.fd = None
        self.token = None
        self.ancestor_fds = []
        entry = directory.lstat()
        if directory.resolve() != directory or not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or entry.st_mode & 0o077:
            raise ValueError('persistent_engine_lock_directory_not_private')
        key = hashlib.sha256(engine_id.encode()).hexdigest()
        self.marker = directory / (key + '.unknown.json')
        try:
            for part in ('/', *directory.parts[1:]):
                ancestor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=self.ancestor_fds[-1] if self.ancestor_fds else None)
                self.ancestor_fds.append(ancestor)
                info = os.fstat(ancestor)
                if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022 or info.st_mode & 0o6000:
                    raise ValueError('persistent_lock_ancestor_not_safe')
            self.directory_fd = self.ancestor_fds[-1]
            held_directory = os.fstat(self.directory_fd)
            if (entry.st_dev, entry.st_ino) != (held_directory.st_dev, held_directory.st_ino):
                raise ValueError('persistent_lock_directory_substituted')
            fd = os.open(key + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=self.directory_fd)
        except BaseException:
            self.close(); raise
        try:
            held = os.fstat(fd)
            if not stat.S_ISREG(held.st_mode) or held.st_uid != os.geteuid() or held.st_nlink != 1 or held.st_mode & 0o077:
                raise ValueError('engine_lock_identity_invalid')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if self.marker.exists() or self.marker.is_symlink():
                raise ValueError('previous_engine_cleanup_unknown_requires_owner_recovery')
            self.fd = fd
        except BaseException:
            os.close(fd)
            self.close()
            raise

    def access_descriptors(self):
        return [*self.ancestor_fds, self.fd]

    def access_arguments(self):
        return [('private=' if index == len(self.ancestor_fds) - 1 else 'ancestor=') + str(fd)
                for index, fd in enumerate(self.ancestor_fds)] + ['private=' + str(self.fd)]

    def mark_started(self, candidate):
        self.token = hashlib.sha256(os.urandom(32)).hexdigest()
        raw = json.dumps({'token': self.token, 'candidate': candidate, 'cleanup': 'unknown_until_verified'}).encode()
        fd = os.open(self.marker.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.directory_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fsync(self.directory_fd)

    def verified_cleanup(self):
        before = os.stat(self.marker.name, dir_fd=self.directory_fd, follow_symlinks=False)
        if self.token is None or not stat.S_ISREG(before.st_mode):
            raise ValueError('owned_engine_marker_changed_cleanup_not_admitted')
        fd = os.open(self.marker.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.directory_fd)
        with os.fdopen(fd, 'rb') as stream:
            held = os.fstat(stream.fileno()); value = closed_json(stream.read(32769))
        after = os.stat(self.marker.name, dir_fd=self.directory_fd, follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns) or (held.st_dev, held.st_ino) != (after.st_dev, after.st_ino) or value.get('token') != self.token:
            raise ValueError('owned_engine_marker_changed_cleanup_not_admitted')
        os.unlink(self.marker.name, dir_fd=self.directory_fd)
        os.fsync(self.directory_fd)
        self.token = None

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None
        for fd in reversed(self.ancestor_fds): os.close(fd)
        self.ancestor_fds = []


def source_hashes():
    paths = [ROOT / 'tests/platform/native_compose.py', ROOT / 'tests/platform/native_go.py', ROOT / '.github/workflows/platform-compose.yml']
    paths.extend(sorted((ROOT / 'tests/platform').glob('test_native_cohorts*.py')))
    for folder in ('platform', 'contracts/v1', 'sdk/python'):
        for p in (ROOT / folder).rglob('*'):
            if '__pycache__' in p.parts or p.suffix in ('.pyc', '.pyo'): continue
            if p.is_symlink(): raise ValueError('candidate_source_symlink_refused')
            if p.is_file(): paths.append(p)
    return {p.relative_to(ROOT).as_posix(): digest(p) for p in paths}


def load_helpers():
    # Importing the reviewed collector does not invoke its main or preparation.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('agentmux_native_go_helpers', ROOT / 'tests/platform/native_go.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sdk_dependencies(source_root):
    versions = {}
    for line in (source_root / 'sdk/python/requirements.lock').read_text().splitlines():
        if not re.fullmatch(r'[A-Za-z0-9_-]+==[0-9]+(?:\.[0-9]+)+', line):
            raise ValueError('sdk_dependency_lock_invalid')
        name, expected = line.split('==')
        observed = importlib.metadata.version(name)
        if observed != expected: raise ValueError('prepared_sdk_dependencies_differ_from_lock')
        versions[name] = observed
    return versions


def load_status_sdk(source_root):
    sdk_dependencies(source_root)
    sys.dont_write_bytecode = True
    name = '_agentmux_native_compose_sdk_' + hashlib.sha256(str(source_root).encode()).hexdigest()[:16]
    package = source_root / 'sdk/python/agentmux_contracts'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, package / '__init__.py', submodule_search_locations=[str(package)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try: spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None); raise
    module = sys.modules[name]
    # Empty input must reach a configured local validator and fail its shape.
    try: module.validate('startup-status-observation', {}, schema_dir=source_root / 'contracts/v1/schemas')
    except module.ContractError as error:
        if str(error) != 'schema_invalid': raise ValueError('offline_l04_validator_preflight_failed') from None
    else: raise ValueError('offline_l04_validator_did_not_reject_empty_shape')
    return module


def validate_status_shape(value, source_root):
    try:
        load_status_sdk(source_root).validate('startup-status-observation', value, schema_dir=source_root / 'contracts/v1/schemas')
    except Exception:
        raise ValueError('complete_l04_status_shape_invalid') from None


def validate_inventory(raw, sources, names=NAMES):
    objects = []
    decoder = json.JSONDecoder()
    text = raw.strip()
    while text:
        item, end = decoder.raw_decode(text)
        objects.append(item); text = text[end:].lstrip()
    if len(objects) != 1 or objects[0].get('ImportPath') != PACKAGE:
        raise ValueError('tagged_launcher_inventory_invalid')
    item = objects[0]
    files = item.get('TestGoFiles', []) + item.get('XTestGoFiles', [])
    declared = []
    for name in files:
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError('inventory_file_invalid')
        path = sources / 'platform/launcher' / name
        declared.extend(re.findall(r'^func (Test\w+)\(t \*testing.T\)', path.read_text(), re.M))
    if any(declared.count(name) != 1 for name in names):
        raise ValueError('selected_compose_declaration_missing_or_duplicate')
    return {'package': PACKAGE, 'files': files, 'requiredTests': list(names)}


def clean_safe_json(raw):
    if len(raw) > 512 * 1024 or PRIVATE_MATERIAL.search(raw):
        raise ValueError('artifact_private_or_oversized')
    value = closed_json(raw)
    if not isinstance(value, dict):
        raise ValueError('artifact_not_object')
    return value


def valid_apple_compiler(value):
    return bool(re.match(r'^Apple clang version [0-9]+(?:\.[0-9]+){1,2}(?:\s|$)', value))


def admit_native_events(raw, code, package, required=None):
    helpers = load_helpers()
    result = (helpers.admit_required_events(raw, code, package, required) if required is not None
              else helpers.admit_events(raw, code, package))
    started = ended = False
    complete = True
    try:
        for line in raw.splitlines():
            if not line.strip(): continue
            event = closed_json(line)
            if not isinstance(event, dict) or event.get('Package') != package or ended:
                complete = False; continue
            action = event.get('Action')
            if action not in ('start', 'run', 'pause', 'cont', 'output', 'pass', 'fail', 'skip') or (not event.get('Test') and action not in ('start', 'output', 'pass', 'fail', 'skip')):
                complete = False
            if action == 'start' and not event.get('Test'):
                if started: complete = False
                started = True
            else:
                if not started: complete = False
                if not event.get('Test') and action in ('pass', 'fail', 'skip'): ended = True
    except (ValueError, TypeError): complete = False
    result['completePackageLifecycle'] = complete and started and ended
    if not result['completePackageLifecycle']: result['status'] = 'failed'
    return result


def validate_fixture_records(found, selected, selection_pin, engine, source_root=ROOT):
    required = {'fixture.json', 'baseline.json', 'cold-owner-status.json', 'concurrent-reuse-status.json',
                'warm-reuse-status.json', 'recovered-owner-status.json', 'concurrent-warm.json', 'recovery.json', 'cleanup.json'}
    if selected is None or engine is None or not required <= found.keys() or FAILURE_FILES & found.keys():
        raise ValueError('fixture_records_or_expected_bindings_missing')
    fixture = found['fixture.json']; d = selected['docker']
    expected = {'target': selected['target'], 'selectionPin': selection_pin, 'actualGOOS': selected['goos'],
                'actualGOARCH': selected['goarch'], 'actualWSL': False, 'dockerBackend': 'native-unix',
                'engineId': d['engineId'], 'image': selected['image'], 'cachedImageId': engine['imageId'],
                'goVersion': 'go1.27.2', 'kernelCGOEnabled': selected['goos'] == 'darwin',
                'protectedInstallRetained': selected['goos'] == 'darwin', 'privateConfigRetained': True,
                'expectedVersions': {'Client': d['clientVersion'], 'Server': d['serverVersion'], 'Compose': d['composeVersion']}}
    if any((fixture.get(k) is not v) if type(v) is bool else fixture.get(k) != v for k, v in expected.items()):
        raise ValueError('fixture_enrollment_or_native_identity_differs')
    for key, pattern in (('instanceId', r'instance_[a-f0-9]{32}'), ('profileId', r'profile_[a-f0-9]{32}'),
                         ('project', r'amx-p02-bootstrap-[a-f0-9]{16}'), ('releaseDigest', r'sha256:[a-f0-9]{64}'),
                         ('kernelBinaryDigest', r'sha256:[a-f0-9]{64}')):
        if not re.fullmatch(pattern, fixture.get(key, '')): raise ValueError('fixture_identity_incomplete')
    if type(fixture.get('hostPort')) is not int or not 0 < fixture['hostPort'] < 65536:
        raise ValueError('fixture_port_invalid')
    def timestamp(value):
        if not isinstance(value, str): return False
        try: return datetime.fromisoformat(value.replace('Z', '+00:00')).utcoffset() is not None
        except ValueError: return False
    for name, disposition, readiness in (('cold-owner-status.json', 'started', 'ready'),
                                        ('concurrent-reuse-status.json', 'reused', 'unknown'),
                                        ('warm-reuse-status.json', 'reused', 'unknown'),
                                        ('recovered-owner-status.json', 'started', 'ready')):
        record = found[name]; instance = record.get('instance', {}); persistence = record.get('persistence', {})
        validate_status_shape(record, source_root)
        if record.get('schemaVersion') != '1.0.0' or record.get('disposition') != disposition or type(record.get('sourceRevision')) is not int or record['sourceRevision'] < 1 or not timestamp(record.get('observedAt')) or not re.fullmatch(r'attempt_[a-f0-9]{32}', record.get('startupAttemptId', '')):
            raise ValueError('public_status_envelope_incomplete')
        for key, value in {'instanceId': fixture['instanceId'], 'profileId': fixture['profileId'],
                           'composeProject': fixture['project'], 'contextDisplayName': d['context'],
                           'endpoint': 'tls://127.0.0.1:' + str(fixture['hostPort']), 'readiness': 'degraded'}.items():
            if instance.get(key) != value: raise ValueError('public_status_identity_or_readiness_differs')
        if persistence.get('profile') != fixture['profileId'] or persistence.get('readiness') != readiness or persistence.get('backend') != 'nats_jetstream' or record.get('work', {}).get('state') != 'unavailable' or record.get('hubs', {}).get('inventoryState') != 'unavailable':
            raise ValueError('public_status_persistence_or_unavailable_state_differs')
    baseline = found['baseline.json']
    for identity, item in baseline.items():
        if not HEX.fullmatch(identity) or not isinstance(item, dict) or set(item) != {'Id', 'State', 'DeclaredPorts', 'ActivePorts'} or item['Id'] != identity or item['State'] not in ('created', 'restarting', 'running', 'removing', 'paused', 'exited', 'dead'):
            raise ValueError('baseline_identity_or_projection_incomplete')
        for key in ('DeclaredPorts', 'ActivePorts'):
            ports = item[key]
            if ports is None: continue
            if not isinstance(ports, dict): raise ValueError('baseline_port_map_invalid')
            for port, bindings in ports.items():
                if not isinstance(port, str) or not re.fullmatch(r'[0-9]+/(?:tcp|udp|sctp)', port):
                    raise ValueError('baseline_port_key_invalid')
                if bindings is None: continue
                if not isinstance(bindings, list): raise ValueError('baseline_port_bindings_invalid')
                for binding in bindings:
                    if not isinstance(binding, dict) or set(binding) != {'HostIp', 'HostPort'} or any(not isinstance(v, str) for v in binding.values()):
                        raise ValueError('baseline_port_binding_projection_incomplete')
    guards = [v for k, v in found.items() if k.startswith('baseline-guard-')]
    if not guards or any(v.get('unchanged') is not True or type(v.get('existingContainerCount')) is not int or v.get('existingContainerCount') != len(baseline) or not timestamp(v.get('at')) for v in guards):
        raise ValueError('baseline_guard_evidence_incomplete')
    warm = found['concurrent-warm.json']; recovery = found['recovery.json']; cleanup = found['cleanup.json']
    for key in ('sameContainerAfterWarm', 'sameKernelIncarnationAfterWarm', 'originalPersistenceRecordRetained'):
        if warm.get(key) is not True: raise ValueError('warm_preservation_incomplete')
    if any(type(warm.get(k)) is not int for k in ('startedSessions', 'reusedConcurrentSessions', 'retainedRoleLeases')) or warm.get('startedSessions') != 1 or warm.get('reusedConcurrentSessions') != 1 or warm.get('retainedRoleLeases') != 4:
        raise ValueError('concurrent_owner_or_role_leases_incomplete')
    for key in ('kernelIncarnationChanged', 'sameContainerAfterRecovery', 'originalPersistenceRecordRetained'):
        if recovery.get(key) is not True: raise ValueError('recovery_preservation_incomplete')
    if recovery.get('cleanupError') is not False or recovery.get('retainedRoleLeasesReleased') != 4:
        raise ValueError('recovery_cleanup_or_leases_incomplete')
    def children(rows, exited):
        if not isinstance(rows, list) or len(rows) != 4 or {r.get('Role') for r in rows if isinstance(r, dict)} != ROLES:
            raise ValueError('exact_four_role_children_missing')
        if any(type(r.get('PID')) is not int or r['PID'] < 1 or r.get('Exited') is not exited or type(r.get('ExitCode')) is not int for r in rows) or len({r['PID'] for r in rows}) != 4:
            raise ValueError('child_identity_or_reaping_incomplete')
        return {(r['Role'], r['PID']) for r in rows}
    if children(warm.get('liveProtectedChildren'), False) != children(recovery.get('originalChildrenReaped'), True) or children(recovery.get('recoveredLiveChildren'), False) != children(recovery.get('recoveredChildrenReaped'), True):
        raise ValueError('child_reaping_identity_changed')
    container = cleanup.get('containerId', '')
    if not HEX.fullmatch(container) or not isinstance(cleanup.get('ownedIDs'), dict) or set(cleanup['ownedIDs']) != {container} or cleanup['ownedIDs'][container] is not True or cleanup.get('state') != 'stopped' or cleanup.get('volumeRetained') is not True or not timestamp(cleanup.get('at')):
        raise ValueError('exact_owned_container_stop_incomplete')
    volume = cleanup.get('volume', {})
    labels = {'agentmux.instance.id': fixture['instanceId'], 'agentmux.profile.id': fixture['profileId'],
              'agentmux.release.digest': fixture['releaseDigest'], 'com.docker.compose.project': fixture['project']}
    if volume.get('Name') != fixture['project'] + '_data' or not timestamp(volume.get('CreatedAt')) or volume.get('Labels') != labels:
        raise ValueError('retained_volume_identity_incomplete')


def collect_fixture_artifacts(home, evidence, selected=None, selection_pin=None, engine=None, source_root=ROOT):
    base = home / '.cache/agentmux-governance'
    dirs = [] if not base.exists() else list(base.glob('p02-bootstrap-private-*'))
    if len(dirs) != 1 or dirs[0].is_symlink() or not dirs[0].is_dir():
        raise ValueError('fixture_tree_missing_ambiguous_or_substituted')
    directory = dirs[0]
    found = {}
    destination = evidence / 'fixture'
    destination.mkdir(mode=0o700)
    for file in directory.iterdir():
        name = file.name
        if name not in SAFE_FILES and not re.fullmatch(r'baseline-guard-[a-f0-9]{8}.json', name):
            continue
        if file.is_symlink() or not file.is_file():
            raise ValueError('fixture_artifact_not_regular')
        raw = read_stable_file(file, 512 * 1024)
        value = clean_safe_json(raw)
        found[name] = value
        (destination / name).write_bytes(raw)
    validate_fixture_records(found, selected, selection_pin, engine, source_root)
    return {'files': {p.name: digest(p) for p in destination.iterdir()}, 'cleanupVerified': True,
            'limits': ['Owner recovery is lifetime-context cancellation, not abrupt host death.', 'Private fixtures, volumes and protected versions remain retained.']}


def run_command(command, cwd, env, deadline, workspace, helpers, label, maximum=30, pass_fds=()):
    stdout, stderr = workspace / (label + '.stdout'), workspace / (label + '.stderr')
    remaining = helpers.remaining_timeout(deadline, maximum)
    with stdout.open('wb') as out, stderr.open('wb') as err:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True, pass_fds=pass_fds)
        code, timed_out = helpers.wait_owned(child, remaining)
    if stdout.stat().st_size > 64 * 1024 * 1024 or stderr.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('subprocess_output_oversized')
    return {'command': command, 'exitCode': code, 'timedOut': timed_out,
            'stdout': stdout, 'stderr': stderr}


def successful(result):
    if result['exitCode'] != 0 or result['timedOut']:
        raise ValueError('prerequisite_command_failed_or_timed_out')
    return result['stdout'].read_text().strip()


def completion_admitted(report):
    return (report.get('sourceUnchangedDuringRun') is True
        and report.get('persistentLockAccessAdmitted') is True
        and report.get('executedSourceUnchangedDuringRun') is True
        and report.get('enrollmentUnchangedDuringRun') is True
        and report.get('preparedToolsUnchangedDuringRun') is True
        and report.get('privateFilesystem', {}).get('status') == 'passed'
        and report.get('composeTests', {}).get('status') == 'passed'
        and report.get('composeTests', {}).get('timedOut') is False
        and report.get('fixtureArtifacts', {}).get('cleanupVerified') is True
        and bool(report.get('commands'))
        and all(c.get('status') == 'completed' and c.get('exitCode') == 0 and c.get('timedOut') is False for c in report['commands']))


def verify_files(prereq, selected):
    for path, pin in [(prereq['goExecutable'], prereq['goSHA256']), (prereq['natsExecutable'], prereq['natsSHA256']), (selected['docker']['executable'], prereq['dockerExecutableSHA256']), (prereq['compilerExecutable'], prereq['compilerSHA256'])]:
        p = Path(path)
        if not p.is_file() or p.is_symlink() or digest(p) != pin or not os.access(p, os.X_OK):
            raise ValueError('prepared_tool_changed_or_unavailable')
    directory = Path(prereq['dockerConfig'])
    actual = {}
    for p in directory.rglob('*'):
        if p.is_symlink():
            raise ValueError('docker_configuration_symlink_refused')
        if p.is_file():
            actual[p.relative_to(directory).as_posix()] = digest(p)
    if actual != prereq['dockerConfigHashes']:
        raise ValueError('docker_configuration_differs_from_enrollment')
    config = closed_json((directory / 'config.json').read_bytes())
    if config not in ({}, {'auths': {}}):
        raise ValueError('docker_auth_or_ambient_configuration_refused')


def qualify(args, report, helpers):
    host = native_host()
    selected = validate_selection(read_pinned(args.selection, args.selection_sha256, 16384), args.target, host, args.workspace)
    prereq = validate_prerequisites(read_pinned(args.prerequisites, args.prerequisites_sha256), args.target)
    report['selectionSHA256'] = args.selection_sha256
    report['prerequisitesSHA256'] = args.prerequisites_sha256
    report['actualTarget'] = '/'.join(host)
    report['hostVersion'] = platform.mac_ver()[0] if host[0] == 'darwin' else platform.release()
    report['executionUID'] = os.geteuid()
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'AMX_DOCKER_FIXTURE', 'AMX_BROKER_INSPECT_FIXTURE', 'AMX_OWNER_BRIDGE_DOCKER_FIXTURE', 'AGENTMUX_NATS_SERVER'):
        if os.environ.get(key):
            raise ValueError('ambient_engine_or_inspector_override_refused')
    cohort = getattr(args, 'darwin_cohort', None)
    if cohort and host != ('darwin', 'arm64'):
        raise ValueError('cohort_requires_native_darwin_arm64')
    if not cohort and host[0] == 'darwin' and (not args.allow_protected_fixture_install or not prereq['darwinProtectedInstallAuthorized']):
        raise ValueError('protected_mac_fixture_install_not_authorized')
    branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT, text=True).strip()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not branch:
        permitted = subprocess.check_output(['git', 'rev-parse', 'refs/remotes/origin/feat/agentmux-platform-rearchitecture'], cwd=ROOT, text=True).strip()
        if permitted != commit:
            raise ValueError('detached_candidate_not_feature_branch_head')
    elif branch != 'feat/agentmux-platform-rearchitecture':
        raise ValueError('candidate_branch_not_authorized')
    if commit != args.candidate_commit or subprocess.check_output(['git', 'status', '--porcelain', '--', 'platform', 'contracts/v1', 'sdk/python', 'tests/platform/native_go.py', 'tests/platform/native_compose.py', '.github/workflows/platform-compose.yml'], cwd=ROOT):
        raise ValueError('candidate_branch_commit_or_source_not_clean')
    if cohort and subprocess.check_output(['git', 'status', '--porcelain', '--', 'tests/platform'], cwd=ROOT):
        raise ValueError('cohort_collector_sources_not_clean')
    report['sourceCommit'] = commit
    report['sourceHashes'] = source_hashes()
    report['sdkDependencies'] = sdk_dependencies(ROOT)
    report['pythonVersion'] = sys.version
    verify_files(prereq, selected)
    docker_cohort = cohort in DOCKER_COHORTS
    args.engine_lease = (EngineLease(Path(prereq['qualificationLockDirectory']), selected['docker']['engineId'])
                         if not cohort or docker_cohort else None)
    source = args.workspace / 'source'
    for folder in ('platform', 'contracts/v1', 'sdk/python'):
        shutil.copytree(ROOT / folder, source / folder, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
    executed = {p.relative_to(source).as_posix(): digest(p) for p in source.rglob('*') if p.is_file()}
    if executed != {p: v for p, v in report['sourceHashes'].items() if p.startswith(('platform/', 'contracts/v1/', 'sdk/python/'))}:
        raise ValueError('executed_copy_does_not_match_candidate')
    report['executedSourceHashes'] = executed
    load_status_sdk(source)
    report['offlineStatusValidatorPreflight'] = 'passed'
    home = args.workspace / 'home'; home.mkdir(mode=0o700)
    env = {'HOME': str(home), 'TMPDIR': str(home), 'PATH': str(Path(prereq['goExecutable']).parent) + os.pathsep + os.defpath,
           'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '', 'GOPROXY': 'off', 'GOSUMDB': 'off',
           'GOCACHE': str(args.workspace / 'go-cache'), 'GOPATH': str(args.workspace / 'go-path'), 'GOMODCACHE': prereq['moduleCache'],
           'CGO_ENABLED': '1', 'CC': prereq['compilerExecutable'], 'DOCKER_CONFIG': prereq['dockerConfig'],
           'AGENTMUX_TEST_NATS': prereq['natsExecutable'], 'AMX_BOOTSTRAP_DOCKER_AUTHORIZED': '1',
           'AMX_BOOTSTRAP_SELECTION_FILE': str(args.selection), 'AMX_BOOTSTRAP_SELECTION_SHA256': args.selection_sha256,
           'GORACE': 'atexit_sleep_ms=0', 'PYTHONDONTWRITEBYTECODE': '1'}
    # The fixtures refuse the ambient server override but use AGENTMUX_TEST_NATS for owned test brokers.
    if host[0] == 'darwin':
        if prereq['compilerExecutable'] != '/usr/bin/clang' or not Path(selected['sdkRoot']).is_dir():
            raise ValueError('native_apple_compiler_or_sdk_unavailable')
        env.update(SDKROOT=selected['sdkRoot'], AMX_DARWIN_INSTALL_AUTHORIZED='1',
                   CGO_CFLAGS='-isysroot "' + selected['sdkRoot'] + '"', CGO_LDFLAGS='-isysroot "' + selected['sdkRoot'] + '"')
    deadline = time.monotonic() + (helpers.DARWIN_COHORTS[cohort][2] + 600 if cohort else BUDGET)
    calls = 0
    def invoke(command, label, maximum=30, pass_fds=()):
        nonlocal calls
        calls += 1
        started = time.monotonic()
        record = {'name': label, 'argv': command, 'status': 'running', 'exitCode': None, 'timedOut': None}
        report.setdefault('commands', []).append(record)
        helpers.atomic_report(args.evidence / 'result.json', report)
        try:
            result = run_command(command, source / 'platform', env, deadline, args.workspace, helpers, str(calls) + '-' + label, maximum, pass_fds)
            record.update(status='completed', exitCode=result['exitCode'], timedOut=result['timedOut'], stdoutSHA256=digest(result['stdout']), stderrSHA256=digest(result['stderr']))
        except BaseException:
            record['status'] = 'interrupted_or_failed'
            raise
        finally:
            record['seconds'] = round(time.monotonic() - started, 3)
            helpers.atomic_report(args.evidence / 'result.json', report)
        return result
    go = prereq['goExecutable']; docker = selected['docker']; prefix = [docker['executable'], '--context', docker['context']]
    if successful(invoke([go, 'version'], 'go-version')) != f'go version go1.27.2 {host[0]}/{host[1]}':
        raise ValueError('actual_native_go_version_differs')
    helpers.validate_module(closed_json(successful(invoke([go, 'mod', 'edit', '-json'], 'module'))))
    module = closed_json(successful(invoke([go, 'list', '-mod=readonly', '-m', '-json', 'github.com/nats-io/nats.go'], 'resolved-module')))
    if module.get('Version') != 'v1.54.0' or module.get('Replace'):
        raise ValueError('resolved_module_differs_from_pin')
    if successful(invoke([go, 'mod', 'verify'], 'module-cache-integrity', 120)) != 'all modules verified':
        raise ValueError('prepared_module_cache_integrity_failed')
    report['compilerVersion'] = successful(invoke([prereq['compilerExecutable'], '--version'], 'compiler')).splitlines()[0]
    if host[0] == 'darwin' and not valid_apple_compiler(report['compilerVersion']):
        raise ValueError('actual_apple_compiler_invalid')
    if host[0] == 'darwin':
        sdk = successful(invoke(['/usr/bin/xcrun', '--sdk', selected['sdkRoot'], '--show-sdk-path'], 'sdk-path'))
        version = successful(invoke(['/usr/bin/xcrun', '--sdk', selected['sdkRoot'], '--show-sdk-version'], 'sdk-version'))
        if sdk != selected['sdkRoot'] or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,2}', version):
            raise ValueError('actual_sdk_differs_from_enrollment')
        report['nativeSDK'] = {'path': sdk, 'version': version}
    if successful(invoke([prereq['natsExecutable'], '-v'], 'nats-version')) != 'nats-server: v2.15.0':
        raise ValueError('actual_nats_version_differs')
    if cohort and not docker_cohort:
        run_darwin_cohort(args, report, helpers, selected, prereq, source, home, env, invoke, executed, deadline=deadline)
        return
    gate_source = args.workspace / 'held-private-gate.go'; gate_binary = args.workspace / 'held-private-gate'
    gate_source.write_text(PRIVATE_GATE_SOURCE, encoding='utf-8', newline='\n')
    successful(invoke([go, 'build', '-mod=readonly', '-trimpath', '-o', str(gate_binary), str(gate_source)], 'build-held-private-gate', 180))
    gate_binary_sha256 = digest(gate_binary)
    def check_held_access(label):
        if digest(gate_source) != hashlib.sha256(PRIVATE_GATE_SOURCE.encode()).hexdigest() or digest(gate_binary) != gate_binary_sha256:
            raise ValueError('held_access_helper_source_changed')
        if successful(invoke([str(gate_binary), *args.engine_lease.access_arguments()], label, pass_fds=args.engine_lease.access_descriptors())) != 'held_private_access_admitted':
            raise ValueError('persistent_lock_native_access_denied')
    check_held_access('held-private-access')
    report['persistentLockAccessAdmitted'] = True
    report['privateGateHelper'] = {'sourceSHA256': digest(gate_source), 'binarySHA256': gate_binary_sha256, 'heldDescriptorCount': len(args.engine_lease.access_descriptors())}
    if closed_json(successful(invoke(prefix + ['context', 'inspect', docker['context'], '--format', '{{json .Endpoints.docker.Host}}'], 'context'))) != docker['endpoint']:
        raise ValueError('actual_engine_endpoint_differs')
    versions = closed_json(successful(invoke(prefix + ['version', '--format', '{{json .}}'], 'docker-version')))
    if versions.get('Client', {}).get('Version') != docker['clientVersion'] or versions.get('Server', {}).get('Version') != docker['serverVersion']:
        raise ValueError('actual_docker_versions_differ')
    if successful(invoke(prefix + ['compose', 'version', '--short'], 'compose-version')).removeprefix('v') != docker['composeVersion']:
        raise ValueError('actual_compose_version_differs')
    if closed_json(successful(invoke(prefix + ['info', '--format', '{{json .ID}}'], 'engine-id'))) != docker['engineId']:
        raise ValueError('actual_engine_identity_differs')
    image = closed_json(successful(invoke(prefix + ['image', 'inspect', selected['image'], '--format', '{{json .}}'], 'image')))
    if image.get('Os') != 'linux' or image.get('Architecture') != host[1] or not re.fullmatch(r'sha256:[a-f0-9]{64}', image.get('Id', '')):
        raise ValueError('cached_image_architecture_or_identity_invalid')
    report['engineObserved'] = {'engineId': docker['engineId'], 'imageId': image['Id'], 'architecture': image['Architecture']}
    if cohort:
        run_darwin_cohort(args, report, helpers, selected, prereq, source, home, env, invoke, executed, check_held_access, deadline)
        return
    inventory = successful(invoke([go, 'list', '-mod=readonly', '-tags', 'agentmux_bootstrap_docker', '-json', './launcher'], 'inventory'))
    report['selectionInventory'] = validate_inventory(inventory, source)
    private = invoke([go, 'test', '-race', '-mod=readonly', '-count=1', '-timeout=5m', '-json', './privatefs'], 'privatefs', 360)
    def copy_test_logs(label, result):
        for kind in ('stdout', 'stderr'):
            raw = result[kind].read_bytes()
            if PRIVATE_MATERIAL.search(raw):
                raise ValueError('raw_test_artifact_private_material_refused')
            (args.evidence / (label + '.' + kind)).write_bytes(raw)
    copy_test_logs('privatefs', private)
    report['privateFilesystem'] = admit_native_events(private['stdout'].read_text(), private['exitCode'], 'github.com/controlLogix/agentmux/platform/privatefs')
    if private['timedOut'] or report['privateFilesystem']['status'] != 'passed':
        raise ValueError('native_private_filesystem_checks_failed')
    check_held_access('held-private-access-before-effects')
    args.engine_lease.mark_started(args.candidate_commit)
    report['effectsMayBeLive'] = True
    helpers.atomic_report(args.evidence / 'result.json', report)
    tests = invoke([go, 'test', '-race', '-mod=readonly', '-count=1', '-timeout=20m', '-json', '-tags', 'agentmux_bootstrap_docker', '-run', PATTERN, './launcher'], 'compose', 20 * 60)
    report['composeTests'] = admit_native_events(tests['stdout'].read_text(), tests['exitCode'], PACKAGE, NAMES)
    report['composeTests']['timedOut'] = tests['timedOut']
    report['composeTests']['command'] = tests['command']
    copy_test_logs('compose', tests)
    report['fixtureArtifacts'] = collect_fixture_artifacts(home, args.evidence, selected, args.selection_sha256, report['engineObserved'], source)
    check_held_access('held-private-access-after-effects')
    verify_files(prereq, selected)
    report['preparedToolsUnchangedDuringRun'] = True
    if read_pinned(args.selection, args.selection_sha256, 16384) != selected or read_pinned(args.prerequisites, args.prerequisites_sha256) != prereq:
        raise ValueError('enrollment_changed_during_collection')
    report['enrollmentUnchangedDuringRun'] = True
    report['sourceUnchangedDuringRun'] = source_hashes() == report['sourceHashes']
    report['executedSourceUnchangedDuringRun'] = executed == {p.relative_to(source).as_posix(): digest(p) for p in source.rglob('*') if p.is_file()}
    if not completion_admitted(report):
        raise ValueError('compose_or_source_qualification_failed')
    args.engine_lease.verified_cleanup()
    report.update(status='passed', composeSelectionQualified=True, effectsMayBeLive=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--target', choices=TARGETS)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--selection', type=Path)
    parser.add_argument('--selection-sha256')
    parser.add_argument('--prerequisites', type=Path)
    parser.add_argument('--prerequisites-sha256')
    parser.add_argument('--candidate-commit')
    parser.add_argument('--allow-protected-fixture-install', action='store_true')
    parser.add_argument('--darwin-cohort', choices=('darwin-frontend-budget', 'darwin-frontend-receipt',
                        'darwin-signed-role-lifecycle', 'darwin-installed-cli', 'darwin-installed-cli-port',
                        'darwin-creator-history', 'darwin-startup-owner', 'darwin-runtime-rollback',
                        'darwin-normal-self', 'darwin-normal-identity', 'darwin-normal-parent',
                        'darwin-live-role-recovery', 'darwin-installed-cli-slow-consumer'))
    parser.add_argument('--cohort-prerequisites', type=Path)
    parser.add_argument('--cohort-prerequisites-sha256')
    args = parser.parse_args(argv)
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
        return 0 if result.wasSuccessful() else 1
    if bool(args.cohort_prerequisites) != bool(args.cohort_prerequisites_sha256):
        parser.error('Cohort prerequisites need both an explicit path and separate pin.')
    if (args.cohort_prerequisites and not args.darwin_cohort) or (args.darwin_cohort and args.allow_protected_fixture_install):
        parser.error('Cohorts consume separately installed artifacts; installation mode cannot be combined.')
    if any(getattr(args, key) is None for key in ('target', 'workspace', 'evidence', 'selection', 'selection_sha256', 'prerequisites', 'prerequisites_sha256', 'candidate_commit')):
        parser.error('All explicit candidate, enrollment, workspace and evidence arguments are required.')
    for path in (args.workspace, args.evidence):
        if not absolute(str(path)) or path.resolve() != path or path == ROOT or ROOT in path.parents or any(p == path or p in path.parents or path in p.parents for p in (args.selection, args.prerequisites, args.cohort_prerequisites) if p is not None):
            parser.error('Use canonical disposable directories outside checkout and enrollment files.')
    if args.workspace == args.evidence or args.workspace in args.evidence.parents or args.evidence in args.workspace.parents:
        parser.error('Workspace and evidence directories must be separate.')
    for path in (args.workspace, args.evidence):
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(path.iterdir()):
            parser.error('Disposable directories must be empty; no old result or source is reusable.')
    helpers = load_helpers()
    report = {'recordedAt': datetime.now(timezone.utc).isoformat(), 'status': 'failed',
              'requestedTarget': args.target, 'composeSelectionQualified': False, 'effectsMayBeLive': False,
              'installedCLI': {'status': 'unexecuted', 'reason': 'Separate actual CLI fixture awaits reviewed native selection.'},
              'phaseAccepted': False, 'limits': ['Compose selection only; installed CLI, abrupt host death and complete phase matrix remain separate.', 'No provisioning, image pull or broad resource cleanup is performed by this collector.']}
    helpers.atomic_report(args.evidence / 'result.json', report)
    try:
        qualify(args, report, helpers)
    except BaseException as error:
        report.update(status='failed', composeSelectionQualified=False, failureType=type(error).__name__)
        if report['effectsMayBeLive']:
            report['cleanupState'] = 'unknown_retained_requires_exact_owner_recovery'
        print('Native Compose collection failed. Inspect the source-bound report; do not assume owned resources stopped.', file=sys.stderr)
    finally:
        try:
            if report['status'] == 'passed' and source_hashes() != report.get('sourceHashes'):
                report.update(status='failed', composeSelectionQualified=False, sourceUnchangedDuringRun=False)
            report['artifactHashes'] = {p.relative_to(args.evidence).as_posix(): digest(p) for p in args.evidence.rglob('*') if p.is_file() and p.name != 'result.json'}
            helpers.atomic_report(args.evidence / 'result.json', report)
        finally:
            if getattr(args, 'engine_lease', None) is not None:
                args.engine_lease.close()
    return 0 if report['status'] == 'passed' else 1


class Controls(unittest.TestCase):
    def selection(self, system='linux', arch='amd64'):
        return {'schemaVersion': '1.0.0', 'target': 'native-' + system, 'goos': system, 'goarch': arch,
                'workspaceRoot': '/qualify/source', 'image': 'docker.io/library/nats@sha256:' + 'a' * 64,
                'natsVersion': '2.15.0', 'compiler': '/usr/bin/clang' if system == 'darwin' else '',
                'sdkRoot': '/sdk/MacOSX.sdk' if system == 'darwin' else '',
                'docker': {'backend': 'native-unix', 'executable': '/bin/docker', 'context': 'approved',
                           'endpoint': 'unix:///var/run/docker.sock', 'engineId': 'enrolled-engine',
                           'clientVersion': '29.8.0', 'serverVersion': '29.8.0', 'composeVersion': '5.5.1'}}

    def test_all_four_targets_and_wrong_actual_host(self):
        for target, host in TARGETS.items():
            self.assertEqual(validate_selection(self.selection(*host), target, host, Path('/qualify'))['goarch'], host[1])
            with self.assertRaises(ValueError):
                validate_selection(self.selection(*host), target, ('linux', 'other'), Path('/qualify'))

    def test_closed_json_duplicate_and_nonfinite_refused(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}'):
            with self.assertRaises(ValueError): closed_json(value)

    def test_selection_no_default_remote_floating_or_missing_fields(self):
        for key, value in [('context', 'default'), ('endpoint', 'tcp://remote:2375'), ('composeVersion', '5.5.2'), ('backend', 'windows-interop')]:
            item = self.selection(); item['docker'][key] = value
            with self.assertRaises(ValueError): validate_selection(item, 'linux-amd64', ('linux', 'amd64'), Path('/qualify'))
        item = self.selection(); del item['sdkRoot']
        with self.assertRaises(ValueError): validate_selection(item, 'linux-amd64', ('linux', 'amd64'), Path('/qualify'))

    def test_safe_artifact_rejects_private_bytes_and_nonobjects(self):
        self.assertEqual(clean_safe_json(b'{"volumeRetained":true}'), {'volumeRetained': True})
        for raw in (b'{"password":"private"}', b'[]', b'-----BEGIN PRIVATE KEY-----', b'{"a":1,"a":2}'):
            with self.assertRaises(ValueError): clean_safe_json(raw)

    def prerequisites(self):
        return {'schemaVersion': '1.0.0', 'target': 'linux-amd64', 'goExecutable': '/tools/go',
                'goSHA256': 'a' * 64, 'natsExecutable': '/tools/nats', 'natsSHA256': 'b' * 64,
                'dockerExecutableSHA256': 'c' * 64, 'compilerExecutable': '/tools/cc', 'compilerSHA256': 'd' * 64,
                'dockerConfig': '/config', 'dockerConfigHashes': {'config.json': 'e' * 64},
                'darwinProtectedInstallAuthorized': False, 'moduleCache': '/tools/modules', 'qualificationLockDirectory': '/persistent-locks'}

    def test_prerequisite_contract_rejects_missing_pins_and_auth_inventory(self):
        self.assertEqual(validate_prerequisites(self.prerequisites(), 'linux-amd64')['moduleCache'], '/tools/modules')
        for mutate in (lambda p: p.pop('goSHA256'), lambda p: p.update(goSHA256=''),
                       lambda p: p.update(dockerConfigHashes={'config.json': 'e' * 64, 'credentials.json': 'f' * 64}),
                       lambda p: p.update(target='darwin-arm64')):
            record = self.prerequisites(); mutate(record)
            with self.assertRaises(ValueError): validate_prerequisites(record, 'linux-amd64')

    def test_real_selection_file_requires_separate_pin_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'selection.json'; raw = json.dumps(self.selection()).encode(); path.write_bytes(raw)
            pin = hashlib.sha256(raw).hexdigest()
            self.assertEqual(read_pinned(path, pin)['target'], 'native-linux')
            with self.assertRaises(ValueError): read_pinned(path, '0' * 64)
            link = Path(directory) / 'link.json'; link.symlink_to(path)
            with self.assertRaises(ValueError): read_pinned(link, pin)

    def test_expired_budget_never_spawns_child(self):
        helpers = load_helpers()
        with mock.patch.object(subprocess, 'Popen') as spawn:
            with self.assertRaises(TimeoutError):
                run_command(['/never'], Path('/'), {}, 0, Path('/tmp'), helpers, 'not-started')
            spawn.assert_not_called()

    def test_engine_lease_serializes_and_retains_unknown_cleanup(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            directory = Path(temporary).resolve(); directory.chmod(0o700)
            first = EngineLease(directory, 'engine')
            try:
                with self.assertRaises(BlockingIOError): EngineLease(directory, 'engine')
                first.mark_started('a' * 40)
            finally: first.close()
            with self.assertRaises(ValueError): EngineLease(directory, 'engine')
            self.assertTrue(first.marker.is_file())

    def test_engine_lease_releases_only_its_verified_marker(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            directory = Path(temporary).resolve(); directory.chmod(0o700)
            first = EngineLease(directory, 'engine')
            try:
                first.mark_started('a' * 40); first.verified_cleanup()
            finally: first.close()
            second = EngineLease(directory, 'engine'); second.close()

    def test_engine_marker_substitution_cannot_clear_uncertainty(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            directory = Path(temporary).resolve(); directory.chmod(0o700)
            first = EngineLease(directory, 'engine')
            try:
                first.mark_started('a' * 40); first.marker.write_text('{"token":"foreign"}')
                with self.assertRaises(ValueError): first.verified_cleanup()
                self.assertTrue(first.marker.exists())
            finally: first.close()

    def test_zero_exit_timeout_is_not_success(self):
        with self.assertRaises(ValueError): successful({'exitCode': 0, 'timedOut': True})

    def test_source_drift_timeout_interrupted_command_or_missing_cleanup_cannot_qualify(self):
        record = {'sourceUnchangedDuringRun': True, 'executedSourceUnchangedDuringRun': True,
                  'persistentLockAccessAdmitted': True,
                  'enrollmentUnchangedDuringRun': True, 'preparedToolsUnchangedDuringRun': True,
                  'privateFilesystem': {'status': 'passed'}, 'composeTests': {'status': 'passed', 'timedOut': False},
                  'fixtureArtifacts': {'cleanupVerified': True},
                  'commands': [{'status': 'completed', 'exitCode': 0, 'timedOut': False}]}
        self.assertTrue(completion_admitted(record))
        for key in ('sourceUnchangedDuringRun', 'executedSourceUnchangedDuringRun', 'enrollmentUnchangedDuringRun', 'preparedToolsUnchangedDuringRun'):
            bad = dict(record); bad[key] = False; self.assertFalse(completion_admitted(bad))
        for replace in ({'composeTests': {'status': 'passed', 'timedOut': True}},
                        {'commands': [{'status': 'interrupted_or_failed', 'exitCode': 0, 'timedOut': False}]},
                        {'fixtureArtifacts': {'cleanupVerified': False}}, {'commands': []}):
            self.assertFalse(completion_admitted(dict(record, **replace)))

    def test_unknown_failure_retains_failed_checkpoint_without_running_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); evidence = root / 'evidence'
            args = ['--target', 'linux-amd64', '--workspace', str(root / 'workspace'), '--evidence', str(evidence),
                    '--selection', str(root / 'selection.json'), '--selection-sha256', 'a' * 64,
                    '--prerequisites', str(root / 'prerequisites.json'), '--prerequisites-sha256', 'b' * 64,
                    '--candidate-commit', 'c' * 40]
            with mock.patch(__name__ + '.native_host', side_effect=ValueError('not_native')), mock.patch.object(subprocess, 'Popen') as spawn:
                self.assertEqual(main(args), 1); spawn.assert_not_called()
            report = closed_json((evidence / 'result.json').read_bytes())
            self.assertEqual(report['status'], 'failed'); self.assertFalse(report['composeSelectionQualified'])
            self.assertEqual(report['installedCLI']['status'], 'unexecuted')
            self.assertNotIn('not_native', json.dumps(report))

    def test_safe_fixture_collection_never_copies_private_adjacent_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / 'home'; directory = home / '.cache/agentmux-governance/p02-bootstrap-private-fixture'
            directory.mkdir(parents=True); evidence = Path(temporary) / 'evidence'; evidence.mkdir()
            selected, values, engine = self.fixture_records()
            for name, value in values.items(): (directory / name).write_text(json.dumps(value))
            (directory / 'server-key.pem').write_text('private'); (directory / 'broker.json').write_text('private')
            result = collect_fixture_artifacts(home, evidence, selected, 'a' * 64, engine)
            self.assertTrue(result['cleanupVerified']); self.assertEqual(set(result['files']), set(values))

    def fixture_records(self):
        selected = self.selection(); fixture = {'target': 'native-linux', 'selectionPin': 'a' * 64, 'actualGOOS': 'linux',
            'actualGOARCH': 'amd64', 'actualWSL': False, 'dockerBackend': 'native-unix', 'engineId': 'enrolled-engine',
            'image': selected['image'], 'cachedImageId': 'sha256:' + 'b' * 64, 'goVersion': 'go1.27.2',
            'kernelCGOEnabled': False, 'protectedInstallRetained': False, 'privateConfigRetained': True,
            'expectedVersions': {'Client': '29.8.0', 'Server': '29.8.0', 'Compose': '5.5.1'},
            'instanceId': 'instance_' + 'c' * 32, 'profileId': 'profile_' + 'd' * 32, 'project': 'amx-p02-bootstrap-' + 'e' * 16,
            'releaseDigest': 'sha256:' + 'f' * 64, 'kernelBinaryDigest': 'sha256:' + '1' * 64, 'hostPort': 12345}
        at = '2026-10-14T08:00:00Z'; values = {'fixture.json': fixture, 'baseline.json': {},
            'baseline-guard-aaaaaaaa.json': {'unchanged': True, 'existingContainerCount': 0, 'at': at}}
        for name, disposition, readiness in (('cold-owner-status.json', 'started', 'ready'),
                                            ('concurrent-reuse-status.json', 'reused', 'unknown'),
                                            ('warm-reuse-status.json', 'reused', 'unknown'),
                                            ('recovered-owner-status.json', 'started', 'ready')):
            values[name] = {'schemaVersion': '1.0.0', 'disposition': disposition, 'sourceRevision': 1,
                'observationId': 'observation_' + '4' * 32,
                'observedAt': at, 'startupAttemptId': 'attempt_' + '2' * 32,
                'caller': {'principalId': 'fixture_owner', 'kind': 'human',
                           'authenticatedIdentityRef': {'id': 'fixture_owner_record', 'ownerHubId': 'fixture_hub', 'revision': 1},
                           'scope': {'organizationId': 'fixture_org', 'projectId': None, 'workspaceId': None}},
                'errors': [],
                'instance': {'instanceId': fixture['instanceId'], 'profileId': fixture['profileId'],
                             'composeProject': fixture['project'], 'contextDisplayName': 'approved',
                             'endpoint': 'tls://127.0.0.1:12345', 'readiness': 'degraded',
                             'displayName': 'Disposable bootstrap hub', 'installedVersion': '1.2.3', 'runningVersion': '1.2.3',
                             'mode': 'local', 'contextFingerprint': 'sha256:' + '5' * 64, 'dashboard': None,
                             'services': [{'serviceId': role, 'availability': 'available', 'unavailableReason': None,
                                           'readiness': 'ready', 'observedAt': at, 'sourceRevision': 1} for role in sorted(ROLES)] +
                                         [{'serviceId': role, 'availability': 'unavailable', 'unavailableReason': 'not_implemented',
                                           'readiness': 'unknown', 'observedAt': None, 'sourceRevision': None} for role in ('work', 'hub_federation')]},
                'persistence': {'profile': fixture['profileId'], 'readiness': readiness, 'backend': 'nats_jetstream',
                                'availability': 'available', 'serverId': 'fixture_server', 'domainId': 'fixture_domain',
                                'storagePressure': {'state': 'unknown', 'percentUsed': None},
                                'replicationHealth': {'state': 'unknown', 'replicas': None}, 'observedAt': at},
                'work': {'state': 'unavailable', 'active': None, 'projects': None, 'reserved': None, 'sourceCursor': None, 'observedAt': None},
                'hubs': {'inventoryState': 'unavailable', 'entries': []}}
        children = lambda exited, offset: [{'Role': role, 'PID': offset + index, 'Exited': exited, 'ExitCode': 0 if exited else -1} for index, role in enumerate(sorted(ROLES))]
        values['concurrent-warm.json'] = {'sameContainerAfterWarm': True, 'sameKernelIncarnationAfterWarm': True,
            'originalPersistenceRecordRetained': True, 'startedSessions': 1, 'reusedConcurrentSessions': 1,
            'retainedRoleLeases': 4, 'liveProtectedChildren': children(False, 100)}
        values['recovery.json'] = {'kernelIncarnationChanged': True, 'sameContainerAfterRecovery': True,
            'originalPersistenceRecordRetained': True, 'cleanupError': False, 'retainedRoleLeasesReleased': 4,
            'originalChildrenReaped': children(True, 100), 'recoveredLiveChildren': children(False, 200), 'recoveredChildrenReaped': children(True, 200)}
        container = '3' * 64
        values['cleanup.json'] = {'at': at, 'containerId': container, 'ownedIDs': {container: True}, 'state': 'stopped', 'volumeRetained': True,
            'volume': {'Name': fixture['project'] + '_data', 'CreatedAt': at, 'Labels': {'agentmux.instance.id': fixture['instanceId'],
                'agentmux.profile.id': fixture['profileId'], 'agentmux.release.digest': fixture['releaseDigest'], 'com.docker.compose.project': fixture['project']}}}
        return selected, values, {'imageId': fixture['cachedImageId']}

    def test_missing_cleanup_or_failure_evidence_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / 'home'; directory = home / '.cache/agentmux-governance/p02-bootstrap-private-fixture'
            directory.mkdir(parents=True); evidence = Path(temporary) / 'evidence'; evidence.mkdir()
            (directory / 'cleanup-unverified.json').write_text('{"manualRecoveryRequired":true}')
            with self.assertRaises(ValueError): collect_fixture_artifacts(home, evidence)

    def test_exact_scope_and_order_admission(self):
        helpers = load_helpers()
        events = [{'Action': 'start', 'Package': PACKAGE}]
        for name in NAMES:
            events += [{'Action': 'run', 'Package': PACKAGE, 'Test': name}, {'Action': 'pass', 'Package': PACKAGE, 'Test': name}]
        events.append({'Action': 'pass', 'Package': PACKAGE})
        encode = lambda rows: '\n'.join(json.dumps(row) for row in rows)
        self.assertEqual(helpers.admit_required_events(encode(events), 0, PACKAGE, NAMES)['status'], 'passed')
        for rows in (events[:-1], [events[-1]] + events[:-1], events[:1] + events[2:3] + events[1:2] + events[3:]):
            self.assertEqual(helpers.admit_required_events(encode(rows), 0, PACKAGE, NAMES)['status'], 'failed')
        skipped = [dict(row, Action='skip') if row.get('Test') == NAMES[0] and row['Action'] == 'pass' else row for row in events]
        self.assertEqual(helpers.admit_required_events(encode(skipped), 0, PACKAGE, NAMES)['status'], 'failed')

    def test_review_compiler_requires_numeric_version(self):
        self.assertTrue(valid_apple_compiler('Apple clang version 17.0.0 (build)'))
        self.assertFalse(valid_apple_compiler('Apple clang version malformed'))

    def test_review_package_start_required_before_test_and_terminal_events(self):
        rows = []
        for name in NAMES:
            rows += [{'Action': 'run', 'Package': PACKAGE, 'Test': name}, {'Action': 'pass', 'Package': PACKAGE, 'Test': name}]
        rows.append({'Action': 'pass', 'Package': PACKAGE})
        raw = '\n'.join(json.dumps(row) for row in rows)
        self.assertEqual(admit_native_events(raw, 0, PACKAGE, NAMES)['status'], 'failed')

    def test_repaired_artifacts_bind_status_volume_children_and_enrollment(self):
        import copy
        selected, records, engine = self.fixture_records()
        validate_fixture_records(records, selected, 'a' * 64, engine)
        for mutate in (lambda r: r.pop('warm-reuse-status.json'), lambda r: r.pop('baseline.json'),
                       lambda r: r['cleanup.json']['volume']['Labels'].update({'agentmux.instance.id': 'foreign'}),
                       lambda r: r['recovery.json']['originalChildrenReaped'][0].update(PID=999),
                       lambda r: r['recovery.json']['recoveredChildrenReaped'][0].update(Exited=False),
                       lambda r: r['fixture.json'].update(actualWSL=True),
                       lambda r: r['cold-owner-status.json']['instance'].update(profileId='foreign')):
            bad = copy.deepcopy(records); mutate(bad)
            with self.assertRaises(ValueError): validate_fixture_records(bad, selected, 'a' * 64, engine)

    def test_complete_package_lifecycle_refuses_late_start_and_trailing_events(self):
        rows = [{'Action': 'start', 'Package': PACKAGE}]
        for name in NAMES:
            rows += [{'Action': 'run', 'Package': PACKAGE, 'Test': name}, {'Action': 'pass', 'Package': PACKAGE, 'Test': name}]
        rows.append({'Action': 'pass', 'Package': PACKAGE})
        for bad in (rows[1:2] + rows[:1] + rows[2:], rows + [{'Action': 'output', 'Package': PACKAGE, 'Output': 'late'}],
                    rows[:1] + [{'Action': 'unexpected', 'Package': PACKAGE}] + rows[1:]):
            self.assertEqual(admit_native_events('\n'.join(json.dumps(r) for r in bad), 0, PACKAGE, NAMES)['status'], 'failed')

    def test_lock_held_descriptors_cover_ancestors_private_directory_and_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            directory = Path(temporary).resolve(); directory.chmod(0o700)
            lease = EngineLease(directory, 'engine')
            try:
                args = lease.access_arguments(); descriptors = lease.access_descriptors()
                self.assertEqual(len(args), len(descriptors))
                self.assertTrue(all(a.startswith('ancestor=') for a in args[:-2]))
                self.assertTrue(all(a.startswith('private=') for a in args[-2:]))
                self.assertIn('privatefs.CheckDescriptor(file, access)', PRIVATE_GATE_SOURCE)
                self.assertIn('privatefs.PrivateObject', PRIVATE_GATE_SOURCE)
                self.assertIn('privatefs.PublicAncestor', PRIVATE_GATE_SOURCE)
            finally: lease.close()

    def test_review_lock_access_denial_cannot_qualify(self):
        record = {'sourceUnchangedDuringRun': True, 'executedSourceUnchangedDuringRun': True,
                  'enrollmentUnchangedDuringRun': True, 'preparedToolsUnchangedDuringRun': True,
                  'privateFilesystem': {'status': 'passed'}, 'composeTests': {'status': 'passed', 'timedOut': False},
                  'fixtureArtifacts': {'cleanupVerified': True}, 'persistentLockAccessAdmitted': False,
                  'commands': [{'status': 'completed', 'exitCode': 0, 'timedOut': False}]}
        self.assertFalse(completion_admitted(record))

    def test_review_warm_status_file_is_allowlisted(self):
        self.assertIn('warm-reuse-status.json', SAFE_FILES)

    def test_review_minimal_cleanup_without_identity_or_reaping_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / 'home'; directory = home / '.cache/agentmux-governance/p02-bootstrap-private-fixture'
            directory.mkdir(parents=True); evidence = Path(temporary) / 'evidence'; evidence.mkdir()
            values = {'fixture.json': {'target': 'native-linux'}, 'concurrent-warm.json': {'sameContainerAfterWarm': True},
                      'recovery.json': {'cleanupError': False}, 'cleanup.json': {'volumeRetained': True, 'state': 'stopped'},
                      'baseline-guard-aaaaaaaa.json': {'unchanged': True}}
            for name, value in values.items(): (directory / name).write_text(json.dumps(value))
            with self.assertRaises(ValueError): collect_fixture_artifacts(home, evidence)

    def test_review_complete_l04_records_required(self):
        selected, records, engine = self.fixture_records()
        records['cold-owner-status.json'].pop('observationId', None)
        with self.assertRaises(ValueError): validate_fixture_records(records, selected, 'a' * 64, engine)

    def test_review_nested_baseline_port_projection_required(self):
        selected, records, engine = self.fixture_records()
        identity = '9' * 64
        records['baseline.json'] = {identity: {'Id': identity, 'State': 'running', 'DeclaredPorts': {'4222/tcp': [{'HostIp': True}]}, 'ActivePorts': None}}
        records['baseline-guard-aaaaaaaa.json']['existingContainerCount'] = 1
        with self.assertRaises(ValueError): validate_fixture_records(records, selected, 'a' * 64, engine)

    def test_full_l04_nested_fields_and_port_bindings_are_not_optional(self):
        import copy
        selected, records, engine = self.fixture_records()
        for mutate in (lambda r: r['cold-owner-status.json'].pop('caller'),
                       lambda r: r['cold-owner-status.json'].pop('errors'),
                       lambda r: r['cold-owner-status.json']['instance'].pop('services'),
                       lambda r: r['cold-owner-status.json']['instance']['services'][0].pop('sourceRevision'),
                       lambda r: r['cold-owner-status.json']['persistence'].pop('storagePressure'),
                       lambda r: r['cold-owner-status.json']['work'].update(active=0)):
            bad = copy.deepcopy(records); mutate(bad)
            with self.assertRaises(ValueError): validate_fixture_records(bad, selected, 'a' * 64, engine)
        identity = '9' * 64
        for projection in ([], {'4222/tcp': {}}, {'4222/tcp': [None]}, {'4222/tcp': [{'HostIp': '127.0.0.1'}]},
                           {'4222/tcp': [{'HostIp': True, 'HostPort': '1234'}]}):
            bad = copy.deepcopy(records)
            bad['baseline.json'] = {identity: {'Id': identity, 'State': 'running', 'DeclaredPorts': projection, 'ActivePorts': None}}
            bad['baseline-guard-aaaaaaaa.json']['existingContainerCount'] = 1
            with self.assertRaises(ValueError): validate_fixture_records(bad, selected, 'a' * 64, engine)


if __name__ == '__main__':
    raise SystemExit(main())
