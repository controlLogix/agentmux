"""Run existing local orchestration effects inside the enrolled owner handoff.

The adapter is deliberately small. It does not authorize, select a project, or
accept a callback. The owner supplies one frozen effect and its verified actor, and
the adapter invokes the existing domain functions in the already selected checkout.
"""
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
import io
import json
import os
from pathlib import Path
import re
import subprocess
import threading

from agentmux_contracts import ContractError, canonical_bytes, strict_loads
from .commands import (OrchestrationPolicyBinding, PreparedOrchestrationEffect,
                       prepare_command)

_CAPTURE_LOCK = threading.Lock()


@dataclass(frozen=True, repr=False)
class OrchestrationObservation:
    outcome: str
    result: bytes = field(repr=False)

    def __repr__(self):
        return f'<OrchestrationObservation {self.outcome}>'

    def private_copy(self):
        return strict_loads(self.result)


class OrchestrationDomainAdapter:
    """Fixed calls into run and claim domains; no arbitrary execution hook."""
    def __init__(self, binding):
        if type(binding) is not OrchestrationPolicyBinding:
            raise ContractError('orchestration_adapter_configuration')
        self._binding = binding

    def __repr__(self):
        return '<OrchestrationDomainAdapter private>'

    def _result(self, effect, code, stdout, stderr):
        outcome = 'applied' if code == 0 else 'refused'
        result = None
        if code == 0 and effect.command == 'run-start':
            candidate = stdout.strip()
            result = {'runId': candidate} if re.fullmatch(r'[a-f0-9]{6}', candidate) else None
        elif code == 0 and effect.command == 'run-assign':
            candidate = stdout.strip()
            result = ({'jobId': candidate} if re.fullmatch(r'[a-f0-9]{6}/[1-9][0-9]{0,3}', candidate)
                      else None)
        if code == 0 and effect.command in ('run-start', 'run-assign') and result is None:
            outcome = 'uncertain'
        value = {'command': effect.command, 'outcome': outcome, 'exitCode': code,
                 'result': result}
        return OrchestrationObservation(outcome, canonical_bytes(value))

    def perform(self, effect, *, actor, provenance):
        if (type(effect) is not PreparedOrchestrationEffect or type(actor) is not str
                or re.fullmatch(r'[a-z][a-z0-9_-]{0,95}', actor) is None
                or provenance != self._binding.orchestrator_agent):
            raise ContractError('orchestration_effect_refused')
        rebound = prepare_command(strict_loads(effect.candidate), self._binding)
        if rebound != effect:
            raise ContractError('orchestration_effect_refused')
        try:
            selected = Path(self._binding.repository).resolve(strict=True)
            current = Path.cwd().resolve(strict=True)
        except OSError:
            raise ContractError('orchestration_environment_unavailable') from None
        if current != selected:
            raise ContractError('orchestration_environment_mismatch')

        command = effect.private_input()
        out, err = io.StringIO(), io.StringIO()
        # redirect_stdout is process-global. Serialize this legacy adapter until the
        # run domain exposes typed results instead of printing identifiers.
        with _CAPTURE_LOCK:
            try:
                import coordination
                self._require_run_binding(command)
                with coordination._owner_effect(effect, actor=actor, provenance=provenance), \
                        redirect_stdout(out), redirect_stderr(err):
                    code = self._perform(command)
                if code == 0 and effect.command == 'run-start':
                    run_id = out.getvalue().strip()
                    if re.fullmatch(r'[a-f0-9]{6}', run_id) is None:
                        raise ContractError('orchestration_effect_uncertain')
                    self._bind_run(run_id)
            except ContractError:
                raise
            except Exception:
                return OrchestrationObservation('uncertain', canonical_bytes({
                    'command': effect.command, 'outcome': 'uncertain', 'exitCode': None,
                    'result': None}))
            return self._result(effect, code, out.getvalue(), err.getvalue())

    def _owner_binding(self):
        return {'resourceRef': strict_loads(self._binding.resource_ref),
                'scope': strict_loads(self._binding.scope),
                'environmentRef': (None if self._binding.environment_ref is None
                    else strict_loads(self._binding.environment_ref)),
                'repository': self._binding.repository}

    def _run_binding_path(self, run_id):
        import run
        return run.run_dir(run_id) / '.orchestration-owner.json'

    def _bind_run(self, run_id):
        path = self._run_binding_path(run_id)
        try:
            if path.exists() or path.is_symlink():
                raise OSError()
            path.write_bytes(canonical_bytes(self._owner_binding()))
            os.chmod(path, 0o600)
        except OSError:
            raise ContractError('orchestration_effect_uncertain') from None

    def _require_run_binding(self, command):
        if command['command'] not in ('run-assign', 'run-complete', 'run-teardown'):
            return
        path = self._run_binding_path(command['runId'])
        try:
            if (path.is_symlink() or canonical_bytes(strict_loads(path.read_bytes()))
                    != canonical_bytes(self._owner_binding())):
                raise ValueError()
        except (OSError, ValueError, TypeError):
            raise ContractError('orchestration_scope_mismatch') from None

    def _perform(self, command):
        name = command['command']
        if name in ('run-start', 'run-assign', 'run-complete'):
            import run
            if name == 'run-start':
                return run.cmd_start(Namespace(request=command['request'], by=None))
            if name == 'run-assign':
                return run.cmd_assign(Namespace(run=command['runId'], worker=command['worker'],
                    reviewer=command['reviewer'], task=command['task'], brief=command['brief']))
            return run.cmd_complete(Namespace(run=command['runId'], by=None, force=False))
        if name in ('claim-for', 'release-for'):
            import coordination
            if name == 'claim-for':
                try:
                    live = coordination.live_agents()
                except Exception:
                    raise ContractError('orchestration_holder_unavailable') from None
                if command['holder'] not in live:
                    raise ContractError('orchestration_holder_unavailable')
                return coordination.cmd_claim(Namespace(resource=command['resource'],
                    holder=command['holder'], ttl=command['ttl'], note=command['note'],
                    task=command['task'] or '', depends_on=command['dependsOn'],
                    owner_binding=self._owner_binding()))
            return coordination.cmd_release(Namespace(resource=command['resource'],
                holder=command['holder'], force=False,
                expected_holder=command['holder'], owner_binding=self._owner_binding()))
        if name == 'orchestrator-start':
            return self._start_orchestrator(command['request'])
        if name == 'orchestrator-stop':
            return self._stop_orchestrator()
        if name == 'run-teardown':
            return self._teardown(command['runId'])
        raise ContractError('orchestration_effect_unavailable')

    def _agentmux(self, *args, timeout=90, expected_target=None, request=None):
        script = Path(__file__).resolve().parents[1] / 'agentmux.sh'
        environment = dict(os.environ)
        environment['AGENTMUX_REPO'] = self._binding.repository
        # These legacy values may remain in a parent shell during migration. They are
        # neither passed to nor consulted by the owner-controlled process effect.
        environment.pop('AGENTMUX_ORCHESTRATOR_WARRANT', None)
        environment.pop('AGENTMUX_AGENT', None)
        if expected_target is not None:
            environment['AGENTMUX_KILL_EXPECTED_TARGET'] = expected_target
            environment['AGENTMUX_OWNER_TERMINATION'] = '1'
        if request is not None:
            environment['AGENTMUX_OWNER_REQUEST'] = request
        try:
            return subprocess.run(['bash', str(script), *args], cwd=self._binding.repository,
                env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            raise ContractError('orchestration_effect_uncertain') from None

    def _start_orchestrator(self, request):
        # The agent definition remains the source of its CLI and posture. `spawn` is
        # the established process implementation; this owner supplies every argument.
        result = self._agentmux('spawn', self._binding.orchestrator_agent,
            '--cwd', self._binding.repository, '--agentdef', self._binding.orchestrator_agent,
            '--role', 'lead', request=request)
        if result.returncode == 75:
            raise ContractError('orchestration_effect_uncertain')
        return result.returncode

    def _snapshot(self, name):
        import coordination
        try:
            result = subprocess.run(['tmux', '-L', coordination.SOCKET, 'list-panes',
                '-s', '-t', '=' + name,
                '-F', '#{pid}|#{start_time}|#{session_id}|#{session_created}|#{pane_id}|#{pane_pid}'],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            raise ContractError('orchestration_process_identity_unavailable') from None
        if result.returncode != 0:
            detail = (result.stderr or '').strip().lower()
            if ('no server running' in detail
                    or 'error connecting to ' in detail and '(no such file or directory)' in detail
                    or "can't find session:" in detail):
                return None
            raise ContractError('orchestration_process_identity_unavailable')
        rows = result.stdout.splitlines()
        pattern = re.compile(r'[1-9][0-9]*\|[0-9]+\|\$[0-9]+\|[0-9]+\|%[0-9]+\|[1-9][0-9]*')
        parts = [row.split('|') for row in rows]
        if (not rows or any(pattern.fullmatch(row) is None for row in rows)
                or len({tuple(row[:4]) for row in parts}) != 1
                or len({row[4] for row in parts}) != len(rows)):
            raise ContractError('orchestration_process_identity_unavailable')
        # Preserve tmux's pane order because the established kill path compares the
        # supplied snapshot byte-for-byte while holding the spawn lock.
        return tuple(tuple(row) for row in parts)

    def _kill_selected(self, name):
        snapshot = self._snapshot(name)
        if snapshot is None:
            return False
        expected = '\n'.join('|'.join(row) for row in snapshot)
        result = self._agentmux('kill', name, timeout=90, expected_target=expected)
        if result.returncode != 0:
            raise ContractError('orchestration_process_changed')
        return True

    def _remove_sidecars(self, name):
        home = Path(os.environ.get('AGENTMUX_HOME', str(Path.home() / '.agentmux')))
        for path in (home / 'run').glob(name + '.*'):
            try:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            except OSError:
                raise ContractError('orchestration_cleanup_incomplete') from None

    def _stop_orchestrator(self):
        killed = self._kill_selected(self._binding.orchestrator_agent)
        return 0 if killed or self._snapshot(self._binding.orchestrator_agent) is None else 1

    def _teardown(self, run_id):
        import coordination
        import run
        if (not run.valid_run(run_id) or not run.run_dir(run_id).is_dir()
                or not run.complete_path(run_id).exists()):
            return 2
        state = run.fold(run.load_events(run_id))
        names = []
        for row in state['jobs'].values():
            for role in ('worker', 'reviewer'):
                name = row.get(role)
                if name and name not in names:
                    names.append(name)
        killed = 0
        for name in names:
            for claim in coordination.all_claims(include_expired=True):
                if claim.get('holder') == name:
                    code = coordination.cmd_release(Namespace(resource=claim['resource'],
                        holder=name, force=True, expected_holder=name,
                        owner_binding=self._owner_binding()))
                    if code != 0:
                        raise ContractError('orchestration_cleanup_incomplete')
            if self._kill_selected(name):
                killed += 1
        coordination.journal('done', f'run {run_id} torn down',
            f'{killed} agent(s) closed; courier and dashboard left running',
            self._binding.orchestrator_agent)
        return 0
