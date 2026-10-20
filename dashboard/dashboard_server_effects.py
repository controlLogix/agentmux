"""Concrete dashboard effects behind the retained dashboard command owner."""
import re
from types import SimpleNamespace

from agentmux_contracts import ContractError
from dashboard_commands import DashboardDomainEffects
import ccstore
import runsview


class DashboardServerEffects(DashboardDomainEffects):
    """Reuse existing domain validation while removing HTTP authority fields."""
    def __init__(self, bind_host):
        if not isinstance(bind_host, str) or bind_host not in ('127.0.0.1', '::1'):
            raise ContractError('dashboard_effect_configuration')
        self._bind_host = bind_host

    def __repr__(self):
        return '<DashboardServerEffects private>'

    def _write(self, db, action, body, actor):
        # Import lazily so server can import this adapter during process startup.
        from server import Handler
        handler = object.__new__(Handler)
        handler.server = SimpleNamespace(server_address=(self._bind_host, 0))
        trusted = dict(body)
        trusted['actor'] = actor
        return Handler.board_write(handler, db, action, trusted)

    def apply_transactional(self, db, target, action, body, actor):
        if target != '/api/board/' + action:
            raise ContractError('dashboard_effect_target_mismatch')
        return self._write(db, action, body, actor)

    def apply_external(self, target, action, body, actor):
        if action == 'run-review':
            match = re.fullmatch(r'/api/runs/([0-9a-f]{6})/review', target)
            if match is None:
                raise ContractError('dashboard_effect_target_mismatch')
            decision = body.get('decision')
            note = body.get('note')
            if (decision not in ('approved', 'changes')
                    or note is not None and not isinstance(note, str)):
                raise ContractError('dashboard_effect_input_invalid')
            runsview.write_approval(match.group(1), actor, note, decision)
            return {'ok': True}
        if target != '/api/board/' + action:
            raise ContractError('dashboard_effect_target_mismatch')
        with ccstore.connection() as db:
            return self._write(db, action, body, actor)

