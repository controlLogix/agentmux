"""Retire a stopped profile's repository definitions owner (AMUX-728).

Installed entry: ``retire-definitions-owner --repository-root PATH --hub-id HUB
[--apply]``. Without ``--apply`` it only reports whether the fence can be
retired. The fence must name HUB and no live owner may hold its lease; see
DefinitionService.retire_retained_writer. Only closed codes leave the process.
"""
import json
import os
from pathlib import Path
import re
import sys

import ccboard
from definition_service import DefinitionScope, DefinitionService

SCHEMA_VERSION = '1.0.0'
_HUB = re.compile(r'[a-z][a-z0-9_-]{0,63}')
_CODES = {'definition_owner_fence_absent', 'definition_owner_fence_mismatch', 'definition_owner_running'}


def _arguments(arguments):
    apply = arguments[4:] == ['--apply']
    if (len(arguments) not in (4, 5) or arguments[0] != '--repository-root' or arguments[2] != '--hub-id'
            or (len(arguments) == 5 and not apply)):
        return None
    root, hub = arguments[1], arguments[3]
    if (not os.path.isabs(root) or os.path.normpath(root) != root or '\x00' in root
            or not os.path.isdir(root) or not _HUB.fullmatch(hub)):
        return None
    return Path(root), hub, apply


def _diagnostic(code):
    sys.stderr.write(json.dumps({'schemaVersion': SCHEMA_VERSION, 'kind': 'definitions-owner-retirement-diagnostic',
                                 'code': code}) + '\n')
    return 1


def main(arguments):
    selected = _arguments(arguments)
    if selected is None:
        return _diagnostic('definitions_retirement_arguments_invalid')
    root, hub, apply = selected
    global_root = Path(os.environ.get('AGENTMUX_HOME', str(Path.home() / '.agentmux')))
    service = DefinitionService(DefinitionScope(root, Path.home(), global_root, str(root)))
    try:
        result = service.retire_retained_writer('repo', hub, apply=apply)
    except ccboard.Refused as error:
        code = error.args[0] if error.args and error.args[0] in _CODES else 'definitions_retirement_refused'
        return _diagnostic(code)
    except Exception:
        return _diagnostic('definitions_retirement_failed')
    sys.stdout.write(json.dumps({'schemaVersion': SCHEMA_VERSION, 'kind': 'definitions-owner-retirement',
                                 'outcome': result['outcome'], 'hubId': result['hubId'], 'applied': apply}) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
