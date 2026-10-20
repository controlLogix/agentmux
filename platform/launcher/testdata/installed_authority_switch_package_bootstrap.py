"""Run the recovery check against one exact installed client package."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys


def fail():
    raise SystemExit("installed authority-switch package root refused")


root = Path(os.environ.get("AMX_INSTALLED_AUTHORITY_SWITCH_PACKAGE_ROOT", ""))
installation = os.environ.get("AMX_INSTALLED_AUTHORITY_SWITCH_PACKAGE_ID", "")
if (not root.is_absolute() or str(root) != os.path.normpath(root)
        or len(installation) != 64
        or any(character not in "0123456789abcdef" for character in installation)):
    fail()
try:
    manifest = (root / "client-manifest.json").read_bytes()
    parsed = json.loads(manifest)
except Exception:
    fail()
if (hashlib.sha256(manifest).hexdigest() != installation
        or parsed.get("kind") != "ordinary-python-client"
        or parsed.get("pythonVersion") != "3.14.4"):
    fail()

app = root / "app"
paths = [root / "site-packages", app / "sdk/python", app]
if any(not path.is_dir() for path in paths):
    fail()
testdata = Path(__file__).resolve().parent
sys.path[:0] = [str(testdata), *(str(path) for path in paths)]

from agentmux_contracts import validation
from hub import (authority_switch_recovery_client, client_launch_selection,
                 client_launch_session, store)
from identity import application_enrollment, application_service_selection
from state_owner import authority_switch, authority_switch_service, ledger
for module in (validation, authority_switch_recovery_client,
               client_launch_selection, client_launch_session, store,
               application_enrollment, application_service_selection,
               authority_switch, authority_switch_service, ledger):
    if not Path(module.__file__).resolve().is_relative_to(app):
        fail()

runpy.run_path(str(testdata / "installed_authority_switch_operation.py"),
               run_name="__main__")
