"""Run operator preparation against one exact installed client package."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys


def fail():
    raise SystemExit("installed operator package root refused")


root = Path(os.environ.get("AMX_INSTALLED_OPERATOR_PACKAGE_ROOT", ""))
installation = os.environ.get("AMX_INSTALLED_OPERATOR_PACKAGE_ID", "")
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

# Bootstrap enrollment is test-only and is intentionally absent from the
# installed runtime. Load that one exact helper into the installed identity
# package without making any other repository identity module importable.
import identity
if tuple(Path(path).resolve() for path in identity.__path__) != (app / "identity",):
    fail()
bootstrap_path = Path(__file__).resolve().parents[3] / "identity/bootstrap.py"
spec = importlib.util.spec_from_file_location("identity.bootstrap", bootstrap_path)
if spec is None or spec.loader is None:
    fail()
bootstrap = importlib.util.module_from_spec(spec)
sys.modules["identity.bootstrap"] = bootstrap
try:
    spec.loader.exec_module(bootstrap)
except BaseException:
    del sys.modules["identity.bootstrap"]
    raise

from agentmux_contracts import validation
from identity import application_service_selection, authority, ingress
import integration_owner
from integration_owner import operator_provisioning
from native_security import secret_custody
if tuple(Path(path).resolve() for path in integration_owner.__path__) != (app / "integration_owner",):
    fail()
for module in (validation, application_service_selection, authority, ingress,
               operator_provisioning, secret_custody):
    if not Path(module.__file__).resolve().is_relative_to(app):
        fail()

runpy.run_path(str(Path(__file__).with_name("installed_operator_enrollment.py")),
               run_name="__main__")
