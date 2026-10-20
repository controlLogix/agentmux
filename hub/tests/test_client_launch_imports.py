"""Isolated import-order checks; no foreign module is unloaded by the guard."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ClientLaunchImports(unittest.TestCase):
    def run_probe(self, script):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix='agentmux-import-probe-') as directory:
            foreign = Path(directory)
            (foreign / 'agentmux_contracts.py').write_text("raise AssertionError('shadow module executed')\n")
            environment = dict(os.environ)
            environment.pop('PYTHONPATH', None)
            result = subprocess.run([sys.executable, '-c', script, str(root / 'sdk/python'), str(foreign)],
                                    cwd=root, env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_bundle_path_is_promoted_before_earlier_foreign_path(self):
        self.run_probe('''import os, sys
sdk, foreign = sys.argv[1:]
sys.path[:0] = [foreign, sdk]
from hub.client_launch_imports import use_bundled_sdk
use_bundled_sdk()
import agentmux_contracts
assert sys.path[0] == sdk
assert os.path.realpath(agentmux_contracts.__file__) == os.path.realpath(os.path.join(sdk, 'agentmux_contracts', '__init__.py'))
''')

    def test_preloaded_foreign_module_is_rejected_and_retained(self):
        self.run_probe('''import importlib.util, os, sys, types
sdk, foreign = sys.argv[1:]
from hub.client_launch_imports import use_bundled_sdk, BundledSDKError
module = types.ModuleType('agentmux_contracts')
module.__file__ = os.path.join(foreign, 'agentmux_contracts.py')
module.__spec__ = importlib.util.spec_from_file_location('agentmux_contracts', module.__file__)
sys.modules['agentmux_contracts'] = module
before = list(sys.path)
try:
    use_bundled_sdk()
except BundledSDKError as error:
    assert str(error) == 'Bundled SDK import is unavailable.'
else:
    raise AssertionError('foreign module accepted')
assert sys.modules['agentmux_contracts'] is module
assert sys.path == before
''')

    def test_loaded_bundled_modules_remain_the_same_objects(self):
        self.run_probe('''import sys
sdk, foreign = sys.argv[1:]
sys.path.insert(0, sdk)
import agentmux_contracts
from hub.client_launch_imports import use_bundled_sdk
original = agentmux_contracts
wire = sys.modules['agentmux_contracts.wire']
sys.path.insert(0, foreign)
use_bundled_sdk()
assert sys.path[0] == sdk
assert sys.modules['agentmux_contracts'] is original
assert sys.modules['agentmux_contracts.wire'] is wire
''')

    def test_foreign_submodule_is_rejected_even_with_trusted_package(self):
        self.run_probe('''import importlib.util, os, sys, types
sdk, foreign = sys.argv[1:]
sys.path.insert(0, sdk)
import agentmux_contracts
from hub.client_launch_imports import use_bundled_sdk, BundledSDKError
module = types.ModuleType('agentmux_contracts.wire')
module.__file__ = os.path.join(foreign, 'wire.py')
module.__spec__ = importlib.util.spec_from_file_location('agentmux_contracts.wire', module.__file__)
sys.modules['agentmux_contracts.wire'] = module
try:
    use_bundled_sdk()
except BundledSDKError:
    pass
else:
    raise AssertionError('foreign submodule accepted')
assert sys.modules['agentmux_contracts.wire'] is module
''')
