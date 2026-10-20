"""Core import controls; these do not qualify Process execution."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


class OptionalProcessImportTests(unittest.TestCase):
    def test_present_module_keeps_original_class(self):
        from . import receiver
        from .process_resource import ProcessResource
        self.assertIs(receiver.ProcessResource, ProcessResource)
        self.assertEqual(receiver._PROCESS_RESOURCE_TYPES, (ProcessResource,))

    def test_present_module_errors_are_not_optional_absence(self):
        probe = r'''
import importlib.abc
import importlib.util
import json
import sys
sys.path[:0] = json.loads(sys.argv[1])
kind = sys.argv[2]
class BrokenProcess(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'capability_owner.process_resource':
            return importlib.util.spec_from_loader(fullname, self)
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        if kind == 'nested':
            raise ModuleNotFoundError('missing nested dependency', name='process_dependency_missing')
        if kind == 'same-name':
            raise ModuleNotFoundError('broken present module', name=module.__name__)
        raise ImportError('broken present Process module')
sys.meta_path.insert(0, BrokenProcess())
try:
    import capability_owner.receiver
except ImportError as exc:
    if kind == 'nested':
        assert type(exc) is ModuleNotFoundError and exc.name == 'process_dependency_missing'
    elif kind == 'same-name':
        assert type(exc) is ModuleNotFoundError and exc.name == 'capability_owner.process_resource'
    else:
        assert type(exc) is ImportError
else:
    raise AssertionError('present Process import failure was suppressed')
'''
        paths = [str(Path(value or '.').resolve()) for value in sys.path]
        for kind in ('nested', 'same-name', 'import-error'):
            with self.subTest(kind=kind):
                result = subprocess.run(
                    [sys.executable, '-I', '-S', '-B', '-c', probe,
                     json.dumps(paths), kind], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '')
