from pathlib import Path
import importlib.util,sys,unittest
p=Path(__file__).parent;source=p/sys.argv[1]
spec=importlib.util.spec_from_file_location('collector',source);c=importlib.util.module_from_spec(spec);sys.modules['collector']=c;spec.loader.exec_module(c)
if sys.argv[2]=='darwin':
 method=(p/'metadata-control-method.py.txt').read_text();exec(method[4:].replace('\n    ','\n'),c.__dict__)
 c.RunnerTests.test_synthetic_darwin_metadata_never_uses_process_fake=c.test_synthetic_darwin_metadata_never_uses_process_fake
 suite=unittest.TestSuite([c.RunnerTests('test_synthetic_darwin_metadata_never_uses_process_fake')])
else:suite=unittest.defaultTestLoader.loadTestsFromTestCase(c.RunnerTests)
r=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not r.wasSuccessful())
