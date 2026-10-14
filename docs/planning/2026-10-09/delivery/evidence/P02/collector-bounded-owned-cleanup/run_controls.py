import importlib.util,sys,unittest
from pathlib import Path
p=Path(__file__).parent
spec=importlib.util.spec_from_file_location('collector',p/'native_go.py');c=importlib.util.module_from_spec(spec);sys.modules['collector']=c;spec.loader.exec_module(c)
if sys.argv[1]=='focused':
 names=['test_owned_builtin_timeout_reaps_actual_child','test_owned_cleanup_timeout_retains_owner_and_retry_resolves','test_owned_cleanup_interruption_retains_owner','test_owned_cleanup_stop_failure_never_disappears_after_reap','test_owned_cleanup_shutdown_reaps_exact_retained_child','test_interrupted_owned_wait_stops_and_reaps_before_propagation','test_interruption_after_reaping_never_signals_saved_identity']
 suite=unittest.TestSuite(c.RunnerTests(n) for n in names)
else:suite=unittest.defaultTestLoader.loadTestsFromTestCase(c.RunnerTests)
r=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not r.wasSuccessful())
