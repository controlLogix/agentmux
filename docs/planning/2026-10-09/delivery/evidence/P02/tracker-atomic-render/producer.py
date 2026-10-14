import importlib.util,pathlib,tempfile,json,hashlib
from unittest.mock import patch
source=pathlib.Path('C:/Users/RyanHelms/GitHub/agentmux/docs/planning/2026-10-09/delivery/track.py');spec=importlib.util.spec_from_file_location('delivery_track',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='agentmux-render-check-') as directory:
 target=pathlib.Path(directory)/'board.md';target.write_bytes(b'previous\n');m.write_text_atomic(target,'new \u03bb\n');assert target.read_bytes()=='new \u03bb\n'.encode('utf-8');assert list(pathlib.Path(directory).iterdir())==[target]
 before=target.read_bytes()
 with patch.object(m.os,'replace',side_effect=OSError(22,'injected replacement failure')):
  try:m.write_text_atomic(target,'must not replace\n')
  except OSError as e:assert e.errno==22
  else:raise AssertionError('replacement error suppressed')
 assert target.read_bytes()==before;assert list(pathlib.Path(directory).iterdir())==[target]
 state=pathlib.Path(directory)/'state.json';m.save(state,{'label':'\u03bb'});assert json.loads(state.read_text(encoding='utf-8'))=={'label':'\u03bb'}
record={'sourceSHA256':hashlib.sha256(source.read_bytes()).hexdigest(),'scope':'Delivery documentation writes only; not runtime or phase acceptance','controls':{'utf8LFReplacementAndOwnedTempCleanup':'passed','replacementFailurePreservesOldFileAndRaises':'passed','trackerJsonUsesSameAtomicWriter':'passed'},'actualWindowsTrackerRender':'passed'}
out=pathlib.Path('C:/Users/RyanHelms/GitHub/agentmux/docs/planning/2026-10-09/delivery/evidence/P02/tracker-atomic-render');out.mkdir(parents=True,exist_ok=True);(out/'controls.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(record))
