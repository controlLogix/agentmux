import pathlib,hashlib,json,tempfile,subprocess,os,time,shutil
cache=pathlib.Path('/home/ryan/.cache/agentmux-governance')
compile=cache/'p02-midboot-bounded-caller-compile-4lx9btnv'
companion=compile/'src/platform/launcher/installed_cli_midboot_compose_integration_linux_test.go'
predicate=compile/'src/platform/launcher/installed_cli_midboot_metadata_predicate_test.go'
controls=compile/'reader-controls-draft.go'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
expected={str(companion):'d1ea990d646e9a8e91bc88fea91e87dc89704460b5ac6cd5cd870c3e28cdfc5f',str(predicate):'2ff0cd87051d8a25263ea2ba59ced3cb83f0148ecf6f73bd046f5a52aad83e16',str(controls):'cf2ed920290124e6c287dafb0c15ca0593002e20e4e520a51b2e4f81002ce20b'}
before={p:sha(pathlib.Path(p)) for p in expected};assert before==expected,'source_pin_mismatch'
raw=companion.read_bytes();marker=b'func composeCLIMidBootBoundedEnvironment(path string)(data []byte,readErr,closeErr error){'
assert raw.count(marker)==1,'extraction_ambiguous'
body=raw[raw.index(marker):];assert body.endswith(b'}\n') and body.count(b'func ')==1,'extraction_not_exact_terminal_function'
out=pathlib.Path(tempfile.mkdtemp(prefix='p02-midboot-reader-pure-',dir=cache))
reader=b'package launcher\n\nimport (\n "io"\n "os"\n)\n\n'+body
(out/'reader.go').write_bytes(reader)
(out/'predicate_test.go').write_bytes(predicate.read_bytes())
(out/'reader_controls_test.go').write_bytes(controls.read_bytes())
assert (out/'reader.go').read_bytes().split(b'\n\n',2)[2]==body,'extracted_function_drift'
copies={p.name:sha(p) for p in out.iterdir()}
extraction={'source':str(companion),'sourceSHA256':before[str(companion)],'functionSHA256':hashlib.sha256(body).hexdigest(),'standaloneSHA256':sha(out/'reader.go'),'exactBytesRetained':True,'wrapperOnly':'package launcher plus io/os imports','sourceBefore':before,'copiedPins':copies}
(out/'extraction.json').write_text(json.dumps(extraction,indent=2)+'\n')
argv=['/home/ryan/.cache/agentmux-governance/runtime-comparison/go/bin/go','test','-race','-count=1','-json',str(out/'reader.go'),str(out/'predicate_test.go'),str(out/'reader_controls_test.go')]
env=os.environ.copy();env.update({'GOPROXY':'off','GOSUMDB':'off','GOWORK':'off','GOENV':'off','GORACE':'atexit_sleep_ms=0','AMX_BOOTSTRAP_DOCKER_AUTHORIZED':'0'})
for key in ['AMX_BOOTSTRAP_SELECTION_FILE','AMX_BOOTSTRAP_SELECTION_SHA256']:env.pop(key,None)
inv={'argv':argv,'cwd':str(compile/'src/platform'),'environment':{k:env[k] for k in ['GOPROXY','GOSUMDB','GOWORK','GOENV','GORACE','AMX_BOOTSTRAP_DOCKER_AUTHORIZED']},'explicitFileList':True,'launcherTestMainExcluded':True,'integrationFilesExcluded':True,'startedUnix':time.time()}
(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');shutil.copyfile('/mnt/c/Users/RyanHelms/AppData/Local/Temp/agentmux-midboot-reader-pure.py',out/'run.py');print(out,flush=True)
with (out/'events.jsonl').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:r=subprocess.run(argv,cwd=compile/'src/platform',env=env,stdout=stdout,stderr=stderr)
after={p:sha(pathlib.Path(p)) for p in expected};inv.update({'endedUnix':time.time(),'directExit':r.returncode,'sourceAfter':after,'sourceUnchanged':before==after,'copiedSourceUnchanged':copies=={n:sha(out/n) for n in copies}});(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');(out/'exit.txt').write_text(str(r.returncode)+'\n');print('exit',r.returncode,flush=True)