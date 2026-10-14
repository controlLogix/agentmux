import pathlib,json,hashlib,sys,os,subprocess,time
root=pathlib.Path('/home/ryan/.cache/agentmux-tests/p02-owner-bridge-tls-candidate-aeeryxie')
repo=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
cache=pathlib.Path('/home/ryan/.cache/agentmux-governance/typescript-sdk')
sys.path.insert(0,str(root/'tests/contracts'))
os.environ.update(AGENTMUX_CONTRACT_PYTHON='/home/ryan/.cache/agentmux-governance/p01-contracts-python/bin/python',AGENTMUX_CONTRACT_NODE='/usr/bin/node',AGENTMUX_CONTRACT_TS_CLI=str(cache/'dist/cli.js'),AGENTMUX_SCHEMA_DIR=str(root/'contracts/v1/schemas'))
import test_conformance as wire
maps={}
for name in ('package.json','package-lock.json','tsconfig.json'):
 a=repo/'sdk/typescript'/name;b=cache/name
 maps['sdk/typescript/'+name]={'source':hashlib.sha256(a.read_bytes()).hexdigest(),'prepared':hashlib.sha256(b.read_bytes()).hexdigest()}
for a in (repo/'sdk/typescript/src').rglob('*.ts'):
 name=a.relative_to(repo/'sdk/typescript');b=cache/name
 maps['sdk/typescript/'+str(name)]={'source':hashlib.sha256(a.read_bytes()).hexdigest(),'prepared':hashlib.sha256(b.read_bytes()).hexdigest()}
if any(v['source']!=v['prepared'] for v in maps.values()): raise SystemExit('prepared SDK source mismatch')
compiled={str(p.relative_to(cache)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (cache/'dist').glob('*.js')}
corpus=json.loads((root/'outputs/admission-corpus.json').read_text());cases=[('host-owner-status-reply',c['value'],c['accepted'],c['name']) for c in corpus]
for p in sorted((root/'outputs').glob('*.json')):
 if p.name!='admission-corpus.json': cases.append(('startup-status-observation',json.loads(p.read_text()),True,p.name))
results=[]
for lang in ('python','typescript'):
 client=wire.Client(lang);responses=client.many([{'op':'validate','schema':schema,'value':value} for schema,value,expected,name in cases])
 for (schema,value,expected,name),response in zip(cases,responses):
  passed=response.get('ok') is expected and (response.get('result') is True if expected else 'result' not in response)
  results.append({'language':lang,'schema':schema,'name':name,'expected':expected,'passed':passed})
record={'ok':all(r['passed'] for r in results),'checks':len(results),'corpusCases':len(corpus),'generatedOutputs':len(cases)-len(corpus),'checksDetail':results,'typescriptSourceMirror':maps,'typescriptCompiled':compiled,'schemas':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'contracts/v1/schemas').glob('*.json')},'pythonSource':{str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'sdk/python').rglob('*.py')}}
(root/'sdk-result.json').write_text(json.dumps(record,indent=2));print(json.dumps({k:record[k] for k in ('ok','checks','corpusCases','generatedOutputs')}));sys.exit(0 if record['ok'] else 1)

