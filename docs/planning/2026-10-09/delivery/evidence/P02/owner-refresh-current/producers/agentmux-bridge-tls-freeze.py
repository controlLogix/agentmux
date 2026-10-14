import pathlib,hashlib,json,shutil,tempfile,subprocess,os,time,sys
src=pathlib.Path('/mnt/c/Users/RyanHelms/GitHub/agentmux')
def hashes(root):
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'platform').rglob('*') if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum'))}
dst=pathlib.Path(tempfile.mkdtemp(prefix='p02-owner-bridge-tls-candidate-',dir='/home/ryan/.cache/agentmux-tests'))
before=hashes(src)
for name in ('platform','contracts','sdk/python','tests/contracts'): shutil.copytree(src/name,dst/name)
after=hashes(src);copied=hashes(dst)
result={'path':str(dst),'copyStable':before==after==copied,'source':copied};(dst/'freeze.json').write_text(json.dumps(result,indent=2)); print(json.dumps({'path':str(dst),'copyStable':result['copyStable']}))
if not result['copyStable']: sys.exit(2)
