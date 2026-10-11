import pathlib,subprocess,json,hashlib,sys,os
root=pathlib.Path(__file__).resolve().parent; f=root/'result.json'; previous=f.read_bytes(); report=json.loads(previous); records=report['records']; git='C:/Program Files/Git/cmd/git.exe'
for repo in ('calc','report'):
 path=root/'original demo repos'/repo
 for key,value in [('user.name','hubdemo'),('user.email','hubdemo@localhost')]:
  a=[git,'-C',str(path),'config','--local',key,value];p=subprocess.run(a,capture_output=True,text=True,timeout=15);records.append({'name':'private-demo-git-identity','argv':a,'cwd':os.getcwd(),'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}); assert p.returncode==0
 for key in ('user.name','user.email'):
  a=[git,'-C',str(path),'config','--local','--get',key];p=subprocess.run(a,capture_output=True,text=True,timeout=15);records.append({'name':'private-demo-git-identity-readback','argv':a,'cwd':os.getcwd(),'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}); assert p.returncode==0
p=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests'],cwd=root/'original demo repos'/'calc',capture_output=True,text=True,timeout=20);records.append({'name':'windows-original-calc-baseline-tests','argv':[sys.executable,'-m','unittest','discover','-s','tests'],'cwd':str(root/'original demo repos'/'calc'),'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});assert p.returncode==0
verify="""import pathlib,json,subprocess,hashlib,sys
report=json.loads(pathlib.Path(sys.argv[1]).read_text());source='/mnt/c/Users/RyanHelms/GitHub/agentmux';refs=list(report['sourceHashes']);queries=''.join(report['commit']+':'+k+'\\n' for k in refs).encode(); data=subprocess.check_output(['git','-C',source,'cat-file','--batch'],input=queries);offset=0;mismatches=[]
for key in refs:
 end=data.index(b'\\n',offset);header=data[offset:end].split();size=int(header[-1]);offset=end+1;blob=data[offset:offset+size];offset+=size+1
 if hashlib.sha256(blob).hexdigest()!=report['sourceHashes'][key]:mismatches.append(key)
base=pathlib.Path(report['linuxFixture']);tokens=list((base/'state').rglob('token'))+list((base/'state').rglob('operator.token'));print(json.dumps({'gitBlobSourceReferences':len(refs),'gitBlobMismatches':mismatches,'tokensLeft':[str(p) for p in tokens]}));assert not mismatches and not tokens
"""
wsl='/mnt/'+root.drive[0].lower()+root.as_posix()[2:]
a=['wsl.exe','-d','Ubuntu-26.04','--','python3','-c',verify,wsl+'/result.json'];p=subprocess.run(a,capture_output=True,text=True,timeout=45);records.append({'name':'exact-source-git-blob-and-token-cleanup-verification','argv':a,'cwd':os.getcwd(),'exitCode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});assert p.returncode==0,(p.stdout,p.stderr)
report['previousReportSha256']=hashlib.sha256(previous).hexdigest();report['scripts'].append({'path':str(pathlib.Path(__file__)),'sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()});f.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'report':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'verification':json.loads(p.stdout)}))
