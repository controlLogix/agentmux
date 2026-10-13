import pathlib,os,json,subprocess
from report import summary
homecalc=pathlib.Path(os.path.expanduser('~/hubdemo/calc'))
assert summary('a',[1,2,3])=='a: n=3 mean=2.00'
expected=pathlib.Path(os.environ['FIXTURE_CALC'])
assert homecalc.samefile(expected)
marker=homecalc/'fixture-marker.txt'
assert marker.read_text()=='Private shared calc marker.\n'
git=subprocess.run(['git','-C',str(homecalc),'rev-parse','HEAD'],capture_output=True,text=True)
assert git.returncode==0
print(json.dumps({'expandedHomeCalc':str(homecalc),'sameFile':homecalc.samefile(expected),'marker':marker.read_text(),'summary':summary('a',[1,2,3]),'calcGitHead':git.stdout.strip(),'resolvedCalcModule':__import__('calc').__file__}))
