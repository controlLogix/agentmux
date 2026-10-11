import os,json,pathlib,sys
root=pathlib.Path(__file__).resolve().parent
data={'pid':os.getpid(),'TERM':os.environ.get('TERM'),'COLORTERM':os.environ.get('COLORTERM'),'case':sys.argv[1]}
(root/(sys.argv[1]+'-term.json')).write_text(json.dumps(data,indent=2)+'\n')
print('WINDOWS_TERM:'+str(data['TERM']),flush=True)
