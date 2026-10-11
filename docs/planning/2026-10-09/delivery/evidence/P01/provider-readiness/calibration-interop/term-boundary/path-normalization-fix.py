import pathlib,json,sys
root=pathlib.Path(sys.argv[1]).resolve()
for name in ['result.json','default-pane.log','default-request.json','allowlist.json']:
    p=root/name
    if p.exists():(root/('initial-'+name)).write_bytes(p.read_bytes())
(root/'default.exit').unlink(missing_ok=True)
manifest=json.loads((root/'allowlist.json').read_text())
for kind in ['default','forward']:
    request=json.loads((root/(kind+'-request.json')).read_text());request['cwd']=str(root);request['argv'][1]=str(root/'terminal-child.py')
    manifest[kind]['argv']=request['argv'];manifest[kind]['files'][1]['path']=request['argv'][1]
    (root/(kind+'-request.json')).write_text(json.dumps(request))
(root/'allowlist.json').write_text(json.dumps(manifest,indent=2))