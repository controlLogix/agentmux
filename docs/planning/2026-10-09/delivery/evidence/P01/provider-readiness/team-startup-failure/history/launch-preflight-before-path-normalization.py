import pathlib,hashlib,json,os
P=pathlib.Path
def sha(path):return hashlib.sha256(P(path).read_bytes()).hexdigest()
def verify_grok(proof_path,expected_sha,environment):
 assert sha(proof_path)==expected_sha
 proof=json.loads(P(proof_path).read_text())
 canonical=P(proof['canonicalProfile'])
 assert environment.get('GROK_HOME')==str(canonical)
 assert not any(key.startswith('ORCA_') for key in environment)
 assert not any(key in environment for key in ['GROK_CONFIG','GROK_CONFIG_PATH'])
 for item in [proof['config'],proof['hookProgram'],*proof['nativeHookFiles'],*proof['documentation'],*proof['clients']]:assert sha(item['path'])==item['sha256'], 'Reviewed Grok source changed: '+item['path']
 expected={P(item['path']).resolve() for item in proof['nativeHookFiles']}
 actual={path.resolve() for path in (canonical/'hooks').rglob('*') if path.is_file()}
 assert actual==expected, 'Native Grok hook source set changed'
 for name in ['plugins','managed_config.toml','requirements.toml','lsp.json']:assert not (canonical/name).exists(), 'Unexpected native Grok source: '+name
 for key,value in proof['documentedProcessOnlyGrokEnv'].items():assert environment.get(key)==value
 assert proof['config']['nativeMcpServersCount']==0 and proof['config']['enabledPluginsCount']==0 and proof['config']['pluginExtraPathsCount']==0 and proof['config']['nativeHooksInConfig'] is False
 return {'reviewedSourcesRevalidated':True,'nativeSourceAbsenceRevalidated':True,'orcaEnvironmentExcluded':True}
def verify_launch(request,root,environment):
 assert not any(key.startswith('ORCA_') for key in environment)
 if request['provider']=='claude':
  settings=json.loads((root/'claude-process-settings.json').read_text())
  assert settings==request['generatedClaudeSettings']
  assert settings=={'permissions':{'defaultMode':'bypassPermissions','allow':[],'deny':[]}}, 'Unsupported original generated Claude permission/gate settings'
 if request['provider']=='grok':
  assert P(environment['GROK_HOME']).resolve()==P(r'C:/Users/RyanHelms/.grok').resolve()
  return verify_grok(root/'grok-readiness-review.json',request['grokReadinessSha256'],environment)
 return {'orcaEnvironmentExcluded':True}
