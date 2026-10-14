from pathlib import Path
import subprocess,os,json,shutil,uuid
src=Path('/home/ryan/.cache/agentmux-governance/p02-raw-cleanup-e6120d5e');out=Path('/home/ryan/.cache/agentmux-governance')/('p02-raw-cleanup-negative-'+uuid.uuid4().hex[:8]);out.mkdir();shutil.copytree(src/'platform',out/'platform');p=out/'platform/deployment/raw_transport_cleanup.go';body=p.read_text();start=body.index('func closeRawTransport(');body=body[:start]+'''func closeRawTransport(dialer *observeDialer, cause error, code string) (error, bool) {
 if dialer != nil { dialer.close() }
 return cause, false
}
''';p.write_text(body);inv=json.loads((src/'focused-invocation.json').read_text());inv['args'][-1]='^TestRawTransportCleanupActualSocketFailureAndRetry$';inv['cwd']=str(out/'platform');env=os.environ.copy();env.update(inv['fixedEnvironment']);(out/'invocation.json').write_text(json.dumps(inv,indent=2)+'\n');(out/'mutation.txt').write_text('Discard only the real raw owner cleanup error and retain no retry wrapper, matching the historical scalar cleanup behavior.\n');print(out,flush=True)
with(out/'test.jsonl').open('wb')as stdout,(out/'test.stderr').open('wb')as stderr:r=subprocess.run(inv['args'],cwd=out/'platform',env=env,stdout=stdout,stderr=stderr)
(out/'exit.json').write_text(json.dumps({'exitCode':r.returncode})+'\n');print(r.returncode)