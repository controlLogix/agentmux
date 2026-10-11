"""Archive explicit P01 fixtures after root review. This file has not been run."""
import argparse, hashlib, json, pathlib, subprocess

REPO = pathlib.Path(r'C:\Users\RyanHelms\GitHub\agentmux')
TEMP = pathlib.Path(r'C:\Users\RyanHelms\AppData\Local\Temp')
SOURCE_COMMIT = '36cc149a774d823716c81d7b5443b852cb0c63d1'
TARGET = REPO / 'docs/planning/2026-10-09/delivery/evidence/P01/provider-readiness/calibration-interop'
GROUPS = {
 'wsl-job': ('agentmux-wsl-job-351571061b144f89a2540eb8ba8258df', [
  'generate-initial-failed.py','generate.py','original-forward.py','supervisor.py','synthetic.py','wsl-driver.py','request.json','result.json','run.log','wsl-result.json','parent-ready.json','child-ready.json','supervisor-ready.json','supervisor.exit','cancel.request','hashes.json']),
 'console-job': ('agentmux-console-job-46a04b568cb24935a16d1c3c8e649a5a', [
  'generate.py','supervisor.py','synthetic.py','wsl-driver.py','allowlist.json','help-request.json','help-result.json','help-pane-final.log','help.exit','synthetic-request.json','synthetic-result.json','synthetic-pane.log','synthetic-pane-final.log','synthetic.exit','parent-ready.json','child-ready.json','supervisor-ready.json','cancel.request','wsl-result.json','hashes.json']),
 'callback-readiness': ('agentmux calibration readiness 296d26db665349dd9441ebb6f8591886', [
  'prepare.py','readiness-supplement.py','result.json','windows-worker.py','calc-worker-prereqone.json','calc-worker-prereqtwo.json','callback bin/agentmux_windows.py','callback bin/agentmux.cmd']),
 'callback-readiness-initial-failure': ('agentmux calibration readiness 43660b2e43df41fbba0a781bda326f18', ['prepare.py','setup-failure.json']),
 'mcp-override-probe': ('agentmux-mcp-override-probe-ef9edb64c6804e9d928a88a4780fe0ca', ['probe.py','result.json','supervisor-bare-mcp.py','supervisor-fix.diff']),
 'term-boundary': ('agentmux-term-boundary-02a947edcbd54ca6ae25d05af0d54bac', [
  'prepare.py','validate.py','path-normalization-fix.py','wsl-driver.py','previous-calib-supervisor.py','updated-calib-supervisor.py','console-supervisor.py','terminal-child.py','result.json','initial-result.json','initial-default-pane.log','initial-default-request.json','initial-allowlist.json','default-request.json','default-result.json','default-term.json','default-linux-term.txt','default-pane.log','default.exit','forward-request.json','forward-result.json','forward-term.json','forward-linux-term.txt','forward-pane.log','forward.exit','allowlist.json','input-request.json','prepared-request.json','prepare.log','hashes.json']),
 'original-calibration-first-failure': ('agentmux original calibration b9a895d39b07416f8d98025d127f414f', [
  '20261011-181922-calib.json','attempt-result.json','codex-fixture.py','courier-cleanup.json','early-abort-live-capture.json','early-abort-review-before-courier-cleanup.json','early-abort-review.json','fixture.json','orchestrate.log','prepare-fixture.py','prepared-only.json','run-calib.py','callback bin/agentmux_windows.py','callback bin/agentmux.cmd',
  'windows-supervisors/calc-worker-codex_1819/supervisor.py','windows-supervisors/calc-worker-codex_1819/input-request.json','windows-supervisors/calc-worker-codex_1819/prepared-request.json','windows-supervisors/calc-worker-codex_1819/launch-ready.json','windows-supervisors/calc-worker-codex_1819/launch-result.json','windows-supervisors/calc-worker-codex_1819/cancel.request']),
 'original-calibration-term-retry': ('agentmux original calibration TERM retry a06988fc16c443bf8c988ca64e975078', [
  'startup-pane.log','diagnostic.json','diagnostic-producer.py','attempt-result.json','codex-fixture.py','environment-fix.diff','fixture.json','orchestrate.log','prepare-fixture.py','prepared-only.json','run-calib.py','callback bin/agentmux_windows.py','callback bin/agentmux.cmd',
  'windows-supervisors/calc-worker-codex_1828/supervisor.py','windows-supervisors/calc-worker-codex_1828/input-request.json','windows-supervisors/calc-worker-codex_1828/prepared-request.json','windows-supervisors/calc-worker-codex_1828/launch-ready.json','windows-supervisors/calc-worker-codex_1828/launch-result.json','windows-supervisors/calc-worker-codex_1828/cancel.request']),
}
SOURCE_PROOF = [('callback-readiness','result.json'),('original-calibration-first-failure','fixture.json'),('original-calibration-term-retry','fixture.json')]
README = '''# Calibration interoperability evidence

These records belong to P01 preservation and prerequisite testing. They do not accept the phase or implement the later plugin supervisor.

The synthetic Windows Job Object checks prove bounded parent/child cleanup for their exact fixtures. The console checks prove a line-input/line-output handshake and visible installed Codex help. The callback readiness fixture proves synthetic Windows-to-WSL callbacks and the original calc baseline; it does not prove real agent tool execution. Initial failed producers and their retained failure records are separate evidence.

The TERM boundary check records actual tmux `tmux-256color` reaching Windows as `dumb` without forwarding, then reaching Windows unchanged with `TERM/w`. Its initial short/long Windows path comparison failed before launching a child. This proves terminal-variable propagation, not successful Codex calibration. The real callback requires Linux `AGENTMUX_WSL_CWD` unchanged via `/w`; the older generic synthetic `/pw` CWD proof is not that callback contract.

The first actual original calibration failed before any task claim at a dumb-terminal modal. Its original score records E1=false, E2=true, E3=true, E4=false, E5=false, E6=false and `error_free=false`. A zero harness process exit is not acceptance. Job cleanup recorded zero active Windows processes and unchanged Windows config bytes, which proves cleanup rather than task completion.

The TERM retry is unscored. Its retained startup error is `invalid transport in mcp_servers."agent-browser"`; no original E1-E6 report exists. It does not qualify as a successful run. The original supervisor source retains the failed quoted-key override behavior.

The separate MCP override probe uses the installed client with a private synthetic configuration. It records failure for the quoted dotted key and success for the bare key on the current server name. Its replacement supervisor and diff are retained. It does not use personal auth, run a model, or prove that the next calibration succeeds. The previous supervisor is retained in the TERM boundary and actual failed-attempt records.

The original calibration scenario, eight-minute timeout, 120-second drain, and fourteen-minute outer bound remain distinct from early failure cleanup. Four required real-provider scenarios remain open. No synthetic worker or help command replaces them.

The archive preserves allowlisted bytes and hashes. It excludes token files, credentials, personal profile artifacts, SQLite/log directories, demo Git repositories, and unrelated state. Config/auth contents and hashes are not part of this archive. Ordinary Windows-owned rollout or auth-refresh persistence remains possible.

The source proof compares all 67 recorded runtime references in each named source report with exact Git blobs at `36cc149a774d823716c81d7b5443b852cb0c63d1`. It does not claim that every external producer or installed provider came from that commit.
'''

def sha(data): return hashlib.sha256(data).hexdigest()
def git(*args): return subprocess.check_output(['git','-C',str(REPO),*args])
def validate_sources():
    verified=[]
    for group,name in SOURCE_PROOF:
        directory,_=GROUPS[group]
        path=TEMP/directory/name
        obj=json.loads(path.read_bytes())
        assert obj['commit']==SOURCE_COMMIT, (path,'wrong source commit')
        references=obj['sourceHashes']; assert len(references)==67, (path,len(references))
        for relative,expected in references.items():
            assert not pathlib.PurePosixPath(relative).is_absolute() and '..' not in pathlib.PurePosixPath(relative).parts
            actual=sha(git('show',SOURCE_COMMIT+':'+relative))
            assert actual==expected, (path,relative,expected,actual)
        verified.append({'group':group,'report':name,'reportSha256':sha(path.read_bytes()),'sourceCommit':SOURCE_COMMIT,'runtimeReferenceCount':67,'exactGitBlobsMatch':True})
    first=json.loads((TEMP/GROUPS['original-calibration-first-failure'][0]/'20261011-181922-calib.json').read_bytes())
    assert first['checks']=={'E1_all_top_done':False,'E2_no_dead_delivery':True,'E3_no_failed_bell':True,'E4_no_blocked_or_died':False,'E5_all_acked':False,'E6_verified':False}
    assert first['error_free'] is False
    retry=json.loads((TEMP/GROUPS['original-calibration-term-retry'][0]/'attempt-result.json').read_bytes())
    assert not retry['originalReports'], 'Retry acquired a score; review narrative and allowlist first'
    parser_directory=TEMP/GROUPS['mcp-override-probe'][0]
    parser=json.loads((parser_directory/'result.json').read_bytes())
    assert parser['passed'] is True
    records={record['case']:record for record in parser['records']}
    assert records['quoted']['exitCode']==1 and 'invalid transport' in records['quoted']['stderr']
    assert records['bare']['exitCode']==0 and records['bare']['namesAndEnabled']==[{'name':'agent-browser','enabled':False}]
    for source,expected in parser['sourceHashes'].items():assert sha(pathlib.Path(source).read_bytes())==expected, source
    verified.append({'group':'mcp-override-probe','report':'result.json','reportSha256':sha((parser_directory/'result.json').read_bytes()),'sourceFileCount':len(parser['sourceHashes']),'sourceFilesMatch':True,'quotedExitCode':1,'bareExitCode':0,'passed':True})
    return verified

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    if not args.apply: raise SystemExit('Prepared only. Root must review this explicit allowlist and use --apply to archive it.')
    assert git('branch','--show-current').decode().strip()=='feat/agentmux-platform-rearchitecture'
    assert not TARGET.exists(), 'Do not overwrite an existing evidence archive'
    verified=validate_sources()
    entries=[]; payload=[]
    for group,(directory,names) in GROUPS.items():
        base=(TEMP/directory).resolve()
        for name in names:
            relative=pathlib.PurePosixPath(name)
            assert not relative.is_absolute() and '..' not in relative.parts
            source=base.joinpath(*relative.parts)
            assert source.is_file() and not source.is_symlink(), source
            assert source.resolve().is_relative_to(base), source
            data=source.read_bytes()
            assert source.read_bytes()==data, 'Source changed while reading '+str(source)
            destination=pathlib.PurePosixPath(group)/relative
            entries.append({'path':str(destination),'source':str(source),'bytes':len(data),'sha256':sha(data)})
            payload.append((destination,data,source))
    # All validation and reading finish before any repository write.
    TARGET.mkdir(parents=True)
    for destination,data,source in payload:
        target=TARGET.joinpath(*destination.parts);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        assert target.read_bytes()==data and sha(source.read_bytes())==sha(data)
    (TARGET/'.gitattributes').write_bytes(b'*.json -text whitespace=cr-at-eol\n*.log -text -whitespace\n*.py -text -whitespace\n*.cmd -text -whitespace\n*.diff -text -whitespace\n*.txt -text whitespace=cr-at-eol\n*.exit -text whitespace=cr-at-eol\n*.request -text whitespace=cr-at-eol\n')
    (TARGET/'README.md').write_bytes(README.encode('utf-8'))
    manifest={'schemaVersion':1,'sourceCommit':SOURCE_COMMIT,'scope':'P01 calibration interoperability prerequisites and failed actual attempts; no phase acceptance.','sourceVerification':verified,'entries':entries,'excluded':['tokens','credential files','personal profile artifacts','SQLite/log directories','Git repositories','unrelated fixture state']}
    (TARGET/'archive.json').write_bytes((json.dumps(manifest,indent=2)+'\n').encode('utf-8'))
    print(json.dumps({'target':str(TARGET),'copiedFiles':len(entries),'sourceReportsVerified':len(verified),'phaseAccepted':False},indent=2))

if __name__=='__main__':main()