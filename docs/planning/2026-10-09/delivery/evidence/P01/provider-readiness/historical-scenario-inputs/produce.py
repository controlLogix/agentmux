import ast
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path('C:/Users/RyanHelms/GitHub/agentmux')
COMMIT = '2aed3e7206e81cf119562647879c90a29457b08a'
references = []

def read(path):
    raw = subprocess.check_output(['git', '-C', str(REPO), 'show', COMMIT + ':' + path])
    references.append({'retentionCommit': COMMIT, 'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    return raw

harness = read('hub/demo/orchestrate.py').decode('utf-8')
scorer = read('hub/demo/scoreboard.py').decode('utf-8')
setup = read('hub/demo/setup_repos.sh').decode('utf-8')
read('hub/demo/README.md')
read('evals/orchestrations/SCOREBOARD.md')
tree = ast.parse(harness)
definitions = {line.split()[0]: line.strip() for line in harness.splitlines() if line.startswith('  E')}
all_paths = subprocess.check_output(['git', '-C', str(REPO), 'ls-tree', '-r', '--name-only', COMMIT, 'evals/orchestrations']).decode().splitlines()
scenarios = []
for name in ['team', 'crossrepo', 'swarm']:
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'sc_' + name)
    source = ast.get_source_segment(harness, node)
    records = []
    for path in sorted(p for p in all_paths if p.endswith('-' + name + '.json')):
        report = json.loads(read(path))
        agents = report.get('agents', [])
        provider_labels = sorted(set('codex' if 'codex' in a else 'claude' if 'claude' in a else 'grok' if 'grok' in a else 'unknown' for a in agents))
        records.append({
            'sourcePath': path, 'run': report['run'], 'started': report['started'],
            'executionSourceCommit': None, 'clientVersions': None, 'agents': agents,
            'providerLabelsObserved': provider_labels,
            'providerEvidenceLimit': 'Agent labels are retained observations, not verified executable identities. Codex-labelled lead roles may reflect the optional Claude substitution; the report does not record that environment flag.',
            'checks': report.get('checks', {}), 'errorFree': report.get('error_free', False),
            'errors': report.get('errors', []), 'stats': report.get('stats', {}),
            'verification': report.get('verify'), 'work': report.get('work', []),
            'skipEvidence': 'These reports lack a complete raw test log and explicit skipped-check fields. Missing fields do not prove zero skips.'})
    passing = [r for r in records if r['errorFree'] and len(r['checks']) == 6 and all(r['checks'].values())]
    selected = passing[-1] if passing else records[-1]
    mix = ([{'repo': 'calc', 'role': 'lead', 'cli': 'claude'}, {'repo': 'calc', 'role': 'worker', 'cli': 'codex'}, {'repo': 'calc', 'role': 'reviewer', 'cli': 'grok'}] if name == 'team' else
           [{'repo': 'report', 'role': 'lead', 'cli': 'claude'}, {'repo': 'calc', 'role': 'worker', 'cli': 'codex'}, {'repo': 'report', 'role': 'worker', 'cli': 'grok'}] if name == 'crossrepo' else
           [{'repo': 'calc', 'role': 'worker', 'cli': x} for x in ['codex', 'claude', 'grok']])
    scenarios.append({'scenario': name, 'originalProviderMix': mix, 'originalScenarioSource': source,
        'selectedHistoricalBaseline': selected['run'],
        'selectionReason': 'Latest retained report with all six named checks true; all earlier failures and successful reports remain included. This selects recorded behavior, not an exact historical runtime environment.' if passing else 'No all-six-check passing report is retained; latest retained outcome selected without inventing a passing baseline.',
        'baselineChecks': selected['checks'], 'allHistoricalReports': records,
        'historicalWorkDifferences': [{'run': r['run'], 'workItemCount': len(r['work']), 'topLevelCount': sum(w.get('parent_id') is None for w in r['work']),
            'workStates': sorted(set(w['state'] for w in r['work'])), 'workTitles': [w['title'] for w in r['work']],
            'recordedUncommittedChanges': 'UNCOMMITTED:' in (r['verification'] or ''), 'errorFree': r['errorFree']} for r in records],
        'targetRun': None, 'baselineTargetComparisonComplete': False})
out = {'schemaVersion': 1, 'scope': 'Historical comparison inputs for three remaining original scenarios. No provider calls, new scenario execution, runtime change or phase acceptance.',
    'retentionCommit': COMMIT, 'historicalExecutionCommitKnown': False, 'assertionDefinitions': definitions,
    'sourceReferences': references, 'scenarios': scenarios,
    'actualRunPrerequisites': [
        'Use the original Claude, Codex and Grok provider mix. Keep HUBDEMO_NO_CLAUDE unset; setting it substitutes Codex for Claude and cannot qualify the original mix.',
        'Crossrepo work text explicitly names ~/hubdemo/calc, independently of HUBDEMO_BASE. Provide a fixture-scoped home/path mapping for that exact path or record the unresolved mismatch; do not edit the task text to hide it.',
        'The generated report module imports calc through CALC_PATH or os.path.expanduser("~/hubdemo/calc"); setup_repos.sh does not set CALC_PATH. Verify the Windows tool process and Linux verifier both resolve this dependency to the same disposable calc checkout. A Linux HOME mapping alone does not establish the Windows expanduser result.',
        'Original main calls ~/.local/bin/agentmux and resets calc/report using setup_repos.sh --reset. The fixture must supply that launcher and process-local Git identity without touching the user repositories.',
        'Original verification invokes python3 from the operator environment. Record that interpreter separately from each Windows client tool interpreter.',
        'Retain original 120-second delivery drain and all E1-E6 assertions. E6 can report success while also recording UNCOMMITTED changes, so independently prove the requested commits and clean repositories.',
        'Team requires actual lead decomposition, worker completion, reviewer result and parent completion. Crossrepo requires actual ordered delegation across both repositories. Swarm requires mixed-provider first-claim contention and four actual function implementations.',
        'Use Windows-owned installed clients and existing auth/config through WSL forwarding. An available Windows-owned Grok credential source is still required; these historical records supply no credentials.',
        'Retain exact client versions, source hashes, callback actor identities and final exact job/config cleanup evidence for each actual new run. Synthetic observer evidence is not a substitute.'
    ], 'excluded': ['Historical timeline and pane tails', 'Personal profiles, credentials and private model reasoning'], 'phaseAccepted': False}
(ROOT / 'historical-inputs.json').write_text(json.dumps(out, indent=2) + '\n', encoding='utf-8')
manifest = {'files': [{'path': n, 'bytes': (ROOT / n).stat().st_size, 'sha256': hashlib.sha256((ROOT / n).read_bytes()).hexdigest()} for n in ['produce.py', 'historical-inputs.json']], 'gitReferences': len(references), 'modelExecuted': False}
(ROOT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'directory': str(ROOT), 'sourceReferences': len(references), 'scenarios': [{'name': s['scenario'], 'records': len(s['allHistoricalReports']), 'selectedBaseline': s['selectedHistoricalBaseline']} for s in scenarios]}))
