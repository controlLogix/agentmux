#!/usr/bin/env bash
# Offline spawn integration tests: isolated state, fake tmux/providers, no model calls.
set -euo pipefail
python3 - <<'PY'
import json, os, pathlib, subprocess, tempfile, concurrent.futures
repo = pathlib.Path.cwd()
with tempfile.TemporaryDirectory(prefix='agentmux-launch-') as td:
    root = pathlib.Path(td)
    harness = root / 'agentmux.sh'
    harness.write_text((repo / 'agentmux.sh').read_text())
    bindir = root / 'bin'; bindir.mkdir()
    state = root / 'state'; state.mkdir()
    src = root / 'claude-source'; src.mkdir()
    (src / 'settings.json').write_text(json.dumps({'hooks': {'bad': True}, 'statusLine': {},
        'permissions': {'defaultMode': 'bypassPermissions', 'allow': ['Bash', 'Write'],
                        'additionalDirectories': ['/']}}))
    (src / 'CLAUDE.md').write_text('shared instructions')
    (src / 'history.jsonl').write_text('private history')
    tmux = bindir / 'tmux'
    tmux.write_text('''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[3:]
root = pathlib.Path(os.environ['FAKE_STATE'])
cmd = args[0]
def target():
    return args[args.index('-t')+1].lstrip('=')
if cmd == 'has-session':
    sys.exit(0 if (root / target()).exists() else 1)
elif cmd == 'new-session':
    name = args[args.index('-s')+1]
    (root / name).write_text(args[-1])
    (root / (name + '.dir')).write_text(args[args.index('-c')+1])
elif cmd == 'list-sessions':
    print('\\n'.join(sorted(p.name for p in root.iterdir() if not p.name.endswith('.dir'))))
elif cmd == 'list-panes':
    print('%1')
elif cmd == 'display-message':
    print('0')
''')
    tmux.chmod(0o755)
    for name, body in [('sleep', 'exit 0'), ('claude', 'echo "--restricted --strict-mcp-config"')]:
        path = bindir / name; path.write_text('#!/bin/sh\n' + body + '\n'); path.chmod(0o755)
    env = dict(os.environ, AGENTMUX_HOME=str(root / 'home'), AGENTMUX_NO_COURIER='1',
               CLAUDE_CONFIG_DIR=str(src), FAKE_STATE=str(state), PATH=str(bindir)+':'+os.environ['PATH'])
    env.pop('AGENTMUX_NO_BYPASS', None)
    counter = 0
    def run(name, *args, extra=None, success=True, error=None):
        result = subprocess.run(['bash', str(harness), 'spawn', name, '--cwd', str(root), *args],
            env=dict(env, **(extra or {})), text=True, capture_output=True, timeout=15)
        assert (result.returncode == 0) == success, (args, result.returncode, result.stdout, result.stderr)
        if error: assert error in result.stderr, result.stderr
        if not success: assert not (state / name).exists(), 'failed spawn created a session'
        return result
    def check(label):
        global counter
        counter += 1; print('ok', counter, label, flush=True)
    for flag in ('--agentdef', '--posture', '--persona-file', '--tools', '--deny-tools', '--team', '--role', '--task'):
        run('missing', flag, success=False, error='needs a value')
    run('unknown', '--postuer', 'read-only', success=False, error='unknown option')
    for flag, value in [('--agentdef', '../escape'), ('--agentdef', 'x\nforged'),
        ('--posture', 'yolo'), ('--team', 'TM-1\rforged'), ('--role', 'admin'), ('--team', 'TM-'+'1'*509),
        ('--tools', 'Read,$(touch pwned)'), ('--deny-tools', 'Read,,Write')]:
        run('bad', flag, value, success=False, error='invalid')
    check('missing, unknown, and malformed flags fail before tmux')
    for cli in ('codex', 'claude'):
        for posture in ('unrestricted', 'workspace-write', 'read-only'):
            name = cli + '-' + posture
            run(name, '--cli', cli, '--posture', posture)
            command = (state / name).read_text()
            assert (root / 'home/run' / (name+'.posture')).read_text() == posture+'\n'
            assert (root / 'home/run' / (name+'.perms')).read_text() == ('UNRESTRICTED\n' if posture == 'unrestricted' else 'sandboxed\n')
            if cli == 'codex':
                assert ('--dangerously-bypass-approvals-and-sandbox' if posture == 'unrestricted'
                    else '--sandbox '+posture+' --ask-for-approval never') in command
            else:
                cfg = json.loads((root / 'home/claude-config' / name / 'settings.json').read_text())
                assert cfg['permissions']['defaultMode'] == {'unrestricted':'bypassPermissions',
                    'workspace-write':'acceptEdits', 'read-only':'default'}[posture]
                assert 'hooks' not in cfg and not cfg['permissions']['allow']
                assert not (root / 'home/claude-config' / name / 'history.jsonl').exists()
                if posture != 'unrestricted':
                    assert '--restricted' in command and '--strict-mcp-config' in command
                    assert 'Bash' in cfg['permissions']['deny'] and 'Agent' in cfg['permissions']['deny']
                if posture == 'read-only':
                    assert {'Write','Edit'}.issubset(cfg['permissions']['deny'])
                    assert "--tools 'Read,Grep,Glob'" in command
    check('Codex/Claude posture matrix, denies, isolated settings and permission sidecars')
    for cli in ('codex', 'claude'):
        result = run(cli+'-clamp', '--cli', cli, '--posture', 'unrestricted', extra={'AGENTMUX_NO_BYPASS':'1'})
        assert 'clamps unrestricted to workspace-write' in result.stderr
        run(cli+'-ro-brake', '--cli', cli, '--posture', 'read-only', extra={'AGENTMUX_NO_BYPASS':'1'})
        assert (root / 'home/run' / (cli+'-ro-brake.posture')).read_text() == 'read-only\n'
    check('machine ceiling logs clamp and preserves read-only')
    run('grok-unrestricted', '--cli', 'grok')
    for posture in ('read-only', 'workspace-write'):
        run('grok-'+posture, '--cli', 'grok', '--posture', posture, success=False, error='cannot enforce')
    run('grok-clamp', '--cli', 'grok', extra={'AGENTMUX_NO_BYPASS':'1'}, success=False, error='cannot enforce')
    run('shell-posture', '--cli', 'shell', '--posture', 'read-only', success=False, error='cannot enforce')
    check('unverified Grok/custom postures fail closed, including machine clamp')
    persona = root / 'persona secret.txt'; persona.write_text('PRIVATE PERSONA $(touch SHOULD_NOT_EXIST)\nsecond line\n')
    run('metadata', '--agentdef', 'reviewer', '--posture', 'unrestricted', '--team', 'TM-042',
        '--role', 'reviewer', '--persona-file', str(persona), '--tools', 'Read,Grep', '--deny-tools', 'Write')
    for field, expected in [('agentdef','reviewer'), ('posture','unrestricted'), ('team','TM-042'), ('role','reviewer')]:
        raw = (root / 'home/run' / ('metadata.'+field)).read_bytes()
        assert raw == expected.encode()+b'\n' and len(raw) <= 512
        assert all(32 <= c < 127 for c in raw[:-1])
    copied = root / 'home/run/metadata.persona'
    assert copied.stat().st_mode & 0o777 == 0o600
    assert copied.read_text().startswith(persona.read_text()) and '[degraded:' in copied.read_text()
    assert 'PRIVATE PERSONA' not in (state / 'metadata').read_text()
    assert not (root / 'SHOULD_NOT_EXIST').exists()
    check('four bounded one-line sidecars; private persona copy; degraded tool prose; no command interpolation')
    run('unsafe-tools', '--cli', 'claude', '--posture', 'read-only', '--tools', 'Bash', success=False, error='cannot be enabled')
    run('allow-tools', '--cli', 'claude', '--posture', 'read-only', '--tools', 'Read', '--deny-tools', 'Grep')
    assert "--tools 'Read'" in (state / 'allow-tools').read_text()
    assert 'Grep' in json.loads((root/'home/claude-config/allow-tools/settings.json').read_text())['permissions']['deny']
    check('Claude named tool restrictions cannot reopen bounded tools')
    stale = root / 'home/claude-config/stale'; stale.mkdir(); (stale/'settings.json').write_text('{}')
    with concurrent.futures.ThreadPoolExecutor() as pool:
        futures = [pool.submit(run, 'parallel-'+posture, '--cli', 'claude', '--posture', posture)
                   for posture in ('read-only', 'unrestricted')]
        for future in futures: future.result()
    assert not stale.exists()
    for posture in ('read-only', 'unrestricted'):
        assert (root / 'home/claude-config' / ('parallel-'+posture) / 'settings.json').exists()
    check('concurrent different-posture spawns retain separate configs; GC prunes only dead agents')
    # Corrupt the actual published file between generation and readback. The
    # prove-it gate must catch this, rather than checking the intended object.
    mv = bindir / 'mv'
    mv.write_text('''#!/bin/bash
/bin/mv "$@" || exit
last="${@: -1}"
case "$last" in */settings.json) printf '%s\\n' '{"permissions":{"defaultMode":"default","deny":[]}}' > "$last" ;; esac
'''); mv.chmod(0o755)
    run('corrupt', '--cli', 'claude', '--posture', 'read-only', success=False, error='could not prove')
    mv.unlink()
    (src/'settings.json').write_text('{invalid')
    run('broken-source', '--cli', 'claude', '--posture', 'unrestricted', success=False, error='could not prove')
    check('published-settings corruption and broken source fail the spawn without permissive fallback')
    # AMUX-745: a native Codex worker gets folder trust for its own checkout, for this
    # launch only, and only inside a repository root the owner approved at enrollment.
    import shlex
    real = pathlib.Path(os.path.realpath(root))
    approved = real / 'approved'; (approved / 'repo').mkdir(parents=True); (approved / 'other/deep').mkdir(parents=True)
    (real / 'outside/deep').mkdir(parents=True); (real / 'approved-evil').mkdir(); (approved / 'a"b').mkdir()
    (approved / 'escape').symlink_to(real / 'outside'); (real / 'via-link').symlink_to(approved / 'repo')
    # "lnk/.." is lnk's target's parent to the kernel, but lnk's own parent to a logical cd.
    (approved / 'repo/out-lnk').symlink_to(real / 'outside/deep'); (approved / 'repo/in-lnk').symlink_to(approved / 'other/deep')
    (approved / 'withcfg/.codex').mkdir(parents=True)
    cfgroot = real / 'cfgroot'; (cfgroot / 'repo').mkdir(parents=True); (cfgroot / '.codex').mkdir()
    (real / '.codex').mkdir()   # above every approved root: Codex does not read it
    homeroot = real / 'homeroot'; (homeroot / 'repo').mkdir(parents=True); (homeroot / '.codex').mkdir()
    native = dict(AGENTMUX_NATIVE_CORE_ROOT=str(root / 'native'), AGENTMUX_SOCKET='agentmux-native-test',
                  AGENTMUX_NATIVE_CORE_TRUST_ROOTS='\n'.join(map(str, (real / 'elsewhere', approved, cfgroot, homeroot))))
    def launched(name):
        return shlex.split((state / name).read_text().split(' exec ', 1)[1])
    for name, cwd, granted, extra in (('native-trusted', approved / 'repo', approved / 'repo', {}),
            ('native-via-link', real / 'via-link', approved / 'repo', {}),
            ('native-in-dotdot', approved / 'repo/in-lnk/..', approved / 'other', {}),
            ('native-home-codex', homeroot / 'repo', homeroot / 'repo', {'HOME': str(homeroot)})):
        result = run(name, '--cli', 'codex', '--cwd', str(cwd), extra=dict(native, **extra))
        grant = 'projects={"%s"={trust_level="trusted"}}' % granted
        assert launched(name)[-4:] == ['-c', 'check_for_update_on_startup=false', '-c', grant], launched(name)
        assert (root / 'home/run' / (name + '.trust')).read_text() == str(granted) + '\n'
        assert (state / (name + '.dir')).read_text() == str(granted), 'the pane must start in the trusted folder'
        assert (root / 'home/run' / (name + '.cwd')).read_text() == str(granted) + '\n'
        pane_check = (state / name).read_text().split(' exec ', 1)[0]
        assert '|| exit 97;' in pane_check and str(granted) in pane_check, pane_check
        assert result.stdout.rstrip('\n').endswith(f'trust:   {granted}, this launch only (approved root '
                                                   f'{homeroot if name == "native-home-codex" else approved})'), result.stdout
    for name, cwd in (('native-escape', approved / 'escape'), ('native-prefix', real / 'approved-evil'),
                      ('native-outside', real / 'outside'), ('native-out-dotdot', approved / 'repo/out-lnk/..')):
        run(name, '--cli', 'codex', '--cwd', str(cwd), extra=native, success=False,
            error='outside the repository roots approved at enrollment')
    for name, cwd in (('native-own-codex', approved / 'withcfg'), ('native-root-codex', cfgroot / 'repo')):
        run(name, '--cli', 'codex', '--cwd', str(cwd), extra=native, success=False,
            error="would let the repository change this worker's Codex settings")
    run('native-quote', '--cli', 'codex', '--cwd', str(approved / 'a"b'), extra=native, success=False,
        error='cannot be named in a trust grant')
    unapproved = {key: value for key, value in native.items() if key != 'AGENTMUX_NATIVE_CORE_TRUST_ROOTS'}
    run('native-unapproved', '--cli', 'codex', '--cwd', str(approved / 'repo'), extra=unapproved, success=False,
        error='outside the repository roots approved at enrollment')
    (root / 'home/run/codex-plain.trust').write_text('/stale\n')
    run('codex-plain', '--cli', 'codex', '--cwd', str(approved / 'repo'))
    assert not any(word.startswith(('projects=', 'check_for_update')) for word in launched('codex-plain'))
    assert not (root / 'home/run/codex-plain.trust').exists()
    listed = subprocess.run(['bash', str(harness), 'list'], env=env, text=True, capture_output=True, timeout=15)
    section = listed.stdout.split('Codex folder trust granted at launch (this launch only):', 1)
    assert len(section) == 2, listed.stdout + listed.stderr
    assert f'native-trusted {approved / "repo"}' in ' '.join(section[1].split()), section[1]
    assert 'codex-plain' not in section[1]
    check('native Codex trust: one launch, approved roots only, real paths, no repository .codex, pane starts '
          'where checked, shown by list; no grant outside native spawns')
    print(f'passed {counter}, failed 0')
PY
