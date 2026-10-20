#!/usr/bin/env bash
# agentmux - drive other coding-agent CLIs (codex, claude, ...) in tmux panes.
#
# Runs inside WSL or on macOS (see the portability block below). Each agent is one tmux session on a dedicated tmux server
# socket ("agentmux"), so it never collides with an interactive tmux.
#
# Canonical source: <checkout>/agentmux.sh

set -uo pipefail

# --- portability: WSL/Linux and macOS ------------------------------------------
#
# The harness was written against GNU userland in WSL. macOS ships BSD tools and
# lacks tac, flock, timeout and setsid outright. Each shim below is defined ONLY when
# the real command is missing, so a Linux box keeps running exactly what it ran
# before; nothing here changes behaviour where the GNU tool exists.
#
# bash itself must be 4.1+ (`exec {fd}>`, associative arrays). macOS /bin/bash is 3.2;
# install.sh points the launcher at a Homebrew bash instead.
case "$(uname -s)" in Darwin) AGENTMUX_OS=macos ;; *) AGENTMUX_OS=linux ;; esac

command -v tac >/dev/null 2>&1 || tac() { tail -r "$@"; }

# timeout SECS CMD...: perl's alarm survives exec, so CMD is killed by SIGALRM at the
# deadline. Exit status differs from GNU (142, not 124); no caller here tests it.
command -v timeout >/dev/null 2>&1 || timeout() {
  local secs="$1"; shift
  perl -e 'alarm shift @ARGV; exec @ARGV or exit 127' "$secs" "$@"
}

# setsid is NOT shimmed as a function: `func &` forks a subshell, so $! would name the
# subshell rather than the daemon and a later kill would miss it. See detach_run.

# flock [-x|-s|-u] [-n] [-w SECS] FD. Only the fd form is used in this repo. A child
# can take the lock for us because flock(2) locks belong to the open file
# description, which the child shares with this shell and which outlives the child.
command -v flock >/dev/null 2>&1 || flock() {
  local op=LOCK_EX nb=0 wait="" fd=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -x|-e) op=LOCK_EX ;; -s) op=LOCK_SH ;; -u) op=LOCK_UN ;;
      -n) nb=1 ;; -w) wait="$2"; shift ;;
      *) fd="$1" ;;
    esac
    shift
  done
  python3 -c '
import fcntl, math, sys, time
fd, op, nb, wait = int(sys.argv[1]), getattr(fcntl, sys.argv[2]), sys.argv[3] == "1", sys.argv[4]
seconds = float(wait) if wait else 0
if not math.isfinite(seconds):
    sys.exit("flock shim: timeout must be finite")
if op == fcntl.LOCK_UN or not (nb or wait):
    fcntl.flock(fd, op); sys.exit(0)
deadline = time.monotonic() + seconds
while True:
    try:
        fcntl.flock(fd, op | fcntl.LOCK_NB); sys.exit(0)
    except BlockingIOError:
        if time.monotonic() >= deadline:
            sys.exit(1)
        time.sleep(0.05)
' "$fd" "$op" "$nb" "$wait"
}

# How a person reaches the tmux socket: through wsl.exe from Windows, directly on a Mac.
attach_prefix() { [ "$AGENTMUX_OS" = linux ] && printf 'wsl -d Ubuntu -- '; }

# `mv -T SRC DEST`: never move INTO DEST if a directory appeared there. BSD mv has no
# -T; rename(2) itself has exactly that semantics, and archives never cross devices.
mv_T() {
  if [ "$AGENTMUX_OS" = linux ]; then mv -T -- "$1" "$2"; return; fi
  perl -e 'rename $ARGV[0], $ARGV[1] or die "mv: $ARGV[0] -> $ARGV[1]: $!\n"' "$1" "$2"
}

# Octal permission bits of a file: GNU `stat -c %a`, BSD `stat -f %Lp`.
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

# ISO-8601 to the second with a colon in the offset, as GNU `date -Is` prints it.
iso_now() { date -Is 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z | sed 's/\(..\)$/:\1/'; }

SOCKET="agentmux"
if [ -n "${AGENTMUX_NATIVE_CORE_ROOT:-}" ]; then
  SOCKET="${AGENTMUX_SOCKET:?selected native transport required}"
fi
# Where THIS script lives on disk, for the idle watchdog to re-invoke minutes later.
#
# Not $0 and not BASH_SOURCE alone: agentmux is habitually run through process
# substitution (`bash <(tr -d '\r' < agentmux.sh)`) because the working tree has CRLF
# line endings, and inside that both are a /dev/fd entry that stops existing the
# moment the pipeline ends. Every candidate is therefore CHECKED, and a path that is
# not a real file is discarded rather than handed to a background process that would
# fail on it every tick forever - which is exactly what happened the first time.
agentmux_self() {
  local candidate
  for candidate in "${AGENTMUX_REPO:-}/agentmux.sh" \
                   "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)/agentmux.sh" \
                   "$(cd "$(dirname "$0")" 2>/dev/null && pwd)/agentmux.sh" \
                   "$PWD/agentmux.sh"; do
    case "$candidate" in /dev/fd/*|/proc/self/fd/*) continue ;; esac
    [ -f "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}

# Encode the MCP argument array before quoting it for the pane's shell.
# A checkout path may contain spaces, quotes or backslashes.
agentmux_mcp_config() {
  local self
  self="$(agentmux_self)" || return 1
  python3 - "$(dirname "$self")/hub/cli.py" "${1:-}" <<'PYMCP'
import json
import sys
arguments = [sys.argv[1], "mcp"]
if sys.argv[2]:
    arguments += ["--enrolled", "--selection", sys.argv[2], "--managed-worker"]
print(json.dumps({"mcpServers": {"agentmux": {
    "command": "python3", "args": arguments}}}))
PYMCP
}
# Agent callbacks reach the Python client before any local state is created.
# The client validates the complete scoped context and rejects lifecycle verbs.
if [ "${AGENTMUX_WINDOWS_CALLBACK+x}" = x ]; then
  if [ "${1:-}" != hub ]; then
    printf 'agentmux: Windows agent callbacks support hub commands only\n' >&2
    exit 1
  fi
  _callback_self="$(agentmux_self)" || exit 1
  shift
  exec python3 "$(dirname "$_callback_self")/hub/cli.py" "$@"
fi
ROOT="${AGENTMUX_HOME:-$HOME/.agentmux}"
LOGDIR="$ROOT/logs"
RUNDIR="$ROOT/run"
mkdir -p "$LOGDIR" "$RUNDIR"

# Sampling and idle detection. Both were set when stillness was the ONLY completion
# signal, and both were the dominant cost of an orchestrated turn: a 1500ms sample
# with a 5000ms quiet window adds six seconds after a model has already finished -
# measured longer than the model's own thinking time. cmd_wait now prefers a CLI's
# busy marker where one is known, and these govern the fallback.
POLL_MS="${AGENTMUX_POLL_MS:-250}"      # how often to sample the pane
QUIET_MS="${AGENTMUX_QUIET_MS:-2000}"   # pane unchanged this long => idle (fallback)
TIMEOUT_S="${AGENTMUX_TIMEOUT_S:-300}"  # hard ceiling for wait/ask
COLS="${AGENTMUX_COLS:-200}"
ROWS="${AGENTMUX_ROWS:-50}"

ESC=$(printf '\033')

tm() { tmux -L "$SOCKET" "$@"; }
die() { printf 'agentmux: %s\n' "$*" >&2; exit 1; }
have() { tm has-session -t "=$1" 2>/dev/null; }
need() { have "$1" || die "no such agent: '$1' (try: agentmux list)"; }

# Strip ANSI CSI / OSC / charset escapes and CRs so captured text is diffable.
strip_ansi() {
  sed -e "s/${ESC}\[[0-9;:?]*[ -\/]*[@-~]//g" \
      -e "s/${ESC}\][^\a]*\a//g" \
      -e "s/${ESC}[()][A-Za-z0-9]//g" \
      -e "s/${ESC}[=>]//g" \
      -e 's/\r//g'
}

# Drop leading and trailing blank lines, leave the middle alone.
trim_edges() { sed -e '/./,$!d' | tac | sed -e '/./,$!d' | tac; }

# C:\foo or C:/foo -> /mnt/c/foo ; anything else passes through unchanged.
to_wsl_path() {
  case "$1" in
    [A-Za-z]:[\\/]*) wslpath -u "$1" 2>/dev/null || printf '%s' "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}

# Newest nvm-managed node bin dir, so panes get the Linux toolchain ahead of
# the Windows shims that WSL interop appends to PATH. On macOS without nvm, the
# Homebrew (or other PATH) node is the right one and there are no shims to beat.
node_bin() {
  local d
  d="$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1)"
  if [ -z "$d" ] && [ "$AGENTMUX_OS" = macos ] && command -v node >/dev/null 2>&1; then
    d="$(dirname "$(command -v node)")"
  fi
  printf '%s\n' "$d"
}

# The claude config dir this machine ACTUALLY uses.
#
# Do not assume ~/.claude. A setup may export CLAUDE_CONFIG_DIR from .bashrc or
# .profile - neither of which is sourced by `wsl.exe -- bash -s`, so the harness's
# own environment is not evidence of what an interactive session resolves to.
# Ask a login shell instead, and only fall back to ~/.claude.
effective_claude_dir() {
  local d="${CLAUDE_CONFIG_DIR:-}"
  # $SHELL, not bash: a macOS operator's login shell is zsh, configured in .zprofile.
  [ -z "$d" ] && d="$("${SHELL:-bash}" -lc 'printf "%s" "${CLAUDE_CONFIG_DIR:-}"' 2>/dev/null)"
  [ -n "$d" ] && [ -d "$d" ] && { printf '%s' "$d"; return 0; }
  printf '%s' "$HOME/.claude"
}

# Config dir for spawned claude agents.
#
# Claude Code's permissive mode lives in settings.json, but the operator's own
# settings.json may be shared with a Windows install (see link-windows-state.sh).
# Setting bypassPermissions there would silently put the operator's OWN
# interactive sessions into bypass mode, so spawned agents get their own
# CLAUDE_CONFIG_DIR: a per-entry mirror that keeps skills, plugins and CLAUDE.md
# shared but owns its settings.json.
#
# Dropped from the agent's settings.json copy:
#   hooks      - the operator's SessionEnd hooks kill MCP servers and check git;
#                a spawned agent must not fire those on exit.
#   statusLine - references host-specific paths.
#
# NOT symlinked into the mirror - mutable operator state. These entries may point
# at the Windows profile; linking them could let a spawned agent overwrite or
# prune the operator's own history and backups.
#
# ARCHIVE, NEVER DELETE (TM-211, C14 / R-EVID-1). The mirror is where a spawned
# claude keeps its projects/ session transcripts - projects is deliberately NOT
# linked above, so the transcript of what an agent actually did lives only here.
# This GC used to `rm -rf` every mirror whose agent was not live, which is how the
# 2026-09-29 credential failure below could not be reconstructed the next morning:
# every mirror had already been deleted by the next spawn, evidence and all.
#
# Credentials are the one thing an archive must never hold. They are adopted back
# into the shared store first (claude_credentials_sync), then stripped from the
# mirror BEFORE it moves, so no archived copy ever contains a token even briefly.
# Called while holding the spawn lock, including the interval before new-session.
claude_config_gc() {
  local d agent dest
  [ -d "$ROOT/claude-config" ] && [ ! -L "$ROOT/claude-config" ] || return 0
  # A dead mirror can hold the ONLY valid refresh token on the box (see
  # claude_credentials_sync). If adopting it failed, stripping it would destroy the
  # login, so archive nothing this round and leave every mirror where it is.
  claude_credentials_sync || {
    printf 'agentmux: credential sync failed; claude-config GC skipped this round\n' >&2
    return 0
  }
  for d in "$ROOT/claude-config"/*; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    agent="${d##*/}"
    [[ "$agent" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || continue
    have "$agent" && continue
    strip_credentials "$d" || continue
    mkdir -p "$ROOT/claude-config/.archive" && chmod 700 "$ROOT/claude-config/.archive" || continue
    dest="$(archive_dest "$ROOT/claude-config/.archive" "$agent" "")"
    mv_T "$d" "$dest" || continue
    archive_prune "$ROOT/claude-config/.archive" "$agent" \
      "${AGENTMUX_CLAUDE_ARCHIVE_KEEP:-10}" "${AGENTMUX_CLAUDE_ARCHIVE_MB:-2048}" || true
  done
}

# Remove anything credential-shaped from a tree about to be archived.
#
# Matches names, not contents: .credentials.json today, plus any *credential* or
# *token* file or link a future claude release adds. -delete on a symlink removes
# the link, never its target, and find does not descend through links, so the
# shared store and the operator's linked skills/plugins are never touched. Fails
# (and the caller archives nothing) if anything matching is still there afterwards.
strip_credentials() {
  local tree="$1"
  find "$tree" \( -type f -o -type l \) \( -iname '*credential*' -o -iname '*token*' \) \
    -delete 2>/dev/null
  [ -z "$(find "$tree" \( -type f -o -type l \) \( -iname '*credential*' -o -iname '*token*' \) -print -quit 2>/dev/null)" ]
}

# Move a non-empty pane log into logs/archive/ and apply retention: the newest
# AGENTMUX_LOG_ARCHIVE_KEEP (default 20) per agent, and never more than
# AGENTMUX_LOG_ARCHIVE_MB (default 2048) in total. Returns 0 when there was nothing
# to archive; non-zero only when a log existed and could not be moved. Pruning is
# best-effort - a failed prune must not turn into a truncated log.
archive_log() {
  local name="$1" log="$LOGDIR/$1.log" dest
  [ -s "$log" ] && [ ! -L "$log" ] || return 0
  mkdir -p "$LOGDIR/archive" || return 1
  dest="$(archive_dest "$LOGDIR/archive" "$name" .log)"
  mv_T "$log" "$dest" || return 1
  archive_prune "$LOGDIR/archive" "$name" \
    "${AGENTMUX_LOG_ARCHIVE_KEEP:-20}" "${AGENTMUX_LOG_ARCHIVE_MB:-2048}" || true
}

# Archive naming and retention, shared by pane logs and claude mirrors.
#
# Names are <agent>.<UTC stamp>[-N]<ext>. Agent names cannot contain '.' (spawn
# validates them), so the "<agent>." prefix identifies one agent's archives
# exactly, and -N only breaks a same-second collision. Nothing that does not match
# that shape is ever pruned - the archive may hold things this code did not write.
archive_dest() {
  local dir="$1" name="$2" ext="$3" stamp n=0 dest
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dest="$dir/$name.$stamp$ext"
  while [ -e "$dest" ] || [ -L "$dest" ]; do
    n=$((n + 1))
    dest="$dir/$name.$stamp-$n$ext"
  done
  printf '%s' "$dest"
}

# Keep the newest KEEP archives for NAME, then delete oldest-first across ALL
# agents until DIR is at most MB megabytes. Sizes are lstat sizes and rmtree never
# follows a link, so a mirror's links to shared skills count as nothing and are
# never followed out of the archive.
archive_prune() {
  python3 - "$@" <<'PYPRUNE'
import os, re, shutil, sys
d, name, keep, mb = sys.argv[1:5]
keep = int(keep) if keep.isdigit() else 20
cap = (int(mb) if mb.isdigit() else 2048) * 1024 * 1024
shape = re.compile(r'^([A-Za-z0-9_-]{1,64})\.(\d{8}T\d{6}Z)(?:-(\d+))?(\.log)?$')
def entries():
    out = []
    for e in os.listdir(d):
        m = shape.match(e)
        if m:
            out.append(((m.group(2), int(m.group(3) or 0)), m.group(1), os.path.join(d, e)))
    return sorted(out)
def size(p):
    if os.path.islink(p) or not os.path.isdir(p):
        return os.lstat(p).st_size
    total = 0
    for root, dirs, files in os.walk(p):
        for f in dirs + files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total
def remove(p):
    if os.path.isdir(p) and not os.path.islink(p):
        shutil.rmtree(p, ignore_errors=True)
    else:
        os.unlink(p)
mine = [e for e in entries() if e[1] == name]
for _, _, p in mine[:max(0, len(mine) - keep)]:
    remove(p)
rows = [(k, p, size(p)) for k, _, p in entries()]
total = sum(s for _, _, s in rows)
for _, p, s in rows:
    if total <= cap:
        break
    remove(p)
    total -= s
PYPRUNE
}

# ONE credential store for every spawned claude (TM-212).
#
# HOW IT WORKED BEFORE. claude_config_dir linked every entry of the operator's
# config dir into each mirror, .credentials.json included, but only when the name
# was absent (`[ -e ] || ln -s`). Claude Code rewrites that file on every OAuth
# refresh, and the rewrite REPLACES the symlink with a regular file rather than
# writing through it. From then on that agent had a private copy. Refresh tokens
# rotate: the agent that refreshed got the only valid refresh token, in its own
# mirror, and the shared file was left holding one the server had already retired.
# Nothing ever repaired it, because a real file satisfies `-e`. Measured
# 2026-09-29: the WSL login expired at 23:15 and could not refresh, and an agent's
# mirror held a REAL 669-byte .credentials.json written by claude at 23:11 instead
# of a link. Then the GC deleted that mirror, and the live token with it.
#
# HOW IT WORKS NOW. On every spawn, every GC, every kill and every idle-watchdog
# tick, each mirror's .credentials.json is checked:
#   - a link to the shared file: left alone.
#   - a REAL file (the refresh replaced the link): if it is valid (parses, has a
#     claudeAiOauth refresh token) and newer than the shared file - or the shared
#     file is missing or invalid - it is ADOPTED: written atomically over the
#     shared file's real target, mode 0600. The newest refresh wins, so the token
#     the server currently honors is the one everybody uses.
#   - then the real file, a wrong link or a dangling one is replaced by the link,
#     atomically (symlink to a temp name, rename over).
# The window where one agent holds a private copy is therefore bounded by the next
# of those events - about a minute while the watchdog runs - rather than forever.
# Only names and sizes are ever printed; token contents never leave the file.
claude_credentials_sync() {
  local shared_dir
  [ -d "$ROOT/claude-config" ] || return 0
  [ ! -L "$ROOT/claude-config" ] || return 1
  shared_dir="$(effective_claude_dir)"
  python3 - "$shared_dir" "$ROOT/claude-config" <<'PYCRED'
import json, os, pathlib, re, sys, tempfile
shared_dir, cfg_root = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
shared = shared_dir / '.credentials.json'
agent_name = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
def valid(p):
    try:
        oauth = json.loads(p.read_text()).get('claudeAiOauth') or {}
        return bool(oauth.get('refreshToken'))
    except Exception:
        return False
def mtime(p):
    try:
        return p.stat().st_mtime
    except OSError:
        return -1.0
mirrors = [d for d in sorted(cfg_root.iterdir())
           if agent_name.match(d.name) and d.is_dir() and not d.is_symlink()]
diverged = [d / '.credentials.json' for d in mirrors
            if (d / '.credentials.json').is_file() and not (d / '.credentials.json').is_symlink()]
candidates = sorted((p for p in diverged if valid(p)), key=mtime)
if candidates:
    best = candidates[-1]
    if not valid(shared) or mtime(best) > mtime(shared):
        target = pathlib.Path(os.path.realpath(shared))
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(prefix='.credentials.agentmux.', dir=target.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(best.read_bytes())
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        print(f"agentmux: adopted {best.parent.name}'s newer claude credential into {shared}",
              file=sys.stderr)
if not (shared.exists() or shared.is_symlink()):
    sys.exit(0)
for d in mirrors:
    link = d / '.credentials.json'
    if link.is_symlink() and os.readlink(link) == str(shared):
        continue
    if link.exists() and link.is_dir() and not link.is_symlink():
        continue
    tmp = d / f'.credentials.json.agentmux-link-{os.getpid()}'
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(str(shared), tmp)
    os.replace(tmp, link)
    print(f'agentmux: repaired {d.name}/.credentials.json -> shared store', file=sys.stderr)
PYCRED
}

# The same sync from outside spawn, under the spawn lock so it cannot interleave
# with a spawn's GC or mirror build. Best-effort: never fails a kill or a tick.
claude_credentials_sync_locked() {
  [ -d "$ROOT/claude-config" ] || return 0
  (
    flock -w 10 -x 9 || exit 0
    claude_credentials_sync
  ) 9>"$ROOT/.spawn.lock" || true
}

# EP-032 (docs/FEDERATION.md 7.2, 10): when this hub federates with other people,
# an unrestricted claude agent gets the agentmux MCP server and the privileged-tool
# gate hook. Restricted postures already deny mcp__* and disable hooks.
federation_on() {
  python3 - "$ROOT/hub/federation.toml" 2>/dev/null <<'PYFED'
import sys, tomllib
try:
    c = tomllib.load(open(sys.argv[1], 'rb'))
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if c.get('federation', {}).get('enabled') else 1)
PYFED
}

claude_config_dir() {
  local name="$1" posture="$2" tools="$3" deny_tools="$4"
  local d="$ROOT/claude-config/$name" src entry base tmp gate=""
  if [ "$posture" = unrestricted ] && federation_on; then
    local _self; _self="$(agentmux_self)" && gate="python3 $(dirname "$_self")/hub/fed/hooks/privileged_gate.py"
  fi
  src="$(effective_claude_dir)"
  [ ! -L "$ROOT/claude-config" ] && [ ! -L "$d" ] || return 1
  mkdir -p "$d" || return 1
  chmod 700 "$d" || return 1
  if [ -d "$src" ]; then
    for entry in "$src"/* "$src"/.[!.]*; do
      [ -e "$entry" ] || continue
      base="${entry##*/}"
      case "$base" in
        settings.json|settings.local.json|sessions|history.jsonl|backups|projects|todos|statsig|shell-snapshots|ide) continue ;;
      esac
      [ -e "$d/$base" ] || ln -s "$entry" "$d/$base" 2>/dev/null
    done
  fi
  tmp="$(mktemp "$d/.settings.XXXXXX")" || return 1
  if ! python3 - "$src/settings.json" "$tmp" "$posture" "$tools" "$deny_tools" "$gate" <<'PYCFG'
import json, pathlib, sys
src, dst, posture, tools, deny, gate = sys.argv[1:]
cfg = json.loads(pathlib.Path(src).read_text()) if pathlib.Path(src).is_file() else {}
for key in ('hooks', 'statusLine', 'permissions', 'enabledPlugins', 'mcpServers'):
    cfg.pop(key, None)
if gate:
    # The ONLY hook a spawned agent gets: remote work never triggers privileged tools.
    cfg['hooks'] = {'PreToolUse': [{'matcher': 'Bash|mcp__.*', 'hooks': [{'type': 'command', 'command': gate}]}]}
# Replace inherited permissions: operator allow rules/additionalDirectories must
# never reopen a bounded agent's filesystem or permission modes.
mode = {'unrestricted': 'bypassPermissions', 'workspace-write': 'acceptEdits',
        'read-only': 'default'}[posture]
blocked = deny.split(',') if deny else []
if posture != 'unrestricted':
    blocked += ['Bash', 'PowerShell', 'Agent', 'Task', 'NotebookEdit', 'mcp__*']
if posture == 'read-only':
    blocked += ['Write', 'Edit']
cfg['permissions'] = {'defaultMode': mode, 'allow': [], 'deny': sorted(set(blocked))}
if posture != 'unrestricted':
    cfg['permissions']['disableBypassPermissionsMode'] = 'disable'
    cfg['disableAllHooks'] = True
pathlib.Path(dst).write_text(json.dumps(cfg, indent=2) + '\n')
PYCFG
  then
    rm -f "$tmp"
    return 1
  fi
  mv -f "$tmp" "$d/settings.json" || return 1
  # Read the published file independently. No fallback to stale/permissive settings.
  python3 - "$d/settings.json" "$posture" "$deny_tools" <<'PYPROVE' || return 1
import json, sys
cfg = json.load(open(sys.argv[1]))
p = cfg['permissions']
posture = sys.argv[2]
assert p['defaultMode'] == {'unrestricted': 'bypassPermissions',
    'workspace-write': 'acceptEdits', 'read-only': 'default'}[posture]
required = set(filter(None, sys.argv[3].split(',')))
if posture != 'unrestricted':
    required.update(['Bash', 'PowerShell', 'Agent', 'Task', 'NotebookEdit', 'mcp__*'])
    assert p['disableBypassPermissionsMode'] == 'disable'
    assert not p['allow'] and not p.get('additionalDirectories')
    assert cfg['disableAllHooks'] is True
if posture == 'read-only':
    required.update(['Write', 'Edit'])
assert required.issubset(p['deny'])
PYPROVE
  printf '%s' "$d"
}

# Path to the scripted Atlassian CLI, or empty if task management is not set up.
#
# MCP cannot be reached from a shell script, so Jira lifecycle calls go through
# taskmgmt/task.py. Both the CLI and a 0600 config must exist; otherwise every
# hook below silently no-ops, so agentmux keeps working with no Atlassian setup.
task_cli() {
  local cli="${AGENTMUX_TASK_CLI:-${AGENTMUX_REPO:-}/taskmgmt/task.py}"
  [ -n "${AGENTMUX_REPO:-}${AGENTMUX_TASK_CLI:-}" ] || return 1
  [ -f "$cli" ] || return 1
  [ -f "$ROOT/atlassian.json" ] || return 1
  command -v python3 >/dev/null 2>&1 || return 1
  printf '%s' "$cli"
}

# Fire a task.py subcommand without ever letting it break the caller. A Jira
# outage must not stop an agent spawning or a pane being killed.
task_try() {
  local cli; cli="$(task_cli)" || return 0
  timeout 45 python3 "$cli" "$@" 2>&1 | sed 's/^/  jira: /' || true
}

# tmux pane target for an agent. "=name" matches a session but is NOT a valid
# pane target, so resolve to the stable pane id (%N) recorded at spawn time.
pane_of() {
  local p
  p="$(cat "$RUNDIR/$1.pane" 2>/dev/null)"
  if [ -z "$p" ] || ! tm has-session -t "=$1" 2>/dev/null; then
    p="$(tm list-panes -t "$1" -F '#{pane_id}' 2>/dev/null | head -1)"
    [ -n "$p" ] && printf '%s\n' "$p" > "$RUNDIR/$1.pane"
  fi
  printf '%s' "$p"
}

pane_hash() {
  tm capture-pane -p -t "$(pane_of "$1")" 2>/dev/null | strip_ansi | sed 's/[[:space:]]*$//' | cksum
}

usage() {
  cat <<'USAGE'
agentmux - drive other agent CLIs in tmux panes

  spawn <name> [--cli codex|claude|grok|shell|<cmd>] [--cwd DIR] [--model M]
               [--task ABC-123] [--auth METHOD]
               [--agentdef NAME] [--posture read-only|workspace-write|unrestricted]
               [--persona-file PATH] [--tools CSV] [--deny-tools CSV]
               [--team TM-042] [--role lead|worker|reviewer|researcher]
               [--client-selection ABSOLUTE_PATH] (managed Claude only)
                               start an agent in a detached tmux session.
                               --task binds a Jira issue: recorded in run/, shown
                               by `list` and the dashboard, and exported to the
                               pane as $AGENTMUX_TASK
                               --auth picks an auth method from dashboard/auth.json
                               (account OAuth, an API key, Vertex, or
                               any OpenAI-compatible endpoint). Omit it to use the
                               CLI's configured default.
                               List them: python3 taskmgmt/setup_auth.py --list
                               grok = xAI's CLI, authenticated by ACCOUNT LOGIN
                               (`grok login`), no API key required
  send   <name> [--force] <text...>
                               type text + Enter into the agent. Refuses if the pane
                               is showing a prompt (an update notice, a trust dialog),
                               because Enter would actuate that instead - use `key`
                               to answer a modal, or --force to override
  key    <name> <keys...>      tmux key names only, no text, no implicit Enter
                               (Enter, Escape, Down, C-c) - use for modals
  read   <name> [--lines N]    current pane contents, ANSI stripped
  tail   <name> [--lines N]    scrollback log for the agent
  wait   <name> [--timeout S] [--quiet S]
                               block until the pane stops changing
  ask    <name> <text...>      send, wait for idle, then print the pane
  post   <to> [--kind K] [--ref R] [--from NAME] <text...>
                               queue a message FOR ANOTHER AGENT in this agent's
                               outbox, ~/.agentmux/queue/<sender>.jsonl. The sender
                               is $AGENTMUX_AGENT inside a pane, else 'orchestrator'.
                               K is one of plan request reply status finding error.
                               Queueing is not delivery - the courier does that
  courier start|stop|status|once|watch|dead|requeue
                               deliver queued messages to their recipients with
                               `send`. `start` detaches and writes a pidfile;
                               `once` makes a single pass, which is what a test or a
                               cron line wants. A recipient that is down, or showing
                               a prompt, is retried rather than forced
  inbox  [name] [--clear]      read messages delivered to a VIRTUAL address -
                               one with no pane, such as 'orchestrator' (this
                               session). Without this, replies addressed to the
                               orchestrator were retried and then discarded
  run    start "<request>"      open a run; prints the run id. Orchestrator only -
                               refused from inside an agent pane, as is `complete`
  run    assign <run> --worker <a> --reviewer <b> [--brief T]
                               create a job. The reviewer must not be the worker
  run    submit [job]          worker: I am done (job defaults to $AGENTMUX_JOB)
  run    verdict <job> --pass|--fail [--reason-file F]
                               REVIEWER ONLY - a worker cannot sign off its own work.
                               Identity comes from the pane, not from --by: omit it.
                               A pane cannot verify as someone else, and a name that
                               is not a live session is refused
  run    status <run> [--json] one line per job; safe to paste into a fresh session
  run    complete <run> [--force]
                               THE GATE. Refuses until every job is verified. --force
                               records what was unfinished before anything is torn down
  run    teardown <run>        close only THIS run's agents; courier stays up
  claim  <resource> [--ttl S] [--note T] [--task ID] [--depends-on R]
                               TAKE A WORK LOCK before editing anything another agent
                               could touch. Atomic: exactly one agent wins. Refused
                               with the holder's name if someone else has it. Leases
                               expire (default 1800s) so a dead agent frees its work
  release <resource>           give it back when you are done
  claim/release --for <agent>  claim in a WORKER's name. Orchestrator only, and only
                               for an agent that is live: it is how dispatch hands a
                               worker the files it was started for, not a way for one
                               agent to act as another
  claims [--json] [--all]      who is working on what, right now
  tasks  [--mine] [--all] [--json]
                               the TASK BOARD: open work, by epic
  task   start|done|block|todo|park|backlog <id> [--reason R]
  task   add <epic-id> "<title>"
                               move or create board work. Status changes are
                               journalled too: the board records state, the journal
                               records that someone decided it
  dispatch [<id>] [--cli C] [--dry-run]
                               hand ONE ready card to a fresh agent: spawn, claim its
                               files, move it in_progress through the board's own gate,
                               then brief it. No id takes the top of the queue. An
                               unready card is refused BY THE BOARD, not by dispatch
  collect [<id>]               reconcile dispatched cards: release claims, reap the
                               pane, park what died. NEVER closes a task - the done
                               gate wants evidence and an actor, and that judgment
                               is not the collector's to make
  pool   once|start|stop|status|resume
                               the pickup loop: collect, then fill free slots up to
                               dispatchWip, preferring cards whose files do not
                               overlap. Off unless dispatchEnabled is set; config is
                               re-read every tick, so turning it off does not mean
                               finding the process
  epic   new "<title>" | status <id> <s> | use <id> | list
                               every task belongs to an epic; `use` sets the active one
  board  config [<name> [<value>]]
                               the board's own settings - the gates, the WIP limit and
                               the dispatch policy. No arguments prints all of them
  journal <kind> <subject> [--body B]
                               write to the SHARED journal every agent and the
                               dashboard can read. kinds: claim release conflict note
                               handoff blocked done plan
  list                         show agents, state and cwd
  kill   <name> | --all        stop agent(s)
  reap   [--dry-run]           remove run/ sidecars for agents with no live tmux
                               session. A reboot takes the tmux server without
                               going through `kill`, so orphans accumulate; the
                               dashboard shows each as `stale` but never removes it.
                               Logs are left alone
  idle   [--minutes N] [--dry-run]
                               close agents with no pane activity for N minutes
                               (default 60, AGENTMUX_IDLE_MINUTES, 0 disables).
                               Attached sessions are never closed. Runs
                               automatically every minute while any agent is up
  attach <name>                print the command to watch the agent live
  exec   <text...> [--cwd DIR] [--model M]
                               headless one-shot "codex exec", no tmux
  version                      print VERSION and the checkout's commit

Spawned codex/claude agents run with the provider's master permission bypass by
default (unrestricted). Set AGENTMUX_NO_BYPASS=1 to spawn sandboxed instead.

Env: AGENTMUX_QUIET_MS, AGENTMUX_TIMEOUT_S, AGENTMUX_POLL_MS, AGENTMUX_COLS/ROWS
     AGENTMUX_NO_BYPASS, AGENTMUX_NO_COURIER, AGENTMUX_SETTLE_MS
     AGENTMUX_WAIT_NO_MARKER=1   wait on stillness only, not the CLI's busy
                                 marker. Use if a CLI changes its footer and
                                 `ask` starts returning early
     AGENTMUX_COURIER_INTERVAL, AGENTMUX_SEND_DELAY[_MULTILINE]
     AGENTMUX_IDLE_MINUTES       close an agent after this many minutes with no
                                 pane activity (default 60; 0 disables)
USAGE
}

# Auth method resolution.
#
# WHY A HELPER RATHER THAN A CASE BLOCK: the set of auth methods is data
# (dashboard/auth.json), so the harness must not hardcode which ones exist. It asks
# the manifest what a method needs, and gets back shell-ready exports plus any extra
# CLI flags.
#
# Secrets are NOT returned. A method's secret env var names are declared in the
# manifest and their VALUES live in $ROOT/env (0600), which is sourced into the pane
# separately - so a key never passes through this variable, this script's output, or
# the tmux command line.
#
# Prints:  <flags>\t<exports>
# Returns: 1 if the method is unknown or not fully configured.
auth_resolve() {
  local method="$1" cli="$2" repo="${AGENTMUX_REPO:-}"
  [ -n "$repo" ] || { printf 'agentmux: AGENTMUX_REPO is unset; cannot read the auth manifest\n' >&2; return 1; }
  python3 - "$repo" "$method" "$cli" "$ROOT" <<'PY'
import json, os, pathlib, re, sys, shlex

repo, method_id, cli = sys.argv[1], sys.argv[2], sys.argv[3]
manifest = pathlib.Path(repo) / "dashboard" / "auth.json"
root = pathlib.Path(sys.argv[4])

try:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    methods = {m["id"]: m for m in data["methods"]}
    providers = {p["id"]: p for p in data["providers"]}
except (OSError, ValueError, KeyError) as err:
    sys.exit(f"agentmux: cannot read {manifest}: {err}")

method = methods.get(method_id)
if method is None:
    sys.exit(f"agentmux: unknown --auth method '{method_id}'. "
             f"Run: python3 taskmgmt/setup_auth.py --list")
if method["cli"] != cli:
    sys.exit(f"agentmux: --auth {method_id} is for --cli {method['cli']}, not {cli}")
provider = providers.get(method.get("provider"))
if provider is None:
    sys.exit(f"agentmux: {method_id} names an unknown provider "
             f"{method.get('provider')!r} in {manifest}")

settings = {}
path = root / "auth.json"
if path.exists():
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as err:
        sys.exit(f"agentmux: {path} is not valid JSON: {err}")
# Two scopes: shared provider attributes (a region, a key) and per-method ones (a
# model id, a gateway URL). Keeping them apart is what stops two CLIs on the same
# provider from overwriting each other's model.
shared = (settings.get("providers") or {}).get(provider["id"], {})
mine = (settings.get("methods") or {}).get(method_id, {})

# A provider's SECRETS are declared here as NAMES and their values live in
# $ROOT/env. Only presence is checked and no value is read into this process.
#
# WHY THIS IS HERE: the gate used to validate settings[] only. An api-key method
# declares no settings, so codex-api-key and claude-api-key resolved as "configured"
# with no key stored at all, and the CLI died inside the pane with nothing pointing
# at the cause. setup_auth --list and /api/auth both checked secrets correctly; only
# the spawn path did not.
env_names = set()
env_path = root / "env"
if env_path.exists():
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            found = re.match(r"\s*export\s+([A-Z][A-Z0-9_]*)=", line)
            if found:
                env_names.add(found.group(1))
    except OSError as err:
        sys.exit(f"agentmux: cannot read {env_path}: {err}")

missing = [f"{provider['id']}.{s['key']}" for s in provider.get("settings", [])
           if s["key"] not in shared]
missing += [f"{method_id}.{s['key']}" for s in method.get("settings", [])
            if s["key"] not in mine]
secrets = [name for name in provider.get("secrets", []) if name not in env_names]
if missing or secrets:
    # A secret is entered against the PROVIDER, a setting against the method, so point
    # at whichever command can actually fix what is missing.
    fix = (f"--provider {provider['id']}" if secrets else method_id)
    sys.exit(f"agentmux: --auth {method_id} is not configured (missing "
             f"{', '.join(missing + secrets)}). "
             f"Run: python3 taskmgmt/setup_auth.py {fix}")

exports = []
for name, literal in (method.get("env") or {}).items():
    exports.append(f"export {name}={shlex.quote(str(literal))};")
for name, key in (method.get("env_from_provider") or {}).items():
    exports.append(f"export {name}={shlex.quote(str(shared[key]))};")
for name, key in (method.get("env_from_method") or {}).items():
    exports.append(f"export {name}={shlex.quote(str(mine[key]))};")

flags = []
if "codex_profile" in method:
    profile = pathlib.Path(os.environ.get("CODEX_HOME") or (pathlib.Path.home() / ".codex"))
    if not (profile / f"{method_id}.config.toml").is_file():
        sys.exit(f"agentmux: codex profile for {method_id} is missing. "
                 f"Run: python3 taskmgmt/setup_auth.py {method_id}")
    # Replaces the yolo profile: codex layers exactly one -p/--profile.
    flags.append(f"--profile {method_id}")
    # Pass the model EXPLICITLY as well, even though the profile also names one.
    # The profile is a file only setup_auth.py writes, but the model is switchable from
    # the dashboard's Settings, which writes ~/.agentmux/auth.json. A flag overrides the
    # profile, so a model chosen in the UI takes effect on the next spawn without the
    # TOML having to be regenerated - and there is only one authority for it.
    chosen_model = mine.get("model")
    if chosen_model:
        flags.append(f"-m {shlex.quote(str(chosen_model))}")

print(" ".join(flags) + "\t" + " ".join(exports))
PY
}

# The configured default method for a CLI, or empty if none is set.
auth_default_for() {
  local cli="$1"
  python3 - "$cli" "$ROOT" <<'PY' 2>/dev/null
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[2]) / "auth.json"
if path.exists():
    try:
        print(json.loads(path.read_text(encoding="utf-8")).get("active", {}).get(sys.argv[1], ""))
    except ValueError:
        pass
PY
}

cmd_spawn() (
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "spawn needs a name"
  local cli="codex" cwd="$PWD" model="" task="" summary="" created="" auth=""
  local agentdef="" posture="unrestricted" persona_file="" tools="" deny_tools="" team="" role=""
  local posture_explicit=0 client_selection=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --cli|--cwd|--model|-m|--task|--auth|--agentdef|--posture|--persona-file|--tools|--deny-tools|--team|--role|--client-selection)
        [ $# -ge 2 ] && [ -n "$2" ] && [[ "$2" != --* ]] || die "spawn: $1 needs a value"
        ;;
      *) die "spawn: unknown option '$1'" ;;
    esac
    case "$1" in
      --cli) cli="$2" ;; --cwd) cwd="$2" ;; --model|-m) model="$2" ;;
      --task) task="$2" ;; --auth) auth="$2" ;; --agentdef) agentdef="$2" ;;
      --posture) posture="$2"; posture_explicit=1 ;; --persona-file) persona_file="$2" ;;
      --tools) tools="$2" ;; --deny-tools) deny_tools="$2" ;;
      --team) team="$2" ;; --role) role="$2" ;;
      --client-selection) client_selection="$2" ;;
    esac
    shift 2
  done
  if [ -n "$client_selection" ]; then
    [ "$cli" = claude ] && [ "$posture" = unrestricted ] && [ "${AGENTMUX_NO_BYPASS:-0}" != 1 ] || die "--client-selection requires managed Claude with unrestricted posture"
    [[ "$client_selection" = /* ]] || die "--client-selection requires an absolute private selection path"
  fi
  [ -z "$agentdef" ] || [[ "$agentdef" =~ ^[a-z][a-z0-9-]{0,63}$ ]] || die "invalid --agentdef"
  [ -z "$team" ] || { [ "${#team}" -le 511 ] && [[ "$team" =~ ^TM-[0-9]+$ ]]; } || die "invalid --team (expected TM-042)"
  case "$role" in ''|lead|worker|reviewer|researcher) ;; *) die "invalid --role" ;; esac
  case "$posture" in read-only|workspace-write|unrestricted) ;; *) die "invalid --posture" ;; esac
  local value
  for value in "$tools" "$deny_tools"; do
    [ -z "$value" ] || { [ "${#value}" -le 511 ] && [[ "$value" =~ ^[A-Za-z][A-Za-z0-9_]*(,[A-Za-z][A-Za-z0-9_]*)*$ ]]; } || die "invalid tool CSV (expected tool names)"
  done
  if [ -n "$persona_file" ]; then
    persona_file="$(to_wsl_path "$persona_file")"
    [ -f "$persona_file" ] && [ ! -L "$persona_file" ] && [ -r "$persona_file" ] || die "--persona-file must be a readable regular file, not a symlink"
  fi
  have "$name" && die "agent '$name' already exists (kill it first)"

  # A name reaches three places that make an unchecked one dangerous rather than
  # merely untidy: the pane environment (as $AGENTMUX_AGENT, inside single quotes,
  # so a quote character escapes into the launch command), a sidecar path under
  # run/, and a queue filename the courier and the dashboard both read back. The
  # accepted set is a subset of ccstore.py's NAME_PATTERN - '.' is excluded because
  # tmux gives it meaning in a target specifier.
  printf '%s' "$name" | grep -Eq '^[A-Za-z0-9_-]{1,64}$' \
    || die "agent name must be 1-64 chars of letters, digits, '_' or '-' (got '$name')"

  # Jira binding. Two accepted forms:
  #   --task ABC-123        bind an existing issue
  #   --task new:"Summary"  create the issue first, then bind the returned key
  #
  # Validated, never passed through: this value reaches the pane environment and a
  # sidecar the dashboard renders, so an unchecked string is both a shell- and a
  # display-injection vector.
  if [ -n "$task" ]; then
    case "$task" in
      new:*)
        summary="${task#new:}"
        [ -n "$summary" ] || die '--task new: needs a summary, e.g. --task new:"Fix the thing"'
        task_cli >/dev/null || die "--task new: needs taskmgmt/task.py plus ~/.agentmux/atlassian.json"
        created="$(timeout 60 python3 "$(task_cli)" create --summary "$summary"                     --label agentmux --label "agent-$name" 2>/dev/null | tail -1)"
        printf '%s' "$created" | grep -Eq '^[A-Z][A-Z0-9_]+-[0-9]+$'           || die "could not create a Jira issue (got '${created:-<empty>}')"
        task="$created"
        printf "created Jira issue %s for agent '%s'
" "$task" "$name"
        ;;
      *)
        printf '%s' "$task" | grep -Eq '^[A-Z][A-Z0-9_]+-[0-9]+$'           || die "--task must be ABC-123 or new:\"Summary\" (got '$task')"
        ;;
    esac
  fi

  cwd="$(to_wsl_path "$cwd")"
  [ -d "$cwd" ] || die "not a directory: $cwd"

  # The machine brake is a workspace-write ceiling; read-only stays read-only.
  if [ "${AGENTMUX_NO_BYPASS:-0}" = 1 ] && [ "$posture" = unrestricted ]; then
    printf 'agentmux: AGENTMUX_NO_BYPASS clamps unrestricted to workspace-write\n' >&2
    posture=workspace-write
  fi
  # Team members must claim, journal and prove identity outside the workspace.
  if [ -n "$team" ] && [ "$posture" != unrestricted ]; then
    die "sandbox posture '$posture' is incompatible with dispatch/team coordination: tmux socket and claim/journal state are outside the workspace"
  fi
  local bypass=0
  [ "$posture" = unrestricted ] && bypass=1
  case "$cli" in
    codex|claude) ;;
    grok)
      # Installed Grok exposes named sandbox profiles, but neither --help nor
      # inspect establishes a filesystem policy for these two contract levels.
      # Permission modes alone are not a filesystem boundary. Fail closed.
      [ "$posture" = unrestricted ] || die "grok cannot enforce posture '$posture': no verified sandbox profile"
      ;;
    *)
      [ "$posture_explicit" = 0 ] && [ -z "$agentdef$tools$deny_tools$persona_file$team$role" ] || die "cannot enforce agent definition flags for CLI '$cli'"
      ;;
  esac
  # Protect config GC and same-name preparation until the pane exists. flock is
  # released by this subshell even on validation/config/launch failure.
  local spawn_lock
  exec {spawn_lock}>"$ROOT/.spawn.lock" || die "cannot open spawn lock"
  flock -x "$spawn_lock" || die "cannot lock spawn"
  have "$name" && die "agent '$name' already exists (kill it first)"
  claude_config_gc

  local nb launch env_prefix
  nb=""
  [ -n "${AGENTMUX_NATIVE_CORE_ROOT:-}" ] || nb="$(node_bin)"
  # ~/.grok/bin holds xAI's grok CLI. Its installer adds that to .bashrc, which a
  # tmux pane never sources (non-login, non-interactive), so add it explicitly.
  # ~/.local/bin is where install.sh puts `agentmux` itself. Without it an agent's own
  # shell cannot run `agentmux hub inbox` or `agentmux post` - measured 2026-09-29 on a
  # shell pane: "agentmux: command not found". It only ever worked where a CLI happened
  # to start a login shell that added it.
  env_prefix="export PATH='${nb}:'\$HOME'/.local/bin:'\$HOME'/.grok/bin:'\$PATH;"
  if [ -n "${AGENTMUX_NATIVE_CORE_ROOT:-}" ]; then
    local native_path native_home
    printf -v native_path '%q' "$AGENTMUX_NATIVE_CORE_ROOT/app/native-bin:/usr/bin:/bin"
    printf -v native_home '%q' "$HOME"
    env_prefix="export PATH=$native_path HOME=$native_home; unset CODEX_MANAGED_BY_BUN CODEX_MANAGED_BY_PNPM CODEX_MANAGED_BY_VITE_PLUS;"
  fi
  # An issue key is not a secret, so exporting it directly is fine. Contrast
  # $ROOT/env below, which is SOURCED precisely so credentials never reach the
  # tmux command line or `ps`. The key is validated in the arg loop above.
  [ -n "$task" ] && env_prefix="$env_prefix export AGENTMUX_TASK='${task}';"
  # The agent's own name. Without it an agent has no way to know what it is called,
  # so it cannot fill in the sender field and `agentmux post` has nothing to
  # attribute. Validated against the pattern above, so the quoting holds.
  env_prefix="$env_prefix export AGENTMUX_AGENT='${name}';"
  # The pane runs under the shared tmux server, whose environment is whatever the
  # FIRST spawn had - not this caller's. Without this, an agent spawned under a
  # private AGENTMUX_HOME runs `agentmux hub inbox --ack` against the default hub
  # and acks there instead (2026-10-02). Only exported when set, so a default spawn
  # is unchanged.
  if [ -n "${AGENTMUX_HOME:-}" ]; then
    local quoted_home
    printf -v quoted_home '%q' "$AGENTMUX_HOME"
    env_prefix="$env_prefix export AGENTMUX_HOME=$quoted_home;"
  fi
  # Private env for spawned panes - API keys for custom providers (e.g.
  # XAI_API_KEY for the codex "grok" profile) go in $ROOT/env, mode 0600, on the
  # Linux filesystem. It is SOURCED at pane start rather than interpolated into
  # the tmux command, so the value never appears in `ps` output, in
  # `#{pane_start_command}`, or in this script's own logs. Panes are non-login
  # shells, so ~/.bashrc and ~/.profile are not read - this is the hook for them.
  if [ -f "$ROOT/env" ]; then
    case "$(file_mode "$ROOT/env")" in
      600|400) ;;
      *) printf "agentmux: %s/env is not mode 0600 - refusing to load it.\n         chmod 600 '%s/env'\n" "$ROOT" "$ROOT" >&2; return 1 ;;
    esac
    env_prefix="$env_prefix set -a; . '$ROOT/env'; set +a;"
  fi
  # THE ORCHESTRATOR'S WARRANT SECRET, and only for the pane it names.
  #
  # Deliberately NOT $ROOT/env, which the block above sources into EVERY pane - that
  # would hand the credential to every worker on the box and leave only the name
  # binding standing. Sourced the same way for the same reason: the value never
  # appears in `ps`, in #{pane_start_command}, or in this script's logs.
  if [ -f "$ROOT/orchestrator.warrant" ] && [ -f "$ROOT/orchestrator.env" ]; then
    local warranted
    warranted="$(python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("agent",""))
except Exception:
    pass' "$ROOT/orchestrator.warrant" 2>/dev/null)"
    if [ -n "$warranted" ] && [ "$warranted" = "$name" ]; then
      case "$(file_mode "$ROOT/orchestrator.env")" in
        600|400) env_prefix="$env_prefix set -a; . '$ROOT/orchestrator.env'; set +a;" ;;
        *) printf "agentmux: %s/orchestrator.env is not mode 0600 - refusing to load it.
" "$ROOT" >&2; return 1 ;;
      esac
    fi
  fi
  # Auth method. An explicit --auth wins; otherwise use whatever setup_auth.py
  # recorded as this CLI's active method. No method configured means the CLI's own
  # built-in default (an existing OAuth login), which is the pre-existing behavior.
  local auth_flags="" auth_exports="" auth_line=""
  [ -n "$auth" ] || auth="$(auth_default_for "$cli")"
  if [ -n "$auth" ]; then
    auth_line="$(auth_resolve "$auth" "$cli")" || return 1
    auth_flags="${auth_line%%$(printf '\t')*}"
    auth_exports="${auth_line#*$(printf '\t')}"
    [ -n "$auth_exports" ] && env_prefix="$env_prefix $auth_exports"
  fi

  local quoted_model="" quoted_path="" ccd="" cli_help=""
  [ -z "$model" ] || printf -v quoted_model '%q' "$model"
  case "$cli" in
    codex)
      # --no-daemon IS LOAD-BEARING, NOT A PREFERENCE.
      # codex 0.159 runs a SHARED app-server daemon and delegates every shell
      # command to it. That daemon is a singleton: the first pane to start it wins,
      # and it keeps THAT pane's environment for its whole life. Measured 2026-09-29
      # with five codex agents up - every one of them saw $AGENTMUX_AGENT=agora-image,
      # the first to spawn, so a claim or a journal entry from any of the five would
      # have been filed in agora-image's name. resolve_identity exists to stop exactly
      # that and cannot see it, because the crossover happens below the shell it checks.
      # The daemon also execs under seccomp (Seccomp: 2) in its own mount and network
      # namespaces, so connect() to the tmux socket returns EPERM, live_agents() raises
      # TmuxUnavailable, and `agentmux claim` exits 2. That is what blocked all four art
      # agents on TM-137: they could not claim, so they correctly refused to edit.
      # The bypass flag below cannot fix either half - it configures THIS client, while
      # the exec happens inside the daemon.
      launch="codex --no-daemon${auth_flags:+ $auth_flags}${model:+ -m $quoted_model}"
      # Live web search is OPT-IN. codex does not search unless launched with
      # --search, and 0.159 has no config.toml key that is confirmed to do the
      # same (web_search_request is gone from `codex features list`). Research
      # tasks that need current facts - schedules, prices, news - set
      # AGENTMUX_CODEX_SEARCH=1 at spawn. Everything else keeps no network egress
      # from the model.
      [ "${AGENTMUX_CODEX_SEARCH:-0}" = 1 ] && launch="$launch --search"
      if [ "$bypass" = 1 ]; then
        launch="$launch --dangerously-bypass-approvals-and-sandbox"
      else
        launch="$launch --sandbox $posture --ask-for-approval never"
      fi
      ;;
    claude)
      ccd="$(claude_config_dir "$name" "$posture" "$tools" "$deny_tools")" || die "could not prove claude posture '$posture'"
      printf -v quoted_path '%q' "$ccd"
      env_prefix="$env_prefix export CLAUDE_CONFIG_DIR=$quoted_path;"
      printf -v quoted_path '%q' "$ccd/settings.json"
      launch="claude${model:+ --model $quoted_model} --settings $quoted_path --setting-sources ''"
      if [ "$bypass" = 0 ]; then
        cli_help="$(claude --help 2>/dev/null)" || die "cannot verify claude restricted mode"
        [[ "$cli_help" == *--restricted* ]] || die "claude cannot enforce bounded posture: --restricted unavailable"
        launch="$launch --restricted --strict-mcp-config --mcp-config '{\"mcpServers\":{}}'"
        # Positive builtin set closes alternative writers/delegation paths. An
        # explicit --tools must be a subset, never reopen a shell via --restricted.
        local bounded_tools="Read,Grep,Glob" requested
        [ "$posture" = read-only ] || bounded_tools="$bounded_tools,Write,Edit"
        if [ -n "$tools" ]; then
          local -a requested_tools
          IFS=, read -r -a requested_tools <<< "$tools"
          for requested in "${requested_tools[@]}"; do
            [[ ",$bounded_tools," == *",$requested,"* ]] || die "tool '$requested' cannot be enabled under $posture"
          done
        else
          tools="$bounded_tools"
        fi
      fi
      [ -z "$tools" ] || launch="$launch --tools '$tools'"
      [ -z "$deny_tools" ] || launch="$launch --disallowedTools '$deny_tools'"
      if [ "$bypass" = 1 ] && { [ -n "$client_selection" ] || federation_on; }; then
        local _mcp
        _mcp="$(agentmux_mcp_config "$client_selection")" || die "could not prepare the agentmux MCP configuration"
        printf -v quoted_path '%q' "$_mcp"
        [ -n "${_mcp:-}" ] && launch="$launch --mcp-config $quoted_path"
      fi
      ;;
    grok) launch="grok --permission-mode bypassPermissions${model:+ -m $quoted_model}" ;;
    shell) launch="${SHELL:-/bin/bash}" ;;
    *) launch="$cli" ;;
  esac

  # Copy before launch without following an old sidecar symlink. Persona content
  # is never interpolated into a command; workers receive only its file path.
  local persona_tmp=""
  if [ -n "$persona_file" ] || { [ "$cli" != claude ] && [ -n "$tools$deny_tools" ]; }; then
    persona_tmp="$(mktemp "$RUNDIR/.persona.XXXXXX")" || die "cannot create persona"
    if [ -n "$persona_file" ]; then
      cat -- "$persona_file" > "$persona_tmp" || { rm -f "$persona_tmp"; die "cannot copy persona"; }
    fi
    if [ "$cli" != claude ] && [ -n "$tools$deny_tools" ]; then
      printf '\n[degraded: named tool restrictions are advisory on %s]\nUse only these tools when specified: %s\nDo not use these tools: %s\n' "$cli" "${tools:-unspecified}" "${deny_tools:-none}" >> "$persona_tmp"
      printf 'agentmux: degraded: %s named tool restrictions recorded in persona\n' "$cli" >&2
    fi
    chmod 600 "$persona_tmp" && mv -f "$persona_tmp" "$RUNDIR/$name.persona" || die "cannot publish private persona"
    [ "$(file_mode "$RUNDIR/$name.persona")" = 600 ] || die "persona must be mode 0600"
    printf -v quoted_path '%q' "$RUNDIR/$name.persona"
    env_prefix="$env_prefix export AGENTMUX_PERSONA_FILE=$quoted_path;"
  else
    rm -f "$RUNDIR/$name.persona"
  fi

  # A shared tmux server must not reuse another pane's callback selection.
  # Values are paths/context only; inline tokens never go into pane commands.
  local callback_key callback_value
  for callback_key in AGENTMUX_WINDOWS_CALLBACK AGENTMUX_WSL_DISTRO AGENTMUX_WSL_BIN AGENTMUX_WSL_CWD AGENTMUX_HUB_URL AGENTMUX_HUB_TOKEN_FILE AGENTMUX_SOCKET TMUX_TMPDIR AGENTMUX_NATIVE_CORE_ROOT AGENTMUX_NATIVE_CORE_TMUX AGENTMUX_NATIVE_CORE_CODEX CODEX_MANAGED_PACKAGE_ROOT CODEX_MANAGED_BY_NPM; do
    if declare -p "$callback_key" >/dev/null 2>&1; then
      printf -v callback_value '%q' "${!callback_key}"
      env_prefix="$env_prefix export $callback_key=$callback_value;"
    else
      env_prefix="$env_prefix unset $callback_key;"
    fi
  done
  env_prefix="$env_prefix unset AGENTMUX_SPAWN_WINDOWS_CALLBACK;"
  if [ "${AGENTMUX_SPAWN_WINDOWS_CALLBACK:-}" = 1 ]; then
    env_prefix="$env_prefix export AGENTMUX_WINDOWS_CALLBACK=1; unset AGENTMUX_HUB_TOKEN;"
  fi
  if [ -n "${AGENTMUX_NATIVE_CORE_ROOT:-}" ]; then
    # Credential settings may be sourced above; they cannot replace selected tools.
    env_prefix="$env_prefix export PATH=$native_path HOME=$native_home;"
  fi

  tm new-session -d -s "$name" -c "$cwd" -x "$COLS" -y "$ROWS" \
     "${env_prefix} exec ${launch}" \
     || die "failed to start tmux session"
  local pane
  pane="$(tm list-panes -t "$name" -F '#{pane_id}' 2>/dev/null | head -1)"
  [ -n "$pane" ] || die "spawned '$name' but could not resolve its pane"
  printf '%s\n' "$pane" > "$RUNDIR/$name.pane"

  tm set-option -t "=$name" history-limit 50000 >/dev/null 2>&1
  tm set-option -t "=$name" mouse on >/dev/null 2>&1   # scroll works when you attach
  # ARCHIVE THE PREVIOUS LOG, NEVER TRUNCATE IT (TM-211, C14 / R-EVID-1). Agent
  # names are roles - rev, lead, worker2 are respawned under the same name all day -
  # so `: >` here erased the only pane record of the previous run the moment its
  # successor started, often before anyone had asked what it delivered. If the move
  # fails, append to the old log rather than truncate it: a mixed log is recoverable,
  # an emptied one is not.
  if archive_log "$name"; then
    : > "$LOGDIR/$name.log"
  else
    printf "agentmux: could not archive %s.log; appending to it instead of truncating\n" "$name" >&2
    printf '\n===== agentmux: respawned %s at %s =====\n' "$name" "$(iso_now)" >> "$LOGDIR/$name.log"
  fi
  tm pipe-pane -o -t "$pane" "cat >> '$LOGDIR/$name.log'"

  printf '%s\n' "$cli" > "$RUNDIR/$name.cli"
  printf '%s\n' "$cwd" > "$RUNDIR/$name.cwd"
  printf '%s\n' "$launch" > "$RUNDIR/$name.launch"
  iso_now > "$RUNDIR/$name.started"
  if ! { printf '%s\n' "$agentdef" > "$RUNDIR/$name.agentdef" &&
         printf '%s\n' "$posture" > "$RUNDIR/$name.posture" &&
         printf '%s\n' "$team" > "$RUNDIR/$name.team" &&
         printf '%s\n' "$role" > "$RUNDIR/$name.role"; }; then
    tm kill-session -t "=$name" 2>/dev/null
    rm -f "$RUNDIR/$name".*
    die "could not record spawn metadata"
  fi
  # Record an enrolled owner's bounded request in the same generation as the
  # process sidecars. This remains under the spawn lock, so a same-name replacement
  # cannot inherit the request. A failed write removes the process and its metadata.
  if [ -n "${AGENTMUX_OWNER_REQUEST:-}" ]; then
    if [ "${#AGENTMUX_OWNER_REQUEST}" -gt 8192 ] \
       || ! printf '%s\n' "$AGENTMUX_OWNER_REQUEST" > "$RUNDIR/$name.request"; then
      if tm kill-session -t "=$name" 2>/dev/null; then
        rm -f "$RUNDIR/$name".*
        die "could not record orchestration request; new session removed"
      fi
      printf 'could not record orchestration request; termination unconfirmed and metadata retained\n' >&2
      return 75
    fi
    chmod 600 "$RUNDIR/$name.request" 2>/dev/null || {
      if tm kill-session -t "=$name" 2>/dev/null; then
        rm -f "$RUNDIR/$name".*
        die "could not protect orchestration request; new session removed"
      fi
      printf 'could not protect orchestration request; termination unconfirmed and metadata retained\n' >&2
      return 75
    }
  fi
  # Read back by `list` and by the dashboard through its hardened read_field().
  [ -n "$task" ] && printf '%s\n' "$task" > "$RUNDIR/$name.task"
  # Which auth method this agent actually started with. An id from auth.json, never
  # a credential - the dashboard reads this file, so it must be safe to display.
  [ -n "$auth" ] && printf '%s\n' "$auth" > "$RUNDIR/$name.auth"
  # Recorded explicitly: for claude the bypass lives in the pane's environment,
  # not the launch line, so the launch line alone cannot tell you the posture.
  case "$cli" in
    codex|claude|grok) [ "$bypass" = 1 ] && echo UNRESTRICTED || echo sandboxed ;;
    *)            echo n/a ;;
  esac > "$RUNDIR/$name.perms"

  # Liveness gate. tmux new-session exits 0 even when the child dies instantly,
  # so without this a bad flag or a missing binary reports a successful spawn
  # and only surfaces later as "no such agent". Measured on a broken codex.
  sleep 2
  # Two ways the child can be gone: the session vanished with it, or - under
  # `remain-on-exit on` - the session survives holding a dead pane. Checking only
  # the session passes the second case and reports a successful spawn for a
  # process that already exited.
  local dead=""
  have "$name" || dead="session gone"
  [ -z "$dead" ] && [ "$(tm display-message -p -t "$pane" '#{pane_dead}' 2>/dev/null)" = "1" ] \
    && dead="pane dead (remain-on-exit)"
  if [ -n "$dead" ]; then
    printf "spawn FAILED: '%s' exited immediately (%s).\n" "$name" "$dead" >&2
    printf "launch line was: %s\n" "$launch" >&2
    if [ -s "$LOGDIR/$name.log" ]; then
      printf -- '--- last output ---\n' >&2
      strip_ansi < "$LOGDIR/$name.log" | tail -15 >&2
    fi
    rm -f "$RUNDIR/$name".* 2>/dev/null
    return 1
  fi

  # Keep kill and replacement spawn excluded until all sidecars and the initial
  # liveness check are complete, including failed-start cleanup.
  flock -u "$spawn_lock"
  exec {spawn_lock}>&-

  printf "spawned '%s' [%s] in %s\n" "$name" "$cli" "$cwd"
  [ -n "$auth" ] && printf "  auth: %s\n" "$auth"

  # Bring the message courier up with the first agent.
  #
  # Nothing survives a reboot here - the tmux server, the Bedrock gateway and the
  # courier all have to be started again, and a courier that is not running fails
  # SILENTLY: `post` succeeds, the message sits in the queue, and the recipient
  # simply never hears anything. Tying it to spawn means messaging works whenever
  # there is anything to message, without a boot-time service.
  #
  # AGENTMUX_NO_COURIER=1 opts out. Failure here is never fatal to a spawn.
  #
  # Takes the same lock as stop_courier_if_idle (#17). This agent's session is already
  # up before we get here, so a concurrent `kill` either holds the lock and sees this
  # session on its re-check, or waits and sees it. Either way it does not stop a
  # courier this agent is about to depend on.
  # A retired courier stays retired (TM-214): the hub delivers now, and a courier
  # restarted by the next spawn would race it for the same panes.
  if [ "${AGENTMUX_NO_COURIER:-0}" != "1" ] && [ ! -e "$ROOT/hub/courier-retired" ] \
     && [ -n "${AGENTMUX_REPO:-}" ] && [ -f "$AGENTMUX_REPO/taskmgmt/courier.py" ]; then
    local clock="$RUNDIR/.courier.lock" cwaited=0
    mkdir -p "$RUNDIR" 2>/dev/null
    until mkdir "$clock" 2>/dev/null; do
      cwaited=$((cwaited + 1))
      [ "$cwaited" -gt 50 ] && { rm -rf "$clock" 2>/dev/null; cwaited=0; }
      sleep 0.1
    done
    if ! python3 "$AGENTMUX_REPO/taskmgmt/courier.py" --status 2>/dev/null \
         | grep -q '^courier:   running'; then
      cmd_courier start >/dev/null 2>&1 \
        && printf "  courier: started (queued messages will be delivered)\n"
    fi
    rm -rf "$clock" 2>/dev/null
  fi
  # Same lifecycle as the courier, for the same reason: tie it to there being an
  # agent, so nothing polls an empty tmux server and nothing has to be started at
  # boot. Idempotent - a watchdog already running is left alone.
  if start_idle_watchdog && [ "${AGENTMUX_IDLE_MINUTES:-$IDLE_MINUTES}" != 0 ]; then
    printf '  idle:    closes after %sm without pane activity\n' \
      "${AGENTMUX_IDLE_MINUTES:-$IDLE_MINUTES}"
  fi
  case "$cli" in codex|claude|grok) printf '  posture: %s\n' "$posture" ;; esac
  printf "watch it:  %stmux -L %s attach -t %s\n" "$(attach_prefix)" "$SOCKET" "$name"
)

# Does the pane currently show a blocking prompt that is NOT the agent's normal input?
#
# WHY THIS EXISTS. `send` appends Enter, so sending text while a modal is up actuates the
# modal's default rather than talking to the agent. That is not theoretical: a codex
# "Update available! 1. Update now / Press enter to continue" prompt appeared on a fresh
# spawn, a routine `send` landed on it, and Enter selected "Update now" — which ran
# npm install and took the agent down mid-session.
#
# Matching the LAST few lines only, because these prompts live at the bottom of the pane
# and the same words appear harmlessly in scrollback.
# The patterns below are in three groups, and the second and third exist because the
# first was not enough. Measured 2026-09-22 on a fresh `claude` pane: it shows THREE
# modals in a row - folder trust, bypass-permissions consent, then an Opus effort
# recommendation - and none of them matched. `send` typed into the second one, Enter
# selected its default of "No, exit", and the agent died. That is bug 30 all over
# again on a different CLI, so the guard now covers the shapes rather than one CLI's
# wording:
#
#   1. explicit question forms  - the original set
#   2. confirm/cancel footers   - "Enter to confirm", "Esc to cancel"
#   3. a SELECTED option line   - a caret or arrow followed by an answer word, or by
#                                 a numbered choice
#
# Group 3 needs care: `❯` and `›` are also the IDLE input prompts of claude and codex.
# It only fires when the marker is followed by an answer-shaped word or "N.", which an
# empty prompt never is.
#
# Matching the LAST few lines only, because these prompts live at the bottom of the pane
# and the same words appear harmlessly in scrollback.
# Split in two so the PATTERN can be tested without a tmux server or a real CLI:
# modal_text takes the text, modal_prompt supplies it from a pane.
# dashboard/test_modal_guard.sh exercises modal_text against captured samples.
modal_text() {
  printf '%s' "$1" | grep -Eqi \
    'press enter to continue|update now \(runs|\[y/n\]|\(y/n\)|do you (want|trust)|allow this|press any key|select an option|continue\? *$|enter to confirm|esc to cancel|no, (exit|quit)|yes, i (accept|trust)|trust this folder|^[[:space:]]*[│|]?[[:space:]]*[❯›▶>][[:space:]]+([0-9]+\.|yes\b|no\b|switch\b|keep\b|continue\b|sign in\b|log ?in\b)'
}

modal_prompt() {
  local pane="$1" tail_text
  tail_text="$(tm capture-pane -p -t "$pane" 2>/dev/null | grep -v '^[[:space:]]*$' | tail -8)"
  modal_text "$tail_text"
}

# ── unblock ──────────────────────────────────────────────────────────────────
#
# THE PROMPTS THAT ANSWER THEMSELVES, AND THE ONES THAT MUST NOT.
#
# `send` refuses while a pane shows a modal and the courier retries without ever
# forcing, so nothing is lost - but nothing ANSWERS either, and a pane parked on a
# first-run dialog waits for a human who may be hours away. Four panes sat on the
# same codex update prompt this week.
#
# The reason there is no generic "just press Enter" is in the samples
# dashboard/test_modal_guard.sh pins. The defaults are hostile:
#
#     codex   1. Update now (runs npm install -g)   <- preselected
#     claude  > No, exit / Yes, I accept            <- default KILLS the agent
#
# So this answers only prompts it can positively identify, and always with the
# option that DECLINES or keeps the current state - never the highlighted default.
# Everything else is reported and left alone, because a folder-trust dialog, a
# bypass-permissions consent and an account chooser are decisions, not nuisances,
# and a harness that clicks through those has removed the point of the guard.
#
# modal_answer prints "<keys>|<what it is>|<why this answer>" for a prompt it knows,
# and nothing at all for one it does not.
modal_answer() {
  local text="$1"
  # codex's update nag. VERIFIED on four live panes 2026-09-27: "2" selects Skip.
  # Never 1 - that is the one that runs npm install -g inside the agent's pane.
  if printf '%s' "$text" | grep -Eqi 'update available' &&
     printf '%s' "$text" | grep -Eqi 'update now \(runs'; then
    printf '2|codex update nag|Skip; option 1 runs npm install -g in the pane'
    return 0
  fi
  return 1
}

# Why a known prompt is still NOT ours to answer. Printed so the refusal names the
# decision rather than just declining to act.
modal_decision() {
  local text="$1"
  printf '%s' "$text" | grep -Eqi 'do you trust|trust this folder|trust the contents' \
    && { printf 'a trust decision about this directory'; return 0; }
  printf '%s' "$text" | grep -Eqi 'accept all responsibility|yes, i accept' \
    && { printf 'a consent decision, and its default is "No, exit"'; return 0; }
  printf '%s' "$text" | grep -Eqi 'account with subscription|sign in with|console account' \
    && { printf 'an account choice'; return 0; }
  printf '%s' "$text" | grep -Eqi '\[y/n\]|\(y/n\)|overwrite' \
    && { printf 'a yes/no whose consequence this cannot see'; return 0; }
  return 1
}

cmd_unblock() {
  local dry=0 targets=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run) dry=1; shift ;;
      --all)     shift ;;
      -*)        die "unblock: unknown flag '$1' (valid: --all, --dry-run)" ;;
      *)         targets="$targets $1"; shift ;;
    esac
  done
  if [ -z "${targets// /}" ]; then
    targets="$(tm list-sessions -F '#{session_name}' 2>/dev/null)"
  fi
  [ -n "${targets// /}" ] || { printf 'no agents\n'; return 0; }

  local name pane text answer keys what why decision stuck=0 freed=0
  for name in $targets; do
    pane="$(pane_of "$name" 2>/dev/null)"
    if [ -z "$pane" ]; then
      printf '  %-22s no pane\n' "$name"; continue
    fi
    text="$(tm capture-pane -p -t "$pane" 2>/dev/null | grep -v '^[[:space:]]*$' | tail -8)"
    if ! modal_text "$text"; then
      printf '  %-22s working\n' "$name"; continue
    fi
    if answer="$(modal_answer "$text")"; then
      keys="${answer%%|*}"; what="${answer#*|}"; why="${what#*|}"; what="${what%%|*}"
      if [ "$dry" = 1 ]; then
        printf '  %-22s WOULD press %-6s %s (%s)\n' "$name" "$keys" "$what" "$why"
      else
        tm send-keys -t "$pane" -- "$keys"
        printf '  %-22s pressed %-6s %s (%s)\n' "$name" "$keys" "$what" "$why"
        freed=$((freed + 1))
      fi
      continue
    fi
    stuck=$((stuck + 1))
    if decision="$(modal_decision "$text")"; then
      printf '  %-22s NEEDS A PERSON - %s\n' "$name" "$decision"
    else
      printf '  %-22s NEEDS A PERSON - an unrecognised prompt\n' "$name"
    fi
    printf '                         look:   agentmux read %s --lines 12\n' "$name"
    printf '                         answer: agentmux key %s <Escape|Down|Enter|2>\n' "$name"
  done
  [ "$dry" = 1 ] || printf '\n%s answered, %s left for a person\n' "$freed" "$stuck"
  return 0
}

cmd_send() {
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "send needs a name"
  need "$name"
  local force=0
  if [ "${1:-}" = "--force" ]; then force=1; shift; fi
  local text="$*" pane
  [ -n "$text" ] || die "send needs text"
  pane="$(pane_of "$name")"
  [ -n "$pane" ] || die "cannot resolve pane for '$name'"

  # Refuse rather than actuate someone else's default. `key` exists precisely for
  # answering a modal deliberately, and it sends no implicit Enter.
  if [ "$force" != 1 ] && modal_prompt "$pane"; then
    printf "agentmux: '%s' is showing a prompt, not its normal input. Refusing to send:\n" "$name" >&2
    printf '%s\n' "  Enter would actuate that prompt's default instead of talking to the agent." >&2
    printf '%s\n' "  Look:   agentmux read $name --lines 12" >&2
    printf '%s\n' "  Answer: agentmux key $name Escape     (or Down/Enter as appropriate)" >&2
    printf '%s\n' "  Override if you are sure: agentmux send $name --force <text>" >&2
    return 1
  fi
  # The newline test must use $'\n'. "$(printf '\n')" collapses to the empty
  # string (command substitution strips trailing newlines), so it matches every
  # prompt and would wrap single-line sends in paste markers as well.
  # The gap between the text and the Enter.
  #
  # tmux itself orders these: both go to the same server queue. The wait is for the
  # CLIENT - a TUI reading a bracketed paste needs to have consumed it before Enter
  # arrives, or it submits a partial line. 0.4s was picked by eye and is pure latency
  # on every single delivery; at a 100ms courier interval it became the largest
  # remaining cost. Tunable, and lower for a single line, which no TUI needs time to
  # reassemble.
  # LENGTH MATTERS AS MUCH AS NEWLINES, and only newlines were being counted.
  #
  # The gap below exists because a TUI reading a bracketed paste has to consume it
  # before Enter arrives. But a TUI decides what a paste IS by the size of the burst,
  # not by whether it contains a newline: codex turns any large single line into a
  # "[Pasted Content NNNN chars]" placeholder in its composer. At the single-line gap
  # of 0.08s the Enter arrived mid-assembly and did nothing, so the brief sat in the
  # composer unsent, looking exactly like an agent that had ignored it. Measured on
  # tm-100-worker3: a 1024-character single-line send, still in the composer minutes
  # later, submitted by one further Enter.
  local gap
  if [ "${text#*$'\n'}" != "$text" ]; then
    # multi-line: bracketed paste, else each newline submits the prompt early
    tm send-keys -t "$pane" -l -- "${ESC}[200~${text}${ESC}[201~"
    gap="${AGENTMUX_SEND_DELAY_MULTILINE:-0.25}"
  elif [ "${#text}" -ge "${AGENTMUX_SEND_PASTE_CHARS:-512}" ]; then
    tm send-keys -t "$pane" -l -- "$text"
    gap="${AGENTMUX_SEND_DELAY_MULTILINE:-0.25}"
  else
    tm send-keys -t "$pane" -l -- "$text"
    gap="${AGENTMUX_SEND_DELAY:-0.08}"
  fi
  sleep "$gap"
  tm send-keys -t "$pane" Enter
  # AND CONFIRM IT WENT. The gap is a guess about how long a TUI needs, and a guess
  # that is wrong costs a silently unsent instruction - the failure this whole verb
  # is supposed to make impossible. A composer still holding a paste placeholder
  # after the Enter has not submitted, so send one more. Bounded at two extra tries,
  # and skipped entirely for short text, which no TUI defers.
  if [ "${#text}" -ge "${AGENTMUX_SEND_PASTE_CHARS:-512}" ]; then
    local try
    for try in 1 2; do
      sleep 0.4
      tm capture-pane -p -t "$pane" 2>/dev/null \
        | grep -qiE '\[pasted content|\[[0-9]+ lines pasted' || break
      tm send-keys -t "$pane" Enter
    done
  fi
}

# Forward tmux key names with NO text and NO implicit Enter. This is the only
# safe way to answer a modal: cmd_send always appends Enter, which actuates
# whatever the child CLI has focused. Permission-bypass flags remove approval
# prompts but not first-run or account-level modals, so this stays necessary.
#   agentmux key rev Escape
#   agentmux key rev Down Down Enter
cmd_key() {
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "key needs a name"
  need "$name"
  [ $# -gt 0 ] || die "key needs at least one tmux key name (Enter, Escape, Down, C-c, ...)"

  # Validate before sending. tmux send-keys treats an unrecognised key NAME as
  # literal text and still exits 0, so a typo silently types itself into the
  # agent and submits: `key rev Dowm Enter` would enter the word "Dowm". That is
  # the same silent-success failure this verb exists to avoid, so reject
  # anything not recognisably a key name rather than pass it through.
  local k
  for k in "$@"; do
    case "$k" in
      Enter|Escape|Tab|BTab|Space|BSpace|Backspace|Up|Down|Left|Right) ;;
      Home|End|PageUp|PageDown|PPage|NPage|Insert|IC|Delete|DC) ;;
      F1|F2|F3|F4|F5|F6|F7|F8|F9|F10|F11|F12) ;;
      [CMS]-[!-~]|[CMS]-[CMS]-[!-~]) ;;                   # C-c, M-x, C-M-a
      [CMS]-Enter|[CMS]-Tab|[CMS]-Up|[CMS]-Down|[CMS]-Left|[CMS]-Right) ;;
      # ONE PRINTABLE CHARACTER, because the modal this verb exists for is a
      # NUMBERED MENU. codex greets a fresh pane with
      #     1. Update now (runs `npm install -g @openai/codex`)   <- preselected
      #     2. Skip
      # and the documented answer is `key`, precisely so nothing appends Enter and
      # actuates the highlighted option. But `key <pane> 2` was refused, leaving no
      # way to answer it at all: `send` would type 2 AND Enter, and Enter on a menu
      # whose first option is an npm install is the accident the whole verb is here
      # to prevent. Four panes sat on that modal, unanswerable, until this.
      #
      # It does not weaken the guard above. That guard exists because tmux treats an
      # unrecognised key NAME as literal text and still exits 0, so `Dowm` silently
      # types itself - and every tmux key name is two characters or more. A single
      # character cannot be a mistyped name, so admitting exactly one is unambiguous.
      [!-~]) ;;
      *) die "not a recognized tmux key name: '$k'
       (valid: Enter Escape Tab BTab Space BSpace Up Down Left Right Home End
        PageUp PageDown Insert Delete F1-F12, a modifier form like C-c or M-x,
        or a single printable character such as 2 or y for a numbered menu)
       To type literal TEXT, use 'send' instead - but note send appends Enter." ;;
    esac
  done

  local pane
  pane="$(pane_of "$name")"
  [ -n "$pane" ] || die "cannot resolve pane for '$name'"
  # `--` so a key name can never be parsed as a send-keys option.
  tm send-keys -t "$pane" -- "$@" || die "send-keys failed for keys: $*"
  printf "sent keys to '%s': %s\n" "$name" "$*"
}

cmd_read() {
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "read needs a name"
  need "$name"
  local lines=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --lines|-n) lines="${2:?--lines needs a number}"; shift 2 ;;
      # `*) shift` silently swallowed typos: `read rev --line 20` dropped both tokens
      # and fell back to the default, which for read/tail is the entire pane - the
      # multi-thousand-token dump --lines exists to avoid. Fail loudly instead.
      *) die "read: unknown option '$1' (only --lines is accepted)" ;;
    esac
  done
  local out
  out="$(tm capture-pane -p -J -t "$(pane_of "$name")" | strip_ansi | sed 's/[[:space:]]*$//' | trim_edges)"
  if [ -n "$lines" ]; then
    printf '%s\n' "$out" | tail -n "$lines"
  else
    printf '%s\n' "$out"
  fi
}

cmd_tail() {
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "tail needs a name"
  local lines=200
  while [ $# -gt 0 ]; do
    case "$1" in
      --lines|-n) lines="${2:?--lines needs a number}"; shift 2 ;;
      # A silently discarded typo here returns the default 200 lines of raw scrollback
      # - up to ~10k tokens of redraw noise - when the caller asked for fewer.
      *) die "tail: unknown option '$1' (only --lines is accepted)" ;;
    esac
  done
  [ -f "$LOGDIR/$name.log" ] || die "no log for '$name'"
  strip_ansi < "$LOGDIR/$name.log" | tail -n "$lines"
}

cmd_wait() {
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "wait needs a name"
  need "$name"
  local timeout="$TIMEOUT_S" quiet_ms="$QUIET_MS"
  while [ $# -gt 0 ]; do
    case "$1" in
      --timeout|-t) timeout="${2:?--timeout needs seconds}"; shift 2 ;;
      --quiet|-q)   quiet_ms=$(( ${2:?--quiet needs seconds} * 1000 )); shift 2 ;;
      # `wait rev --timout 30` used to silently use the default timeout, so a caller
      # who asked for 30s could block for 300 and never learn why.
      *) die "wait: unknown option '$1' (wait takes --timeout and --quiet)" ;;
    esac
  done
  # A CLI that TELLS us it is working beats guessing from stillness.
  #
  # Measured 2026-09-22 on a real codex turn: transport 200ms, inference 4273ms, and
  # then SIX SECONDS of the harness waiting to be sure the model had stopped. The
  # wait was longer than the thinking. That is what an operator experiences as lag,
  # and no amount of courier tuning touches it.
  #
  # These CLIs put an interrupt hint in the footer while and only while they are
  # working, so its ABSENCE plus a short settle is a completion signal rather than a
  # timeout. Absence is the safe direction to test: a marker that fails to appear
  # costs a few seconds of extra waiting, whereas inventing an "I am done" pattern
  # that shows up mid-turn would truncate the agent's answer.
  #
  # Only for CLIs whose footers were actually captured. Anything else - `shell`, a
  # passthrough command, a CLI that changes its footer in a future release - falls
  # back to the quiet timer, which always worked and still does.
  # AGENTMUX_WAIT_NO_MARKER=1 forces the old stillness-only behavior. Needed if a CLI
  # changes its footer in a release and the marker stops matching: the symptom would be
  # `ask` returning early, and this is the switch that proves or disproves it without
  # editing the harness. It is also how the before/after timings were measured.
  local cli settle_ms="${AGENTMUX_SETTLE_MS:-600}" use_marker=0
  cli="$(cat "$RUNDIR/$name.cli" 2>/dev/null || echo '')"
  if [ "${AGENTMUX_WAIT_NO_MARKER:-0}" != "1" ]; then
    case "$cli" in codex|claude|grok) use_marker=1 ;; esac
  fi

  busy_marker() {
    tm capture-pane -p -J -t "$(pane_of "$1")" 2>/dev/null | strip_ansi \
      | tail -6 | grep -Eqi 'esc to interrupt|ctrl\+c:cancel|ctrl-c to stop|to interrupt'
  }

  local last="" stable=0 elapsed=0 cur
  local deadline_ms=$(( timeout * 1000 ))
  local sleep_s
  sleep_s="$(awk -v m="$POLL_MS" 'BEGIN{printf "%.3f", m/1000}')"
  while :; do
    have "$name" || { printf "agent '%s' exited\n" "$name" >&2; return 3; }
    cur="$(pane_hash "$name")"
    if [ "$cur" = "$last" ]; then
      stable=$(( stable + POLL_MS ))
    else
      stable=0; last="$cur"
    fi
    # Fast path: the CLI is not advertising work and the screen has settled.
    if [ "$use_marker" = 1 ] && [ "$stable" -ge "$settle_ms" ] \
       && ! busy_marker "$name"; then
      printf 'idle after %ss (no busy marker)\n' "$(( elapsed / 1000 ))" >&2
      return 0
    fi
    if [ "$stable" -ge "$quiet_ms" ]; then
      printf 'idle after %ss\n' "$(( elapsed / 1000 ))" >&2
      return 0
    fi
    if [ "$elapsed" -ge "$deadline_ms" ]; then
      printf 'timeout after %ss (agent still busy)\n' "$timeout" >&2
      return 2
    fi
    sleep "$sleep_s"
    elapsed=$(( elapsed + POLL_MS ))
  done
}

cmd_ask() {
  local name="${1:-}"; shift || true
  [ -n "$name" ] || die "ask needs a name"
  need "$name"
  # `--lines` exists here for two reasons, and the second one is a bug fix.
  #
  # Cost: `ask` used to return the ENTIRE pane - 200 cols x 50 rows, ~10k characters,
  # ~2.5-3.5k tokens - into the CALLER's context, on every call, permanently. Most of
  # that is banner, footer, spinner residue and the echo of the question. For an
  # orchestrator whose context is re-sent every turn, ten asks is 30k tokens of pane
  # furniture that never leaves. This is the single highest-leverage token change in
  # the harness and it is a handful of lines.
  #
  # Correctness: the old arg loop put every unrecognised token into `words`, which
  # becomes the prompt. So `agentmux ask rev --lines 20 "check this"` did not fail -
  # it typed "--lines 20 check this" AT THE AGENT. Silent prompt corruption. Unknown
  # flags are now refused rather than smuggled into the text.
  local timeout="$TIMEOUT_S" quiet_s=$(( QUIET_MS / 1000 ))
  local lines="${AGENTMUX_ASK_LINES:-40}"
  local -a words=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --timeout|-t) timeout="${2:-$TIMEOUT_S}"; shift 2 ;;
      --quiet|-q)   quiet_s="${2:-5}"; shift 2 ;;
      --lines|-n)   lines="${2:-40}"; shift 2 ;;
      --all)        lines=""; shift ;;
      --) shift; while [ $# -gt 0 ]; do words+=("$1"); shift; done ;;
      -*) die "ask: unknown option '$1'
       (ask takes --timeout, --quiet, --lines, --all; use -- before a prompt
        that legitimately starts with a dash)" ;;
      *) words+=("$1"); shift ;;
    esac
  done
  local text="${words[*]}"
  [ -n "$text" ] || die "ask needs text"
  cmd_send "$name" "$text"
  sleep 1
  cmd_wait "$name" --timeout "$timeout" --quiet "$quiet_s"
  local rc=$?
  printf -- '----- %s -----\n' "$name"
  if [ -n "$lines" ]; then
    cmd_read "$name" --lines "$lines"
  else
    cmd_read "$name"
  fi
  return "$rc"
}

# Append a message to THIS agent's outbox, ~/.agentmux/queue/<sender>.jsonl.
#
# The queue existed long before anything wrote to it from an agent: the dashboard
# rendered it and dashboard/seed_queue.py was the only producer. This is the verb an
# agent actually calls, and `agentmux courier` is what delivers the result.
#
# The sender is $AGENTMUX_AGENT, exported into every spawned pane. Outside a pane
# there is no such variable, so it falls back to 'orchestrator' - which is exactly
# what the Claude Code session driving all this is.
#
# Written through python3 rather than printf because a body is arbitrary agent text:
# newlines, quotes and backslashes all have to survive into one JSON line intact,
# and hand-rolling that escaping in shell is how a queue file gets corrupted.
cmd_post() {
  local recipient="${1:-}"; shift || true
  [ -n "$recipient" ] || die "post needs a recipient: agentmux post <name> [--kind K] <text...>"
  local kind="status" ref="" sender="${AGENTMUX_AGENT:-orchestrator}" strict=0
  local -a words=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --kind) kind="${2:-}"; shift 2 ;;
      --ref)  ref="${2:-}";  shift 2 ;;
      --from) sender="${2:-}"; shift 2 ;;
      --strict) strict=1; shift ;;
      --) shift; while [ $# -gt 0 ]; do words+=("$1"); shift; done ;;
      # Worse here than in `ask`, because `post` is the AUTOMATED path:
      # `post rev --knid request "check"` left kind as `status` and made the BODY
      # "--knid request check", which the courier types into the agent's pane and
      # Enters, persists to queue/*.jsonl, and the dashboard renders as that agent's
      # own words. Refuse rather than smuggle it into the message.
      -*) die "post: unknown option '$1'
       (post takes --kind, --ref, --from, --strict; use -- before a body that
        legitimately starts with a dash)" ;;
      *) words+=("$1"); shift ;;
    esac
  done
  local text="${words[*]}"
  [ -n "$text" ] || die "post needs a message body"
  case "$kind" in
    plan|request|reply|status|finding|error|claim|release) ;;
    *) die "kind must be one of: plan request reply status finding error claim release (got '$kind')" ;;
  esac

  # THE HUB FIRST (TM-214, docs/PROTOCOL.md section 10). When the hub is up and knows
  # the recipient - a protocol session, an adopted legacy name, or a virtual address -
  # the message goes into hub.db and is acked end to end, instead of into a queue
  # file the courier types into a pane. AGENTMUX_POST_VIA=queue forces the old path;
  # =hub refuses to fall back. Once the courier is retired there IS no fallback: a
  # queued line would never be delivered, so a hub refusal is a hard error.
  local via="${AGENTMUX_POST_VIA:-auto}"
  [ -e "$ROOT/hub/courier-retired" ] && [ "$via" = auto ] && via=hub
  if [ "$via" != queue ] && [ -S "$ROOT/hub/hub.sock" ]; then
    local _self hub_out
    _self="$(agentmux_self)" || die "post: cannot locate the agentmux checkout"
    [ "$sender" = "${AGENTMUX_AGENT:-orchestrator}" ] \
      || printf 'agentmux: note - --from is ignored by the hub; it identifies the sender itself\n' >&2
    if hub_out="$(python3 "$(dirname "$_self")/hub/cli.py" post --to "$recipient" --kind "$kind" \
                  ${ref:+--ref "$ref"} -- "$text" 2>&1)"; then
      printf '%s\n' "$hub_out"
      return 0
    fi
    [ "$via" = hub ] && die "post: the hub refused: $hub_out"
    # auto: the hub does not know this recipient or this sender (an unadopted legacy
    # pane). The courier still serves those - fall through to the queue.
  elif [ "$via" = hub ]; then
    die "post: the courier is retired but the hub is not running (agentmux hub start)"
  fi

  # Tell the caller NOW if this address cannot receive, rather than letting the
  # courier discover it over several minutes of retries. A not-yet-spawned agent is
  # legitimate, so this warns by default and only refuses under --strict.
  local virtual="${AGENTMUX_VIRTUAL_AGENTS:-orchestrator}"
  if ! have "$recipient" \
     && ! printf '%s' ",$virtual," | grep -q ",$recipient,"; then
    printf "agentmux: warning - '%s' is not a running agent and not a virtual address.\n" "$recipient" >&2
    printf '%s\n' "  It will be retried while the courier waits for it to appear, then kept" >&2
    printf '%s\n' "  in the dead-letter file rather than delivered." >&2
    printf "  running now: %s\n" "$(tm list-sessions -F '#{session_name}' 2>/dev/null | tr '\n' ' ')" >&2
    printf "  virtual:     %s\n" "$virtual" >&2
    [ "${strict:-0}" = 1 ] && die "refusing to queue for an unreachable recipient (--strict)"
  fi

  python3 - "$ROOT" "$sender" "$recipient" "$kind" "$ref" "$text" <<'PY' || return 1
import json, os, pathlib, re, sys, time

root, sender, recipient, kind, ref, body = sys.argv[1:7]
name = re.compile(r"[A-Za-z0-9_.-]{1,64}")
for label, value in (("sender", sender), ("recipient", recipient)):
    if not name.fullmatch(value):
        sys.exit(f"agentmux: {label} '{value}' is not a valid agent name")

queue = pathlib.Path(root) / "queue"
queue.mkdir(parents=True, exist_ok=True)
path = queue / f"{sender}.jsonl"
# Refuse a link rather than write through one: the outbox is read back by the
# dashboard and the courier, so a symlinked or hardlinked queue file is a way to
# get agent-authored text appended to something else entirely.
if path.is_symlink() or (path.exists() and path.stat().st_nlink != 1):
    sys.exit(f"agentmux: {path} is a link - refusing to write to it")

record = {
    "at": time.strftime("%Y-%m-%dT%H:%M:%S") + time.strftime("%z"),
    "sender": sender, "recipient": recipient, "kind": kind,
    "body": body[:65536], "ref": ref[:256] or None,
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record) + "\n")
os.chmod(path, 0o600)
print(f"posted {kind} to {recipient}")
PY
}

# Work coordination: claims, dependencies and the shared journal.
#
# Conversation is not coordination. Three unrestricted agents on one repo will edit the
# same file unless something stops them, and a message asking politely does not stop
# anything - the other agent may not be reading. A claim is an atomically created FILE
# (O_EXCL), so exactly one agent wins a race; the broadcast that follows is a courtesy,
# not the mechanism.
#
# The holder defaults to $AGENTMUX_AGENT, so inside a pane an agent never has to know
# or type its own name - and cannot claim on someone else's behalf by accident.
coord_py() {
  local repo="${AGENTMUX_REPO:-}"
  [ -n "$repo" ] || die "AGENTMUX_REPO is unset; cannot find taskmgmt/coordination.py"
  local script="$repo/taskmgmt/coordination.py"
  [ -f "$script" ] || die "not found: $script"
  printf '%s' "$script"
}

dispatch_py() {
  local repo="${AGENTMUX_REPO:-}"
  [ -n "$repo" ] || die "AGENTMUX_REPO is unset; cannot find taskmgmt/dispatch.py"
  local script="$repo/taskmgmt/dispatch.py"
  [ -f "$script" ] || die "not found: $script"
  printf '%s' "$script"
}

# The board-to-agent verbs. Each one refuses from inside a pane for the same
# reason `run complete` does: an agent that can dispatch can dispatch itself, and
# a worker deciding to spawn more workers is how a pool becomes a fork bomb with a
# task board attached.
cmd_dispatch() {
  [ -z "${AGENTMUX_AGENT:-}" ]     || die "dispatch is the orchestrator's to call, and this is the '$AGENTMUX_AGENT' pane."
  python3 "$(dispatch_py)" dispatch "$@"
}

cmd_collect() {
  [ -z "${AGENTMUX_AGENT:-}" ]     || die "collect is the orchestrator's to call, and this is the '$AGENTMUX_AGENT' pane."
  python3 "$(dispatch_py)" collect "$@"
}

cmd_pool() {
  [ -z "${AGENTMUX_AGENT:-}" ]     || die "pool is the orchestrator's to call, and this is the '$AGENTMUX_AGENT' pane."
  python3 "$(dispatch_py)" pool "$@"
}

cmd_claim() {
  local resource="${1:-}"; shift || true
  [ -n "$resource" ] || die "claim needs a resource, e.g. agentmux claim taskmgmt/courier.py --note 'adding backoff'"
  # --holder is NOT passed through from "$@": argparse takes the last occurrence, so
  # appending user args after ours let `claim x --holder victim` claim in someone
  # else's name. Identity comes from the environment here, full stop.
  # Python enforces the same binding for direct CLI callers.
  for arg in "$@"; do
    case "$arg" in --holder|--holder=*) die "claim: --holder is set from \$AGENTMUX_AGENT and cannot be overridden" ;; esac
  done
  python3 "$(coord_py)" claim "$resource" --holder "${AGENTMUX_AGENT:-orchestrator}" "$@"
}

cmd_release() {
  local resource="${1:-}"; shift || true
  [ -n "$resource" ] || die "release needs a resource"
  for arg in "$@"; do
    case "$arg" in --holder|--holder=*) die "release: --holder is set from \$AGENTMUX_AGENT and cannot be overridden" ;; esac
  done
  python3 "$(coord_py)" release "$resource" --holder "${AGENTMUX_AGENT:-orchestrator}" "$@"
}

cmd_claims() { python3 "$(coord_py)" claims "$@"; }

# The task board, from the command line.
#
# The board existed and agents did not use it, because using it meant hand-writing JSON
# at an HTTP endpoint. A rule that says "use the task board" and a board that takes a
# curl invocation are not compatible - one of them loses, and it is never the
# convenient one.
# Runs: the completion protocol.
#
# `run complete` is the gate the operator asked for - it refuses until every job has
# been verified by a reviewer who is not the worker. Teardown is separate and explicit,
# because completion and killing agents are different decisions: a forced completion
# still wants the panes alive long enough to have been captured.
run_py() {
  local repo="${AGENTMUX_REPO:-}"
  [ -n "$repo" ] || die "AGENTMUX_REPO is unset; cannot find taskmgmt/run.py"
  local script="$repo/taskmgmt/run.py"
  [ -f "$script" ] || die "not found: $script"
  printf '%s' "$script"
}

cmd_run() {
  local action="${1:-status}"; shift || true
  local me="${AGENTMUX_AGENT:-orchestrator}"

  # --by IS NOT THE CALLER'S TO CHOOSE, and until now half of these verbs let it be.
  #
  # This is the third appearance of one bug. cmd_task refuses --agent and cmd_claim
  # refuses --holder, both with the same note: argparse takes the LAST occurrence, so
  # appending user arguments after ours signs the record in somebody else's name.
  # cmd_run never got the guard, and its verbs disagreed with each other by accident
  # of argument order:
  #
  #     verdict)  run.py verdict "$@" --by "$me"          <- ours last, ours wins
  #     submit)   run.py submit "$1" --by "$me" "${@:2}"  <- theirs last, THEIRS wins
  #
  # Measured: as `orchestrator`, `agentmux run submit <job> --by dev` wrote a submit
  # event recorded `by: "dev"`. The verdict half refused the identical trick. That a
  # worker cannot mark its own homework is the whole mechanism runs exist for, and it
  # is checked against `by` - so a `by` the caller can set is the mechanism with its
  # one input handed to the person it constrains.
  #
  # Refused rather than reordered. Reordering would make submit behave like verdict
  # and leave the next verb to get it right by luck; refusing says so.
  for arg in "$@"; do
    case "$arg" in --by|--by=*)
      die "run: --by is set from \$AGENTMUX_AGENT and cannot be overridden" ;;
    esac
  done

  case "$action" in
    start)    python3 "$(run_py)" start "${1:?a one-line description of the request}" --by "$me" ;;
    assign)   python3 "$(run_py)" assign "$@" ;;
    submit)   python3 "$(run_py)" submit "${1:-${AGENTMUX_JOB:-}}" --by "$me" "${@:2}" ;;
    verdict)  python3 "$(run_py)" verdict "$@" --by "$me" ;;
    status)   python3 "$(run_py)" status "$@" ;;
    complete)
      # CLOSE THE AGENTS THE RUN JUST FINISHED WITH.
      #
      # complete already detects them and prints "agents are still running - tear them
      # down with: agentmux run teardown <run>" - and then nothing did it, so a pair of
      # agents whose every job was verified sat at their prompts for the full 60-minute
      # idle watchdog. Do the thing it recommends.
      #
      # Safe to do automatically because cmd_run_teardown takes the agent names from
      # THIS run's ledger, so no other run's agent and none of the operator's own is
      # touched. AGENTMUX_KEEP_AGENTS=1 keeps them when you want to read the panes.
      local run_id="${1:-}"
      # Tell run.py to skip its "close them yourself" line: we are about to.
      local will=""
      [ "${AGENTMUX_KEEP_AGENTS:-}" = "1" ] || will=1
      AGENTMUX_WILL_TEARDOWN="$will" python3 "$(run_py)" complete "$@" --by "$me" || return $?
      if [ "${AGENTMUX_KEEP_AGENTS:-}" = "1" ]; then
        printf '  agents kept (AGENTMUX_KEEP_AGENTS=1); close them with: agentmux run teardown %s\n' "$run_id"
      else
        cmd_run_teardown "$run_id"
      fi
      ;;
    teardown) cmd_run_teardown "$@" ;;
    *) die "run: start|assign|submit|verdict|status|complete|teardown" ;;
  esac
}

# Close a run's agents - and ONLY that run's agents.
#
# Deliberately not `kill --all`, which kills every agent including other runs' and the
# operator's own, and skips claim release and sidecar removal entirely. The names come
# from the ledger, so an agent that was never part of this run is never touched.
#
# Also deliberately not `cmd_kill`: that ends with stop_courier_if_idle, which would
# stop the courier the moment this run's agents were the last ones - and the operator's
# decision is that the courier stays up. It also fires two serial 45s Jira calls per
# bound agent, which can put six minutes inside a teardown.
cmd_run_teardown() {
  # Check before reading the run or touching claims, sessions, or sidecars. Reuse
  # the same outside-pane rule as the Python run verbs, without a test bypass.
  python3 - "$(coord_py)" <<'PYIDENTITY' || return $?
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
import coordination
try:
    coordination.orchestrator_identity("teardown", allow_test_identity=False)
except coordination.IdentityError as err:
    print(err, file=sys.stderr)
    sys.exit(2)
PYIDENTITY
  local run_id="${1:-}"
  [ -n "$run_id" ] || die "teardown needs a run id"
  # A NON-EMPTY STRING WAS THE ONLY CHECK. Every Python run verb validates the id
  # shape, and assign/complete also require the directory to exist - teardown, which
  # KILLS PANES and force-releases their claims, required neither. A typo silently
  # tore down nothing and reported success; worse, teardown on a live run kills a
  # worker and a reviewer mid-job, and cmd_complete deliberately writes FORCED.md
  # BEFORE teardown precisely because "a pane dies with its tmux session" - an
  # unguarded teardown ahead of completion destroys the evidence completion captures.
  #
  # So: the run must exist, and an OPEN run needs --force to be torn down.
  python3 - "$(run_py)" "$run_id" "${2:-}" <<'PYGUARD' || return $?
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
import run as runmod
run_id, flag = sys.argv[2], sys.argv[3]
if not runmod.valid_run(run_id):
    print(f"teardown: invalid run id {run_id!r}", file=sys.stderr); sys.exit(2)
if not runmod.run_dir(run_id).is_dir():
    print(f"teardown: no such run {run_id}", file=sys.stderr); sys.exit(2)
if not runmod.complete_path(run_id).exists() and flag != "--force":
    print(f"teardown: {run_id} is still open - completing it captures what its agents",
          file=sys.stderr)
    print("  did before their panes die. Close it with `agentmux run complete`, or pass",
          file=sys.stderr)
    print("  --force if you have decided the run is abandoned.", file=sys.stderr)
    sys.exit(2)
PYGUARD
  local names
  names="$(python3 "$(run_py)" status "$run_id" --json 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit
seen = []
for job in data.get("jobs", []):
    for who in (job.get("worker"), job.get("reviewer")):
        if who and who not in seen:
            seen.append(who)
print("\n".join(seen))
')"
  [ -n "$names" ] || { echo "no agents recorded for run $run_id"; return 0; }

  local name killed=0
  while read -r name; do
    [ -n "$name" ] || continue
    # Release anything it still holds, so the next run is not blocked by a lease that
    # outlives the agent by up to half an hour.
    python3 "$(coord_py)" claims --json 2>/dev/null | python3 -c "
import json, sys
try:
    rows = json.load(sys.stdin)
except Exception:
    raise SystemExit
print('\n'.join(r['resource'] for r in rows if r.get('holder') == '$name'))
" | while read -r resource; do
      [ -n "$resource" ] || continue
      python3 "$(coord_py)" release "$resource" --holder "$name" --force >/dev/null 2>&1 \
        && printf '  released %s (held by %s)\n' "$resource" "$name"
    done

    if have "$name"; then
      tm kill-session -t "=$name" 2>/dev/null && { printf '  killed %s\n' "$name"; killed=$((killed + 1)); }
    fi
    rm -f "$RUNDIR/$name".* 2>/dev/null
  done <<EOF
$names
EOF

  printf 'torn down run %s: %s agent(s) killed\n' "$run_id" "$killed"
  # The courier is left running on purpose; see the comment above.
  python3 "$(coord_py)" journal done "run $run_id torn down" \
    --body "$killed agent(s) closed; courier and dashboard left running" \
    --agent "${AGENTMUX_AGENT:-orchestrator}" >/dev/null 2>&1
}

cmd_tasks() { python3 "$(coord_py)" tasks "$@"; }

cmd_task() {
  local action="${1:-}"; shift || true
  local me="${AGENTMUX_AGENT:-orchestrator}"

  # --agent is NOT passed through from "$@", for exactly the reason claim refuses
  # --holder: argparse takes the LAST occurrence, so appending user args after ours
  # would let `task done TM-014 --agent someone-else` sign the board in another
  # agent's name. Outside a pane that check is the only one there is, because
  # resolve_identity will accept any live agent when $AGENTMUX_AGENT is unset.
  for arg in "$@"; do
    case "$arg" in --agent|--agent=*)
      die "task: --agent is set from \$AGENTMUX_AGENT and cannot be overridden" ;;
    esac
  done

  local id status
  case "$action" in
    # The status shorthands. Extra flags survive, so `task block TM-014 --reason
    # "waiting on the gateway"` reaches the verb that wants a reason - the reason
    # is required reading for blocked and parked, and silently dropping it was
    # why cards came back with no explanation on them.
    start|done|block|todo|park|backlog)
      id="${1:?task id}"; shift || true
      case "$action" in
        start) status=in_progress ;;
        done)  status=done ;;
        block) status=blocked ;;
        park)  status=parked ;;
        backlog) status=backlog ;;
        # `todo` is the word people type; the board's vocabulary calls it `open`.
        # It used to be passed through verbatim and the board rejected every one
        # of them - the verb has never worked, because nothing exercised it.
        *)     status=open ;;
      esac
      python3 "$(coord_py)" task-status "$id" "$status" --agent "$me" "$@" ;;
    add)
      python3 "$(coord_py)" task-add "${1:?epic id}" "${2:?title}" --agent "$me" ;;
    # The rest of the board's task verbs, passed straight through. These existed in
    # coordination.py from the day the store landed and were reachable only by
    # invoking python3 by hand - which is the same reason the board went unused
    # before `agentmux tasks` existed. A dispatched worker is told to run
    # `agentmux task evidence`, so it had better be a command.
    new|edit|ac|label|dep|evidence|commit|touch|comment|link|assign|move)
      python3 "$(coord_py)" "task-$action" "$@" --agent "$me" ;;
    # Reads. These take no identity: nothing is being signed.
    show|why|next)
      python3 "$(coord_py)" "task-$action" "$@" ;;
    *) die "task: start|done|block|todo <id> | add <epic-id> \"<title>\" | new|show|edit|ac|label|dep|evidence|commit|touch|comment|link|assign|move|why|next" ;;
  esac
}

cmd_epic() {
  local action="${1:-}"; shift || true
  local me="${AGENTMUX_AGENT:-orchestrator}"
  for arg in "$@"; do
    case "$arg" in --agent|--agent=*)
      die "epic: --agent is set from \$AGENTMUX_AGENT and cannot be overridden" ;;
    esac
  done
  case "$action" in
    new)    python3 "$(coord_py)" epic-new "$@" --agent "$me" ;;
    status) python3 "$(coord_py)" epic-status "$@" --agent "$me" ;;
    use)    python3 "$(coord_py)" board-active "$@" --agent "$me" ;;
    ""|list) python3 "$(coord_py)" tasks ;;
    *) die "epic: new \"<title>\" | status <id> <status> | use <id> | list" ;;
  esac
}

# Board-level settings, as opposed to one card's fields. Read-only with no
# arguments, which is the form worth typing when you want to know why the pool is
# not picking anything up.
cmd_board() {
  local action="${1:-}"; shift || true
  case "$action" in
    config) python3 "$(coord_py)" config "$@" --agent "${AGENTMUX_AGENT:-orchestrator}" ;;
    doctor) python3 "$(coord_py)" doctor "$@" ;;
    history) python3 "$(coord_py)" history "$@" ;;
    find)   python3 "$(coord_py)" find "$@" ;;
    triage) python3 "$(coord_py)" triage "$@" --agent "${AGENTMUX_AGENT:-orchestrator}" ;;
    override) python3 "$(coord_py)" override "$@" --agent "${AGENTMUX_AGENT:-orchestrator}" ;;
    ""|-h|--help) python3 "$(coord_py)" config ;;
    *) die "board: config|doctor|history|find|triage|override" ;;
  esac
}

# THE TEAM VERBS, WHICH WERE REACHABLE ONLY BY INVOKING PYTHON BY HAND.
#
# roster, recruit, approve, retire and hire have existed in coordination.py since
# rosters landed, and none of them was wired into this script - so `agentmux recruit
# TM-100` answered "unknown command" and the only way to staff a card was
# `python3 taskmgmt/coordination.py recruit TM-100`.
#
# That is the same gap, with the same consequence, that cmd_task was written to
# close: the comment there says the task verbs "were reachable only by invoking
# python3 by hand - which is the same reason the board went unused before
# `agentmux tasks` existed". A capability nobody can find is a capability nobody
# uses, and every piece of documentation that said `agentmux recruit` was wrong.
#
# --agent is refused for the same reason cmd_task refuses it: argparse takes the
# LAST occurrence, so appending user arguments after ours would let
# `approve TM-100 --member x --agent someone-else` sign another agent's name to a
# decision. recruit, approve and retire are identity-bound; roster and hire are not
# (roster reads nothing, and hire is attributed to the dashboard).
cmd_team() {
  local action="$1"; shift || true
  local me="${AGENTMUX_AGENT:-orchestrator}"
  for arg in "$@"; do
    case "$arg" in --agent|--agent=*)
      die "$action: --agent is set from \$AGENTMUX_AGENT and cannot be overridden" ;;
    esac
  done
  case "$action" in
    roster|hire) python3 "$(coord_py)" "$action" "$@" ;;
    *)           python3 "$(coord_py)" "$action" "$@" --agent "$me" ;;
  esac
}

cmd_journal() {
  local kind="${1:-}" subject="${2:-}"; shift 2 2>/dev/null || true
  [ -n "$kind" ] && [ -n "$subject" ] \
    || die "journal needs a kind and a subject, e.g. agentmux journal note 'starting the mqtt refactor'"
  python3 "$(coord_py)" journal "$kind" "$subject" --agent "${AGENTMUX_AGENT:-orchestrator}" "$@"
}

# The delivery half. Runs taskmgmt/courier.py, which tails every outbox and hands
# each addressed message to its recipient with `agentmux send`.
#
# `start` detaches deliberately. The Bedrock gateway is a foreground process that
# nothing supervises and that does not survive a reboot, which has cost a session's
# first ten minutes more than once; a background courier with a pidfile at least
# survives the shell that launched it.
cmd_courier() {
  local repo="${AGENTMUX_REPO:-}"
  [ -n "$repo" ] || die "AGENTMUX_REPO is unset; cannot find taskmgmt/courier.py"
  local script="$repo/taskmgmt/courier.py"
  [ -f "$script" ] || die "not found: $script"
  local action="${1:-status}"; shift || true
  case "$action" in
    start)
      mkdir -p "$ROOT/courier"
      if python3 "$script" --status 2>/dev/null | grep -q '^courier:   running'; then
        printf 'courier is already running\n'; return 0
      fi
      # Created and locked down BEFORE nohup writes to it: the courier's output
      # carries message bodies, and a shell redirect would otherwise make the file
      # 0644 while every other piece of courier state is 0600.
      : >> "$ROOT/courier/courier.out"
      chmod 600 "$ROOT/courier/courier.out"
      nohup python3 "$script" --watch "$@" >> "$ROOT/courier/courier.out" 2>&1 &
      disown 2>/dev/null || true
      sleep 1
      python3 "$script" --status | head -1
      ;;
    stop)   python3 "$script" --stop ;;
    status) python3 "$script" --status ;;
    once)   python3 "$script" --once "$@" ;;
    watch)  python3 "$script" --watch "$@" ;;
    dead)   python3 "$script" --dead ;;
    requeue) python3 "$script" --requeue ;;
    *) die "courier: unknown action '$action' (start|stop|status|once|watch|dead|requeue)" ;;
  esac
}

# The permission mode the PANE is actually in, or empty if it cannot be told.
#
# WHY THIS EXISTS: run/<name>.perms records what spawn CONFIGURED, which is not the
# same thing as what the agent ended up in. Measured 2026-09-22: a claude agent
# spawned with bypassPermissions answered its startup dialogs and settled in `auto
# mode`, while `list` went on reporting UNRESTRICTED. Reporting an agent as less
# restricted than it is would be the dangerous direction; reporting it as more
# restricted is merely wrong, and either way a listing that cannot be trusted is worse
# than one that admits it does not know.
#
# Every CLI prints its mode in the pane footer, so read it from there.
observed_perms() {
  local name="$1" footer
  footer="$(tm capture-pane -p -t "$name" 2>/dev/null | strip_ansi | grep -v '^[[:space:]]*$' | tail -6)"
  case "$footer" in
    *"bypass permissions on"*)  printf 'bypass' ;;
    *"auto mode on"*)           printf 'auto' ;;
    *"plan mode on"*)           printf 'plan' ;;
    *"accept edits on"*)        printf 'acceptEdits' ;;
    *"always-approve"*)         printf 'always-approve' ;;
    *"YOLO"*|*"yolo"*)          printf 'yolo' ;;
    *) printf '' ;;
  esac
}

# Mention orphaned sidecars without acting on them. `list` is a read, so it says
# what is there and names the verb; `reap` is what removes anything.
report_stale() {
  local n; n="$(stale_count)"
  [ "$n" = 0 ] && return 0
  printf '\n%s stale sidecar set(s) for agents with no live session - `agentmux reap` removes them\n' "$n"
}

# Read the orchestrator's mail.
#
# The orchestrator is this session - a Claude Code conversation, not a tmux pane - so
# it has no screen for the courier to type into. Messages addressed to it land in
# ~/.agentmux/inbox/<name>.jsonl and are read here. Before this existed every reply an
# agent sent back to `orchestrator` was retried and then thrown away.
cmd_inbox() {
  # Positional-only parsing - `$1` is the name, `$2` must be the flag - read
  # `inbox --clear claude` as name="--clear", which the second case rewrote to
  # "orchestrator". So an operator who asked to clear claude's inbox cleared the
  # ORCHESTRATOR's instead, destructively and silently, while claude's messages
  # stayed unread. A typo in the flag (`--clera`) was ignored outright and the
  # inbox was merely printed, so `--clear` looked like it had run.
  local name="" clear=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --clear) clear=1; shift ;;
      --)
        shift
        if [ $# -gt 0 ]; then name="$1"; shift; fi
        ;;
      -*) die "inbox: unknown option '$1'
       (inbox takes one name and --clear; use -- before a name that
        legitimately starts with a dash)" ;;
      *)
        [ -z "$name" ] || die "inbox takes one name (got '$name' and '$1')"
        name="$1"; shift
        ;;
    esac
  done
  name="${name:-orchestrator}"

  # Validate exactly as cmd_post does. Without this the name was interpolated
  # straight into the path, so `inbox ../queue/claude --clear` resolved OUTSIDE
  # inbox/ onto a real agent outbox and unlinked it - destroying messages that had
  # not been delivered yet. cmd_post rejected such a name and cmd_inbox accepted it,
  # which is the kind of gap that only shows up when someone goes looking. Found by
  # grok reviewing this file.
  printf '%s' "$name" | grep -Eq '^[A-Za-z0-9_.-]{1,64}$' \
    || die "inbox name must be 1-64 chars of letters, digits, '_', '.' or '-' (got '$name')"
  case "$name" in
    .|..) die "inbox name must not be '.' or '..'" ;;
  esac

  local path="$ROOT/inbox/$name.jsonl"
  [ -f "$path" ] || { printf "inbox for '%s' is empty (%s)\n" "$name" "$path"; return 0; }
  python3 - "$path" "$clear" <<'PY'
import json, os, pathlib, secrets, sys

path, clear = pathlib.Path(sys.argv[1]), sys.argv[2] == "1"

# CLAIM THE FILE FIRST WHEN CLEARING, THEN READ WHAT WE CLAIMED.
#
# The previous order was read -> print -> unlink, which loses every message the
# courier appended in between: it was never printed and is then deleted. The courier
# appends with open(path, "a") and has no idea a reader is here, so the window is
# real and silent - and for a completion protocol fed from this inbox it is a route
# to "signal fired without all verifications received".
#
# os.replace is atomic within a filesystem. After it, the courier's next append
# recreates the live file and nothing in flight is touched; we then read the renamed
# staging file, which no longer moves.
#
# #18. THE ARCHIVE IS APPENDED TO, NOT REPLACED.
#
# The snapshot used to be a fixed name - <inbox>.jsonl.read - reached by os.replace,
# so the SECOND clear atomically destroyed what the first one had preserved. The
# comment here promised a destructive read was recoverable; that promise held for
# exactly one generation, and an operator who cleared twice while chasing something
# lost the messages they were chasing. Clearing twice is the normal case.
#
# Staging name is unique (pid + random), so two concurrent clears of the same inbox
# cannot publish each other's partial bytes - the same flaw already fixed in
# courier.write_private. Appends are O_APPEND, so they interleave whole-record and
# neither clear loses the other's. The archive is trimmed to the last ARCHIVE_MAX
# bytes on a record boundary, so "keep it" cannot become "fill the disk".
ARCHIVE_MAX = 4 * 1024 * 1024

if clear:
    staging = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.taking")
    try:
        os.replace(path, staging)
    except OSError as err:
        print(f"could not take the inbox: {err}", file=sys.stderr)
        raise SystemExit(1)

    archive = path.with_suffix(path.suffix + ".read")
    try:
        taken = staging.read_bytes()
        if taken and not taken.endswith(b"\n"):
            taken += b"\n"
        with open(archive, "ab") as out:      # O_APPEND: atomic against a rival clear
            out.write(taken)
        if archive.stat().st_size > ARCHIVE_MAX:
            keep = archive.read_bytes()[-ARCHIVE_MAX:]
            keep = keep.partition(b"\n")[2]  # never leave a half record at the front
            trimmed = archive.with_name(archive.name + f".{os.getpid()}.trim")
            trimmed.write_bytes(keep)
            os.replace(trimmed, archive)
    except OSError as err:
        # The inbox is already claimed at this point. Say what happened and leave the
        # staging file where it is rather than deleting the only copy of the messages.
        print(f"cleared, but could not archive: {err}\n  the messages are in {staging}",
              file=sys.stderr)
        archived_ok = False
    else:
        archived_ok = True
    source = staging
else:
    source = path

rows = []
for line in source.read_text(encoding="utf-8").splitlines():
    if line.strip():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
print(f"{len(rows)} message(s) in {path}\n")
for row in rows:
    print(f"  {row.get('at','')}  from {row.get('sender','?')} "
          f"({row.get('kind','?')})" + (f" ref {row['ref']}" if row.get("ref") else ""))
    for line in (row.get("body") or "").splitlines():
        print(f"      {line}")
    print()
if clear:
    archive = path.with_suffix(path.suffix + ".read")
    if archived_ok:
        # Safely in the archive, so the staging copy is redundant. Removed only on
        # the path where the archive write actually succeeded - the error path
        # deliberately keeps it, because there it is the only copy.
        try:
            source.unlink()
        except OSError:
            pass
        print(f"inbox cleared; the messages above are appended to {archive.name}")
    else:
        print(f"inbox cleared; the messages above are kept in {source.name}")
PY
}

cmd_list() {
  if ! tm list-sessions >/dev/null 2>&1; then
    echo "no agents running"; report_stale; return 0
  fi
  printf '%-14s %-12s %-9s %-14s %-10s %-18s %s\n' NAME CLI STATE PERMS TASK AUTH CWD
  # Process substitution rather than a pipe: a piped `while read` runs in a subshell,
  # so $mismatch would be discarded the moment the loop ended and the note below would
  # never print.
  local mismatch=""
  while read -r n; do
    cli="$(cat "$RUNDIR/$n.cli" 2>/dev/null || echo '?')"
    cwd="$(cat "$RUNDIR/$n.cwd" 2>/dev/null || echo '?')"
    perms="$(cat "$RUNDIR/$n.perms" 2>/dev/null || echo '?')"
    task="$(cat "$RUNDIR/$n.task" 2>/dev/null || echo '-')"
    # Prefer what the pane says over what spawn intended. A '*' marks a value that
    # was configured but could not be confirmed from the pane, so the column never
    # silently presents an assumption as an observation.
    actual="$(observed_perms "$n")"
    if [ -n "$actual" ]; then
      case "$perms:$actual" in
        UNRESTRICTED:bypass|UNRESTRICTED:yolo|UNRESTRICTED:always-approve) ;;
        *) mismatch="$mismatch $n=$actual" ;;
      esac
      perms="$actual"
    else
      perms="$perms*"
    fi
    # An auth method id, never a credential. '-' means the CLI's own built-in
    # default, i.e. an existing OAuth login that agentmux does not manage.
    auth="$(cat "$RUNDIR/$n.auth" 2>/dev/null || echo '-')"
    # A passthrough --cli string can be arbitrarily long; truncate so a long one
    # cannot wreck the alignment of every other row.
    [ "${#cli}" -gt 12 ] && cli="${cli:0:11}+"
    if [ "$(tm list-clients -t "=$n" 2>/dev/null | wc -l)" -gt 0 ]; then
      st="attached"
    else
      st="detached"
    fi
    printf '%-14s %-12s %-9s %-14s %-10s %-18s %s\n' "$n" "$cli" "$st" "$perms" "$task" "$auth" "$cwd"
  done < <(tm list-sessions -F '#{session_name}' 2>/dev/null)

  # Say it plainly when the pane disagrees with what spawn configured, rather than
  # leaving the operator to notice a column they have read a hundred times.
  if [ -n "$mismatch" ]; then
    printf '\nPERMS differs from what spawn configured:%s\n' "$mismatch"
    printf '  the pane is the authority here; a startup dialog can change the mode.\n'
  fi
  printf '%s' "" # keep the function's output tidy when nothing follows
  report_stale
}

# Claim the one-time Jira close-out for an agent. Returns 0 to the SINGLE winner.
#
# #16. Three things can close the same agent out: `kill`, `reap`, and the dashboard's
# own reaper (server.py:maybe_reap). Each checked for a marker and then wrote it -
# check-then-write across three processes, so two could both see "absent". Worse, the
# marker lived at run/<name>.reported and BOTH shell paths then ran
# `rm -f "$RUNDIR/<name>".*`, which deleted the marker microseconds after writing it.
# Its lifetime was effectively zero, so the dashboard reaper saw nothing and posted a
# duplicate close-out comment and a duplicate Confluence report onto a real ticket.
#
# Fixed by moving the marker into run/reported/, which the sidecar glob does not match
# so it OUTLIVES the sweep, and by taking it with noclobber - bash opens with O_EXCL,
# so exactly one of the three wins the create and the other two get rc 1 and skip.
claim_reported() {
  local name="$1" who="${2:-cli}"
  mkdir -p "$RUNDIR/reported" 2>/dev/null || return 1
  # Honour the pre-2026-09-22 marker location so an in-flight upgrade cannot
  # double-post for an agent already closed out by the old code.
  [ -f "$RUNDIR/$name.reported" ] && return 1
  ( set -o noclobber; printf '%s\n' "$who" > "$RUNDIR/reported/$name" ) 2>/dev/null
}

# Remove an agent's sidecars WITHOUT removing the close-out marker.
#
# run/reported/<name> is a sibling directory, so `run/<name>.*` never matched it; this
# wrapper exists so the intent is stated once rather than inferred from a glob.
sweep_sidecars() {
  rm -f "$RUNDIR/$1".* 2>/dev/null
}

# Stop the courier once the last agent is gone.
#
# The mirror of the autostart in `spawn`. Without it the courier outlives every
# agent and polls an empty queue every few seconds until the next reboot - which is
# how it behaved when first written, and it is exactly the kind of orphan this
# session spent its time removing from run/. Started with the first agent, stopped
# with the last.
stop_courier_if_idle() {
  [ "${AGENTMUX_NO_COURIER:-0}" = "1" ] && return 0
  [ -n "${AGENTMUX_REPO:-}" ] && [ -f "$AGENTMUX_REPO/taskmgmt/courier.py" ] || return 0
  # Any session still up means somebody may still be messaging.
  tm list-sessions >/dev/null 2>&1 && return 0

  # #17. `kill last-agent` and `spawn new-agent` race here. The old order was:
  # see no sessions -> --status -> --stop. A spawn landing anywhere in that window
  # starts the courier (or finds it already running and starts nothing), then creates
  # its session a beat later - and this stop tears down the courier the new agent was
  # just told it had. The failure is SILENT in exactly the way the autostart exists to
  # prevent: `post` succeeds, the message sits in the queue, nobody ever hears it.
  #
  # Serialize on a lock directory that `spawn` also takes, then re-check liveness
  # while holding it. mkdir is atomic on every filesystem this runs on.
  local lock="$RUNDIR/.courier.lock" waited=0
  mkdir -p "$RUNDIR" 2>/dev/null
  until mkdir "$lock" 2>/dev/null; do
    waited=$((waited + 1))
    # A crashed holder must not wedge every later kill. Reset after forcing, or a
    # contended lock becomes a hot loop that stomps whoever wins next, forever.
    [ "$waited" -gt 50 ] && { rm -rf "$lock" 2>/dev/null; waited=0; }
    sleep 0.1
  done
  # shellcheck disable=SC2064
  trap "rm -rf '$lock' 2>/dev/null" RETURN

  # Re-check under the lock: a spawn that got in first has its session up by now.
  tm list-sessions >/dev/null 2>&1 && return 0

  python3 "$AGENTMUX_REPO/taskmgmt/courier.py" --status 2>/dev/null \
    | grep -q '^courier:   running' || return 0
  python3 "$AGENTMUX_REPO/taskmgmt/courier.py" --stop >/dev/null 2>&1 \
    && printf 'courier stopped (no agents left)\n'
}

# Pin the complete pane roster without adopting or writing a cached pane ID.
kill_target_snapshot() {
  local raw
  raw="$(tm list-panes -s -t "=$1" -F '#{pid}|#{start_time}|#{session_id}|#{session_created}|#{pane_id}|#{pane_pid}')" || return 1
  printf '%s\n' "$raw" | python3 -c '
import re, sys
rows = sys.stdin.read().splitlines()
pattern = r"[1-9][0-9]*\|[0-9]+\|\$[0-9]+\|[0-9]+\|%[0-9]+\|[1-9][0-9]*"
if not rows or any(not re.fullmatch(pattern, row) for row in rows):
    sys.exit(1)
parts = [row.split("|") for row in rows]
if len({tuple(row[:4]) for row in parts}) != 1 or len({row[4] for row in parts}) != len(rows):
    sys.exit(1)
print("\n".join(sorted(rows)))
'
}

# Missing legacy metadata is known absence. Unreadable or linked metadata is unknown.
kill_run_snapshot() {
  python3 - "$RUNDIR" "$1" <<'PYKILL'
import hashlib, json, os, stat, sys
result = []
try:
    for suffix in ("started", "task"):
        path = os.path.join(sys.argv[1], sys.argv[2] + "." + suffix)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            result.append(None)
            continue
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
                raise ValueError()
            raw = stream.read(65537)
            after = os.fstat(stream.fileno())
            linked = os.lstat(path)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            if len(raw) > 65536 or identity(before) != identity(after) or identity(after) != identity(linked):
                raise ValueError()
            result.append([*identity(after), hashlib.sha256(raw).hexdigest()])
    print(json.dumps(result, separators=(",", ":")))
except (OSError, ValueError):
    sys.exit(1)
PYKILL
}

cmd_kill() (
  local target="${1:-}"
  [ -n "$target" ] || die "kill needs a name or --all"
  if [ "$target" = "--all" ]; then
    if tm kill-server 2>/dev/null; then echo "killed all agents"; else echo "no agents running"; fi
    claude_credentials_sync_locked
    stop_courier_if_idle
    stop_idle_watchdog_if_no_agents
    return 0
  fi
  case "$target" in */*|*$'\n'*|*$'\r'*) die "invalid kill target" ;; esac
  local original run_original current run_current session_id kill_lock
  original="$(kill_target_snapshot "$target")" || die "kill target identity unavailable"
  run_original="$(kill_run_snapshot "$target")" || die "kill run metadata unavailable"
  # Close-out reads logs and claims reporting by name. Keep spawn excluded from
  # that phase too, so those inputs cannot belong to a replacement generation.
  exec {kill_lock}>"$ROOT/.spawn.lock" || die "kill spawn lock unavailable"
  flock -x "$kill_lock" || die "kill spawn lock unavailable"
  current="$(kill_target_snapshot "$target")" || die "kill target identity unavailable"
  run_current="$(kill_run_snapshot "$target")" || die "kill run metadata unavailable"
  [ "$current" = "$original" ] && [ "$run_current" = "$run_original" ] || die "kill target changed while waiting for spawn lock"
  if [ -n "${AGENTMUX_KILL_EXPECTED_TARGET:-}" ] && [ "$original" != "$AGENTMUX_KILL_EXPECTED_TARGET" ]; then
    die "kill target changed before close-out"
  fi
  if [ "${AGENTMUX_OWNER_TERMINATION:-0}" = 1 ] && [ -z "${AGENTMUX_KILL_EXPECTED_TARGET:-}" ]; then
    die "owner termination requires an exact target generation"
  fi
  session_id="$(printf '%s\n' "$original" | head -1 | cut -d '|' -f 3)"

  # Close out Jira BEFORE the session dies: the transition comment and the
  # Confluence report are both built from this agent's pane log, and the log is
  # only meaningful while the sidecars still exist. Both calls are best-effort -
  # task_try swallows failures so a Jira outage cannot stop a kill.
  # The marker is claimed BEFORE the two calls, not after, so a crash between them
  # cannot produce a duplicate on the next reaper pass (#16).
  local bound; bound="$(cat "$RUNDIR/$target.task" 2>/dev/null || true)"
  run_current="$(kill_run_snapshot "$target")" || die "kill run metadata unavailable"
  [ "$run_current" = "$run_original" ] || die "kill run metadata changed before close-out"
  if [ "${AGENTMUX_OWNER_TERMINATION:-0}" != 1 ] && [ -n "$bound" ] \
     && task_cli >/dev/null && claim_reported "$target" killed-by-cli; then
    task_try done "$bound" --from-log "$target"
    task_try report "$target" --title "agentmux run - $target - $bound"
  fi

  # #20. The sweep used to run unconditionally. When kill-session FAILED - a tmux
  # hiccup, a session renamed out from under us - the agent stayed alive with its
  # sidecars deleted: no .cli, so `ask`/`read` could not tell which CLI it was driving;
  # no .task, so its issue was orphaned; and the dashboard listed a live pane it could
  # say nothing about. Deleting the record of a thing you failed to delete is the worst
  # of both outcomes, so the sweep now follows the kill only when the kill worked.
  # Recheck after slow close-out even while cooperating spawns are excluded.
  current="$(kill_target_snapshot "$target")" || die "kill target identity unavailable after close-out"
  run_current="$(kill_run_snapshot "$target")" || die "kill run metadata unavailable after close-out"
  [ "$current" = "$original" ] && [ "$run_current" = "$run_original" ] || die "kill target changed during close-out; state retained"
  local server_pid server_started session_created guard confirmation pane_id pane_pid pairs="" count=""
  IFS='|' read -r server_pid server_started session_id session_created _ <<< "$original"
  guard="#{&&:#{==:#{pid},$server_pid},#{&&:#{==:#{start_time},$server_started},#{==:#{session_created},$session_created}}}"
  while IFS='|' read -r _ _ _ _ pane_id pane_pid; do
    pairs="${pairs:+$pairs|}$pane_id[|]$pane_pid"
    count="${count}1"
  done <<< "$original"
  # Refuse pane changes that occur after the sampled roster check above.
  guard="#{&&:$guard,#{==:#{W:#{P:#{m/r:^($pairs)\$,#{pane_id}|#{pane_pid}}}},$count}}"
  confirmation="$(tm if-shell -F -t "$session_id" "$guard" \
    "kill-session -t $session_id ; display-message -p agentmux-kill-confirmed" \
    'display-message -p agentmux-kill-refused')"
  if [ "$?" = 0 ] && [ "$confirmation" = agentmux-kill-confirmed ]; then
    run_current="$(kill_run_snapshot "$target")" || die "terminated target; cleanup metadata unavailable"
    [ "$run_current" = "$run_original" ] || die "terminated target; changed sidecars retained"
    printf "killed '%s'\n" "$target"
    sweep_sidecars "$target"
    # The pane log and the claude mirror are deliberately NOT removed here: the log
    # is archived by the next spawn of this name and the mirror by the next GC
    # (TM-211). What IS done now is pulling a refresh this agent made back into the
    # shared credential store, so the operator's own claude and every other agent
    # are not left holding the refresh token it just retired (TM-212).
    claude_credentials_sync || true
  else
    printf "could not kill '%s'; its sidecars are left in place\n" "$target" >&2
    stop_courier_if_idle
    stop_idle_watchdog_if_no_agents
    return 1
  fi
  stop_courier_if_idle
  stop_idle_watchdog_if_no_agents
)

# All names that have sidecars under run/, live or not. ERE, because BRE alternation
# (\|) is a GNU extension: BSD sed matched nothing and reap saw no stale agents.
sidecar_names() {
  ls "$RUNDIR" 2>/dev/null \
    | sed -nE 's/\.(cli|cwd|perms|task|auth|pane|launch|started|reported)$//p' \
    | sort -u
}

# How many of those have no live tmux session. Used by `list` to nudge.
stale_count() {
  local name n=0
  while read -r name; do
    [ -n "$name" ] || continue
    have "$name" || n=$((n + 1))
  done <<EOF
$(sidecar_names)
EOF
  printf '%s' "$n"
}

# Remove run/ sidecars whose tmux session no longer exists.
#
# WHY THIS EXISTS: `kill` removes an agent's sidecars, but a reboot takes the whole
# tmux server without going through `kill`, and nothing else ever cleans up.
# Measured 2026-09-22: 45 files for seven agents from a session days earlier. The
# dashboard is honest about them - it labels each `stale`, dims the pane and opens no
# stream - but they never go away, and /api/agents keeps counting them, which is what
# made four smoke.sh stream checks fail against an empty /api/stream-all.
#
# Deletion is deliberately an explicit verb rather than a side effect of listing or
# of a GET. A read that quietly removes state is how you lose the one sidecar that
# would have explained an incident.
# ── idle agents ──────────────────────────────────────────────────────────────
#
# An agent nobody is using still holds a CLI process, a provider session and, if it
# was spawned unrestricted, a shell with the approval bypass turned off. Leaving one
# up for days is how a `dev` pane sits at 3.4 hours of zero activity with an
# unrestricted codex behind it, which is what prompted this.
#
# WHAT COUNTS AS "NO USE": tmux's own `session_activity`, which is the last time the
# pane produced output or received input. That is the honest signal - it moves when
# the agent is thinking out loud, when it prints a result, and when anyone types at
# it. It is NOT wall-clock uptime: a busy agent that has been running for six hours
# is in use, and a fresh one that has done nothing for an hour is not.
#
# WHAT IT WILL NOT DO:
#   - kill an ATTACHED session. Somebody has it on screen; the fact that they have
#     not typed for an hour is not permission to close their terminal.
#   - kill anything when tmux cannot be queried. A failed query is indistinguishable
#     from an idle session, and guessing in that direction ends a live agent.
#   - kill silently. Every timeout goes through cmd_kill, so the bound Jira issue is
#     closed out and the sidecars are swept exactly as a hand-typed kill would.
#
# AGENTMUX_IDLE_MINUTES=0 disables it entirely.
IDLE_MINUTES="${AGENTMUX_IDLE_MINUTES:-60}"

# Sessions idle longer than $1 minutes and not attached. One "name idle_seconds"
# per line. Split out from cmd_idle so the selection can be tested without a tmux
# server - test_idle.sh feeds it a fixture.
idle_candidates() {
  local limit_s="$1" now="$2" line name activity attached idle
  while read -r line; do
    [ -n "$line" ] || continue
    name="${line%% *}"; line="${line#* }"
    activity="${line%% *}"; attached="${line##* }"
    case "$activity$attached" in *[!0-9]*) continue ;; esac
    [ "$attached" != "0" ] && continue
    idle=$(( now - activity ))
    [ "$idle" -ge "$limit_s" ] && printf '%s %s\n' "$name" "$idle"
  done
  return 0
}

cmd_idle() {
  local dry=0 minutes="$IDLE_MINUTES"
  while [ $# -gt 0 ]; do
    case "$1" in
      --dry-run|-n) dry=1; shift ;;
      --minutes|-m) minutes="${2:?--minutes needs a number}"; shift 2 ;;
      *) die "idle takes --minutes N and --dry-run (got '$1')" ;;
    esac
  done
  case "$minutes" in ''|*[!0-9]*) die "idle: --minutes takes a whole number of minutes" ;; esac
  [ "$minutes" = 0 ] && { printf 'idle timeout disabled (AGENTMUX_IDLE_MINUTES=0)\n'; return 0; }

  command -v tmux >/dev/null 2>&1 \
    || die "tmux not found - cannot tell an idle session from a broken query; refusing to act"

  # Every tick also re-converges the claude credential store, so an agent whose
  # OAuth refresh replaced its credential link is repaired within a minute instead
  # of at the next spawn (TM-212). Skipped on a dry run, which must change nothing.
  [ "$dry" = 1 ] || claude_credentials_sync_locked

  local listing
  # No sessions at all is not a failure, it is the normal quiet state.
  listing="$(tm list-sessions -F '#{session_name} #{session_activity} #{session_attached}' 2>/dev/null)" \
    || return 0
  [ -n "$listing" ] || return 0

  local now; now="$(date +%s)"
  local limit_s=$(( minutes * 60 ))
  local name idle killed=0 skipped=0
  while read -r name idle; do
    [ -n "$name" ] || continue
    # ONLY THIS HOME'S AGENTS. The tmux socket is SHARED - every home talks to
    # `-L agentmux` - so list-sessions returns agents belonging to other homes, and
    # without this check an idle sweep run under one home closes another's agents.
    #
    # Measured: an idle watchdog belonging to /tmp/tmp.ozE3zbYxIr, a throwaway
    # scenario home that had already been deleted, logged
    #     closing tm-209-worker2 after 60m idle (limit 60m)  ... closed 6 idle agent(s)
    # and decapitated a live eight-agent team on the operator's board. The two that
    # survived did so only because someone happened to have them attached.
    #
    # $RUNDIR/<name>.cli is written by spawn for every agent this home owns, so its
    # absence means the session is somebody else's business. Not fatal, not silent:
    # counted and reported, because a sweep that quietly skips things is how you end
    # up believing the timeout is armed when it is not.
    if [ ! -f "$RUNDIR/$name.cli" ]; then
      skipped=$((skipped + 1))
      continue
    fi
    if [ "$dry" = 1 ]; then
      printf 'would close %-14s (idle %sm, limit %sm)\n' "$name" "$(( idle / 60 ))" "$minutes"
      continue
    fi
    printf 'closing %s after %sm idle (limit %sm)\n' "$name" "$(( idle / 60 ))" "$minutes"
    # Through cmd_kill, not tmux directly: an agent that times out gets the same
    # close-out as one the operator ends by hand.
    cmd_kill "$name" >/dev/null 2>&1 && killed=$((killed + 1))
  done <<EOF
$(printf '%s\n' "$listing" | idle_candidates "$limit_s" "$now")
EOF
  [ "$dry" = 1 ] || [ "$killed" = 0 ] || printf 'closed %s idle agent(s)\n' "$killed"
  [ "$skipped" = 0 ] || printf '%s idle session(s) left alone: not this home (%s)\n' \
    "$skipped" "$ROOT"
  return 0
}

# The watchdog that makes the timeout automatic.
#
# Same shape as the courier: started with the first agent, stopped with the last, so
# nothing is left polling an empty tmux server. One process regardless of how many
# agents are up. It re-execs this script rather than carrying the logic inline, so a
# fix to cmd_idle reaches a watchdog that is already running on its next tick.
idle_watchdog_running() {
  local pid; pid="$(cat "$RUNDIR/.idle.pid" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

start_idle_watchdog() {
  [ "${AGENTMUX_IDLE_MINUTES:-$IDLE_MINUTES}" = 0 ] && return 1
  idle_watchdog_running && return 0

  local script; script="$(agentmux_self)" || {
    # Better to say the timeout is not armed than to leave a watchdog that cannot
    # find the script it exists to run.
    printf 'agentmux: cannot locate agentmux.sh on disk; idle timeout NOT armed\n' >&2
    printf '          set AGENTMUX_REPO=/path/to/repo to enable it\n' >&2
    return 1
  }
  mkdir -p "$RUNDIR" 2>/dev/null
  local self="$RUNDIR/.idle-watchdog.sh"
  cat > "$self" <<WATCHDOG
#!/usr/bin/env bash
# Started by agentmux spawn; ends when the last agent does. Do not edit - rewritten
# on every spawn from agentmux.sh.
#
# The \`tr -d '\r'\` is not decoration: this repo is checked out with CRLF, so bash
# refuses agentmux.sh read directly. Every other caller uses process substitution
# for the same reason.

# CLOSE EVERY DESCRIPTOR WE WERE HANDED EXCEPT stdio.
#
# A detached daemon inherits the whole fd table of whoever started it, and it then
# holds those files open for its entire life - which here means until the last agent
# exits, potentially days. That is not theoretical: dashboard/run_tests.sh takes its
# single-instance lock with \`exec 200>...\`, spawns agents, and a run killed before
# its EXIT handler left this watchdog (and the \`sleep\` it forks) holding fd 200
# forever. Every later run then refused to start, reporting a port conflict that did
# not exist, and the only way out was hunting the holder with fuser.
#
# Done in the CHILD rather than at each call site so it holds for every caller,
# including ones that have not been written yet.
[ -d /proc/self/fd ] && _fds=/proc/self/fd || _fds=/dev/fd   # macOS has no /proc
for _fd in "\$_fds"/*; do
  _n="\${_fd##*/}"
  [ "\$_n" -gt 2 ] 2>/dev/null && eval "exec \$_n>&-" 2>/dev/null
done
unset _fd _n _fds

# STOP WHEN THIS HOME GOES, not only when the tmux server empties.
#
# The socket is shared, so \`list-sessions\` keeps succeeding as long as ANY home has
# an agent up - which means a watchdog started by a throwaway test outlives that test
# indefinitely and goes on sweeping. Three such orphans were found running against
# deleted /tmp homes, and one of them had closed six live agents.
#
# Same rule the courier follows: a daemon whose home has been deleted has nothing
# left to serve and should stop, rather than keep acting on shared state.
while sleep "\${AGENTMUX_IDLE_TICK:-60}"; do
  [ -d "$RUNDIR" ] || break
  tmux -L "$SOCKET" list-sessions >/dev/null 2>&1 || break
  "$BASH" <(tr -d '\r' < "$script") idle >> "$RUNDIR/.idle.log" 2>&1
done
rm -f "$RUNDIR/.idle.pid" "$self" 2>/dev/null
WATCHDOG
  chmod +x "$self" 2>/dev/null
  # "$BASH", not bash: on macOS the first bash on PATH can be /bin/bash 3.2.
  # macOS has no setsid(1); python execs in place, so $! is still the watchdog's pid.
  if command -v setsid >/dev/null 2>&1; then
    setsid "$BASH" "$self" >/dev/null 2>&1 &
  else
    python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      "$BASH" "$self" >/dev/null 2>&1 &
  fi
  printf '%s\n' "$!" > "$RUNDIR/.idle.pid"
  return 0
}

stop_idle_watchdog_if_no_agents() {
  tm list-sessions >/dev/null 2>&1 && return 0
  local pid; pid="$(cat "$RUNDIR/.idle.pid" 2>/dev/null || true)"
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null
  rm -f "$RUNDIR/.idle.pid" "$RUNDIR/.idle-watchdog.sh" 2>/dev/null
  return 0
}

cmd_reap() {
  local dry=0
  case "${1:-}" in
    --dry-run|-n) dry=1 ;;
    "") ;;
    *) die "reap takes --dry-run or nothing (got '$1')" ;;
  esac

  # If tmux itself is missing, a failed has-session is indistinguishable from a dead
  # session, and guessing in that direction deletes state. Refuse instead.
  command -v tmux >/dev/null 2>&1 \
    || die "tmux not found - cannot tell a dead session from a broken query; refusing to reap"

  local name bound found=0 reaped=0
  while read -r name; do
    [ -n "$name" ] || continue
    if have "$name"; then continue; fi
    found=$((found + 1))
    local files; files="$(ls "$RUNDIR/$name".* 2>/dev/null | wc -l | tr -d " ")"
    if [ "$dry" = 1 ]; then
      printf 'would reap %-14s (%s file(s))\n' "$name" "$files"
      continue
    fi

    # Same close-out as `kill`, for the same reason: an orphan is a dead agent, and
    # its Jira issue should not stay open because the tmux server went away rather
    # than the operator typing `kill`. Best-effort - task_try swallows failures.
    bound="$(cat "$RUNDIR/$name.task" 2>/dev/null || true)"
    # The identity of the dead agent, captured BEFORE the slow part. See below.
    local stamp; stamp="$(cat "$RUNDIR/$name.started" 2>/dev/null || true)"

    if [ -n "$bound" ] && task_cli >/dev/null && claim_reported "$name" reaped-by-cli; then
      task_try done "$bound" --from-log "$name"
      task_try report "$name" --title "agentmux run - $name - $bound"
    fi

    # #15. Those two calls are network round-trips to Jira and Confluence, each with a
    # 90s ceiling - so up to three minutes can pass between `have "$name"` saying the
    # session is dead and this delete. Agent names here are ROLES: claude, rev, codex
    # get respawned under the same name constantly. Respawn inside that window and the
    # sweep deletes a LIVE agent's sidecars, which is #20's damage arriving by a
    # different road.
    #
    # So re-check on the way out, against both liveness and the spawn stamp - the
    # stamp catches a respawn fast enough to have already died again.
    if have "$name"; then
      printf 'skipped %-14s (came back alive during close-out)\n' "$name" >&2
      continue
    fi
    if [ "$(cat "$RUNDIR/$name.started" 2>/dev/null || true)" != "$stamp" ]; then
      printf 'skipped %-14s (respawned during close-out)\n' "$name" >&2
      continue
    fi

    sweep_sidecars "$name"
    reaped=$((reaped + 1))
    printf 'reaped %-14s (%s file(s))\n' "$name" "$files"
  done <<EOF
$(sidecar_names)
EOF

  if [ "$found" = 0 ]; then
    echo "no stale sidecars"
  elif [ "$dry" = 1 ]; then
    printf '%s stale agent(s); run `agentmux reap` to remove them\n' "$found"
  else
    printf '%s stale agent(s) reaped. Logs under %s are untouched.\n' "$reaped" "$LOGDIR"
  fi
}

cmd_attach() {
  local name="${1:-}"
  [ -n "$name" ] || die "attach needs a name"
  need "$name"
  printf '%stmux -L %s attach -t %s\n' "$(attach_prefix)" "$SOCKET" "$name"
  echo "(detach with Ctrl-b d)"
}

cmd_exec() {
  local cwd="$PWD" model=""
  local -a words=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --cwd)      cwd="${2:-}";   shift 2 ;;
      --model|-m) model="${2:-}"; shift 2 ;;
      --) shift; while [ $# -gt 0 ]; do words+=("$1"); shift; done ;;
      # exec runs codex unrestricted, so a mistyped --cwd silently runs in $PWD with
      # the flag pasted into the prompt.
      -*) die "exec: unknown option '$1'
       (exec takes --cwd, --model; use -- before a prompt starting with a dash)" ;;
      *) words+=("$1"); shift ;;
    esac
  done
  local text="${words[*]}"
  [ -n "$text" ] || die "exec needs a prompt"
  cwd="$(to_wsl_path "$cwd")"
  [ -d "$cwd" ] || die "not a directory: $cwd"
  export PATH="$(node_bin):$PATH"
  # Same unrestricted default as cmd_spawn; exec retains its legacy yolo profile.
  local bypass=""
  [ "${AGENTMUX_NO_BYPASS:-0}" != "1" ] && bypass="--profile yolo"
  # stdin is redirected from /dev/null: codex exec inherits stdin otherwise, so
  # when called from inside a heredoc it swallows the rest of the caller's
  # script as prompt text and never runs it (audit D32).
  if [ -n "$model" ]; then
    ( cd "$cwd" && codex exec ${bypass:+$bypass} -m "$model" "$text" < /dev/null )
  else
    ( cd "$cwd" && codex exec ${bypass:+$bypass} "$text" < /dev/null )
  fi
}

# ── the CCC orchestrator ─────────────────────────────────────────────────────
#
# One agent, in its own pane, holding a warrant that lets it call the four verbs an
# orchestration needs: run start, assign, complete, teardown. Everything else it does -
# verdicts, claims, board writes - goes through the ordinary identity path and is
# refused exactly as it would be for any other pane.
#
# ONE AT A TIME, enforced against live sessions rather than stored in a file. A second
# orchestrator is not a concurrency problem to tune, it is two things deciding what is
# finished, and a number in a config that can disagree with reality is a bug generator.

ORCH_DEFAULT_AGENT="ccc-orchestrator"

orchestrator_live() {
  # The warranted name, if a pane by that name is actually running.
  local name; name="$(orchestrator_warranted_name)" || return 1
  [ -n "$name" ] || return 1
  have "$name" && printf '%s\n' "$name" && return 0
  return 1
}

orchestrator_warranted_name() {
  [ -f "$ROOT/orchestrator.warrant" ] || return 1
  python3 -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("agent",""))
except Exception:
    sys.exit(1)' "$ROOT/orchestrator.warrant" 2>/dev/null
}

cmd_orchestrator() {
  local sub="${1:-status}"; shift 2>/dev/null || true
  case "$sub" in
    start)  orchestrator_start "$@" ;;
    stop)   orchestrator_stop  "$@" ;;
    status) orchestrator_status "$@" ;;
    *) printf 'usage: agentmux orchestrator start|stop|status\n' >&2; return 2 ;;
  esac
}

orchestrator_status() {
  local name; name="$(orchestrator_warranted_name 2>/dev/null || true)"
  if [ -z "$name" ]; then
    printf 'orchestrator: no warrant issued\n'
    return 0
  fi
  local expires agent_state
  expires="$(python3 -c 'import json,sys,time
r=json.load(open(sys.argv[1]))
left=int(r.get("expires_at",0)-time.time())
print(f"{left//60}m" if left>0 else "EXPIRED")' "$ROOT/orchestrator.warrant" 2>/dev/null)"
  if have "$name"; then agent_state="running"; else agent_state="NOT running"; fi
  printf 'orchestrator: %s (%s), warrant expires in %s\n' "$name" "$agent_state" "$expires"
}

orchestrator_start() {
  local name="$ORCH_DEFAULT_AGENT" request="" hours=8
  while [ $# -gt 0 ]; do
    case "$1" in
      --agent)   name="${2:-}"; shift 2 ;;
      --request) request="${2:-}"; shift 2 ;;
      --hours)   hours="${2:-8}"; shift 2 ;;
      *) printf 'orchestrator start: unknown option %s\n' "$1" >&2; return 2 ;;
    esac
  done
  [ -n "$request" ] || { printf 'orchestrator start: --request is required - say what it should do\n' >&2; return 2; }

  # ONE AT A TIME. Checked against tmux, not against a file, because a stale file is
  # exactly how you end up with two.
  local existing
  if existing="$(orchestrator_live)"; then
    printf 'orchestrator: %s is already running. Stop it first:\n  agentmux orchestrator stop\n' "$existing" >&2
    return 1
  fi

  printf 'minting a warrant for %s (%sh)...\n' "$name" "$hours"
  AGENTMUX_HOME="$ROOT" python3 -c 'import sys
sys.path.insert(0, sys.argv[1])
import coordination
coordination.issue_warrant(sys.argv[2], cli=sys.argv[3], hours=float(sys.argv[4]),
                           issued_by="agentmux orchestrator start")' \
    "${AGENTMUX_REPO:-$PWD}/taskmgmt" "$name" "shell" "$hours" || {
      printf 'orchestrator: could not mint a warrant\n' >&2; return 1; }

  # THE CLI COMES FROM THE DEFINITION ON DISK, never from here.
  #
  # Hardcoding it was the first version and it was wrong twice over: it named `claude`,
  # which is a Windows binary and is not on PATH inside WSL where the pane actually
  # runs, so the spawn would have failed on this machine; and it duplicated a fact that
  # .agentmux/agents/<name>.md already owns, which is exactly the "only id and name are
  # read from the wire" bound that keeps the definition authoritative.
  local cli
  cli="$(AGENTMUX_REPO="${AGENTMUX_REPO:-$PWD}" python3 -c '
import sys
sys.path.insert(0, sys.argv[1] + "/taskmgmt")
import agentdefs
spec = agentdefs.resolve(sys.argv[2], sys.argv[1])
print(getattr(spec, "cli", None) or (spec or {}).get("cli", "") if spec else "")
' "${AGENTMUX_REPO:-$PWD}" "$name" 2>/dev/null)"
  if [ -z "$cli" ]; then
    printf 'orchestrator: no definition for %s in .agentmux/agents/ - revoking
' "$name" >&2
    AGENTMUX_HOME="$ROOT" python3 -c 'import sys
sys.path.insert(0, sys.argv[1]); import coordination; coordination.revoke_warrant()'       "${AGENTMUX_REPO:-$PWD}/taskmgmt" 2>/dev/null
    return 1
  fi
  printf 'spawning %s (%s)...
' "$name" "$cli"

  # Spawned as --role lead on purpose. dispatch.WORKER_RE is card-scoped and this name
  # does not match it, so collect/pool ignore the orchestrator for free - no new role
  # vocabulary to add in five files.
  if ! cmd_spawn "$name" --cli "$cli" --cwd "${AGENTMUX_REPO:-$PWD}" --role lead; then
    printf 'orchestrator: spawn failed - revoking the warrant\n' >&2
    AGENTMUX_HOME="$ROOT" python3 -c 'import sys
sys.path.insert(0, sys.argv[1]); import coordination; coordination.revoke_warrant()' \
      "${AGENTMUX_REPO:-$PWD}/taskmgmt" 2>/dev/null
    return 1
  fi

  printf '%s\n' "$request" > "$ROOT/run/$name.request" 2>/dev/null || true
  printf '\norchestrator %s is up. Brief it with:\n  agentmux send %s "<your request>"\n' "$name" "$name"
  printf 'Watch it: the Runs view in the CCC, or\n  agentmux attach %s\n' "$name"
}

orchestrator_stop() {
  local name; name="$(orchestrator_warranted_name 2>/dev/null || true)"
  # REVOCATION FIRST, then the kill. A pane that survives the kill is then already
  # powerless, which is the ordering that makes "stop" mean something even when the
  # kill does not land.
  AGENTMUX_HOME="$ROOT" python3 -c 'import sys
sys.path.insert(0, sys.argv[1]); import coordination
print(" ".join(coordination.revoke_warrant()) or "nothing to revoke")' \
    "${AGENTMUX_REPO:-$PWD}/taskmgmt" 2>/dev/null || true
  if [ -n "$name" ] && have "$name"; then
    cmd_kill "$name"
  else
    printf 'orchestrator: no pane to stop\n'
  fi
}

case "${1:-}" in
  spawn)  shift; cmd_spawn  "$@" ;;
  orchestrator) shift; cmd_orchestrator "$@" ;;
  send)   shift; cmd_send   "$@" ;;
  key)    shift; cmd_key    "$@" ;;
  unblock) shift; cmd_unblock "$@" ;;
  read)   shift; cmd_read   "$@" ;;
  tail)   shift; cmd_tail   "$@" ;;
  wait)   shift; cmd_wait   "$@" ;;
  ask)    shift; cmd_ask    "$@" ;;
  post)   shift; cmd_post   "$@" ;;
  courier) shift; cmd_courier "$@" ;;
  inbox)  shift; cmd_inbox  "$@" ;;
  claim)  shift; cmd_claim  "$@" ;;
  release) shift; cmd_release "$@" ;;
  claims) shift; cmd_claims "$@" ;;
  run)    shift; cmd_run    "$@" ;;
  tasks)  shift; cmd_tasks  "$@" ;;
  task)   shift; cmd_task   "$@" ;;
  dispatch) shift; cmd_dispatch "$@" ;;
  collect)  shift; cmd_collect  "$@" ;;
  pool)     shift; cmd_pool     "$@" ;;
  board)    shift; cmd_board    "$@" ;;
  epic)     shift; cmd_epic     "$@" ;;
  roster|recruit|approve|retire|hire) cmd_team "$@" ;;
  journal) shift; cmd_journal "$@" ;;
  list)   shift; cmd_list   "$@" ;;
  kill)   shift; cmd_kill   "$@" ;;
  reap)   shift; cmd_reap   "$@" ;;
  idle)   shift; cmd_idle   "$@" ;;
  attach) shift; cmd_attach "$@" ;;
  exec)   shift; cmd_exec   "$@" ;;
  # The messaging protocol and work hub (docs/PROTOCOL.md). Everything past `hub` is
  # the Python client's; the hub itself decides who the caller is.
  hub)    shift
          _self="$(agentmux_self)" || die "hub: cannot locate the agentmux checkout"
          exec python3 "$(dirname "$_self")/hub/cli.py" "$@" ;;
  # The build a peer is running: VERSION plus the checkout's commit, so two machines in
  # one circle can tell whether they run the same harness.
  version|--version)
          _self="$(agentmux_self)" || die "version: cannot locate the agentmux checkout"
          _repo="$(dirname "$_self")"
          printf 'agentmux %s (%s)\n' "$(tr -d '\r\n' < "$_repo/VERSION" 2>/dev/null || echo unknown)" \
            "$(git -C "$_repo" describe --always --dirty 2>/dev/null || echo no-git)" ;;
  ""|-h|--help|help) usage ;;
  *) die "unknown command '$1' (try: agentmux help)" ;;
esac
