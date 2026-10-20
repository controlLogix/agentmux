'use strict';

// agentmux dashboard — live terminal grid + configuration ribbon.
//
// Invariants:
//  1. Nothing from the backend is interpolated as HTML. Agent names, cli strings
//     and perms come from arbitrary text files; only textContent/classList used.
//  2. Terminals are REUSED across polls. Recreating them would discard scrollback
//     and restart every SSE stream.
//  3. This page is READ-ONLY. It never spawns, signals or writes to an agent. The
//     ribbon composes a command for the operator to run; it does not execute it.
//
// Review fixes applied (grok, 2026-09-18):
//  #1 BLOCKER  eof no longer latches a pane dead — a live agent gets reconnected.
//  #3          no SSE is opened for a stale agent; opened when it goes live.
//  #6          a malformed /api/agents payload no longer destroys every terminal.

const POLL_MS = 3000;
const TAIL_BYTES = 16384;
const MAX_RECONNECT_MS = 30000;
const PREF_KEY = 'agentmux.dashboard.prefs';

// The least a terminal cell may be before the grid scrolls instead of shrinking it.
// Roughly eight rows of text at the legibility floor (8 x ~8.4px) plus the cell's own
// header and status bar. A cell smaller than this shows one or two rows, which reads as
// an idle agent rather than a cramped one.
const MIN_USEFUL_CELL = 130;

const els = {
  grid:    document.getElementById('grid'),
  empty:   document.getElementById('empty'),
  stamp:   document.getElementById('stamp'),
  tmux:    document.getElementById('tmux'),
  banner:  document.getElementById('banner'),
  count:   document.getElementById('count'),
  follow:  document.getElementById('followToggle'),
  ribbon:  document.getElementById('ribbon'),
  rToggle: document.getElementById('ribbonToggle'),
  layout:  document.getElementById('layoutMode'),
  rowH:    document.getElementById('rowHeight'),
  fontSz:  document.getElementById('fontSize'),
  minFont: document.getElementById('minFont'),
  uiScale: document.getElementById('uiScale'),
  syncSz:  document.getElementById('syncSize'),
  jiraBase: document.getElementById('jiraBase'),
  // Views, keyed by the data-view attribute on each nav button. Adding a view is
  // a section and button in index.html plus registerView() for external views.
  // Seven top-level views. Queue, Feed, Journal and Chatter became tabs of Status;
  // Agents and Teams became tabs of Organization; Tickets became a tab of Board;
  // CODESYS became a card in IIOT. A view with tabs declares them in the markup
  // (data-tabs on the tablist, data-panel on each button) and app.js finds them -
  // see collectTabs().
  views: {
    terminals:    document.getElementById('viewTerminals'),
    status:       document.getElementById('viewStatus'),
    board:        document.getElementById('viewBoard'),
    organization: document.getElementById('viewOrganization'),
    iiot:         document.getElementById('viewIiot'),
    github:       document.getElementById('viewGithub'),
    settings:     document.getElementById('viewSettings'),
  },
  navItems: Array.from(document.querySelectorAll('.nav-item')),
  badgeQueue: document.getElementById('badgeQueue'),

  themeSelect: document.getElementById('themeSelect'),
  themeNote:   document.getElementById('themeNote'),
  swatches:    document.getElementById('swatches'),

  statusStamp:    document.getElementById('statusStamp'),
  statusExport:   document.getElementById('statusExport'),
  statusExportAs: document.getElementById('statusExportAs'),

  queueList:    document.getElementById('queueList'),
  queueStamp:   document.getElementById('queueStamp'),
  queueKind:    document.getElementById('queueKind'),
  queueSearch:  document.getElementById('queueSearch'),
  queueFollow:  document.getElementById('queueFollow'),
  queueRefresh: document.getElementById('queueRefresh'),
  planPin:      document.getElementById('planPin'),

  feedList:     document.getElementById('feedList'),
  feedFilters:  document.getElementById('feedFilters'),
  feedStamp:    document.getElementById('feedStamp'),
  feedFollow:   document.getElementById('feedFollow'),
  feedSearch:   document.getElementById('feedSearch'),
  feedClear:    document.getElementById('feedClear'),
  feedSources:  document.getElementById('feedSources'),
  feedSeverity: document.getElementById('feedSeverity'),
  feedMax:      document.getElementById('feedMax'),
  feedPoll:     document.getElementById('feedPoll'),
  feedBadge:    document.getElementById('feedBadge'),
  badgeFeed:    document.getElementById('badgeFeed'),

  boardList:  document.getElementById('boardList'),
  dispatchStrip: document.getElementById('dispatchStrip'),
  boardStamp: document.getElementById('boardStamp'),
  epicTitle:  document.getElementById('epicTitle'),
  epicJira:   document.getElementById('epicJira'),
  epicAdd:    document.getElementById('epicAdd'),
  boardFree:     document.getElementById('boardFree'),
  boardTidy:     document.getElementById('boardTidy'),
  boardExpand:   document.getElementById('boardExpand'),
  boardCollapse: document.getElementById('boardCollapse'),

  journalList:       document.getElementById('journalList'),
  journalStamp:      document.getElementById('journalStamp'),
  journalKind:       document.getElementById('journalKind'),
  journalSubject:    document.getElementById('journalSubject'),
  journalBody:       document.getElementById('journalBody'),
  journalAdd:        document.getElementById('journalAdd'),
  journalSearch:     document.getElementById('journalSearch'),
  journalFilterKind: document.getElementById('journalFilterKind'),

  ticketList:    document.getElementById('ticketList'),
  ticketStamp:   document.getElementById('ticketStamp'),
  ticketSearch:  document.getElementById('ticketSearch'),
  ticketRefresh: document.getElementById('ticketRefresh'),

  atlStamp:   document.getElementById('atlStamp'),
  atlRefresh: document.getElementById('atlRefresh'),
  atlState:   document.getElementById('atlState'),

  authList:    document.getElementById('authList'),
  authStamp:   document.getElementById('authStamp'),
  authRefresh: document.getElementById('authRefresh'),

  iiotStamp:    document.getElementById('iiotStamp'),
  iiotExpand:   document.getElementById('iiotExpand'),
  iiotCollapse: document.getElementById('iiotCollapse'),
  resList:  document.getElementById('resList'),
  resStamp: document.getElementById('resStamp'),
  resRefresh: document.getElementById('resRefresh'),
  spName:  document.getElementById('spawnName'),
  spCli:   document.getElementById('spawnCli'),
  spModel: document.getElementById('spawnModel'),
  spPerm:  document.getElementById('spawnPerm'),
  spCmd:   document.getElementById('spawnCmd'),
  copyBtn: document.getElementById('copyCmd'),
  copyNote:document.getElementById('copyNote'),
  sortBtn: document.getElementById('sortPanes'),
};

// xterm needs a literal colour table, but the app's colours are theme tokens, so
// derive one from the live CSS custom properties instead of hardcoding a palette.
// The old fixed palette survives as the `classic-dark` theme in themes.json.
function xtermTheme() {
  const cs = getComputedStyle(document.documentElement);
  const v = (t) => cs.getPropertyValue(t).trim() || undefined;
  const text = v('--text'), muted = v('--muted'), accent = v('--accent');
  return {
    background: v('--panel-2'), foreground: text, cursor: accent,
    black: v('--panel'), red: v('--danger'), green: v('--safe'), yellow: v('--warn'),
    blue: accent, magenta: v('--accent-dim'), cyan: muted, white: text,
    brightBlack: muted, brightRed: v('--danger'), brightGreen: v('--safe'),
    brightYellow: v('--warn'), brightBlue: accent, brightMagenta: v('--accent-dim'),
    brightCyan: muted, brightWhite: text,
  };
}

const panes = new Map();
let consecutiveFailures = 0;

// ---------------------------------------------------------------- helpers ---

// SSE payloads are base64: agent output contains CR/LF and control bytes that
// would corrupt SSE's line framing. Decode to bytes (not a string) so multi-byte
// UTF-8 survives — xterm accepts Uint8Array and buffers split sequences.
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function fmtUptime(s) {
  if (s === null || s === undefined || !Number.isFinite(s)) return '';
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (d) return `${d}d${h}h`;
  if (h) return `${h}h${String(m).padStart(2, '0')}m`;
  if (m) return `${m}m${String(sec).padStart(2, '0')}s`;
  return `${sec}s`;
}

const stateClass = (s) => ['attached', 'detached', 'stale'].includes(s) ? s : 'stale';
const permClass  = (p) => { const v = String(p || '').toLowerCase();
  return (v === 'unrestricted' || v === 'sandboxed') ? v : 'unknown'; };
const orDash = (v) => (v === null || v === undefined || v === '') ? '—' : String(v);

// ------------------------------------------------------------------ prefs ---

function loadPrefs() {
  let p = {};
  try { p = JSON.parse(localStorage.getItem(PREF_KEY) || '{}') || {}; } catch (_) {}
  if (p.layout) els.layout.value = p.layout;
  if (p.rowH)   els.rowH.value   = p.rowH;
  if (p.fontSz) els.fontSz.value = p.fontSz;
  if (p.minFont) els.minFont.value = p.minFont;
  if (p.uiScale) els.uiScale.value = p.uiScale;
  if (p.syncSz) els.syncSz.checked = true;
  if (typeof p.jiraBase === 'string') els.jiraBase.value = p.jiraBase;
  if (p.cli)    els.spCli.value  = p.cli;
  if (p.perm)   els.spPerm.value = p.perm;
  if (typeof p.model === 'string') els.spModel.value = p.model;
  if (p.ribbonHidden) setRibbon(false);
}
function savePrefs() {
  try {
    localStorage.setItem(PREF_KEY, JSON.stringify({
      layout: els.layout.value, rowH: els.rowH.value, fontSz: els.fontSz.value,
      minFont: els.minFont.value, uiScale: els.uiScale.value,
      syncSz: els.syncSz.checked, jiraBase: els.jiraBase.value,
      cli: els.spCli.value, perm: els.spPerm.value, model: els.spModel.value,
      ribbonHidden: els.ribbon.hidden,
    }));
  } catch (_) { /* private mode */ }
}

// ------------------------------------------------------------------ ribbon ---

function setRibbon(show) {
  els.ribbon.hidden = !show;
  els.rToggle.setAttribute('aria-expanded', String(show));
  requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
}

// Compose the agentmux command. Sanitised to a conservative charset so the
// string we hand the operator cannot carry shell metacharacters.
function composeSpawnCmd() {
  const safe = (v, re) => (re.test(v) ? v : '');
  const name  = safe(els.spName.value.trim(), /^[A-Za-z0-9_.-]{1,64}$/) || '<name>';
  const cli   = safe(els.spCli.value, /^[a-z]{1,10}$/) || 'codex';
  const model = safe(els.spModel.value.trim(), /^[A-Za-z0-9_.:-]{0,40}$/);
  const sandboxed = els.spPerm.value === 'sandboxed';

  let cmd = '';
  if (sandboxed) cmd += 'AGENTMUX_NO_BYPASS=1 ';
  cmd += `agentmux spawn ${name} --cli ${cli}`;
  if (model) cmd += ` --model ${model}`;
  cmd += ' --cwd .';
  els.spCmd.textContent = cmd;     // textContent, never innerHTML
  return cmd;
}

// Scale the chrome with the window.
//
// The reference is a 1500x940 window, which is where the fixed sizes in style.css were
// designed. Width and height are both considered and the smaller wins, because chrome
// that fits the width but not the height just pushes the grid off the bottom.
//
// Quantised to 5% steps. A continuous value would re-zoom on every pixel of a window
// drag, and each change re-lays-out the grid and re-fits every terminal — visible
// thrash for a difference nobody can see.
const UI_REFERENCE_W = 1500;
const UI_REFERENCE_H = 940;
const UI_SCALE_MIN = 0.8;
const UI_SCALE_MAX = 1.35;

function autoUiScale() {
  const byWidth = window.innerWidth / UI_REFERENCE_W;
  const byHeight = window.innerHeight / UI_REFERENCE_H;
  const raw = Math.min(byWidth, byHeight);
  const stepped = Math.round(raw * 20) / 20;      // 5% steps
  return Math.min(UI_SCALE_MAX, Math.max(UI_SCALE_MIN, stepped));
}

// Terminals are deliberately excluded from the zoom (see --ui-scale in style.css), so
// the space left for them changes and every pane must re-fit afterwards.
function applyUiScale() {
  const chosen = els.uiScale.value;
  const scale = chosen === 'auto' ? autoUiScale()
                                  : Math.min(2, Math.max(0.6, parseFloat(chosen) || 1));
  const current = getComputedStyle(document.documentElement)
    .getPropertyValue('--ui-scale').trim();
  if (parseFloat(current) === scale) return;      // nothing to do; avoids needless reflow
  document.documentElement.style.setProperty('--ui-scale', String(scale));
  els.uiScale.title = chosen === 'auto'
    ? `Following the window: ${Math.round(scale * 100)}%. Pick a percentage to pin it.`
    : 'Fixed interface scale. Choose auto to follow the window size.';
  // Two frames: one for the zoom to take effect, one to measure the result.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    relayout();
    panes.forEach((rec) => applyFit(rec));
  }));
}

function applyLayoutPrefs() {
  // The minimum only applies while Text is 'auto'. Disabling it otherwise is the whole
  // lesson from the control that silently did nothing: never present a knob that
  // cannot move anything.
  const autoText = els.fontSz.value === 'auto';
  els.minFont.disabled = !autoText;
  els.minFont.title = autoText
    ? "The smallest size 'auto' may shrink to. Below this the cell scrolls instead."
    : 'Only applies when Text is set to auto.';

  // rows
  const rh = els.rowH.value;
  els.grid.classList.toggle('compact', rh === 'fitcontent');
  if (rh === 'fitcontent') {
    els.grid.style.removeProperty('--rowh');
    els.grid.style.setProperty('--cellmin', '0px');
    requestAnimationFrame(() => panes.forEach((rec) => applyContentHeight(rec)));
  } else if (rh === 'fill') {
    // 'fill' shares the viewport between cells, but it must not divide it into
    // slivers: five agents in a short window gave each ~17px of terminal — one row of
    // text, which is worse than useless because it looks like an idle agent. Below the
    // floor the grid scrolls instead, so every visible cell is worth reading.
    els.grid.style.setProperty('--rowh', `minmax(${MIN_USEFUL_CELL}px, 1fr)`);
    els.grid.style.setProperty('--cellmin', `${MIN_USEFUL_CELL}px`);
  } else {
    els.grid.style.setProperty('--rowh', `minmax(${rh}px, 1fr)`);
    els.grid.style.setProperty('--cellmin', `${rh}px`);
  }
  // Font size is NOT set here any more: applyFit derives it from the cell, the
  // cap and the legibility floor. Setting it here too would fight that on every
  // ribbon change.
  // Not in free mode: there the height is part of the operator's placement, and
  // clearing it would collapse every hand-sized pane on any ribbon change.
  if (rh !== 'fitcontent' && !freeMode()) {
    panes.forEach((rec) => { rec.cell.style.height = ''; });
  }
  // Row height is meaningless in free mode; say so rather than offer a dead knob.
  els.rowH.disabled = freeMode();
  els.rowH.title = freeMode()
    ? 'Not used in free mode — drag a pane’s corner to size it.'
    : 'Cell height';
  relayout();
  requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
}

function wireRibbon() {
  els.rToggle.addEventListener('click', () => { setRibbon(els.ribbon.hidden); savePrefs(); });

  [els.layout, els.rowH, els.fontSz, els.minFont, els.syncSz].forEach((el) =>
    el.addEventListener('change', () => { applyLayoutPrefs(); savePrefs(); }));

  els.uiScale.addEventListener('change', () => { applyUiScale(); savePrefs(); });
  els.sortBtn.addEventListener('click', sortPanes);

  els.jiraBase.addEventListener('input', () => { savePrefs(); panes.forEach(applyTaskBadge); });

  [els.spName, els.spCli, els.spModel, els.spPerm].forEach((el) => {
    el.addEventListener('input',  () => { composeSpawnCmd(); savePrefs(); });
    el.addEventListener('change', () => { composeSpawnCmd(); savePrefs(); });
  });

  els.copyBtn.addEventListener('click', async () => {
    const cmd = composeSpawnCmd();
    try {
      await navigator.clipboard.writeText(cmd);
      els.copyNote.textContent = 'copied';
    } catch (_) {
      els.copyNote.textContent = 'select it manually';
    }
    setTimeout(() => { els.copyNote.textContent = ''; }, 1800);
  });
}

// -------------------------------------------------------------- cell build ---

function buildCell(agent) {
  const cell = document.createElement('section');
  cell.className = 'cell';

  const head = document.createElement('div');
  head.className = 'cell-head';
  const st = document.createElement('span');
  const name = document.createElement('span');
  name.className = 'cell-name'; name.textContent = orDash(agent.name);
  const cli = document.createElement('span'); cli.className = 'cell-cli';
  const spacer = document.createElement('span'); spacer.className = 'spacer';
  const up = document.createElement('span'); up.className = 'cell-up';
  const perm = document.createElement('span');
  const taskEl = document.createElement('span');   // filled by applyTaskBadge

  // Re-request the snapshot: reopening the stream makes the backend send a fresh
  // capture-pane of the CURRENT screen, which is also the repaint path if a TUI
  // got out of sync.
  const reBtn = document.createElement('button');
  reBtn.className = 'cbtn'; reBtn.textContent = '⟳';
  reBtn.title = 'Re-snapshot this pane';

  // Focus: 200x49 is unreadable in a small cell, so let one agent take the whole
  // grid. This is the practical answer to tiny text.
  const zBtn = document.createElement('button');
  zBtn.className = 'cbtn'; zBtn.textContent = '⤢';
  zBtn.title = 'Focus this agent (Esc to exit)';

  // Minimise: collapse to just this header. Keeps the stream running.
  const mBtn = document.createElement('button');
  mBtn.className = 'cbtn'; mBtn.textContent = '–';
  mBtn.title = 'Minimise (stream keeps running)';

  // Close the STREAM, not the agent. Frees one of the server's 16 stream slots
  // and stops traffic for a pane you are not watching. The agent is untouched -
  // this dashboard never signals or kills an agent.
  const xBtn = document.createElement('button');
  xBtn.className = 'cbtn'; xBtn.textContent = '×';
  xBtn.title = 'Close this stream (does NOT kill the agent)';

  // Effective text size and, when the legibility floor binds, how much of the pane
  // is actually on screen. Without this the operator cannot tell "the agent printed
  // nothing" from "the text is scrolled out of view".
  const fit = document.createElement('span');
  fit.className = 'cell-fit';

  head.append(st, name, cli, taskEl, spacer, fit, up, perm, reBtn, mBtn, xBtn, zBtn);

  const termHost = document.createElement('div'); termHost.className = 'term';
  const scaleEl = document.createElement('div'); scaleEl.className = 'term-scale';
  termHost.appendChild(scaleEl);
  const status = document.createElement('div');
  status.className = 'cell-status'; status.textContent = 'connecting…';

  // Bottom-right size grip. Only visible in free mode (CSS), because in a grid mode the
  // track sizes own the geometry and a grip there would fight them.
  const grip = document.createElement('div');
  grip.className = 'cell-grip';
  grip.title = 'Drag to resize this pane';

  cell.append(head, termHost, status, grip);

  // GEOMETRY MUST MATCH THE AGENT PANE. Agent panes are 200x49 and TUI agents
  // (codex, grok) emit absolute cursor addressing - grokrev's log has 12460
  // ESC[row;colH moves. Building the terminal at any other size scrambles the
  // screen. So we take cols/rows from the API and never fit-to-cell; the cell
  // shows a CSS-scaled view instead.
  const cols = Number.isFinite(agent.cols) && agent.cols > 0 ? agent.cols : 80;
  const rows = Number.isFinite(agent.rows) && agent.rows > 0 ? agent.rows : 24;

  const term = new window.Terminal({
    cols, rows,
    disableStdin: true,               // read-only by design
    convertEol: false,
    scrollback: 4000,
    fontSize: parseInt(els.fontSz.value, 10) || 11,
    fontFamily: 'ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace',
    theme: xtermTheme(),
    allowProposedApi: true,
  });

  // No FitAddon: fitting would resize the terminal away from the agent's real
  // geometry, which is exactly what broke TUI rendering.
  term.open(scaleEl);

  const rec = {
    cell, term, termHost, scaleEl, status, cols, rows, reBtn, zBtn, mBtn, xBtn,
    minimized: false, userClosed: false, lastSync: 0, syncTimer: null,
    headEl: head, grip, isTui: String(agent.cli || '').trim() !== 'shell',
    headEls: { st, perm, up, cli, task: taskEl, fit },
    source: null, retryMs: 500, retryTimer: null,
    disposed: false,      // pane is being torn down — never reopen
    streamEnded: false,   // server said eof — MAY reopen if the agent is live (#1)
  };

  const agentName = String(agent.name || '');
  rec.name = agentName;
  makeDraggable(rec, agentName);

  // Measure the cell metrics ONCE, at a known font size, and store them as ratios
  // per 1px of font. A monospace advance width and xterm's line height are both
  // linear in fontSize, so a ratio is font-size independent — which is what makes
  // it safe to PREDICT the size for a new font without measuring at that font.
  //
  // That distinction is the whole lesson from four failed attempts: measuring at
  // the current size in order to choose the next size is a feedback loop, and every
  // one of them ratcheted (188 cols in a 730px cell; 51x199; 182x40 -> 178x37).
  rec.baseFont = parseFloat(els.fontSz.value) || 11;
  requestAnimationFrame(() => {
    measureMetrics(rec);
    applyFit(rec);
  });
  reBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    setStatus(rec, 're-snapshotting…', '');
    openStream(rec, agentName);          // fresh stream => fresh snapshot
  });
  zBtn.addEventListener('click', (e) => { e.stopPropagation(); setFocus(agentName); });

  mBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    rec.minimized = !rec.minimized;
    rec.cell.classList.toggle('min', rec.minimized);
    mBtn.textContent = rec.minimized ? '+' : '–';
    mBtn.title = rec.minimized ? 'Restore' : 'Minimise (stream keeps running)';
    relayout();
    if (!rec.minimized) requestAnimationFrame(() => applyScale(rec));
  });

  xBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (rec.userClosed) {
      rec.userClosed = false;
      xBtn.textContent = '×';
      xBtn.title = 'Close this stream (does NOT kill the agent)';
      openStream(rec, agentName);
    } else {
      rec.userClosed = true;
      closeStream(rec);
      xBtn.textContent = '▷';
      xBtn.title = 'Resume this stream';
      setStatus(rec, 'stream closed by you - agent still running', 'eof');
    }
  });

  if (window.ResizeObserver) {
    rec.ro = new ResizeObserver(() => applyScale(rec));
    rec.ro.observe(termHost);
  }
  return rec;
}

// Scale the (oversized) terminal down so a 200x49 pane is readable in a cell.
// transform-origin is top-left so the scaled view stays anchored.
// ══════════════════════════════════════════════════════════ text fitting ══════
//
// THE PROBLEM. A terminal is built at the AGENT's geometry (200x49 is typical) and
// must never be resized away from it, because TUI agents emit absolute cursor
// addressing — grokrev's log has 12,460 ESC[row;colH moves, and any other grid
// scrambles the screen. So a 200-column pane has to be shown inside a cell that may
// be 300px wide.
//
// WHY THE OLD APPROACH FAILED. It applied a CSS `scale()` transform. A transform
// resamples the already-rendered glyph bitmaps, so at 3 columns text was not merely
// small, it was blurry mush — unreadable at any size. It also made every
// measurement suspect, because offsetWidth reflects an enclosing transform.
//
// THE FIX. Size the FONT instead of transforming pixels. xterm re-renders at
// whatever font size it is given, so glyphs stay crisp at every step, and the
// terminal keeps its 200x49 grid throughout.
//
// THE GUARANTEE. Text never shrinks below the legibility floor. If the whole pane
// cannot fit at the floor, the cell scrolls and the header says how much is visible
// — a readable window on the pane beats an unreadable whole.
const FONT_STEP = 0.5;      // half-px steps: fine enough to fill, coarse enough not to jitter
const HARD_MIN_FONT = 4;
const HARD_MAX_FONT = 32;
const GUTTER_W = 8;         // .term padding-left + a little slack for a scrollbar
const GUTTER_H = 4;

function clampNum(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

// Measure the TRUE grid size and store it as per-1px-of-font ratios. Safe to re-run:
// it normalises by whatever font size is actually applied, so it is not a feedback
// path.
//
// MEASURE `.xterm-screen`, NOT `.xterm`.
//
// `.xterm` is a block that fills its container, so its offsetWidth is the CELL
// width. Dividing that by cols yields "the width a character would need in order to
// fit", not the width one actually occupies — a circular measurement. The earlier
// version did exactly that, so the ratio silently absorbed the cell width, every
// pane reported a different ratio for the same font, and the fit converged on a
// number that left a 182-column pane overflowing 1050px of content into a 709px cell
// while believing it fit.
//
// xterm sizes `.xterm-screen` explicitly to cols x rows cells (inline
// style.width/height), so it is the real grid box. Verified against xterm's own
// internal dimensions: 1050px / 182 cols = 5.769px, matching its cell.width exactly.
// `.xterm-screen` is a documented class, so no private API is needed.
function measureMetrics(rec) {
  const el = rec.term && rec.term.element;
  const screen = el && el.querySelector('.xterm-screen');
  if (!screen || !rec.cols || !rec.rows) return false;
  const font = rec.appliedFont || rec.baseFont || 11;
  const w = screen.offsetWidth, h = screen.offsetHeight;
  // A zero here means xterm has not painted yet; keep any previous ratio rather than
  // poisoning it with a measurement of nothing.
  if (!w || !h || !font) return false;
  rec.wRatio = (w / rec.cols) / font;
  rec.hRatio = (h / rec.rows) / font;
  // Absolute pixels at the current font, for the pane-size sync.
  rec.charW = w / rec.cols;
  rec.charH = h / rec.rows;
  rec.natW = w;
  rec.natH = h;
  return true;
}

// ONE control decides the text size.
//
// It used to be three — a max, a min, and an auto/fixed mode — and in the default
// configuration the one labelled "max" did nothing at all. With a 200-column pane in a
// 709px cell the width-derived size is ~6.4px, so it always clamped UP to the minimum;
// the cap was never the binding constraint. Changing "max font size" from 10 to 20
// produced 7px either way, while the control labelled "min" was the only real lever.
// A control that reads as the font size must change the font size.
//
// So: Text = 'auto' fits the pane and respects the minimum; Text = a number IS the size,
// and the cell scrolls to reach whatever does not fit.
function fontBounds() {
  const raw = els.fontSz.value;
  const floor = clampNum(parseFloat(els.minFont && els.minFont.value) || 7,
                         HARD_MIN_FONT, HARD_MAX_FONT);
  if (raw === 'auto') return { exact: null, cap: HARD_MAX_FONT, floor };
  const size = clampNum(parseFloat(raw) || 11, HARD_MIN_FONT, HARD_MAX_FONT);
  // An explicit size is both the floor and the cap: it is simply the size.
  return { exact: size, cap: size, floor: size };
}

// The font size this cell should use. Pure: reads geometry, writes nothing.
function targetFont(rec) {
  if (!rec.wRatio || !rec.hRatio) return null;
  const { exact, cap, floor } = fontBounds();
  if (exact !== null) return exact;      // an explicit size: use it, scroll for the rest

  const availW = rec.termHost.clientWidth - GUTTER_W;
  if (availW <= 0) return null;
  let fs = availW / (rec.cols * rec.wRatio);

  // Constrain by height too, so the WHOLE pane is visible rather than just its top.
  //
  // Deliberately uses rec.rows, not usedRows(): deriving the font from how much the
  // agent has printed makes the text jump on every frame, and in 'fit content' mode
  // the cell height comes from the font size, which would close the loop.
  //
  // BUT only while height can shrink the text LEGIBLY. In a short cell, fitting all
  // 49 rows can demand 4px text; clamping that to the floor yields marginal text that
  // still does not show every row. When every row cannot be shown at a readable size,
  // the honest trade is fewer rows at a readable size plus a scrollbar — so the height
  // constraint is dropped rather than applied and then clamped.
  if (els.rowH.value !== 'fitcontent') {
    const availH = rec.termHost.clientHeight - GUTTER_H;
    if (availH > 0) {
      const fsHeight = availH / (rec.rows * rec.hRatio);
      if (fsHeight >= floor) fs = Math.min(fs, fsHeight);
    }
  }

  fs = Math.floor(fs / FONT_STEP) * FONT_STEP;
  return clampNum(fs, floor, cap);
}

// A bounded refinement budget.
//
// xterm rounds each cell to whole device pixels, so a ratio measured at one font size
// mispredicts slightly at another: a row 17px tall at 13px font is 1.3077 per px, but
// 9px at 7px font is 1.2857. Over 49 rows that is ~40px of error — enough to land a
// step or two away from the best size. So after applying a font we re-measure and
// recompute; if the answer moved, we apply again.
//
// This is a CONVERGENT loop, not the feedback loop that broke four earlier attempts,
// and the difference is deliberate: the budget is finite, and a size already tried in
// this cycle is never revisited, so it cannot ratchet or oscillate.
const FIT_MAX_PASSES = 4;

function applyFit(rec, pass) {
  if (!rec.term || rec.minimized || rec.disposed) return;
  const host = rec.termHost;
  if (!host || !host.clientWidth) return;

  const refining = Number.isInteger(pass) && pass > 0;
  if (!refining) {
    if (els.syncSz.checked) maybeSyncPaneSize(rec);
    rec.fitTried = null;          // fresh geometry, fresh budget
  }

  // Never transform: it is what made the text blurry. The wrapper stays a plain
  // block so the terminal's own box is its real size and scrolling just works.
  if (rec.scaleEl.style.transform) rec.scaleEl.style.transform = '';

  if (!rec.wRatio && !measureMetrics(rec)) return;

  const fs = targetFont(rec);
  if (fs == null) return;

  if (Math.abs((rec.appliedFont || 0) - fs) >= FONT_STEP / 2) {
    const tried = rec.fitTried || (rec.fitTried = new Set());
    tried.add(fs);
    rec.appliedFont = fs;
    try { rec.term.options.fontSize = fs; } catch (_) { return; }

    // xterm re-renders ASYNCHRONOUSLY, so everything derived from the new size has to
    // be redone on the next frame — including the scroll decision, which was
    // previously made against pre-render geometry and never revisited.
    requestAnimationFrame(() => {
      if (rec.disposed || !measureMetrics(rec)) return;
      const refined = targetFont(rec);
      const nextPass = (pass || 0) + 1;
      if (refined != null
          && Math.abs(refined - fs) >= FONT_STEP / 2
          && nextPass < FIT_MAX_PASSES
          && !tried.has(refined)) {
        applyFit(rec, nextPass);
        return;
      }
      // Settled: either the target agrees, the budget is spent, or the next step
      // would revisit a size already tried (an oscillation — keep what is applied,
      // since the overflow state below makes either choice safe to display).
      rec.fitTried = null;
      applyContentHeight(rec);
      updateOverflowState(rec, fs);
      updateFitNote(rec);
    });
  }

  applyContentHeight(rec);
  updateOverflowState(rec, fs);
  updateFitNote(rec);
}

// Decide whether this cell must scroll, from the geometry as it stands now.
//
// Scroll only when something is genuinely out of view: a permanently scrollable host
// shows a scrollbar that steals width and then causes the very overflow it was meant
// to reveal.
function updateOverflowState(rec, fs) {
  const host = rec.termHost;
  if (!host) return;
  const compact = els.rowH.value === 'fitcontent';
  const natW = rec.cols * rec.wRatio * fs;
  const natH = rec.rows * rec.hRatio * fs;

  const overflowX = natW > host.clientWidth + 1;
  // In 'fit content' the cell is sized to the rows that HAVE content, so the blank
  // remainder of the grid hangs below it by design. Those rows are empty, so
  // clipping them is correct and offering a scrollbar through blank space is not.
  const overflowY = !compact && natH > host.clientHeight + 1;

  host.classList.toggle('scrolls', overflowX || overflowY);
  rec.fit = { fs, natW, natH, overflowX, overflowY, compact };
}

// Say what the operator is looking at. A cell showing 40% of a pane looks identical
// to an idle agent otherwise.
function updateFitNote(rec) {
  const note = rec.headEls && rec.headEls.fit;
  if (!note) return;
  const fit = rec.fit;
  if (!fit || rec.minimized) { note.textContent = ''; note.className = 'cell-fit'; return; }

  const host = rec.termHost;
  const bits = [`${fit.fs}px`];
  let clipped = false;
  if (fit.overflowX) {
    const shown = Math.max(1, Math.floor((host.clientWidth - GUTTER_W)
                                         / (rec.wRatio * fit.fs)));
    bits.push(`${Math.min(shown, rec.cols)}/${rec.cols} cols`);
    clipped = true;
  }
  if (fit.overflowY) {
    const shown = Math.max(1, Math.floor((host.clientHeight - GUTTER_H)
                                         / (rec.hRatio * fit.fs)));
    bits.push(`${Math.min(shown, rec.rows)}/${rec.rows} rows`);
    clipped = true;
  }
  note.textContent = bits.join(' · ');
  note.className = clipped ? 'cell-fit clipped' : 'cell-fit';
  note.title = clipped
    ? `Text is at the ${fontBounds().floor}px legibility floor, so the pane does not `
      + `fit — scroll the cell, or use fewer columns / focus (⤢) to see all of it.`
    : `Auto-fitted to ${fit.fs}px; the whole ${rec.cols}x${rec.rows} pane is visible.`;
}

// Kept as the name the rest of the file calls; fitting replaced scaling.
function applyScale(rec) {
  applyFit(rec);
}

// FOLLOW HAS TO PIN WHATEVER IS ACTUALLY SCROLLING.
//
// There are two scroll contexts per pane and they are mutually exclusive:
//
//   * xterm's own viewport, when the pane fits and xterm is clipping scrollback;
//   * the HOST element, when updateOverflowState has set `.scrolls` because the pane
//     is too large to fit at the legibility floor. xterm's viewport is then full
//     height, so term.scrollToBottom() has nothing to scroll and silently does
//     nothing - which is precisely the case where a pane is big enough to need follow.
//
// The old code only ever did the first. Both are pinned here, because which one
// applies changes as the window resizes under the reader.
function followPane(rec) {
  if (!rec || rec.disposed || rec.minimized) return;
  try { rec.term.scrollToBottom(); } catch (_) {}
  const host = rec.termHost;
  if (host && host.scrollHeight > host.clientHeight) host.scrollTop = host.scrollHeight;
}

function followAll() {
  if (!els.follow || !els.follow.checked) return;
  panes.forEach(followPane);
}

// A re-fit changes the element's height, which moves the host's scroll offset - so a
// followed pane has to be re-pinned AFTER the fit settles, not before it starts.
function followAfterFit(rec) {
  if (!els.follow || !els.follow.checked) return;
  requestAnimationFrame(() => requestAnimationFrame(() => followPane(rec)));
}

// Render the bound Jira issue. The key is re-validated here even though the
// backend validated it on spawn: this builds an href, and a key from a text file
// must never be trusted to be URL-safe. Label uses textContent, so a hostile key
// cannot inject markup either.
const ISSUE_KEY = /^[A-Z][A-Z0-9_]+-[0-9]+$/;

function applyTaskBadge(rec) {
  const el = rec.headEls.task;
  const key = rec.taskKey;
  if (!key || !ISSUE_KEY.test(key)) {
    el.replaceChildren();
    el.className = '';
    return;
  }
  const base = (els.jiraBase.value || '').trim().replace(/\/+$/, '');
  el.replaceChildren();
  if (/^https:\/\/[^\s/]+$/.test(base)) {
    const a = document.createElement('a');
    a.className = 'task-badge';
    a.href = `${base}/browse/${encodeURIComponent(key)}`;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = key;
    a.title = `Open ${key} in Jira`;
    el.appendChild(a);
  } else {
    const sp = document.createElement('span');
    sp.className = 'task-badge';
    sp.textContent = key;
    sp.title = 'Set the Jira base URL in the ribbon to make this a link';
    el.appendChild(sp);
  }
}

function updateCellHead(rec, agent) {
  rec.taskKey = (agent.task === null || agent.task === undefined) ? '' : String(agent.task).trim();
  applyTaskBadge(rec);
  const st = stateClass(agent.state);
  const pc = permClass(agent.perms);
  rec.headEls.st.className = `dot ${st}`;
  rec.headEls.st.title = st === 'stale' ? 'In run/ but no live tmux session' : `session ${st}`;
  rec.headEls.cli.textContent = orDash(agent.cli);
  rec.isTui = String(agent.cli || '').trim() !== 'shell';
  rec.headEls.up.textContent = fmtUptime(agent.uptime_seconds);
  rec.headEls.perm.className = `perm ${pc}`;
  rec.headEls.perm.textContent = pc === 'unknown' ? '—' : String(agent.perms);
  if (pc === 'unrestricted') {
    rec.headEls.perm.title = 'Runs with the provider permission bypass — full access';
  }
  rec.cell.classList.toggle('stale', st === 'stale');
  rec.cell.classList.toggle('unrestricted', pc === 'unrestricted');
}

// ---------------------------------------------------------------- streaming ---

// ════════════════════════════════════════════════════ one shared SSE stream ════
//
// WHY ONE CONNECTION FOR EVERY PANE.
//
// A browser allows only about six concurrent HTTP/1.1 connections per host — six in
// Firefox by default — and an SSE stream holds one open for as long as it lives. With
// seven panes the seventh could never connect, so two panes traded places roughly once a
// second, each reading "disconnected — retrying" half the time. Measured: the two
// alternated perfectly complementarily, and closing one pane's stream only moved the
// problem to whichever pane reconnected last. No server tuning fixes it; the limit is in
// the browser.
//
// So the backend multiplexes every agent over /api/stream-all and tags each frame with
// its agent name. One connection, no ceiling on pane count, and the slot bookkeeping
// becomes trivial.
let sharedSource = null;
let sharedRetryMs = 500;
let sharedRetryTimer = null;

function routeFrame(event, apply) {
  let payload;
  try { payload = JSON.parse(event.data); } catch (_) { return; }
  const rec = panes.get(payload && payload.agent);
  // userClosed means the operator pressed × on that pane: keep ignoring its frames
  // rather than tearing down a connection every other pane is using.
  if (!rec || rec.disposed || rec.userClosed || !payload.b64) return;
  try { apply(rec, b64ToBytes(payload.b64)); } catch (_) {}
}

function closeSharedStream() {
  if (sharedSource) { try { sharedSource.close(); } catch (_) {} sharedSource = null; }
  if (sharedRetryTimer) { clearTimeout(sharedRetryTimer); sharedRetryTimer = null; }
}

// `force` reconnects even if a stream is already open — that is how a re-snapshot is
// requested (the ⟳ button, or a geometry change), since the server only sends a snapshot
// when it first sees an agent on a connection.
function ensureSharedStream(force) {
  if (!force && sharedSource && sharedSource.readyState !== 2) return;
  closeSharedStream();
  let src;
  try {
    src = new EventSource(`api/stream-all?tail=${TAIL_BYTES}`);
  } catch (err) {
    panes.forEach((rec) => setStatus(rec, `stream unavailable: ${err.message}`, 'err'));
    return;
  }
  sharedSource = src;

  src.onopen = () => {
    sharedRetryMs = 500;
    panes.forEach((rec) => {
      rec.source = src;            // every pane is served by this one connection
      rec.streamEnded = false;
      if (!rec.userClosed) setStatus(rec, 'streaming', '');
    });
  };

  src.addEventListener('snapshot', (event) => routeFrame(event, (rec, bytes) => {
    rec.term.reset();
    rec.term.write(bytes);
    setStatus(rec, 'streaming', '');
    // reset() + a re-fit both drop the host to the top, so re-pin after it settles.
    requestAnimationFrame(() => { applyFit(rec); applyContentHeight(rec); followAfterFit(rec); });
  }));

  src.addEventListener('chunk', (event) => routeFrame(event, (rec, bytes) => {
    rec.term.write(bytes);
    if (els.follow.checked) followPane(rec);
    if (els.rowH.value === 'fitcontent') {
      if (rec.hTimer) clearTimeout(rec.hTimer);
      rec.hTimer = setTimeout(() => applyContentHeight(rec), 250);
    }
  }));

  src.addEventListener('gone', (event) => {
    let payload;
    try { payload = JSON.parse(event.data); } catch (_) { return; }
    const rec = panes.get(payload && payload.agent);
    if (rec) { rec.streamEnded = true; setStatus(rec, 'session ended', 'eof'); }
  });

  src.onerror = () => {
    closeSharedStream();
    sharedRetryMs = Math.min(sharedRetryMs * 2, MAX_RECONNECT_MS);
    const seconds = Math.round(sharedRetryMs / 1000);
    panes.forEach((rec) => {
      rec.source = null;
      if (!rec.userClosed) setStatus(rec, `disconnected — retrying in ${seconds}s`, 'err');
    });
    sharedRetryTimer = setTimeout(() => ensureSharedStream(true), sharedRetryMs);
  };
}

// Kept as the name the rest of the file calls. A per-pane "open" is now a request for a
// fresh snapshot of that pane, which means reconnecting the shared stream.
function openStream(rec, name) {
  if (rec.disposed) return;
  rec.streamEnded = false;
  rec.userClosed = false;
  ensureSharedStream(true);
}

// The single-agent endpoint is still served and still tested; this is the old client path,
// unused now but left intact so a single-pane consumer has something to follow.
function openSingleStream(rec, name) {
  if (rec.disposed) return;
  closeStream(rec);
  rec.streamEnded = false;

  let src;
  try {
    src = new EventSource(`api/stream/${encodeURIComponent(name)}?tail=${TAIL_BYTES}`);
  } catch (err) {
    setStatus(rec, `stream unavailable: ${err.message}`, 'err');
    return;
  }
  rec.source = src;

  src.onopen = () => { rec.retryMs = 500; setStatus(rec, 'streaming', ''); };

  // The backend sends the pane's CURRENT rendered screen as a framed snapshot
  // before any log bytes. A mid-stream byte tail cannot reconstruct
  // alternate-screen state, so this is what makes TUI agents render correctly.
  src.addEventListener('snapshot', (ev) => {
    if (!ev.data) return;
    try {
      rec.term.reset();
      rec.term.write(b64ToBytes(ev.data));
      setStatus(rec, 'streaming', '');
      requestAnimationFrame(() => { applyScale(rec); applyContentHeight(rec); followAfterFit(rec); });
    } catch (_) {}
  });

  src.onmessage = (ev) => {
    if (!ev.data) return;
    try { rec.term.write(b64ToBytes(ev.data)); } catch (_) {}
    if (els.follow.checked) followPane(rec);
    // Output changed, so the used-row count may have changed. Debounced because
    // a busy agent can emit many frames a second.
    if (els.rowH.value === 'fitcontent') {
      if (rec.hTimer) clearTimeout(rec.hTimer);
      rec.hTimer = setTimeout(() => applyContentHeight(rec), 250);
    }
  };

  // #1 FIX: eof marks the stream ended but NOT the pane dead. If a later poll
  // still shows this agent alive, syncAgents reopens. Previously this latched
  // rec.closed = true and the cell never recovered — which combined with the
  // backend's over-eager eof could kill a live pane permanently.
  src.addEventListener('eof', () => {
    setStatus(rec, 'stream ended — will reconnect if the agent is still live', 'eof');
    rec.streamEnded = true;
    closeStream(rec);
  });

  src.onerror = () => {
    if (rec.disposed) return;
    closeStream(rec);
    rec.retryMs = Math.min(rec.retryMs * 2, MAX_RECONNECT_MS);
    setStatus(rec, `disconnected — retrying in ${Math.round(rec.retryMs / 1000)}s`, 'err');
    rec.retryTimer = setTimeout(() => openSingleStream(rec, name), rec.retryMs);
  };
}

function closeStream(rec) {
  // Only detach THIS pane. rec.source is the shared connection every other pane is also
  // reading, so closing it here would blank the whole grid because one pane was dismissed.
  rec.source = null;
  if (rec.retryTimer) { clearTimeout(rec.retryTimer); rec.retryTimer = null; }
}

function setStatus(rec, text, kind) {
  rec.status.textContent = text;
  rec.status.className = `cell-status ${kind || ''}`.trim();
}

function destroyPane(name) {
  const rec = panes.get(name);
  if (!rec) return;
  rec.disposed = true;
  closeStream(rec);
  // Every pending timer holds a closure over this record. Leaving them to fire after
  // dispose() is how a torn-down pane resurrects a stream or writes to a dead terminal.
  for (const key of ['reflowTimer', 'syncTimer', 'hTimer', 'retryTimer']) {
    if (rec[key]) { clearTimeout(rec[key]); rec[key] = null; }
  }
  if (rec.ro) { try { rec.ro.disconnect(); } catch (_) {} }
  try { rec.term.dispose(); } catch (_) {}
  rec.cell.remove();
  panes.delete(name);
}

// --------------------------------------------------------- content sizing ---

// How many rows this terminal is REALLY using.
//
// For a line-oriented agent (a shell) that is cursor position + 1, so a pane
// showing three lines reports 3 and its cell can shrink. For a TUI on the
// alternate screen the whole grid is in use, so this returns the full height and
// the cell stays full size - which is the correct answer for both without
// special-casing either.
function usedRows(rec) {
  // A TUI paints its whole grid, so it always needs full height. The CLI name is
  // the reliable signal - codex/claude/grok are full-screen TUIs, `shell` is not,
  // and a buffer scan cannot distinguish them when the TUI is not on the
  // alternate screen (codex is not).
  if (rec.isTui) return rec.rows;
  try {
    const buf = rec.term.buffer.active;
    // capture-pane paints the WHOLE pane grid, blank lines included, so the
    // cursor is normally parked at the bottom of a full-height screen. Cursor
    // position is therefore useless here - scan back for real content instead.
    let last = 0;
    for (let i = 0; i < rec.rows; i++) {
      const line = buf.getLine(buf.baseY + i);
      if (line && line.translateToString(true).trim() !== '') last = i + 1;
    }
    return Math.max(2, Math.min(rec.rows, last + 1));
  } catch (_) {
    return rec.rows;
  }
}

// Height the cell needs for the rows in use, including its own chrome.
//
// Only 'fit content' mode sets a height. The row height is taken at the CURRENTLY
// APPLIED font size, which is why there is no longer a scale factor in here: the
// font is the single thing that determines size.
function applyContentHeight(rec) {
  // In free mode the height is the operator's, not the content's.
  if (freeMode()) return;
  if (els.rowH.value !== 'fitcontent' || rec.minimized) {
    rec.cell.style.height = '';
    return;
  }
  const rowH = liveCharH(rec);
  if (!rowH) return;
  const chrome = (rec.headEl ? rec.headEl.offsetHeight : 26)
               + (rec.status ? rec.status.offsetHeight : 20) + 8;
  const h = Math.round(usedRows(rec) * rowH) + chrome;
  rec.cell.style.height = `${Math.max(56, h)}px`;
}

// Per-row pixel height at the font size in force. Derived from the stored ratio
// rather than read from the DOM, because reading offsetHeight forces layout and this
// runs on every stream frame.
function liveCharH(rec) {
  if (rec.hRatio && rec.appliedFont) return rec.hRatio * rec.appliedFont;
  return rec.charH || 0;
}

// ------------------------------------------------- pane size <- cell size ---

// Ask the backend to resize the AGENT's tmux pane to whatever fits this cell.
// Opt-in: it writes to the agent, and it changes what agentmux read/capture-pane
// returns for that pane (audit D26). Debounced, and never fired for a size we
// already requested.
function maybeSyncPaneSize(rec) {
  if (!rec.name) return;

  // Size the pane against a FIXED reference font — the cap — not against the font
  // currently fitted.
  //
  // rec.charW moves with the fitted font, and the fitted font is chosen to make the
  // pane's columns fit the cell. Feeding one into the other closes the loop: the font
  // shrinks to fit the columns, so more columns are requested, so the font shrinks
  // again. That is exactly what drove 182 -> 97 -> 64 columns in testing, the same
  // ratchet as the original 182x40 -> 180x39 -> 178x37.
  //
  // Against the cap the loop has a fixed point: ask for the columns that fit at the
  // most comfortable size, and the fit then chooses that size, and nothing moves.
  if (!rec.wRatio || !rec.hRatio) return;          // metrics not measured yet
  const charW = rec.wRatio * fontBounds().cap;
  const charH = rec.hRatio * fontBounds().cap;
  if (!charW || !charH) return;

  // Key off the CELL width only. Anything derived from the pane's post-resize
  // state is a feedback path, and every feedback path here ratcheted.
  const cellW = rec.termHost.clientWidth;
  if (!cellW) return;
  if (rec.lastCellW && Math.abs(cellW - rec.lastCellW) < 8) return;  // cell did not really move
  rec.lastCellW = cellW;

  const wantCols = Math.max(20, Math.min(400, Math.floor((cellW - 8) / charW)));

  // ROWS ARE DELIBERATELY NOT SYNCED.
  //
  // Driving rows from cell height is circular once 'fit content' is on: cell
  // height comes from content, content height comes from pane rows, pane rows
  // would come from cell height. That loop oscillated to 51x199 in testing.
  // Width has no such dependency - a cell's width never depends on how many rows
  // the agent wrote - so columns sync safely and rows stay put.
  // tmux resize-window -y N yields a pane of N-1 rows when a status line is
  // present, so asking for exactly rec.rows shrinks it by one every call. That
  // was the 40 -> 39 -> 37 drift. Ask for one more to hold the current height.
  const wantRows = Math.min(200, rec.rows + 1);

  // Validate before sending. rec.rows can be stale or unset (a poll that reported
  // null geometry, or a cell measured before its first /api/agents result), and
  // NaN/undefined serialises to JSON null, which the backend correctly rejects
  // with 400. Skipping quietly is right here - this is an optional convenience,
  // not something worth showing the user an error for.
  if (!Number.isInteger(wantCols) || wantCols < 20  || wantCols > 400) return;
  if (!Number.isInteger(wantRows) || wantRows < 5   || wantRows > 200) return;

  const key = `${wantCols}x${wantRows}`;
  if (rec.lastSyncKey === key) return;
  rec.lastSyncKey = key;

  if (rec.syncTimer) clearTimeout(rec.syncTimer);
  rec.syncTimer = setTimeout(async () => {
    try {
      const res = await fetch(`api/resize/${encodeURIComponent(rec.name)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },   // forces a CORS preflight cross-origin
        body: JSON.stringify({ cols: wantCols, rows: wantRows }),
      });
      if (!res.ok) {
        setStatus(rec, `pane resize refused (HTTP ${res.status})`, 'err');
        return;
      }
      // The next /api/agents poll reports the new geometry and syncAgents calls
      // term.resize(), so we do not resize locally here.
    } catch (err) {
      setStatus(rec, `pane resize failed: ${err.message}`, 'err');
    }
  }, 450);
}

// ------------------------------------------------------------------- focus ---

let focused = null;

function setFocus(name) {
  focused = (focused === name) ? null : name;
  applyFocus();
}

function applyFocus() {
  const on = focused !== null && panes.has(focused);
  if (!on) focused = null;
  els.grid.classList.toggle('focusing', on);
  panes.forEach((rec, name) => {
    rec.cell.classList.toggle('focused', on && name === focused);
    rec.zBtn.textContent = (on && name === focused) ? '⤡' : '⤢';
  });
  relayout();
  requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
}

// ------------------------------------------------------------------ layout ---

// The widest column count at which a WHOLE pane still fits at or above the
// legibility floor. The old rule was a hardcoded cap of 2, which was right for
// 200-column panes on a 1500px screen and wrong everywhere else — a narrow pane or a
// wide monitor can take more, and a very narrow window cannot even take two.
const GRID_GAP = 9;        // keep in step with .grid { gap } in style.css
const GRID_PAD = 24;       // .grid horizontal padding

function autoCols(paneCount) {
  if (paneCount <= 1) return 1;
  const gridW = els.grid.clientWidth || 0;
  // Widest pane wins: a layout that fits the average but clips the widest is not
  // "fits". Fall back to the conventional 200 before any pane has been measured.
  let paneCols = 0, wRatio = 0;
  for (const rec of panes.values()) {
    if (rec.cols > paneCols) paneCols = rec.cols;
    if (rec.wRatio && rec.wRatio > wRatio) wRatio = rec.wRatio;
  }
  if (!gridW || !paneCols || !wRatio) return Math.min(2, paneCount);

  const needed = paneCols * wRatio * fontBounds().floor;   // px for one whole pane
  let best = 1;
  for (let cols = 1; cols <= Math.min(paneCount, 12); cols++) {
    const cellW = (gridW - GRID_PAD - GRID_GAP * (cols - 1)) / cols;
    if (cellW - GUTTER_W >= needed) best = cols;
    else break;
  }
  return best;
}

// ══════════════════════════════════════════════════════════ free placement ════
//
// In 'free' mode the operator owns the arrangement. Panes are absolutely positioned
// from a stored rectangle, dragged by their header, sized by the bottom-right grip —
// and a window resize does NOT move them. Only the `sort` button rearranges.
//
// That is the whole point: a resize still keeps the TEXT readable (applyFit re-runs off
// each pane's own size), but it never reshuffles a layout you arranged by hand.
const PLACE_KEY = 'ccc.panePlacement';
const MIN_PANE_W = 240;
const MIN_PANE_H = MIN_USEFUL_CELL;
const CANVAS_PAD = 12;

// One shared, inert element marking the far corner of the placed panes.
const rec_spacer = (() => {
  const node = document.createElement('div');
  node.className = 'free-spacer';
  node.setAttribute('aria-hidden', 'true');
  return node;
})();

function freeMode() {
  return els.layout.value === 'free' && focused === null;
}

function loadPlacements() {
  try {
    const parsed = JSON.parse(localStorage.getItem(PLACE_KEY) || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (_) { return {}; }
}

function savePlacements(map) {
  try { localStorage.setItem(PLACE_KEY, JSON.stringify(map)); } catch (_) {}
}

function placementOf(name) {
  const stored = loadPlacements()[name];
  if (!stored) return null;
  const { x, y, w, h } = stored;
  if (![x, y, w, h].every((v) => Number.isFinite(v))) return null;
  return { x: Math.max(0, x), y: Math.max(0, y),
           w: Math.max(MIN_PANE_W, w), h: Math.max(MIN_PANE_H, h) };
}

function setPlacement(name, box) {
  const map = loadPlacements();
  map[name] = { x: Math.round(box.x), y: Math.round(box.y),
                w: Math.round(box.w), h: Math.round(box.h) };
  savePlacements(map);
}

// A rectangle for a pane that has never been placed. Tiles into the next free slot
// rather than stacking everything at the origin.
function defaultPlacement(index) {
  const perRow = Math.max(1, Math.floor((els.grid.clientWidth - CANVAS_PAD)
                                        / (MIN_PANE_W + 130 + CANVAS_PAD)) || 1);
  const width = Math.max(MIN_PANE_W,
                         Math.floor((els.grid.clientWidth - CANVAS_PAD * (perRow + 1)) / perRow));
  const height = Math.max(MIN_PANE_H, Math.round(width * 0.52));
  const column = index % perRow, row = Math.floor(index / perRow);
  return { x: CANVAS_PAD + column * (width + CANVAS_PAD),
           y: CANVAS_PAD + row * (height + CANVAS_PAD), w: width, h: height };
}

// Write the stored rectangles onto the cells. Never invents a new position for a pane
// that already has one — that would be the auto-rearranging this mode exists to avoid.
function applyFreeLayout() {
  let index = 0, maxRight = 0, maxBottom = 0;
  for (const [name, rec] of panes) {
    let box = placementOf(name);
    if (!box) {
      box = defaultPlacement(index);
      setPlacement(name, box);
    }
    index += 1;
    rec.cell.style.left = `${box.x}px`;
    rec.cell.style.top = `${box.y}px`;
    rec.cell.style.width = `${box.w}px`;
    rec.cell.style.height = rec.minimized ? '' : `${box.h}px`;
    maxRight = Math.max(maxRight, box.x + box.w);
    maxBottom = Math.max(maxBottom, box.y + box.h);
  }
  // Reachability is handled by a SPACER, not by min-width on the grid itself.
  //
  // Setting min-width on the scrolling element makes its own box that wide, which
  // defeats its `overflow: auto` — the content then overflows an ancestor that clips,
  // and a pane parked past the edge becomes unreachable. Measured: a 1452px canvas
  // reported clientWidth 1452 inside a 900px window, so it was not scrolling at all.
  //
  // `.grid.free` is position: relative, so an absolutely positioned child does extend
  // the scrollable area. A zero-height spacer at the far corner is enough, and it keeps
  // the grid free to size itself to the viewport and scroll properly.
  if (!rec_spacer.parentNode) els.grid.appendChild(rec_spacer);
  rec_spacer.style.left = `${maxRight + CANVAS_PAD}px`;
  rec_spacer.style.top = `${maxBottom + CANVAS_PAD}px`;
}


function clearFreeLayout() {
  if (rec_spacer.parentNode) rec_spacer.remove();
  panes.forEach((rec) => {
    for (const property of ['left', 'top', 'width']) rec.cell.style.removeProperty(property);
    if (els.rowH.value !== 'fitcontent') rec.cell.style.removeProperty('height');
  });
}

// The ONLY automatic rearrangement in free mode, and it happens because the operator
// asked for it. Tidies panes into a grid in the current display order.
function sortPanes() {
  if (!panes.size) return;
  if (els.layout.value !== 'free') {
    // In a grid mode the browser already arranges them; drop any stale free-mode
    // rectangles so switching to free later starts from a tidy state.
    savePlacements({});
    relayout();
    setStatusNote('sorted — grid modes arrange themselves');
    return;
  }
  const names = [...panes.keys()];
  const map = {};
  names.forEach((name, index) => { map[name] = defaultPlacement(index); });
  savePlacements(map);
  applyFreeLayout();
  requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
  setStatusNote(`sorted ${names.length} pane${names.length === 1 ? '' : 's'}`);
}

function setStatusNote(text) {
  els.copyNote.textContent = text;
  setTimeout(() => {
    if (els.copyNote.textContent === text) els.copyNote.textContent = '';
  }, 2600);
}

// Drag to move (by the header) and the grip to size. Pointer events, so mouse, pen and
// touch all work, and setPointerCapture keeps the gesture alive outside the element.
function makeDraggable(rec, name) {
  const start = { x: 0, y: 0, box: null, mode: null };

  const begin = (event, mode) => {
    if (!freeMode() || event.button !== 0) return;
    // A click on a header button is not a drag.
    if (mode === 'move' && event.target.closest('.cbtn, a')) return;
    const box = placementOf(name) || {
      x: rec.cell.offsetLeft, y: rec.cell.offsetTop,
      w: rec.cell.offsetWidth, h: rec.cell.offsetHeight };
    start.x = event.clientX; start.y = event.clientY;
    start.box = box; start.mode = mode;
    rec.cell.classList.add('dragging');
    event.preventDefault();
    event.target.setPointerCapture(event.pointerId);
  };

  const move = (event) => {
    if (!start.mode) return;
    const dx = event.clientX - start.x, dy = event.clientY - start.y;
    const box = start.mode === 'move'
      ? { x: Math.max(0, start.box.x + dx), y: Math.max(0, start.box.y + dy),
          w: start.box.w, h: start.box.h }
      : { x: start.box.x, y: start.box.y,
          w: Math.max(MIN_PANE_W, start.box.w + dx),
          h: Math.max(MIN_PANE_H, start.box.h + dy) };
    rec.cell.style.left = `${box.x}px`;
    rec.cell.style.top = `${box.y}px`;
    rec.cell.style.width = `${box.w}px`;
    rec.cell.style.height = `${box.h}px`;
    start.live = box;
  };

  const end = () => {
    if (!start.mode) return;
    const box = start.live || start.box;
    start.mode = null; start.live = null;
    rec.cell.classList.remove('dragging');
    setPlacement(name, box);
    applyFreeLayout();                  // re-grow the canvas around the new position
    requestAnimationFrame(() => applyFit(rec));   // a resized pane re-fits its text
  };

  rec.headEl.addEventListener('pointerdown', (e) => begin(e, 'move'));
  rec.grip.addEventListener('pointerdown', (e) => begin(e, 'size'));
  for (const target of [rec.headEl, rec.grip]) {
    target.addEventListener('pointermove', move);
    target.addEventListener('pointerup', end);
    target.addEventListener('pointercancel', end);
  }
}

function relayout() {
  // In focus mode a single cell owns the grid.
  if (focused !== null && panes.has(focused)) {
    els.grid.classList.remove('free');
    clearFreeLayout();
    els.grid.style.setProperty('--cols', '1');
    requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
    return;
  }

  if (freeMode()) {
    // Positions are the operator's. Apply what is stored and re-fit the text; do not
    // compute a column count and do not move anything.
    els.grid.classList.add('free');
    applyFreeLayout();
    requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
    return;
  }

  els.grid.classList.remove('free');
  clearFreeLayout();
  const n = panes.size;
  const mode = els.layout.value;
  const cols = mode === 'auto' ? autoCols(n)
                               : Math.max(1, Math.min(12, parseInt(mode, 10) || 1));
  els.grid.style.setProperty('--cols', String(cols));
  requestAnimationFrame(() => panes.forEach((rec) => applyFit(rec)));
}

// ── which agents are alive, and getting from a row to its pane ───────────────
//
// THE PROBLEM THIS SOLVES. Every view in this dashboard names agents - the board
// assigns tasks to them, chatter is between them, the journal and the queue are
// written by them - and none of it said which of those names is a process running
// right now. A board showing `netcap-dev` looks identical whether that agent is
// mid-edit or was torn down an hour ago, and finding its pane meant reading the
// name, switching to Terminals and hunting for it by eye.
//
// So: ONE roster, refreshed by the poll that already fetches it, and one marking
// pass that decorates anything carrying a data-agent attribute. A renderer opts in
// by tagging an element with the agent's name; it does not have to know whether
// that agent is live, subscribe to anything, or re-render when the answer changes.
//
// The marking is DECOUPLED FROM RENDERING on purpose. Views poll at their own
// intervals (the board not at all), so tying "is it live" to a re-render would mean
// a task showing a dead agent as running until something unrelated redrew it. The
// pass walks the DOM instead, so an agent dying updates every view that is on
// screen within one tick.
const liveAgents = new Map();          // name -> agent record from /api/agents

function isLiveAgent(name) {
  return typeof name === 'string' && liveAgents.has(name);
}

// Jump to the pane serving this agent. Sets focus rather than toggling it: arriving
// from a board card, "focus" is an instruction, not a switch whose previous position
// the operator is tracking.
function focusAgent(name) {
  if (!isLiveAgent(name)) return false;
  showView('terminals');
  focused = name;
  applyFocus();
  const rec = panes.get(name);
  if (rec && rec.cell) {
    requestAnimationFrame(() => {
      rec.cell.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      rec.cell.classList.add('just-focused');
      setTimeout(() => rec.cell.classList.remove('just-focused'), 1200);
    });
  }
  return true;
}

// Tag an element as belonging to an agent. `refreshLiveMarks` does the rest.
function markAgent(node, name) {
  if (!node || typeof name !== 'string' || !name) return node;
  node.dataset.agent = name;
  return node;
}

// Walk everything tagged with data-agent and bring it into line with the roster.
// Cheap: an attribute selector over the document, only the classes that actually
// changed are touched, and the click handler is attached once per element.
function refreshLiveMarks(root = document) {
  for (const node of root.querySelectorAll('[data-agent]')) {
    const name = node.dataset.agent;
    const live = isLiveAgent(name);
    if (node.classList.contains('is-live') === live) {
      if (!live) continue;                      // nothing to do, still dead
    }
    node.classList.toggle('is-live', live);
    if (!live) {
      node.removeAttribute('title');
      node.removeAttribute('role');
      node.removeAttribute('tabindex');
      continue;
    }
    const agent = liveAgents.get(name);
    const task = agent && agent.task ? ` · ${agent.task}` : '';
    node.title = `${name} is running (${agent && agent.cli || '?'}${task}) — click to open its pane`;
    node.setAttribute('role', 'button');
    node.tabIndex = 0;
  }
  if (!refreshLiveMarks.wired) {
    refreshLiveMarks.wired = true;
    // ONE delegated listener on the document rather than one per row. These lists
    // are rebuilt wholesale on every poll, so per-element handlers would be
    // re-attached hundreds of times an hour and leak with the nodes they were on.
    const activate = (ev) => {
      const node = ev.target.closest('[data-agent].is-live');
      if (!node) return;
      if (ev.type === 'keydown' && ev.key !== 'Enter' && ev.key !== ' ') return;
      ev.preventDefault();
      ev.stopPropagation();
      focusAgent(node.dataset.agent);
    };
    document.addEventListener('click', activate, true);
    document.addEventListener('keydown', activate, true);
  }
}

function syncAgents(agents) {
  // The roster first: everything that decorates a view reads this, and a board
  // rendered a moment later must not be marked against a stale one.
  //
  // `stale` means the sidecars are there but the tmux session is not, so those
  // names are deliberately NOT in the roster - a row that offers to open a pane
  // which no longer exists is worse than one that offers nothing.
  const rostered = new Set();
  for (const agent of agents) {
    if (agent && typeof agent.name === 'string' && agent.name
        && agent.state !== 'stale') {
      liveAgents.set(agent.name, agent);
      rostered.add(agent.name);
    }
  }
  for (const name of [...liveAgents.keys()]) {
    if (!rostered.has(name)) liveAgents.delete(name);
  }
  refreshLiveMarks();

  const list = agents.slice();
  const seen = new Set();

  list.sort((a, b) => {
    const as = a.state === 'stale' ? 1 : 0, bs = b.state === 'stale' ? 1 : 0;
    if (as !== bs) return as - bs;
    return String(a.name || '').localeCompare(String(b.name || ''));
  });

  let structureChanged = false;

  for (const agent of list) {
    const name = String(agent.name || '');
    if (!name) continue;
    seen.add(name);
    const live = stateClass(agent.state) !== 'stale';

    let rec = panes.get(name);
    if (!rec) {
      rec = buildCell(agent);
      panes.set(name, rec);
      els.grid.appendChild(rec.cell);
      structureChanged = true;
      // #3 FIX: only stream for a live agent. A stale one has no log to follow,
      // so opening would 404 and retry forever.
      if (live) openStream(rec, name);
      else setStatus(rec, 'stale — no live session', 'eof');
    } else if (live && !rec.source && !rec.retryTimer && !rec.userClosed) {
      // #1 + #3 FIX: agent is live but we have no stream — either it just came
      // back from stale, or the server sent a premature eof. Reconnect.
      openStream(rec, name);
    } else if (!live && rec.source) {
      closeStream(rec);
      setStatus(rec, 'stale — no live session', 'eof');
    }
    // The pane was resized — by `sync pane size`, or because someone attached with a
    // different client. Follow it, and then RE-SNAPSHOT.
    //
    // Resizing alone is what produced the gapped, fragmented output: xterm reflows the
    // buffer it already holds, so text that tmux had wrapped at 200 columns gets
    // re-wrapped at 98, splitting lines and leaving orphaned tails ("ng to read",
    // "ine 08"). Those bytes cannot be re-wrapped correctly by anyone — the original
    // line breaks are gone.
    //
    // tmux's own screen is the authority, so throw the stale buffer away and ask the
    // backend for a fresh capture-pane at the new size. Debounced, because a drag with
    // sync enabled emits a burst of sizes and each re-snapshot is a stream restart.
    if (Number.isFinite(agent.cols) && Number.isFinite(agent.rows) &&
        agent.cols > 0 && agent.rows > 0 &&
        (agent.cols !== rec.cols || agent.rows !== rec.rows)) {
      try {
        rec.term.resize(agent.cols, agent.rows);
        rec.cols = agent.cols; rec.rows = agent.rows;
        // Metrics are per-1px-of-font ratios and a resize does not change the font, so
        // they stay valid. (Re-measuring here is what made the old estimate creep
        // 182 -> 180 -> 178 every round.)
        requestAnimationFrame(() => applyFit(rec));

        if (rec.reflowTimer) clearTimeout(rec.reflowTimer);
        rec.reflowTimer = setTimeout(() => {
          rec.reflowTimer = null;
          if (rec.disposed || rec.userClosed || !panes.has(name)) return;
          setStatus(rec, 'geometry changed — re-snapshotting', '');
          openStream(rec, name);      // reset() + a fresh capture-pane of the real screen
        }, 450);
      } catch (_) {}
    }
    updateCellHead(rec, agent);
  }

  for (const name of Array.from(panes.keys())) {
    if (!seen.has(name)) { destroyPane(name); structureChanged = true; }
  }

  // REORDER ONLY WHEN THE ORDER ACTUALLY CHANGED.
  //
  // This used to re-append every cell on every tick. appendChild on a node that is
  // ALREADY in the document does not copy it - it DETACHES and re-inserts it, and a
  // detached element loses the scroll offset of everything inside it. tick() runs at
  // POLL_MS, so that was every pane in the grid being torn out and put back three
  // times a second-and-a-bit, taking the reader's scroll position with it.
  //
  // That is the "it scrolls back to the top after a bit" report, and it is also why
  // follow looked unreliable: a pane pinned to the bottom was re-attached at zero a
  // moment later, so the next frame of output had to scroll it down again from the top.
  //
  // The sort only moves a cell when an agent goes stale, appears or disappears - rare.
  // So compare the desired order against what is in the DOM and touch nothing when
  // they already agree.
  const desired = list
    .map((a) => panes.get(String(a.name || '')))
    .filter(Boolean)
    .map((rec) => rec.cell);
  const current = Array.from(els.grid.children);
  const orderMatches = desired.length === current.length
    && desired.every((cell, i) => cell === current[i]);
  if (!orderMatches) {
    for (const cell of desired) els.grid.appendChild(cell);
  }

  const none = panes.size === 0;
  els.empty.hidden = !none;
  els.grid.hidden = none;
  els.count.textContent = none ? '' : `${panes.size} agent${panes.size === 1 ? '' : 's'}`;

  if (focused !== null && !panes.has(focused)) focused = null;
  if (structureChanged) { relayout(); applyFocus(); }
}

// -------------------------------------------------------------------- poll ---

// TWO KINDS OF BANNER, AND ONLY ONE OF THEM IS THE POLL'S TO CLEAR.
//
// The poll owns "cannot reach the backend", and clears it the moment it can. But
// some conditions are about the PAGE rather than the backend - a view script that
// never loaded, an xterm that is not there - and those do not stop being true
// because /api/agents answered. They used to be written to the same element, so
// the first successful poll wiped them: the operator saw the real explanation for
// half a second, at load, and then a page that looked fine and was not.
let stickyBanner = '';
const showBanner = (m) => { els.banner.textContent = m; els.banner.hidden = false; };
const clearBanner = () => {
  if (stickyBanner) { showBanner(stickyBanner); return; }
  els.banner.hidden = true;
  els.banner.textContent = '';
};
const holdBanner = (m) => { stickyBanner = m; showBanner(m); };

async function tick() {
  try {
    const res = await fetch('api/agents', { cache: 'no-store' });
    if (!res.ok) throw new Error(`backend returned HTTP ${res.status}`);
    const data = await res.json();
    if (!data || typeof data !== 'object') throw new Error('malformed response');

    // #6 FIX: a 200 carrying a bad payload must NOT be read as "zero agents",
    // which would destroy every terminal and its scrollback. Treat it as a
    // failed poll and leave the existing panes alone.
    if (!Array.isArray(data.agents)) throw new Error('response had no agents array');

    syncAgents(data.agents);

    const up = data.tmux_server === true;
    els.tmux.textContent = up ? 'tmux up' : 'tmux down';
    els.tmux.className = `pill ${up ? 'up' : ''}`.trim();

    const when = data.generated_at ? new Date(data.generated_at) : null;
    els.stamp.textContent = (when && !Number.isNaN(when.getTime()))
      ? `updated ${when.toLocaleTimeString()}` : 'updated';
    consecutiveFailures = 0;
    clearBanner();
  } catch (err) {
    consecutiveFailures += 1;
    els.stamp.textContent = `stale — ${consecutiveFailures} failed poll${consecutiveFailures === 1 ? '' : 's'}`;
    if (consecutiveFailures >= 2) {
      showBanner(`Cannot reach the backend (${err.message}). Is server.py still running on 127.0.0.1:8787?`);
    }
  }
}

// ---------------------------------------------------------------- resources ---
//
// Everything here is built with createElement/textContent. Resource names,
// check details and command strings all originate from resources.json and from
// CLI stdout, so none of it may be interpolated as HTML.
//
// Commands are DISPLAYED, never executed, and the backend never accepts a
// secret. Anything credentialed is tagged so it is obvious it must be run in a
// real terminal.

let resourcesLoaded = false;
let resourcesTimer = null;
let resourcesLoading = false;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function renderResources(data) {
  els.resList.replaceChildren();
  const list = Array.isArray(data && data.resources) ? data.resources : [];

  if (data && data.error) {
    els.resList.appendChild(el('p', 'empty', data.error));
    return;
  }
  if (!list.length) {
    els.resList.appendChild(el('p', 'empty', 'No resources declared in resources.json.'));
    return;
  }

  for (const r of list) {
    const state = ['ok', 'partial', 'missing'].includes(r.state) ? r.state : 'missing';
    const card = el('article', `res ${state}`);

    const title = el('div', 'res-title');
    title.appendChild(el('h3', null, r.name || r.id || '?'));
    if (r.kind) title.appendChild(el('span', 'res-kind', r.kind));
    const status = ['configured', 'unavailable', 'unknown'].includes(r.status) ? r.status : state;
    title.appendChild(el('span', `res-state ${state}`, status));
    card.appendChild(title);

    if (r.summary) card.appendChild(el('p', 'res-summary', r.summary));

    if (Array.isArray(r.checks) && r.checks.length) {
      const ul = el('ul', 'res-checks');
      for (const c of r.checks) {
        const li = el('li');
        const mark = c.ok ? 'ok' : (c.optional ? 'opt' : 'bad');
        li.appendChild(el('span', `chk ${mark}`, c.ok ? '✓' : (c.status === 'unknown' ? '?' : (c.optional ? '–' : '✗'))));
        li.appendChild(el('span', 'chk-label', c.label || c.id || ''));
        if (c.detail) {
          const d = el('span', 'chk-detail', c.detail);
          d.title = c.detail;              // title is text, not parsed
          li.appendChild(d);
        }
        if (c.version) li.appendChild(el('span', 'chk-detail', `version ${c.version}`));
        if (c.hint) li.appendChild(el('span', 'chk-detail', c.hint));
        ul.appendChild(li);
      }
      card.appendChild(ul);
    }

    if (Array.isArray(r.actions) && r.actions.length) {
      const wrap = el('div', 'res-actions');
      for (const a of r.actions) {
        if (!a.command) continue;
        const row = el('div', `act${a.secret ? ' secret' : ''}`);
        row.appendChild(el('span', 'act-label', a.label || a.id || ''));
        const cmd = el('code', 'act-cmd', a.command);
        cmd.title = a.note ? `${a.command}

${a.note}` : a.command;
        row.appendChild(cmd);
        if (a.secret) {
          const tag = el('span', 'act-secret-tag', 'your terminal');
          tag.title = 'Handles a credential. Run it yourself - this page never accepts secrets.';
          row.appendChild(tag);
        }
        const copy = el('button', 'btn', 'copy');
        copy.title = 'Copy this command';
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(a.command); copy.textContent = 'copied'; }
          catch (_) { copy.textContent = 'select it'; }
          setTimeout(() => { copy.textContent = 'copy'; }, 1500);
        });
        row.appendChild(copy);
        wrap.appendChild(row);
        if (a.note) wrap.appendChild(el('p', 'res-summary', a.note));
      }
      if (wrap.childElementCount) card.appendChild(wrap);
    }

    if (Array.isArray(r.notes) && r.notes.length) {
      const ul = el('ul', 'res-notes');
      for (const n of r.notes) ul.appendChild(el('li', null, n));
      card.appendChild(ul);
    }

    if (r.docs && /^https:\/\//.test(r.docs)) {
      const p = el('p', 'res-docs');
      const a = el('a', null, 'documentation');
      a.href = r.docs; a.target = '_blank'; a.rel = 'noopener noreferrer';
      p.appendChild(a);
      card.appendChild(p);
    }

    els.resList.appendChild(card);
  }
}

async function loadResources(force) {
  if (resourcesLoading) return;
  resourcesLoading = true;
  els.resStamp.textContent = force ? 're-running probes…' : 'loading resources…';
  els.resRefresh.disabled = true;
  try {
    const res = await fetch(`api/resources${force ? '?refresh=1' : ''}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.refreshing) {
      if (Array.isArray(data.resources) && data.resources.length) renderResources(data);
      else if (!els.resList.childElementCount) renderResources({error: 'Resource checks are running. Refresh shortly.'});
      els.resStamp.textContent = 'resource checks are running; displayed results may be cached';
      resourcesLoaded = false;
      return;
    }
    if (data.error) {
      if (!els.resList.childElementCount) renderResources(data);
      els.resStamp.textContent = `could not load resources: ${data.error}`;
      resourcesLoaded = false;
      return;
    }
    renderResources(data);
    const when = data.generated_at ? new Date(data.generated_at) : null;
    els.resStamp.textContent = (when && !Number.isNaN(when.getTime()))
      ? `probed ${when.toLocaleTimeString()}` : 'probed';
    resourcesLoaded = true;
  } catch (err) {
    resourcesLoaded = false;
    els.resStamp.textContent = `could not load resources: ${err.message}`;
  } finally {
    resourcesLoading = false;
    els.resRefresh.disabled = false;
  }
}

const VIEW_KEY = 'ccc.view';

// What each view needs loaded, and how often to refresh it while visible. A table
// rather than a switch, so a new view is one entry.
// WHY THERE IS NO keepScroll() HERE ANY MORE.
//
// There used to be a wrapper that snapshotted every scrollable element before a view
// loader ran and restored it afterwards, on the theory that the poll's
// replaceChildren() was collapsing each container and clamping scrollTop to 0.
//
// That theory was WRONG, and it was tested: run against the pre-fix build under three
// OBSERVED re-renders, the scroll held there too. The view is the scroll container and
// only an inner list is replaced, so the browser anchors it. The real cause of the
// reported reset was syncAgents() re-appending every pane cell on every tick - see the
// comment there.
//
// Worse, the wrapper caused a bug of its own. The loaders are async, so the restore
// fired whenever the fetch resolved - measured at 3.3 SECONDS after the click on a
// cold load - and by then the operator had scrolled somewhere deliberately. It then
// restored the offset from before the load and threw that away, with a stack reading
//     restoreScroll <- keepScroll <- showView
// A fix for a bug that did not exist, which created one that did. Removed rather than
// patched: the thing it was protecting against does not happen here.
//
// Scroll position across a VIEW SWITCH is handled by viewScroll in showView, which is
// the mechanism that actually helps and runs at a moment when nothing else is touching
// the element.

// ── the activity feed ────────────────────────────────────────────────────────
//
// One stream over the five places state used to live: the journal, the message queue,
// agent state, the resource probes and the courier's dead letters. A fault in any of
// them was previously only visible if you happened to be looking at that one view.
//
// FILTERING IS CLIENT-SIDE ON PURPOSE. The server always merges everything and this
// decides what to draw, so turning a source off is a display preference and not a
// change to what is recorded - two people on the same dashboard can watch different
// slices of the same truth, and nobody can hide a fault from anyone else by
// unticking a box.
const FEED_KEY = 'ccc.feed.v1';
const FEED_SOURCE_LABELS = {
  chatter:  'agent chatter',
  journal:  'journal',
  agent:    'agents',
  provider: 'systems & providers',
  fault:    'faults',
  run:      'runs',
};
const SEVERITY_RANK = { info: 0, warn: 1, error: 2 };

let feedPrefs = {
  sources: Object.keys(FEED_SOURCE_LABELS),
  severity: 'info',
  max: 500,
  poll: 5000,
  badge: true,
};
let feedEntries = [];          // newest first, as the server returns them
let feedSeen = 0;              // how many faults had been seen when the view was open
let feedTimer = null;

function loadFeedPrefs() {
  try {
    const raw = localStorage.getItem(FEED_KEY);
    if (raw) feedPrefs = { ...feedPrefs, ...JSON.parse(raw) };
  } catch (_) {}
  if (!Array.isArray(feedPrefs.sources)) feedPrefs.sources = Object.keys(FEED_SOURCE_LABELS);
  if (els.feedSeverity) els.feedSeverity.value = feedPrefs.severity;
  if (els.feedMax) els.feedMax.value = String(feedPrefs.max);
  if (els.feedPoll) els.feedPoll.value = String(feedPrefs.poll);
  if (els.feedBadge) els.feedBadge.checked = feedPrefs.badge !== false;
}

function saveFeedPrefs() {
  try { localStorage.setItem(FEED_KEY, JSON.stringify(feedPrefs)); } catch (_) {}
}

function feedPasses(entry) {
  if (!feedPrefs.sources.includes(entry.source)) return false;
  if ((SEVERITY_RANK[entry.severity] ?? 0) < (SEVERITY_RANK[feedPrefs.severity] ?? 0)) return false;
  const q = (els.feedSearch && els.feedSearch.value || '').trim().toLowerCase();
  if (!q) return true;
  return `${entry.who} ${entry.text} ${entry.ref} ${entry.source}`.toLowerCase().includes(q);
}

// Chips are built from the SERVER's source list, not a hardcoded one, so a source
// added server-side appears here without a second edit. smoke.sh:181 is the cautionary
// tale: a comment claiming to check the frontend list against the backend's, which
// then hardcoded it and compared the test to itself.
function renderFeedFilters(sources) {
  if (!els.feedFilters) return;
  els.feedFilters.replaceChildren();
  for (const src of sources) {
    const on = feedPrefs.sources.includes(src);
    const chip = el('button', `chip ${on ? 'on' : ''}`, FEED_SOURCE_LABELS[src] || src);
    chip.type = 'button';
    chip.setAttribute('aria-pressed', String(on));
    chip.title = on ? `Hide ${src}` : `Show ${src}`;
    chip.addEventListener('click', () => {
      feedPrefs.sources = on
        ? feedPrefs.sources.filter((x) => x !== src)
        : [...feedPrefs.sources, src];
      saveFeedPrefs();
      renderFeedFilters(sources);
      renderFeedSettings(sources);
      drawFeed();
    });
    els.feedFilters.appendChild(chip);
  }
}

function renderFeedSettings(sources) {
  if (!els.feedSources) return;
  els.feedSources.replaceChildren();
  for (const src of sources) {
    const label = el('label', 'toggle');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = feedPrefs.sources.includes(src);
    box.addEventListener('change', () => {
      feedPrefs.sources = box.checked
        ? [...new Set([...feedPrefs.sources, src])]
        : feedPrefs.sources.filter((x) => x !== src);
      saveFeedPrefs();
      renderFeedFilters(sources);
      drawFeed();
    });
    label.appendChild(box);
    label.appendChild(document.createTextNode(' ' + (FEED_SOURCE_LABELS[src] || src)));
    els.feedSources.appendChild(label);
  }
}

function drawFeed() {
  if (!els.feedList) return;
  const shown = feedEntries.filter(feedPasses).slice(0, feedPrefs.max);
  // Oldest at the top, so the newest line is at the BOTTOM where a follow makes sense
  // and where a terminal-shaped reader expects it.
  shown.reverse();

  publishRows('feed', shown);
  const view = els.views && els.views.status;
  const pinned = !els.feedFollow || els.feedFollow.checked
    || (view && view.scrollHeight - view.clientHeight - view.scrollTop <= 4);

  els.feedList.replaceChildren();
  if (!shown.length) {
    els.feedList.appendChild(el('p', 'empty',
      feedEntries.length ? 'Nothing matches the current filters.' : 'Nothing reported yet.'));
  }
  for (const e of shown) {
    // Feed can contain hundreds of events: default closed with a one-line preview.
    // The feed API has no ID; its immutable event tuple distinguishes same-time sources.
    const row = collapsible(`feed:${JSON.stringify([e.at, e.source, e.who, e.ref, e.text])}`,
      `feed-row ${e.severity}`, false);
    const head = el('summary', 'item-summary');
    head.appendChild(el('span', 'f-at', (e.at || '').slice(11, 19)));
    head.appendChild(el('span', `f-src ${e.source}`, e.source));
    head.appendChild(markAgent(el('span', 'f-who', e.who || '—'), e.who));
    head.appendChild(el('span', 'f-text item-preview', e.text));
    if (e.ref) {
      const ref = el('span', 'f-ref', e.ref);
      ref.title = `ref ${e.ref}`;
      head.appendChild(ref);
    }
    row.append(head, el('p', 'f-text item-body', e.text));
    row.title = `${e.at}  ${e.source}/${e.severity}`;
    els.feedList.appendChild(row);
  }
  // Only scroll when the FEED is the tab on screen. The feed also redraws from a
  // slow background poll so the fault badge keeps working while you are elsewhere,
  // and Status is one scroll container shared by four tabs - so an unguarded
  // follow yanked whatever you were reading in Journal to the bottom every 30s.
  refreshLiveMarks(els.feedList);
  if (pinned && view && panelVisible('status', 'feed')) {
    requestAnimationFrame(() => { view.scrollTop = view.scrollHeight; });
  }
  updateFeedBadge();
}

// Is that tab of that view actually on screen right now? The four Status tabs
// share one view, so "is the feed visible" stopped being a question about the
// current view the moment they were merged - and the badges, which exist to
// report what you are NOT looking at, are wrong if they get this wrong.
function panelVisible(view, name) {
  return currentView === view && !!VIEW_TABS[view] && VIEW_TABS[view].active === name;
}

// The badge counts faults the operator has NOT had on screen. Counting everything
// would make it a permanent red number that stops meaning anything.
function updateFeedBadge() {
  if (!els.badgeFeed) return;
  const faults = feedEntries.filter((e) => e.severity === 'error').length;
  const watching = panelVisible('status', 'feed');
  const unseen = watching ? 0 : Math.max(0, faults - feedSeen);
  if (watching) feedSeen = faults;
  const show = feedPrefs.badge !== false && unseen > 0;
  els.badgeFeed.hidden = !show;
  els.badgeFeed.textContent = show ? String(Math.min(unseen, 99)) : '';
  els.badgeFeed.title = show ? `${unseen} unseen fault(s)` : '';
}

async function loadFeed() {
  try {
    const data = await getJSON(`api/feed?limit=${encodeURIComponent(feedPrefs.max)}`);
    feedEntries = Array.isArray(data.entries) ? data.entries : [];
    const sources = Array.isArray(data.sources) && data.sources.length
      ? data.sources : Object.keys(FEED_SOURCE_LABELS);
    renderFeedFilters(sources);
    renderFeedSettings(sources);
    drawFeed();
    if (els.feedStamp) {
      const counts = feedEntries.reduce((a, e) => (a[e.severity] = (a[e.severity] || 0) + 1, a), {});
      els.feedStamp.textContent =
        `${feedEntries.length} line(s) — ${counts.error || 0} error, ${counts.warn || 0} warn`;
    }
  } catch (err) {
    if (els.feedStamp) els.feedStamp.textContent = `feed unavailable — ${err.message}`;
  }
}

const VIEW_LOADERS = {
  settings: () => { loadAuth(); loadAtlassianState(); if (!resourcesLoaded) loadResources(false); },
};
// The feed's interval is the operator's to set, so it is read from prefs at the
// moment the view opens rather than frozen in this table.
const VIEW_POLL_MS = { settings: 20000 };

// -- tabs within a view, and cards within a view ------------------------------
//
// THE RULE THAT MAKES THIS SAFE TO ADD TO. Only the VISIBLE thing polls. A hidden
// view runs no timer, and a tab that is not the active one runs no timer either -
// so opening Status starts one poller, not four. That is not a performance
// nicety: the MQTT and Modbus panels talk to real equipment, and a page that
// quietly keeps polling a PLC after you navigated away is a page that turns up in
// somebody's network capture and has to be explained.
//
// A view declares its tabs in the markup - data-tabs on the tablist, data-panel on
// each button naming its panel the same way a view names its section (`feed` ->
// `#viewFeed`). Nothing is hardcoded here, so adding a tab is markup plus one
// registerPanel call.
const VIEW_TABS = {};          // view -> { order, panels, active, list }
const VIEW_CARDS = {};         // view -> [{ loader, pollMs, timer }]
const TAB_KEY = 'ccc.tab.v1';

function panelNode(name) {
  return document.getElementById('view' + name[0].toUpperCase() + name.slice(1));
}

function savedTab(view) {
  try {
    const all = JSON.parse(localStorage.getItem(TAB_KEY) || '{}');
    return all && typeof all === 'object' ? all[view] : undefined;
  } catch (_) { return undefined; }
}

function rememberTab(view, panel) {
  try {
    const all = JSON.parse(localStorage.getItem(TAB_KEY) || '{}');
    const next = (all && typeof all === 'object' && !Array.isArray(all)) ? all : {};
    next[view] = panel;
    localStorage.setItem(TAB_KEY, JSON.stringify(next));
  } catch (_) {}
}

function collectTabs() {
  for (const list of document.querySelectorAll('[data-tabs]')) {
    const view = list.dataset.tabs;
    if (!els.views[view]) continue;
    const entry = VIEW_TABS[view] = { order: [], panels: {}, active: null, list };
    for (const button of list.querySelectorAll('.subtab[data-panel]')) {
      const name = button.dataset.panel;
      const node = panelNode(name);
      if (!node) continue;
      entry.order.push(name);
      entry.panels[name] = { button, node, loader: null, pollMs: 0, timer: null };
      button.addEventListener('click', () => showPanel(view, name));
      button.addEventListener('keydown', (ev) => {
        const step = ev.key === 'ArrowRight' ? 1 : ev.key === 'ArrowLeft' ? -1 : 0;
        if (!step) return;
        ev.preventDefault();
        const at = entry.order.indexOf(name);
        const next = entry.order[(at + step + entry.order.length) % entry.order.length];
        entry.panels[next].button.focus();
        showPanel(view, next);
      });
    }
    const remembered = savedTab(view);
    entry.active = entry.panels[remembered] ? remembered : entry.order[0] || null;
  }
}

// Tab loaders for the panels app.js owns. External scripts call registerPanel.
const BUILTIN_PANELS = {
  status: { feed: [loadFeed, 0], queue: [loadQueue, 5000], journal: [loadJournal, 0] },
  board:  { boardtasks: [loadBoard, 0], tickets: [loadTickets, 0] },
};

function applyBuiltinPanels() {
  for (const [view, panels] of Object.entries(BUILTIN_PANELS)) {
    for (const [name, [loader, pollMs]] of Object.entries(panels)) {
      const slot = VIEW_TABS[view] && VIEW_TABS[view].panels[name];
      if (slot) { slot.loader = loader; slot.pollMs = pollMs; }
    }
  }
}

// External panels use the same view<Name> convention as registerView. Validate
// before touching any registry so a bad registration cannot half-apply.
function registerPanel(view, name, loader, pollMs = 0) {
  if (!VIEW_TABS[view]) throw new Error('No tabbed view: ' + view);
  if (typeof name !== 'string' || !/^[a-z][a-z0-9]*$/.test(name)) {
    throw new TypeError('Invalid panel name');
  }
  const slot = VIEW_TABS[view].panels[name];
  if (!slot) throw new Error('Missing panel ' + name + ' in view ' + view);
  if (typeof loader !== 'function') throw new TypeError('Panel loader must be a function');
  if (!Number.isFinite(pollMs) || pollMs < 0) {
    throw new TypeError('Panel poll interval must be a non-negative number');
  }
  slot.loader = loader;
  slot.pollMs = pollMs;
}

// A card is a <details> panel inside a view that refreshes itself. Several scripts
// register cards on the SAME view - IIOT has five - so this appends rather than
// replaces, unlike registerView where one name means one loader.
function registerCard(view, loader, pollMs = 0) {
  if (!els.views[view]) throw new Error('No such view: ' + view);
  if (typeof loader !== 'function') throw new TypeError('Card loader must be a function');
  if (!Number.isFinite(pollMs) || pollMs < 0) {
    throw new TypeError('Card poll interval must be a non-negative number');
  }
  (VIEW_CARDS[view] = VIEW_CARDS[view] || []).push({ loader, pollMs, timer: null });
}

function stopCards(view) {
  for (const card of VIEW_CARDS[view] || []) {
    if (card.timer) { clearInterval(card.timer); card.timer = null; }
  }
}

function startCards(view) {
  for (const card of VIEW_CARDS[view] || []) {
    try { card.loader(); } catch (err) { console.error('card loader failed', err); }
    if (card.pollMs) card.timer = setInterval(card.loader, card.pollMs);
  }
}

function stopPanels(view) {
  const entry = VIEW_TABS[view];
  if (!entry) return;
  for (const slot of Object.values(entry.panels)) {
    if (slot.timer) { clearInterval(slot.timer); slot.timer = null; }
  }
}

function showPanel(view, name, options) {
  const load = !options || options.load !== false;
  const entry = VIEW_TABS[view];
  if (!entry || !entry.panels[name]) return;
  stopPanels(view);
  entry.active = name;
  for (const [id, slot] of Object.entries(entry.panels)) {
    const on = id === name;
    slot.node.hidden = !on;
    slot.button.classList.toggle('active', on);
    slot.button.setAttribute('aria-selected', String(on));
    slot.button.tabIndex = on ? 0 : -1;
  }
  rememberTab(view, name);
  const slot = entry.panels[name];
  if (load && slot.loader) {
    slot.loader();
    // The feed's interval belongs to the operator, so it is read now rather than
    // frozen at the moment the panel was registered.
    const every = name === 'feed' ? feedPrefs.poll : slot.pollMs;
    if (every) slot.timer = setInterval(slot.loader, every);
  }
  updateStatusExport();
}

// External views use the same view<Name> section convention as the built-in views.
// Validate before changing any registry so a bad registration cannot half-apply.
function registerView(name, loader, pollMs = 0) {
  if (typeof name !== 'string' || !/^[a-z][a-z0-9]*$/.test(name)) {
    throw new TypeError('Invalid view name');
  }
  const node = document.getElementById('view' + name[0].toUpperCase() + name.slice(1));
  if (!node) throw new Error('Missing section for view: ' + name);
  if (typeof loader !== 'function') throw new TypeError('View loader must be a function');
  if (!Number.isFinite(pollMs) || pollMs < 0) {
    throw new TypeError('View poll interval must be a non-negative number');
  }
  els.views[name] = node;
  VIEW_LOADERS[name] = loader;
  VIEW_POLL_MS[name] = pollMs;
}

let viewTimer = null;
let currentView = 'terminals';

// WHERE EACH VIEW WAS LEFT.
//
// Setting `hidden` takes an element out of layout, and the browser drops its
// scrollTop when that happens - so reading halfway down the journal, glancing at the
// board and coming back put you at the top with no way to get your place back. The
// views that do not poll (journal, board, tickets, iiot) have no other way to lose
// their position, so this is the whole of their half of the bug.
//
// Keyed by view id and held in memory only: a remembered offset into a list that has
// changed since is worse than none, and a reload legitimately starts at the top.
const viewScroll = new Map();

function showView(which) {
  if (!els.views[which]) which = 'terminals';
  const wasTerm = currentView === 'terminals';

  // Record where the OUTGOING view was before `hidden` discards it.
  const leaving = els.views[currentView];
  if (leaving && !leaving.hidden) viewScroll.set(currentView, leaving.scrollTop);

  currentView = which;
  const onTerm = which === 'terminals';

  for (const [id, node] of Object.entries(els.views)) {
    if (node) node.hidden = id !== which;
  }

  // Restore after layout. The element was display:none a moment ago, so it has no
  // scrollHeight yet and assigning scrollTop now would silently clamp to 0.
  //
  // TWO frames, and NO manual clamp. The first version did both wrong: one frame is
  // not enough for a grid to lay out, and clamping with
  //     Math.min(want, scrollHeight - clientHeight)
  // computes that bound against a box that has not been measured yet, so the bound is
  // 0 and the "restore" writes 0 - turning the fix into the bug it was meant to
  // repair. The browser already clamps an over-large scrollTop correctly once the
  // content is real, so let it.
  const entering = els.views[which];
  if (entering && viewScroll.has(which)) {
    const want = viewScroll.get(which);
    requestAnimationFrame(() => requestAnimationFrame(() => {
      if (entering.hidden || !want) return;
      entering.scrollTop = want;
    }));
  }
  for (const btn of els.navItems) {
    const on = btn.dataset.view === which;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-selected', String(on));
  }

  // The ribbon configures terminals (layout, font, spawn command); it is noise
  // everywhere else. Remember the operator's own collapse choice so switching
  // views does not silently un-collapse it.
  if (onTerm) {
    els.rToggle.disabled = false;
    if (els.ribbonWasOpen !== false) setRibbon(true);
  } else {
    if (wasTerm) els.ribbonWasOpen = !els.ribbon.hidden;
    els.ribbon.hidden = true;
    els.rToggle.disabled = true;
  }

  // Probes and polls spawn work, so only run them for the visible view. Every
  // timer this page owns is stopped here and restarted below for the one view
  // that is now on screen - tabs and cards included, which is why they are torn
  // down for EVERY view rather than only for the one being left.
  if (viewTimer) { clearInterval(viewTimer); viewTimer = null; }
  if (resourcesTimer && which !== 'settings') { clearInterval(resourcesTimer); resourcesTimer = null; }
  // EVERY view, the incoming one included. Clicking the nav button for the view you
  // are already on re-enters it, and without stopping its own timers first that
  // doubles them - one more poll against the same equipment per click, with nothing
  // on screen to show it is happening.
  for (const name of Object.keys(els.views)) {
    stopPanels(name);
    stopCards(name);
  }

  if (onTerm) {
    // Terminals were hidden, so their geometry is stale.
    requestAnimationFrame(() => { relayout(); panes.forEach((rec) => applyFit(rec)); });
  } else {
    const load = VIEW_LOADERS[which];
    if (load) load();
    const every = VIEW_POLL_MS[which];
    if (every) {
      if (which === 'settings') resourcesTimer = setInterval(() => loadResources(false), every);
      else if (load) viewTimer = setInterval(load, every);
    }
    // A tabbed view opens on the tab it was left on, and only that tab loads.
    const tabs = VIEW_TABS[which];
    if (tabs && tabs.active) showPanel(which, tabs.active);
    startCards(which);
  }
  updateStatusExport();

  try { localStorage.setItem(VIEW_KEY, which); } catch (_) {}
}

for (const btn of els.navItems) {
  btn.addEventListener('click', () => showView(btn.dataset.view));
}

// ═════════════════════════════════════════════════════════════════ themes ═════
//
// Themes are data (themes.json). Applying one writes its tokens onto
// documentElement.style, so there is no stylesheet swap and no flash. A theme
// must declare the full token set: a half-defined theme that silently inherits
// is harder to debug than one that fails visibly, so missing tokens are named.

const THEME_KEY = 'ccc.theme';
const IMPORTED_THEMES_KEY = 'ccc.importedThemes';
let builtInThemeIds = new Set();

// A token value must be a COLOUR, and only a colour.
//
// The first version of this allowed any of [#a-z0-9(), .%/-], reasoning that
// excluding ':' excluded URLs. It does not: `url(//example.com/pixel.png)` is
// protocol-relative, matches that class, and makes the browser fetch it the moment
// the token lands on a `background` property. themes.json is local data rather than
// request data, but the filter is the thing that is supposed to make it safe.
//
// So: an explicit shape per accepted colour form, and nothing else.
const COLOUR = new RegExp([
  '^#[0-9a-f]{3,8}$',                                      // #rgb .. #rrggbbaa
  '^(rgb|hsl)a?\\(\\s*[0-9a-f%.,\\s/-]+\\)$',              // rgb()/rgba()/hsl()/hsla()
  '^(color-mix|oklch|oklab|lab|lch)\\(\\s*[a-z0-9%.,\\s/()-]+\\)$',
  '^[a-z]{3,20}$',                                         // named colours, transparent
].join('|'), 'i');

function safeColour(value) {
  const text = String(value).trim();
  // Belt and braces: even if a form above ever admitted it, no fetching functions.
  if (/url\(|image\(|image-set\(|element\(|\/\/|@import|expression/i.test(text)) return null;
  return COLOUR.test(text) ? text : null;
}

let themeData = null;

function validateTheme(theme) {
  // A theme may only set tokens themes.json DECLARES. Otherwise a theme could set
  // --title-h or --nav-w and resize the chrome, which is layout, not theming.
  const declared = new Set(themeData.tokens || []);
  const rejected = [];
  const validated = [];
  for (const [token, value] of Object.entries(theme.tokens || {})) {
    const colour = declared.has(token) && typeof value === 'string' ? safeColour(value) : null;
    if (colour) {
      validated.push([token, colour]);
    } else {
      rejected.push(token);
    }
  }
  const missing = (themeData.tokens || []).filter((t) => !Object.prototype.hasOwnProperty.call(theme.tokens || {}, t));
  const problems = [
    missing.length ? `missing ${missing.join(', ')}` : '',
    rejected.length ? `rejected ${rejected.join(', ')}` : '',
  ].filter(Boolean);
  return { validated, problems };
}

function themeImportStatus(message, warn = false) {
  const status = document.getElementById('themeImportStatus');
  status.textContent = message;
  status.classList.toggle('warn', warn);
}

function parseImportedTheme(text) {
  const theme = JSON.parse(text);
  if (!theme || typeof theme !== 'object' || Array.isArray(theme)) {
    throw new Error('theme must be a JSON object');
  }
  const rejected = Object.keys(theme).filter(k => !['id', 'name', 'note', 'dark', 'tokens'].includes(k));
  if (typeof theme.id !== 'string' || !theme.id.trim()) rejected.push('id');
  for (const key of ['name', 'note']) {
    if (key in theme && typeof theme[key] !== 'string') rejected.push(key);
  }
  if (typeof theme.dark !== 'boolean') rejected.push('dark');
  if (!theme.tokens || typeof theme.tokens !== 'object' || Array.isArray(theme.tokens)) rejected.push('tokens');
  const problems = rejected.length ? [`rejected ${rejected.join(', ')}`] : [];
  if (theme.tokens && typeof theme.tokens === 'object' && !Array.isArray(theme.tokens)) {
    problems.push(...validateTheme(theme).problems);
  }
  if (problems.length) throw new Error(problems.join('; '));
  return theme;
}

function sameTheme(a, b) {
  return ['id', 'name', 'note', 'dark'].every(k => a[k] === b[k]) &&
    themeData.tokens.every(k => a.tokens[k] === b.tokens[k]);
}

function addImportedTheme(theme) {
  const existing = themeData.themes.find(t => t.id === theme.id);
  if (existing) {
    // Reimporting an exact export selects the original without replacing it.
    if (sameTheme(existing, theme)) return;
    throw new Error(`rejected id "${theme.id}": already exists${builtInThemeIds.has(theme.id) ? ' as a built-in theme' : ''}; choose a new id`);
  }
  themeData.themes.push(theme);
}

function renderThemeOptions() {
  els.themeSelect.replaceChildren();
  for (const t of themeData.themes) {
    const option = document.createElement('option');
    option.value = t.id;
    option.textContent = t.name || t.id;
    els.themeSelect.appendChild(option);
  }
}

function importTheme(text) {
  try {
    if (!themeData) throw new Error('themes are not loaded');
    const theme = parseImportedTheme(text);
    addImportedTheme(theme);
    renderThemeOptions();
    applyTheme(theme.id);
    try {
      localStorage.setItem(IMPORTED_THEMES_KEY, JSON.stringify(themeData.themes.filter(t => !builtInThemeIds.has(t.id))));
      themeImportStatus(`Imported ${theme.id}.`);
    } catch (_) {
      themeImportStatus(`Imported ${theme.id} for this session; browser storage is unavailable.`, true);
    }
    return true;
  } catch (err) {
    themeImportStatus(`Import refused: ${err.message}`, true);
    return false;
  }
}

function exportTheme() {
  const theme = themeData && themeData.themes.find(t => t.id === document.documentElement.dataset.theme);
  if (!theme) {
    themeImportStatus('No active theme to export.', true);
    return;
  }
  // Keep original strings, including whitespace, for an exact JSON round trip.
  const text = JSON.stringify(theme, null, 2);
  document.getElementById('themeJSON').value = text;
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'theme.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  themeImportStatus('Exported current theme; JSON is also available below.');
}

function applyTheme(id) {
  if (!themeData) return;
  const theme = themeData.themes.find((t) => t.id === id) || themeData.themes[0];
  if (!theme) return;

  const { validated, problems } = validateTheme(theme);
  els.themeNote.textContent = problems.length
    ? `incomplete theme ${theme.id} - ${problems.join('; ')}`
    : (theme.note || '');
  els.themeNote.classList.toggle('warn', problems.length > 0);
  // Validate the entire palette before changing any colours or persistence.
  // A broken theme must never borrow tokens from the previously selected one.
  if (problems.length) {
    els.themeSelect.value = document.documentElement.dataset.theme || '';
    return;
  }
  for (const [token, colour] of validated) {
    document.documentElement.style.setProperty(token, colour);
  }
  document.documentElement.style.colorScheme = theme.dark ? 'dark' : 'light';
  document.documentElement.dataset.theme = theme.id;
  els.themeSelect.value = theme.id;

  renderSwatches(theme);
  // Terminals carry their own colour table, so retheme the live ones too.
  const t = xtermTheme();
  panes.forEach((rec) => { try { rec.term.options.theme = t; } catch (_) {} });

  try { localStorage.setItem(THEME_KEY, theme.id); } catch (_) {}
}

function renderSwatches(active) {
  els.swatches.replaceChildren();
  for (const t of themeData.themes) {
    const wrap = el('button', 'swatch-wrap');
    wrap.type = 'button';
    wrap.title = `${t.name || t.id}${t.note ? ' - ' + t.note : ''}`;
    const sw = el('div', 'swatch');
    for (const token of ['--bg', '--panel', '--accent', '--safe', '--danger']) {
      const chip = document.createElement('i');
      // Same filter as applyTheme. A swatch assigns straight to a `background`
      // property, so skipping validation here would reopen the hole regardless of
      // how careful applyTheme is.
      chip.style.background = safeColour((t.tokens || {})[token]) || 'transparent';
      sw.appendChild(chip);
    }
    if (t.id === active.id) {
      sw.style.outline = `1px solid ${safeColour((t.tokens || {})['--accent']) || '#fff'}`;
    }
    wrap.appendChild(sw);
    wrap.appendChild(el('span', 'swatch-name', t.id));
    wrap.addEventListener('click', () => applyTheme(t.id));
    els.swatches.appendChild(wrap);
  }
}

async function loadThemes() {
  try {
    themeData = await getJSON('themes.json');
    if (!themeData || !Array.isArray(themeData.themes) || !themeData.themes.length) {
      throw new Error('no themes declared');
    }
    builtInThemeIds = new Set(themeData.themes.map(t => t.id));
    const restoreProblems = [];
    try {
      const stored = JSON.parse(localStorage.getItem(IMPORTED_THEMES_KEY) || '[]');
      if (!Array.isArray(stored)) throw new Error('expected a theme array');
      for (const [index, item] of stored.entries()) {
        try { addImportedTheme(parseImportedTheme(JSON.stringify(item))); }
        catch (err) { restoreProblems.push(`entry ${index + 1}: ${err.message}`); }
      }
    } catch (err) { restoreProblems.push(err.message); }
    renderThemeOptions();
    let want = themeData.default;
    try { want = localStorage.getItem(THEME_KEY) || want; } catch (_) {}
    applyTheme(want);
    els.themeSelect.addEventListener('change', () => applyTheme(els.themeSelect.value));
    if (restoreProblems.length) themeImportStatus(`Could not restore saved themes: ${restoreProblems.join('; ')}`, true);
    document.getElementById('themeImport').addEventListener('click', () => importTheme(document.getElementById('themeJSON').value));
    document.getElementById('themeFile').addEventListener('change', async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      try { importTheme(await file.text()); }
      catch (err) { themeImportStatus(`Could not read file: ${err.message}`, true); }
      event.target.value = '';
    });
    document.getElementById('themeExport').addEventListener('click', exportTheme);
  } catch (err) {
    // The CSS :root block is the cc-dark fallback, so a failure here degrades to
    // the right palette rather than to an unstyled page.
    els.themeNote.textContent = `themes.json failed to load (${err.message}); using the built-in default`;
    els.themeNote.classList.add('warn');
  }
}

// ════════════════════════════════════════════════════════════ data helpers ════

async function getJSON(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// Every mutating call repeats the /api/resize contract: POST, an explicit JSON
// content type (which forces a CORS preflight cross-origin), and nothing secret
// in the body - secrets are still terminal-only.
async function post(path, body) {
  const send = () => fetch(path, {method: 'POST', headers: {
    'Content-Type': 'application/json', ...(window.AgentmuxBrowserAuth?.headers() || {})
  }, body: JSON.stringify(body)});
  let res = await send();
  if (res.status === 401 && window.AgentmuxBrowserAuth) {
    window.AgentmuxBrowserAuth.clear();
    await window.AgentmuxBrowserAuth.signIn();
    res = await send();
  }
  let payload = {};
  try { payload = await res.json(); } catch (_) {}
  if (!res.ok) {
    const hints = Array.isArray(payload.missing)
      ? payload.missing.map(item => item.hint).filter(Boolean) : [];
    const error = new Error([payload.error || `HTTP ${res.status}`, ...hints].join(' · '));
    error.status = res.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function clock(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso).slice(0, 19) : d.toLocaleTimeString();
}

function say(node, msg) { node.textContent = msg; }

// ═══════════════════════════════════════════════════════════════ status ═══════
//
// WHAT EXPORT MEANS HERE, EXACTLY. It writes the rows the active tab is showing
// RIGHT NOW, after every filter, and nothing else. Not the server's full history,
// not the unfiltered buffer. An export that quietly widened the selection would be
// worse than useless in the place these get used - attached to an incident write-up
// as "here is what we were looking at".
//
// Each panel publishes its filtered rows as it renders them, so there is one place
// that knows what is on screen and the download can never drift from the view.
const statusRows = { feed: [], queue: [], journal: [], chatter: [] };

function publishRows(name, rows) {
  statusRows[name] = Array.isArray(rows) ? rows : [];
  updateStatusExport();
}

function activeStatusTab() {
  return (VIEW_TABS.status && VIEW_TABS.status.active) || null;
}

function updateStatusExport() {
  if (!els.statusExport) return;
  const tab = currentView === 'status' ? activeStatusTab() : null;
  const count = tab ? (statusRows[tab] || []).length : 0;
  els.statusExport.disabled = !tab || !count;
  els.statusExport.textContent = count ? `export ${count}` : 'export';
  els.statusExport.title = tab
    ? `Download the ${count} ${tab} row(s) currently on screen, after filters.`
    : 'Open a Status tab to export what it is showing.';
}

// A CSV over rows whose shape varies (the feed and the queue do not carry the same
// fields) needs a column set before it can be written. Take the union in first-seen
// order rather than sorting: the order the rows were built in is the order that
// reads naturally, and alphabetical puts `at` in the middle.
function toCSV(rows) {
  const columns = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) if (!columns.includes(key)) columns.push(key);
  }
  const cell = (value) => {
    if (value === null || value === undefined) return '';
    const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return [columns.join(','), ...rows.map((row) => columns.map((c) => cell(row[c])).join(','))]
    .join('\r\n') + '\r\n';
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoke on the next frame, not immediately: Firefox has not started reading the
  // blob when click() returns and an instant revoke lands an empty file on disk.
  requestAnimationFrame(() => URL.revokeObjectURL(url));
}

function exportStatus() {
  const tab = activeStatusTab();
  const rows = tab ? (statusRows[tab] || []) : [];
  if (!rows.length) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  if (els.statusExportAs && els.statusExportAs.value === 'csv') {
    download(`ccc-${tab}-${stamp}.csv`, toCSV(rows), 'text/csv;charset=utf-8');
  } else {
    download(`ccc-${tab}-${stamp}.json`,
             JSON.stringify({ tab, exported_at: new Date().toISOString(), rows }, null, 2),
             'application/json');
  }
  say(els.statusStamp, `exported ${rows.length} ${tab} row(s)`);
}

// ═══════════════════════════════════════════════════════════ message queue ════

const MSG_KINDS = new Set(['plan', 'request', 'reply', 'status', 'finding',
                           'error', 'claim', 'release']);

async function loadQueue() {
  try {
    const data = await getJSON('api/messages?limit=300');
    const all = Array.isArray(data.messages) ? data.messages : [];
    const want = els.queueKind.value;
    const needle = (els.queueSearch && els.queueSearch.value || '').trim().toLowerCase();
    const rows = all.filter((m) => (!want || m.kind === want) && (!needle ||
      `${m.sender} ${m.recipient} ${m.kind} ${m.body}`.toLowerCase().includes(needle)));
    publishRows('queue', rows);

    // Pin the orchestrator's latest plan: it is the thing you most often want on
    // screen while reading the traffic underneath it.
    const plan = [...all].reverse().find((m) => m.kind === 'plan');
    els.planPin.replaceChildren();
    els.planPin.hidden = !plan;
    if (plan) {
      els.planPin.appendChild(el('h4', null, `${plan.sender || 'orchestrator'} plan - ${clock(plan.at)}`));
      els.planPin.appendChild(el('pre', null, String(plan.body || '')));
    }

    els.queueList.replaceChildren();
    if (!rows.length) {
      els.queueList.appendChild(el('p', 'empty', all.length
        ? 'Nothing matches the current filters.'
        : 'No messages. Agents append JSON lines to $AGENTMUX_HOME/queue/<agent>.jsonl (default: ~/.agentmux/queue/<agent>.jsonl)'));
    }
    for (const m of rows) {
      const kind = String(m.kind || 'status');
      // Queue traffic is unbounded; keep bodies closed while showing a preview.
      // Older messages lack IDs, so use their immutable envelope and body instead.
      const key = m.id ?? JSON.stringify([m.at, m.sender, m.recipient, m.kind, m.body]);
      const row = collapsible(`queue:${key}`, MSG_KINDS.has(kind) ? `msg ${kind}` : 'msg', false);
      const head = el('summary', 'item-summary');
      head.appendChild(el('span', 'msg-at', clock(m.at)));
      const who = markAgent(el('span', 'msg-who', String(m.sender || '?')), m.sender);
      if (m.recipient) who.appendChild(markAgent(el('span', 'to', ` \u2192 ${m.recipient}`), m.recipient));
      head.appendChild(who);
      head.appendChild(el('span', 'msg-kind', kind));
      head.appendChild(el('span', 'item-preview', String(m.body || '')));
      row.append(head, el('div', 'msg-body item-body', String(m.body || '')));
      els.queueList.appendChild(row);
    }

    refreshLiveMarks(els.queueList);
    say(els.queueStamp, `${rows.length} of ${all.length} message${all.length === 1 ? '' : 's'}`);
    if (els.queueFollow.checked && els.queueList.lastElementChild) {
      els.queueList.lastElementChild.scrollIntoView({ block: 'nearest' });
    }
    // Reading the queue is what marks it read.
    if (all.length) markQueueSeen(all[all.length - 1].at);
  } catch (err) {
    say(els.queueStamp, `queue unavailable: ${err.message}`);
  }
}

// The badge exists to say "agents are talking" while you are looking at something
// else, so it cannot be driven by loadQueue() - that only runs when the queue is
// open. /api/messages?since= filters strictly after the timestamp, so the unseen
// count is just the length of that response.
const SEEN_KEY = 'ccc.queueSeenAt';
let queueSeenAt = null;
try { queueSeenAt = localStorage.getItem(SEEN_KEY); } catch (_) {}

function markQueueSeen(newest) {
  if (!newest || newest === queueSeenAt) return;
  queueSeenAt = newest;
  try { localStorage.setItem(SEEN_KEY, newest); } catch (_) {}
  els.badgeQueue.hidden = true;
  els.badgeQueue.textContent = '';
}

async function refreshQueueBadge() {
  if (panelVisible('status', 'queue')) return;   // loadQueue owns it while visible
  try {
    const since = queueSeenAt ? `since=${encodeURIComponent(queueSeenAt)}&` : '';
    const data = await getJSON(`api/messages?${since}limit=1000`);
    const n = Array.isArray(data.messages) ? data.messages.length : 0;
    els.badgeQueue.hidden = n === 0;
    els.badgeQueue.textContent = n > 99 ? '99+' : String(n);
  } catch (_) {
    // The queue is not load-bearing for the terminals; fail quiet rather than
    // putting an error in the chrome of every other view.
  }
}

// ═════════════════════════════════════════════════════════════════ board ══════

// These MUST match EPIC_STATUSES / TASK_STATUSES in ccstore.py - the backend
// rejects anything else. smoke.sh reads these two lines and asserts the backend
// accepts every value, so drift shows up as a test failure rather than a dead
// control. It had drifted: the board store replaced the old per-table words with
// one vocabulary, and these lists still offered `archived`, `todo` and
// `cancelled` - three dropdown entries that 400d on click.
//
// `deleted` is deliberately absent. It is reachable, but through the delete
// button, which confirms first; offering it in a status menu makes destroying a
// card the same gesture as reclassifying one.
const EPIC_STATUSES = ['backlog', 'open', 'in_progress', 'blocked', 'parked', 'done'];
const TASK_STATUSES = ['backlog', 'open', 'in_progress', 'blocked', 'parked', 'done'];

const STATUS_CLASS = /^[a-z_]+$/;   // in_progress has an underscore

// A select, not a click-to-advance chip. The first version cycled forward, which
// meant `blocked` and `cancelled` could be left but never entered - so the one
// status you most need to set during a bad run was the one you could not reach.
function statusSelect(kind, id, status, options, after, stamp) {
  const st = String(status || '');
  const select = document.createElement('select');
  select.className = `status-chip ${STATUS_CLASS.test(st) ? st : ''}`;
  select.title = `${kind} status`;
  for (const value of options) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value.replace('_', ' ');
    option.selected = value === st;
    select.appendChild(option);
  }
  select.addEventListener('change', async () => {
    const wanted = select.value;
    select.disabled = true;
    try { await post('api/board/status', { id, status: wanted }); await after(); }
    catch (err) {
      say(stamp, err.message);
      select.value = st;          // put it back: the change did not happen
      select.disabled = false;
    }
  });
  return select;
}

// Deleting is irreversible and there is no undo, so it always confirms. The journal
// has no delete at all - an append-only log you can quietly edit is not a log.
function deleteButton(kind, id, label, after, stamp, remove = () => post('api/delete', { kind, id })) {
  const btn = el('button', 'cbtn del', '×');
  btn.type = 'button';
  btn.title = `delete ${kind} “${label}”`;
  btn.setAttribute('aria-label', `delete ${kind} ${label}`);
  btn.addEventListener('click', async () => {
    const extra = kind === 'epic' ? '\n\nIts tasks are deleted with it.' : '';
    if (!window.confirm(`Delete ${kind} “${label}”?${extra}\n\nThis cannot be undone.`)) return;
    btn.disabled = true;
    try { await remove(); await after(); }
    catch (err) { say(stamp, err.message); btn.disabled = false; }
  });
  return btn;
}

// The dispatch strip: what the pool would do, and what it is doing.
//
// READ-ONLY, AND THERE IS NO BUTTON HERE ON PURPOSE. The same rule that keeps the
// Terminals view unable to spawn or kill a pane applies to dispatch, and more so:
// dispatching starts an unrestricted agent process that writes to this repository.
// A page cannot be allowed to do that from a click, so the page reports and the
// CLI acts. `agentmux dispatch` / `agentmux pool start` are the verbs.
async function loadDispatch() {
  const strip = els.dispatchStrip;
  if (!strip) return;
  try {
    const data = await getJSON('api/board/dispatchable?limit=20');
    const cfg = data.config || {};
    const flight = Array.isArray(data.inFlight) ? data.inFlight : [];
    const ready = Array.isArray(data.tasks) ? data.tasks : [];
    strip.replaceChildren();

    const on = cfg.dispatchEnabled === true;
    strip.appendChild(el('span', on ? 'status-chip done' : 'status-chip', on ? 'dispatch on' : 'dispatch off'));
    strip.appendChild(el('span', 'epic-meta',
      `${flight.length}/${cfg.dispatchWip ?? '?'} working`));

    if (flight.length) {
      for (const row of flight) {
        strip.appendChild(el('span', 't-agent',
          `${String(row.key)} → ${String(row.agent || '?')}`));
      }
    }
    if (ready.length) {
      strip.appendChild(el('span', 'epic-meta',
        `ready: ${ready.map((t) => String(t.id)).join(', ')}`));
    } else if (!flight.length) {
      strip.appendChild(el('span', 'epic-meta', 'nothing ready for an agent'));
    }
    if (!on && ready.length) {
      strip.appendChild(el('span', 'epic-meta',
        'agentmux board config dispatchEnabled true'));
    }
  } catch (err) {
    strip.replaceChildren(el('span', 'epic-meta', `dispatch unavailable: ${err.message}`));
  }
}

// ── moving things on the board ───────────────────────────────────────────────
//
// TWO KINDS OF MOVEMENT, AND THEY ARE NOT THE SAME KIND OF THING.
//
//   Dragging a TASK onto another epic refiles it. That is real state: it goes
//   through /api/board/move, the store reopens a finished epic that receives an
//   unfinished task, the CLI sees it, and everyone else's dashboard sees it too.
//   So it is confirmed by the drop itself and reported in the stamp, and a refusal
//   from the board (409) is shown rather than swallowed.
//
//   Dragging a CARD positions it. That is a view preference: it lives in this
//   browser, it is never sent anywhere, and it means nothing to anybody else. Free
//   layout is therefore opt-in and `tidy` always brings every card back - the
//   Terminals grid learned the same lesson, that a layout you cannot undo is a
//   layout you stop trusting.
//
// They are deliberately different gestures. Tasks use HTML5 drag-and-drop, which
// gives keyboard-free dragging and a drop target for free; cards move by their own
// handle with pointer events, so grabbing a card never starts a task drag and
// clicking the summary still just collapses the card.
const BOARD_PLACE_KEY = 'ccc.boardPlacements.v1';
const BOARD_FREE_KEY = 'ccc.boardFree';
let boardFree = false;
try { boardFree = localStorage.getItem(BOARD_FREE_KEY) === '1'; } catch (_) {}

function boardPlacements() {
  try {
    const parsed = JSON.parse(localStorage.getItem(BOARD_PLACE_KEY) || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (_) { return {}; }
}

function saveBoardPlacement(key, box) {
  const all = boardPlacements();
  if (box) all[key] = box; else delete all[key];
  try { localStorage.setItem(BOARD_PLACE_KEY, JSON.stringify(all)); } catch (_) {}
}

function applyBoardFree() {
  els.boardList.classList.toggle('free', boardFree);
  const placed = boardPlacements();
  for (const card of els.boardList.querySelectorAll('.epic')) {
    const key = card.dataset.epic || '';
    const box = boardFree ? placed[key] : null;
    if (box) {
      card.style.left = `${box.x}px`;
      card.style.top = `${box.y}px`;
      if (box.w) card.style.width = `${box.w}px`;
    } else {
      card.style.left = card.style.top = card.style.width = '';
    }
  }
  // An absolutely positioned child does not stretch its parent, so the container
  // would collapse to nothing and the page would stop scrolling to reach a card
  // dragged past the fold.
  if (boardFree) {
    let bottom = 0;
    for (const card of els.boardList.querySelectorAll('.epic')) {
      bottom = Math.max(bottom, card.offsetTop + card.offsetHeight);
    }
    els.boardList.style.minHeight = `${bottom + 24}px`;
  } else {
    els.boardList.style.minHeight = '';
  }
}

function makeCardMovable(card, handle, key) {
  handle.addEventListener('pointerdown', (ev) => {
    if (!boardFree || ev.button !== 0) return;
    ev.preventDefault();
    const list = els.boardList.getBoundingClientRect();
    const box = card.getBoundingClientRect();
    const grabX = ev.clientX - box.left;
    const grabY = ev.clientY - box.top;
    // Fix the width before going absolute: a card sized by the grid collapses to
    // its content the instant it leaves the flow, and it visibly jumps under the
    // cursor mid-drag.
    card.style.width = `${box.width}px`;
    card.classList.add('dragging');
    handle.setPointerCapture(ev.pointerId);
    const move = (m) => {
      const x = Math.max(0, m.clientX - list.left - grabX);
      const y = Math.max(0, m.clientY - list.top - grabY);
      card.style.left = `${x}px`;
      card.style.top = `${y}px`;
    };
    const drop = () => {
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', drop);
      handle.removeEventListener('pointercancel', drop);
      card.classList.remove('dragging');
      saveBoardPlacement(key, {
        x: parseFloat(card.style.left) || 0,
        y: parseFloat(card.style.top) || 0,
        w: parseFloat(card.style.width) || 0,
      });
      applyBoardFree();
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', drop);
    handle.addEventListener('pointercancel', drop);
  });
}

async function refileTask(taskKey, epicKey) {
  say(els.boardStamp, `moving ${taskKey} to ${epicKey}…`);
  try {
    await post('api/board/move', { id: taskKey, epic: epicKey });
    await loadBoard();
    say(els.boardStamp, `${taskKey} moved to ${epicKey}`);
  } catch (err) {
    // A refusal here is usually the board protecting an invariant - a closed epic,
    // an unmet dependency - so the reason matters more than the failure.
    say(els.boardStamp, `${taskKey} not moved: ${err.message}`);
  }
}

function setEpicsOpen(open) {
  for (const card of els.boardList.querySelectorAll('details.epic')) {
    card.open = open;
    if (card.dataset.collapseKey) rememberOpen(card.dataset.collapseKey, open);
  }
}

async function loadBoard() {
  loadDispatch();
  try {
    const data = await getJSON('api/board/board');
    const epics = Array.isArray(data.epics) ? data.epics : [];
    const allTasks = Array.isArray(data.tasks) ? data.tasks : [];
    const epicKeys = new Set(epics.map((e) => e.key));
    const ungrouped = allTasks.filter((t) => !epicKeys.has(t.epic));
    const groups = ungrouped.length ? [...epics, { title: 'Tasks without an epic' }] : epics;
    els.boardList.replaceChildren();
    if (!groups.length) els.boardList.appendChild(el('p', 'empty', 'No epics yet. Add one above.'));

    for (const e of groups) {
      // Epics default OPEN: a board that opens collapsed hides the work. The
      // operator's own choice per epic is remembered, as everywhere else.
      const card = collapsible(`board:epic:${e.key || 'none'}`, 'epic', true);
      card.dataset.epic = e.key || '';
      const head = el('summary', 'epic-head item-summary');
      const grip = el('span', 'grip', '∷');
      grip.title = 'Drag to place this card (free layout only)';
      grip.setAttribute('aria-hidden', 'true');
      head.appendChild(grip);
      if (e.key) head.appendChild(el('span', 'board-key', e.key));
      head.appendChild(el('span', 'epic-title', String(e.title || '(untitled)')));
      if (e.jira_key) head.appendChild(el('span', 'epic-meta', String(e.jira_key)));
      const tasks = e.key ? allTasks.filter((t) => t.epic === e.key) : ungrouped;
      const done = tasks.filter((t) => t.status === 'done').length;
      if (tasks.length) head.appendChild(el('span', 'epic-meta', `${done}/${tasks.length}`));
      // An epic is "running" when something inside it is. Put it on the SUMMARY so a
      // collapsed card still says so - otherwise the one signal worth seeing is the
      // one hidden behind the disclosure that made the board readable.
      const busy = new Set();
      for (const [name, agent] of liveAgents) {
        if (tasks.some((t) => t.key === agent.task || t.assignee === name)) busy.add(name);
      }
      for (const name of [...busy].sort()) {
        head.appendChild(markAgent(el('span', 'epic-agent', name), name));
      }
      if (busy.size) card.classList.add('has-live');
      head.appendChild(el('span', 'spacer'));
      card.appendChild(head);
      makeCardMovable(card, grip, e.key || '');

      const controls = el('div', 'epic-controls');
      if (e.key) controls.appendChild(statusSelect('epic', e.key, e.status, EPIC_STATUSES,
                                                   loadBoard, els.boardStamp));
      if (e.key) controls.appendChild(deleteButton('epic', e.key, `${e.key} ${e.title || ''}`,
        loadBoard, els.boardStamp, () => post('api/board/delete', { id: e.key })));
      card.appendChild(controls);

      const rows = el('div', 'task-rows');
      for (const t of tasks) {
        const r = el('div', 'task-row');
        r.draggable = true;
        r.dataset.task = t.key;
        r.dataset.epic = t.epic || '';
        r.addEventListener('dragstart', (ev) => {
          ev.dataTransfer.effectAllowed = 'move';
          ev.dataTransfer.setData('text/plain', t.key);
          r.classList.add('dragging');
        });
        r.addEventListener('dragend', () => r.classList.remove('dragging'));
        const handle = el('span', 'grip', '∷');
        handle.setAttribute('aria-hidden', 'true');
        r.appendChild(handle);
        const keyLink = el('span', 'board-key', t.key);
        keyLink.setAttribute('role', 'button');
        keyLink.setAttribute('tabindex', '0');
        keyLink.setAttribute('aria-label', `Open ${t.key} details`);
        keyLink.addEventListener('click', () => window.CCCOpenCard?.(t.key, loadBoard));
        keyLink.addEventListener('keydown', ev => {
          if (ev.key === 'Enter' || ev.key === ' ') {
            ev.preventDefault(); window.CCCOpenCard?.(t.key, loadBoard);
          }
        });
        r.appendChild(keyLink);
        r.appendChild(statusSelect('task', t.key, t.status, TASK_STATUSES,
                                   loadBoard, els.boardStamp));
        r.appendChild(el('span', 't-title', String(t.title || '')));
        if (t.assignee) {
          r.appendChild(markAgent(el('span', 't-agent', String(t.assignee)), t.assignee));
        }
        // An agent can be bound to a card from ITS side - the `.task` sidecar -
        // without the card naming it back. That is the normal shape during a run,
        // so the board looks both ways; otherwise a card being actively worked on
        // shows nothing at all.
        for (const [name, agent] of liveAgents) {
          if (agent.task === t.key && name !== t.assignee) {
            r.appendChild(markAgent(el('span', 't-agent working', name), name));
          }
        }
        r.appendChild(deleteButton('task', t.key, `${t.key} ${t.title || ''}`,
          loadBoard, els.boardStamp, () => post('api/board/delete', { id: t.key })));
        rows.appendChild(r);
      }
      card.appendChild(rows);

      // Only an epic with a key can receive a task; "Tasks without an epic" is a
      // display grouping, not a destination.
      if (e.key) {
        card.addEventListener('dragover', (ev) => {
          if (!ev.dataTransfer.types.includes('text/plain')) return;
          ev.preventDefault();
          ev.dataTransfer.dropEffect = 'move';
          card.classList.add('drop-target');
        });
        card.addEventListener('dragleave', (ev) => {
          if (!card.contains(ev.relatedTarget)) card.classList.remove('drop-target');
        });
        card.addEventListener('drop', (ev) => {
          ev.preventDefault();
          card.classList.remove('drop-target');
          const key = ev.dataTransfer.getData('text/plain');
          const row = els.boardList.querySelector(`.task-row[data-task="${CSS.escape(key)}"]`);
          if (!key || !row) return;
          if (row.dataset.epic === e.key) return;   // dropped where it already was
          refileTask(key, e.key);
        });
      }

      const add = el('div', 'row');
      const title = el('input', 'rin');
      title.placeholder = 'new task';
      title.size = 16;
      const agent = el('input', 'rin');
      agent.placeholder = 'agent';
      agent.size = 7;
      const btn = el('button', 'btn', 'add task');
      btn.type = 'button';
      const submit = async () => {
        if (!title.value.trim()) return;
        btn.disabled = true;
        try {
          await post('api/tasks', {
            epic_id: e.row, title: title.value.trim(), agent: agent.value.trim() || null,
          });
          await loadBoard();
        } catch (err) { say(els.boardStamp, err.message); btn.disabled = false; }
      };
      btn.addEventListener('click', submit);
      title.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') submit(); });
      add.append(title, agent, btn);
      // Creation still uses the compatibility form endpoint, which takes a row id.
      if (e.key) card.appendChild(add);

      els.boardList.appendChild(card);
    }
    applyBoardFree();
    refreshLiveMarks(els.boardList);
    say(els.boardStamp, `${epics.length} epic${epics.length === 1 ? '' : 's'}`
      + `, ${allTasks.length} task${allTasks.length === 1 ? '' : 's'}`);
  } catch (err) {
    say(els.boardStamp, `board unavailable: ${err.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════ journal ══════

const JOURNAL_KINDS = new Set(['note', 'decision', 'incident', 'change']);

async function loadJournal() {
  try {
    const data = await getJSON('api/journal?limit=200');
    const all = Array.isArray(data.journal) ? data.journal : [];
    const wantKind = (els.journalFilterKind && els.journalFilterKind.value) || '';
    const needle = (els.journalSearch && els.journalSearch.value || '').trim().toLowerCase();
    const rows = all.filter((j) => (!wantKind || j.kind === wantKind) && (!needle ||
      `${j.subject} ${j.body} ${j.agent} ${j.kind}`.toLowerCase().includes(needle)));
    publishRows('journal', rows);
    els.journalList.replaceChildren();
    if (!rows.length) {
      els.journalList.appendChild(el('p', 'empty',
        all.length ? 'Nothing matches the current filters.' : 'Journal is empty.'));
    }
    for (const j of rows) {
      const kind = String(j.kind || 'note');
      // Journal subjects form a useful index; default bodies closed for long histories.
      const key = j.id ?? JSON.stringify([j.at, j.agent, j.kind, j.subject, j.body]);
      const box = collapsible(`journal:${key}`, JOURNAL_KINDS.has(kind) ? `jentry ${kind}` : 'jentry', false);
      const head = el('summary', 'jentry-head item-summary');
      head.appendChild(el('span', 'jentry-subject', String(j.subject || '(no subject)')));
      head.appendChild(el('span', 'status-chip', kind));
      head.appendChild(el('span', 'epic-meta', clock(j.at)));
      if (j.agent) head.appendChild(markAgent(el('span', 'epic-meta j-agent', String(j.agent)), j.agent));
      box.appendChild(head);
      if (j.body) box.appendChild(el('p', 'jentry-body', String(j.body)));
      els.journalList.appendChild(box);
    }
    refreshLiveMarks(els.journalList);
    say(els.journalStamp, `${rows.length} of ${all.length} entr${all.length === 1 ? 'y' : 'ies'}`);
  } catch (err) {
    say(els.journalStamp, `journal unavailable: ${err.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════ tickets ══════

const ISSUE_RE = /^[A-Z][A-Z0-9_]+-[0-9]+$/;
const JIRA_BASE_RE = /^https:\/\/[A-Za-z0-9.-]+$/;

// The issue key and base URL are both validated before either becomes part of an
// href, so a crafted key cannot produce a javascript: URL.
function issueLink(key, base) {
  if (JIRA_BASE_RE.test(base) && ISSUE_RE.test(key)) {
    const a = el('a', 't-key', key);
    a.href = `${base}/browse/${encodeURIComponent(key)}`;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    return a;
  }
  return el('span', 't-key', key);
}

// Commenting and transitioning write to Jira, which is outside this machine and not
// undoable from here, so both confirm first.
function ticketActions(issue, base) {
  const bar = el('div', 'ticket-actions');

  const transitions = el('select', 'rin');
  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = 'transition…';
  transitions.appendChild(placeholder);
  let loaded = false;
  // Fetched on demand: one Jira call per issue up front would burn the hourly
  // rate limit on a list nobody has clicked yet.
  transitions.addEventListener('mousedown', async () => {
    if (loaded) return;
    loaded = true;
    try {
      const data = await getJSON(`api/tickets/transitions?key=${encodeURIComponent(issue.key)}`);
      for (const t of (data.transitions || [])) {
        const option = document.createElement('option');
        option.value = t.id;
        option.textContent = t.name;
        transitions.appendChild(option);
      }
      if (!(data.transitions || []).length) placeholder.textContent = 'no transitions';
    } catch (err) {
      loaded = false;
      placeholder.textContent = 'could not load';
      say(els.ticketStamp, err.message);
    }
  });
  transitions.addEventListener('change', async () => {
    const id = transitions.value;
    if (!id) return;
    const name = transitions.options[transitions.selectedIndex].textContent;
    if (!window.confirm(`Apply “${name}” to ${issue.key} in Jira?\n\nThis changes the real issue.`)) {
      transitions.value = '';
      return;
    }
    transitions.disabled = true;
    try {
      const out = await post('api/tickets/transition', { key: issue.key, transition_id: id });
      say(els.ticketStamp, out.detail || 'done');
      await loadTickets(true);
    } catch (err) {
      say(els.ticketStamp, err.message);
      transitions.value = '';
      transitions.disabled = false;
    }
  });
  bar.appendChild(transitions);

  const text = el('input', 'rin');
  text.placeholder = 'comment…';
  text.size = 30;
  const send = el('button', 'btn', 'comment');
  send.type = 'button';
  const submit = async () => {
    const value = text.value.trim();
    if (!value) return;
    if (!window.confirm(`Post this comment to ${issue.key} in Jira?\n\n${value}`)) return;
    send.disabled = true;
    try {
      const out = await post('api/tickets/comment', { key: issue.key, text: value });
      say(els.ticketStamp, out.detail || 'commented');
      text.value = '';
    } catch (err) { say(els.ticketStamp, err.message); }
    send.disabled = false;
  };
  send.addEventListener('click', submit);
  text.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') submit(); });
  bar.append(text, send);
  return bar;
}

async function loadTickets(force) {
  els.ticketList.replaceChildren();
  try {
    const data = await getJSON(`api/tickets${force ? '?refresh=1' : ''}`);

    // Atlassian is optional. When it is not set up, say what is missing and show
    // the commands - an empty list would read as "no tickets", which is a lie.
    if (!data.configured) {
      const box = el('div', 'notice');
      box.appendChild(el('p', null,
        `Jira is not configured, so there are no tickets to review. ${data.reason || ''}`));
      els.ticketList.appendChild(box);
      const actions = el('div', 'res-actions');
      for (const a of (data.setup || [])) {
        const act = el('div', `act${a.secret ? ' secret' : ''}`);
        act.appendChild(el('span', 'act-label', a.label));
        act.appendChild(el('code', 'act-cmd', a.command));
        if (a.secret) act.appendChild(el('span', 'act-secret-tag', 'your terminal'));
        actions.appendChild(act);
      }
      els.ticketList.appendChild(actions);
      say(els.ticketStamp, 'not configured');
      return;
    }
    if (data.error) {
      const box = el('div', 'notice');
      box.appendChild(el('p', null, `${data.error}. ${data.detail || ''}`));
      els.ticketList.appendChild(box);
      say(els.ticketStamp, data.error);
      return;
    }

    // Prefer the base URL Jira itself reported; fall back to the Settings field.
    const base = (data.base_url || els.jiraBase.value || '').trim().replace(/\/+$/, '');
    const all = data.issues || [];
    const needle = (els.ticketSearch && els.ticketSearch.value || '').trim().toLowerCase();
    const issues = needle ? all.filter((i) =>
      `${i.key} ${i.summary} ${i.status} ${i.assignee} ${(i.labels || []).join(' ')}`
        .toLowerCase().includes(needle)) : all;
    if (!issues.length) {
      els.ticketList.appendChild(el('p', 'empty', all.length
        ? 'Nothing matches the current filter.'
        : `No issues returned${data.project ? ` for project ${data.project}` : ''}.`));
    }
    // Which local epics reference a Jira key, so the board and Jira can be seen
    // together rather than in two places.
    let linked = new Set();
    try {
      const epics = await getJSON('api/epics');
      linked = new Set((epics.epics || []).map((e) => e.jira_key).filter(Boolean));
    } catch (_) { /* the local board is not essential to reviewing tickets */ }

    for (const issue of issues) {
      // Tickets default closed: scan titles/statuses, then expand the issue to act.
      // Include the Jira site so identical issue keys on different sites stay independent.
      const row = collapsible(`ticket:${JSON.stringify([base, issue.key])}`, 'ticket', false);
      const head = el('summary', 'item-summary');
      head.appendChild(issueLink(issue.key, base));
      head.appendChild(el('span', 't-sum', issue.summary || ''));
      if (issue.status) head.appendChild(el('span', 'status-chip', issue.status));
      if (issue.assignee) head.appendChild(el('span', 't-agent', issue.assignee));
      if (linked.has(issue.key)) head.appendChild(el('span', 'res-kind', 'on board'));
      row.appendChild(head);
      row.appendChild(ticketActions(issue, base));
      els.ticketList.appendChild(row);
    }
    say(els.ticketStamp,
        `${issues.length} of ${all.length} issue${all.length === 1 ? '' : 's'}`
        + (data.project ? ` in ${data.project}` : ''));
  } catch (err) {
    say(els.ticketStamp, `tickets unavailable: ${err.message}`);
  }
}

// ════════════════════════════════════════════════════════════ authentication ══
//
// This view configures WHICH auth method each CLI uses. It never accepts a
// credential: entering one is a terminal action (taskmgmt/setup_auth.py, getpass),
// shown here as a command with a "your terminal" tag. The page only ever sends
// {id} to /api/auth/select.

// Collapsed/expanded state, per provider and per method, so a long list stays
// navigable and reopening Settings does not undo how you left it. <details> gives
// keyboard support and correct semantics for free - no ARIA to get wrong.
const OPEN_KEY = 'ccc.authOpen';

// A MAP of key -> boolean, not a set of open keys. With a set there is no way to
// distinguish "collapsed by the operator" from "never seen", so a newly added
// provider would default closed and go unnoticed.
function openState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(OPEN_KEY) || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (_) { return {}; }
}

// Cap both count and serialized size instead of hashing: digests alone still
// accumulate forever. Keep at most 512 choices / 64K UTF-16 code units (~128 KiB),
// leaving quota for other settings even when legacy keys contain full bodies.
// Insertion order records last touch: move the toggled key to the end, then evict
// oldest choices first. Existing maps migrate on their next write; evicted items
// return to their view default. A single over-budget key is not retained.
const OPEN_MAX_ENTRIES = 512;
const OPEN_MAX_CHARS = 64 * 1024;
function rememberOpen(key, isOpen) {
  const entries = Object.entries(openState())
    .filter(([k, value]) => k !== key && typeof value === 'boolean');
  entries.push([key, isOpen]);
  const sizes = entries.map(([k, value]) => JSON.stringify(k).length + (value ? 4 : 5) + 2);
  let chars = 1 + sizes.reduce((sum, size) => sum + size, 0);
  let first = 0;
  while (entries.length - first > OPEN_MAX_ENTRIES || chars > OPEN_MAX_CHARS) {
    chars -= sizes[first++];
  }
  const state = Object.fromEntries(entries.slice(first));
  try { localStorage.setItem(OPEN_KEY, JSON.stringify(state)); } catch (_) {}
}

// Both markup and JS-created cards use the same keys and storage map. Keep
// OPEN_KEY unchanged so existing provider/method preferences survive upgrades.
const wiredCollapsibles = new WeakSet();
function wireCollapsible(box, key, startOpen) {
  if (wiredCollapsibles.has(box)) return box;
  wiredCollapsibles.add(box);
  // The key goes ON the element, not just into this closure. A card built in JS
  // was otherwise indistinguishable from an unmanaged <details> once it was in the
  // document, so "collapse all" could set them but never record the choice - they
  // sprang back open on the next render, which read as the button not working.
  box.dataset.collapseKey = key;
  const remembered = openState()[key];
  box.open = typeof remembered === 'boolean' ? remembered : startOpen;
  box.addEventListener('toggle', () => rememberOpen(key, box.open));
  return box;
}

// Declarative contract: <details data-collapse-key="unique-key" open>
// <summary>Title</summary>...</details>. Omit `open` to default closed.
// No view-specific registration is needed; native controls retain their nodes.
function initCollapsibles(root = document) {
  root.querySelectorAll('details[data-collapse-key]').forEach(box => {
    const key = box.dataset.collapseKey;
    if (key) wireCollapsible(box, key, box.open);
  });
}

// `startOpen` applies until the operator has toggled this particular key.
function collapsible(key, cls, startOpen) {
  return wireCollapsible(el('details', cls), key, startOpen);
}

function stateChip(configured, missing) {
  const chip = el('span', `res-state ${configured ? 'ok' : 'missing'}`,
    configured ? 'ready' : 'needs setup');
  if (!configured && missing.length) chip.title = `Missing: ${missing.join(', ')}`;
  return chip;
}

// An editable non-secret setting, rendered as a text field. Secrets never appear
// here — entering one stays a terminal action.
function settingEditor(methodId, row, after, options = {}) {
  const wrap = el('div', 'act');
  wrap.appendChild(el('span', 'act-label', row.label || row.key));

  const field = document.createElement('input');
  field.className = 'rin';
  field.type = 'text';
  field.size = 26;
  field.value = String(row.value ?? '');
  field.placeholder = row.example || row.key;

  const save = el('button', 'btn', 'set');
  save.type = 'button';
  const stamp = options.stamp || els.authStamp;
  const commit = async () => {
    if (save.disabled) return;
    const value = field.value.trim();
    if (!value || value === String(row.value ?? '')) return;
    save.disabled = true;
    try {
      if (options.save) {
        await options.save(value);
        say(stamp, `${row.label || row.key} saved`);
      } else {
        const out = await post('api/auth/setting',
                               { method: methodId, key: row.key, value });
        say(stamp, `${methodId}.${row.key} = ${out.value} — ${out.note || ''}`);
      }
      await after();
    } catch (err) {
      say(stamp, err.message);
      field.value = String(row.value ?? '');
    } finally {
      save.disabled = false;
    }
  };
  save.addEventListener('click', commit);
  field.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') commit(); });

  wrap.append(field, save);
  return wrap;
}

// Non-secret settings show their VALUE; secrets show presence only. Never a value,
// never a length, never a prefix - a prefix is still a leak.
function settingList(rows, secrets) {
  const list = el('ul', 'res-checks');
  for (const r of rows || []) {
    const li = el('li');
    li.appendChild(el('span', `chk ${r.set ? 'ok' : 'bad'}`, r.set ? '✓' : '✗'));
    li.appendChild(el('span', 'chk-label', r.label || r.key));
    li.appendChild(el('span', 'chk-detail',
      r.set ? r.value : (r.example ? `not set — e.g. ${r.example}` : 'not set')));
    list.appendChild(li);
  }
  for (const s of secrets || []) {
    const li = el('li');
    li.appendChild(el('span', `chk ${s.set ? 'ok' : 'bad'}`, s.set ? '✓' : '✗'));
    li.appendChild(el('span', 'chk-label', s.name));
    li.appendChild(el('span', 'chk-detail',
      s.set ? 'set (value never read or shown)' : 'not set'));
    list.appendChild(li);
  }
  return list.childElementCount ? list : null;
}

function setupActions(rows) {
  if (!(rows || []).length) return null;
  const actions = el('div', 'res-actions');
  for (const a of rows) {
    const act = el('div', `act${a.secret ? ' secret' : ''}`);
    act.appendChild(el('span', 'act-label', a.label));
    act.appendChild(el('code', 'act-cmd', a.command));
    if (a.secret) act.appendChild(el('span', 'act-secret-tag', 'your terminal'));
    const copy = el('button', 'btn', 'copy');
    copy.type = 'button';
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(a.command);
        copy.textContent = 'copied';
      } catch (_) { copy.textContent = 'select it'; }
      setTimeout(() => { copy.textContent = 'copy'; }, 1600);
    });
    act.appendChild(copy);
    actions.appendChild(act);
    if (a.note) actions.appendChild(el('p', 'note', a.note));
  }
  return actions;
}

function noteList(notes) {
  if (!(notes || []).length) return null;
  const list = el('ul', 'res-notes');
  for (const n of notes) list.appendChild(el('li', null, n));
  return list;
}

async function loadAuth() {
  try {
    const data = await getJSON('api/auth');
    if (data.error) throw new Error(data.error);
    els.authList.replaceChildren();

    for (const p of (data.providers || [])) {
      // Default open only where there is something to do; a configured provider
      // collapses out of the way.
      const box = collapsible(`p:${p.id}`,
        `auth-provider${p.configured ? '' : ' unconfigured'}`, !p.configured);

      const head = el('summary', 'auth-summary');
      head.appendChild(el('span', 'auth-id', p.id));
      head.appendChild(el('span', 'auth-label', p.label));
      if (p.kind) head.appendChild(el('span', 'res-kind', p.kind));
      // Which CLIs this one provider serves - the point of grouping this way.
      if ((p.clis || []).length) {
        head.appendChild(el('span', 'auth-clis', p.clis.join(' · ')));
      }
      head.appendChild(el('span', 'spacer'));
      const inUse = (p.methods || []).filter((m) => m.active).length;
      if (inUse) head.appendChild(el('span', 'auth-inuse', 'in use'));
      head.appendChild(stateChip(p.configured, p.missing || []));
      box.appendChild(head);

      const body = el('div', 'auth-body');
      if (p.summary) body.appendChild(el('p', 'res-summary', p.summary));

      // Shared attributes, shown ONCE for the provider rather than repeated under
      // every CLI that uses it.
      const shared = settingList(p.settings, p.secrets);
      if (shared) {
        body.appendChild(el('h5', 'auth-sub', `shared by ${(p.clis || []).join(', ') || 'this provider'}`));
        body.appendChild(shared);
      }
      const pSetup = setupActions(p.setup);
      if (pSetup) body.appendChild(pSetup);
      const pNotes = noteList(p.notes);
      if (pNotes) body.appendChild(pNotes);

      for (const m of (p.methods || [])) {
        const mBox = collapsible(`m:${m.id}`,
          `auth-method${m.active ? ' active' : ''}${m.configured ? '' : ' unconfigured'}`,
          false);
        const mHead = el('summary', 'auth-summary');
        mHead.appendChild(el('span', 'auth-cli-tag', m.cli));
        mHead.appendChild(el('span', 'auth-id', m.id));
        if (m.default) mHead.appendChild(el('span', 'res-kind', 'cli default'));
        mHead.appendChild(el('span', 'spacer'));

        const pick = el('button', 'btn', m.active ? 'in use' : 'use this');
        pick.type = 'button';
        pick.disabled = m.active || !m.configured;
        pick.title = m.configured
          ? `Make ${m.id} the default for new ${m.cli} agents`
          : `Not configured: ${m.missing.join(', ')}`;
        // Inside a <summary>, so stop the click from toggling the disclosure too.
        pick.addEventListener('click', async (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          pick.disabled = true;
          try { await post('api/auth/select', { id: m.id }); await loadAuth(); }
          catch (err) { say(els.authStamp, err.message); pick.disabled = false; }
        });
        mHead.appendChild(pick);
        mHead.appendChild(stateChip(m.configured, m.missing || []));
        mBox.appendChild(mHead);

        const mBody = el('div', 'auth-body');
        if (m.label) mBody.appendChild(el('p', 'res-summary', m.label));
        const own = settingList(m.settings, null);
        if (own) {
          mBody.appendChild(el('h5', 'auth-sub', `specific to ${m.id}`));
          mBody.appendChild(own);
        }
        // Editable, for the settings the backend says are editable. A model change here
        // applies to agents spawned from now on; a running agent keeps its own.
        const editable = new Set(m.editable || []);
        const editors = (m.settings || []).filter((row) => editable.has(row.key));
        if (editors.length) {
          mBody.appendChild(el('h5', 'auth-sub', 'change'));
          const box = el('div', 'res-actions');
          for (const row of editors) {
            box.appendChild(settingEditor(m.id, row, loadAuth));
          }
          mBody.appendChild(box);
          mBody.appendChild(el('p', 'note',
            'Applies to agents spawned from now on — a running agent keeps the model it started with.'));
        }
        const mSetup = setupActions(m.setup);
        if (mSetup) mBody.appendChild(mSetup);
        const mNotes = noteList(m.notes);
        if (mNotes) mBody.appendChild(mNotes);
        mBox.appendChild(mBody);

        body.appendChild(mBox);
      }

      box.appendChild(body);
      els.authList.appendChild(box);
    }

    const files = data.files || {};
    const bits = [];
    for (const key of ['settings', 'env']) {
      const f = files[key];
      if (!f) continue;
      const mode = f.mode ? `mode ${f.mode}` : 'absent';
      const warn = f.mode && f.mode !== '600' ? ' — SHOULD BE 600' : '';
      bits.push(`${f.path}: ${mode}${warn}`
        + (key === 'env' && f.count ? ` (${f.count} variables)` : ''));
    }
    const chosen = Object.entries(data.active || {})
      .map(([cli, id]) => `${cli}→${id}`).join('  ');
    say(els.authStamp, (chosen ? chosen + '   ' : '') + bits.join('   '));
    els.authStamp.classList.toggle('warn', bits.some((b) => b.includes('SHOULD BE')));
  } catch (err) {
    say(els.authStamp, `auth unavailable: ${err.message}`);
  }
}

els.authRefresh.addEventListener('click', loadAuth);

// ══════════════════════════════════════════════════════════════════ IIOT ══════

// ═══════════════════════════════════════════════════════════════ atlassian ════
//
// Settings reports what the Board's Atlassian tab is pointed at and whether the
// credential exists. It does NOT accept one: that is still setup_atlassian.py in a
// real terminal, as with every other secret on this page.
async function loadAtlassianState() {
  if (!els.atlState) return;
  els.atlState.replaceChildren();
  try {
    const data = await getJSON('api/tickets');
    if (!data.configured) {
      els.atlState.appendChild(el('p', 'notice',
        `Not configured. ${data.reason || ''} The Board's Atlassian tab will stay empty until this is set up.`));
      const actions = el('div', 'res-actions');
      for (const a of (data.setup || [])) {
        const act = el('div', `act${a.secret ? ' secret' : ''}`);
        act.appendChild(el('span', 'act-label', a.label));
        act.appendChild(el('code', 'act-cmd', a.command));
        if (a.secret) act.appendChild(el('span', 'act-secret-tag', 'your terminal'));
        actions.appendChild(act);
      }
      els.atlState.appendChild(actions);
      say(els.atlStamp, 'not configured');
      return;
    }
    const line = el('div', 'act');
    line.appendChild(el('span', 'act-label', 'Connection'));
    line.appendChild(stateChip(true, []));
    els.atlState.appendChild(line);
    if (data.project) {
      const project = el('div', 'act');
      project.appendChild(el('span', 'act-label', 'Default project'));
      project.appendChild(el('code', 'act-cmd', data.project));
      els.atlState.appendChild(project);
    }
    if (data.base_url) {
      const site = el('div', 'act');
      site.appendChild(el('span', 'act-label', 'Site'));
      site.appendChild(el('code', 'act-cmd', data.base_url));
      els.atlState.appendChild(site);
    }
    if (data.error) els.atlState.appendChild(el('p', 'notice', `${data.error}. ${data.detail || ''}`));
    say(els.atlStamp, data.error ? 'configured, but the last query failed' : 'configured');
  } catch (err) {
    say(els.atlStamp, `unavailable: ${err.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════ wiring ═══════

els.queueRefresh.addEventListener('click', loadQueue);
els.queueKind.addEventListener('change', loadQueue);
if (els.queueSearch) els.queueSearch.addEventListener('input', loadQueue);
if (els.journalSearch) els.journalSearch.addEventListener('input', loadJournal);
if (els.journalFilterKind) els.journalFilterKind.addEventListener('change', loadJournal);
if (els.ticketSearch) els.ticketSearch.addEventListener('input', () => loadTickets(false));
if (els.statusExport) els.statusExport.addEventListener('click', exportStatus);
if (els.atlRefresh) els.atlRefresh.addEventListener('click', loadAtlassianState);

// Board layout controls. `tidy` clears every remembered placement, which is the
// only way a card ever moves without the operator dragging it.
if (els.boardFree) {
  els.boardFree.checked = boardFree;
  els.boardFree.addEventListener('change', () => {
    boardFree = els.boardFree.checked;
    try { localStorage.setItem(BOARD_FREE_KEY, boardFree ? '1' : '0'); } catch (_) {}
    applyBoardFree();
  });
}
if (els.boardTidy) els.boardTidy.addEventListener('click', () => {
  try { localStorage.removeItem(BOARD_PLACE_KEY); } catch (_) {}
  applyBoardFree();
  say(els.boardStamp, 'cards returned to the grid');
});
if (els.boardExpand) els.boardExpand.addEventListener('click', () => setEpicsOpen(true));
if (els.boardCollapse) els.boardCollapse.addEventListener('click', () => setEpicsOpen(false));

// IIOT cards. Same contract as the board's: the operator's own per-card choice is
// remembered, and these two buttons set every one of them at once.
function setIiotOpen(open) {
  for (const card of document.querySelectorAll('#viewIiot details.card')) {
    card.open = open;
    if (card.dataset.collapseKey) rememberOpen(card.dataset.collapseKey, open);
  }
}
if (els.iiotExpand) els.iiotExpand.addEventListener('click', () => setIiotOpen(true));
if (els.iiotCollapse) els.iiotCollapse.addEventListener('click', () => setIiotOpen(false));

els.epicAdd.addEventListener('click', async () => {
  const title = els.epicTitle.value.trim();
  if (!title) return;
  const key = els.epicJira.value.trim();
  if (key && !ISSUE_RE.test(key)) { say(els.boardStamp, `not an issue key: ${key}`); return; }
  els.epicAdd.disabled = true;
  try {
    await post('api/epics', { title, jira_key: key || null });
    els.epicTitle.value = '';
    els.epicJira.value = '';
    await loadBoard();
  } catch (err) { say(els.boardStamp, err.message); } finally { els.epicAdd.disabled = false; }
});

els.journalAdd.addEventListener('click', async () => {
  const subject = els.journalSubject.value.trim();
  if (!subject) return;
  els.journalAdd.disabled = true;
  try {
    await post('api/journal', {
      kind: els.journalKind.value,
      subject,
      body: els.journalBody.value.trim() || null,
    });
    els.journalSubject.value = '';
    els.journalBody.value = '';
    await loadJournal();
  } catch (err) { say(els.journalStamp, err.message); } finally { els.journalAdd.disabled = false; }
});

els.ticketRefresh.addEventListener('click', () => loadTickets(true));
els.resRefresh.addEventListener('click', () => loadResources(true));

// Re-fit on window resize. relayout() recomputes the column count (auto mode depends on
// the viewport width) and then fits every pane, so one path covers a ribbon change and a
// window drag alike.
//
// Debounced, because a drag fires this continuously and each pass re-zooms the chrome,
// re-lays-out the grid and re-fits every terminal. relayout() runs immediately so the
// grid tracks the drag; the chrome scale settles once the drag stops.
let resizeTimer = null;
window.addEventListener('resize', () => {
  relayout();
  if (resizeTimer) clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    resizeTimer = null;
    applyUiScale();          // no-op unless the stepped scale actually changed
  }, 180);
});

// Close the streams when the page goes away. Without this the browser logs a
// "connection interrupted while the page was loading" error for every open
// EventSource on each reload — noise that buries genuine errors, and the console is
// the only place a runtime fault in this page shows up.
window.addEventListener('pagehide', () => {
  panes.forEach((rec) => {
    rec.disposed = true;
    try { if (rec.source) rec.source.close(); } catch (_) {}
  });
});
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && focused !== null) { focused = null; applyFocus(); }
});

// The view scripts load first and subscribe once to this synchronous event.
// Register before restoring the saved view, including on a reload into a tab.
//
// ORDER MATTERS. collectTabs() must run before ccc:ready, because registerPanel
// refuses a view it has not collected - and the scripts that call it are already
// loaded and waiting on that event. applyBuiltinPanels() then fills in the panels
// app.js owns itself.
initCollapsibles();
collectTabs();
applyBuiltinPanels();

window.CCC = { el, getJSON, post, say, deleteButton, collapsible, settingEditor,
               registerView, registerPanel, registerCard, publishRows, download,
               stateChip, initCollapsibles,
               // Live-agent marking, for the views drawn by their own scripts.
               markAgent, refreshLiveMarks, isLiveAgent, focusAgent };
window.dispatchEvent(new Event('ccc:ready'));

// A VIEW SCRIPT THAT DID NOT LOAD MUST SAY SO.
//
// Every panel on this page is drawn by a script that registers itself on the event
// above. If one of those files never reaches the browser, nothing registers, its
// panel renders nothing, and there is no error anywhere an operator would look -
// the page appears to work, with two cards inexplicably blank.
//
// The way that actually happens: server.py serves static files from an ALLOWLIST,
// so a new .js file is invisible until it is added there and the server is
// restarted. A page whose HTML is newer than the process serving it therefore asks
// for scripts that come back as a JSON 404, which the browser refuses to execute.
// The inline listener at the top of index.html records exactly that, and this turns
// it into the one sentence that names the problem and the fix.
if (Array.isArray(window.CCC_SCRIPT_ERRORS) && window.CCC_SCRIPT_ERRORS.length) {
  const missing = [...new Set(window.CCC_SCRIPT_ERRORS)];
  holdBanner(`Some panels will be empty: ${missing.join(', ')} did not load. `
    + `This usually means the dashboard server is an older process than the files `
    + `on disk — restart it (dashboard/restart.sh), then reload this page.`);
  console.error('CCC: view scripts failed to load:', missing.join(', '));
}

if (!window.Terminal) {
  // Sticky: a missing xterm does not become present because the backend answered.
  holdBanner('xterm.js failed to load from vendor/ — terminals cannot render.');
} else {
  loadPrefs();
  wireRibbon();
  applyUiScale();
  loadThemes();
  let startView = 'terminals';
  try { startView = localStorage.getItem(VIEW_KEY) || 'terminals'; } catch (_) {}
  showView(startView);
  ensureSharedStream(false);
  refreshQueueBadge();
  // Slower than POLL_MS: it merges files on every call, and unread traffic is not
  // something you need sub-second.
  // Ticking `follow` must act NOW. Waiting for the next frame of output means an
  // idle agent shows no response at all, which reads as a dead checkbox.
  if (els.follow) els.follow.addEventListener('change', followAll);
  if (els.queueFollow) {
    els.queueFollow.addEventListener('change', () => {
      if (els.queueFollow.checked && els.queueList && els.queueList.lastElementChild) {
        els.queueList.lastElementChild.scrollIntoView({ block: 'nearest' });
      }
    });
  }

  // ── feed controls ──────────────────────────────────────────────────────────
  loadFeedPrefs();
  if (els.feedFollow) els.feedFollow.addEventListener('change', () => drawFeed());
  if (els.feedSearch) els.feedSearch.addEventListener('input', () => drawFeed());
  if (els.feedClear) els.feedClear.addEventListener('click', () => {
    // Clears the SCREEN only. The journal is append-only, the queue files are the
    // courier's and the dead letters are evidence - none of them are this button's
    // to delete, and a "clear" that quietly destroyed them would be a trap.
    feedEntries = [];
    drawFeed();
    if (els.feedStamp) els.feedStamp.textContent = 'cleared on screen — sources untouched';
  });
  if (els.feedSeverity) els.feedSeverity.addEventListener('change', () => {
    feedPrefs.severity = els.feedSeverity.value; saveFeedPrefs(); drawFeed();
  });
  if (els.feedMax) els.feedMax.addEventListener('change', () => {
    feedPrefs.max = parseInt(els.feedMax.value, 10) || 500; saveFeedPrefs(); loadFeed();
  });
  if (els.feedBadge) els.feedBadge.addEventListener('change', () => {
    feedPrefs.badge = els.feedBadge.checked; saveFeedPrefs(); updateFeedBadge();
  });
  if (els.feedPoll) els.feedPoll.addEventListener('change', () => {
    feedPrefs.poll = parseInt(els.feedPoll.value, 10) || 0;
    saveFeedPrefs();
    // Restart on the new interval, without re-running the whole view.
    if (panelVisible('status', 'feed')) showPanel('status', 'feed');
  });

  // The feed is polled in the background at a slow floor even when it is not the
  // visible view, because the whole point of the badge is to tell you a fault landed
  // while you were looking somewhere else. Faults-only would be cheaper, but the
  // endpoint is one cached call and the badge needs the same data the view draws.
  setInterval(() => { if (!panelVisible('status', 'feed')) loadFeed(); }, 30000);
  loadFeed();

  setInterval(refreshQueueBadge, 10000);
  composeSpawnCmd();
  applyLayoutPrefs();
  tick();
  setInterval(tick, POLL_MS);
}
