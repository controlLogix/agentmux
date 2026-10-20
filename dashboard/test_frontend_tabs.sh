#!/usr/bin/env bash
# The sub-tab machinery that Status, Board and Organization are built on, plus the
# Status export. Runs the PRODUCTION functions out of app.js against a DOM stub -
# not a copy of them - so a change to the real code is what makes this fail.
#
# WHAT IT IS PROTECTING. Four views that used to be four top-level views are now
# four tabs of one, and the rule that keeps that safe is that only the visible tab
# polls. Two of those tabs reach equipment (the IIOT cards do the same thing one
# level along), so a tab that keeps its timer after you switch away is not untidy,
# it is a dashboard quietly talking to a PLC nobody is watching. Half these tests
# are about timers being stopped.
set -euo pipefail
if ! command -v node >/dev/null 2>&1; then
  tabs_node_dir=$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)
  [ -z "$tabs_node_dir" ] || export PATH="$tabs_node_dir:$PATH"
fi
node <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const app = fs.readFileSync('dashboard/app.js', 'utf8');
const html = fs.readFileSync('dashboard/index.html', 'utf8');

const slice = (from, to) => {
  const start = app.indexOf(from);
  assert.ok(start >= 0, 'missing anchor: ' + from);
  const end = app.indexOf(to, start);
  assert.ok(end > start, 'missing anchor: ' + to);
  return app.slice(start, end);
};
const tabs = slice('const VIEW_TABS = {};', 'let viewTimer = null;');
const exporter = slice('const statusRows = {', '// ═══════════════════════════════════════════════════════════ message queue');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('PASS ' + name); }
  catch (e) { failed++; console.error('FAIL ' + name, e && e.message); }
}

class El {
  constructor(tag, dataset = {}) {
    this.tag = tag; this.dataset = dataset; this.hidden = false; this.children = [];
    this.events = {}; this.tabIndex = 0; this.focused = 0; this.attrs = {};
    this.classes = new Set();
    this.classList = {
      toggle: (n, on) => { on ? this.classes.add(n) : this.classes.delete(n); },
      contains: (n) => this.classes.has(n),
    };
  }
  addEventListener(type, fn) { (this.events[type] = this.events[type] || []).push(fn); }
  setAttribute(k, v) { this.attrs[k] = v; }
  focus() { this.focused++; }
  querySelectorAll() { return this.children; }
  click() { (this.events.click || []).forEach(fn => fn()); }
  key(k) { (this.events.keydown || []).forEach(fn => fn({key: k, preventDefault(){}})); }
}

// The markup is the contract, so the fixture is BUILT FROM index.html rather than
// hand-written: a tab renamed in the markup and not here would otherwise pass.
function tabsFromMarkup() {
  const out = {};
  for (const block of html.split('data-tabs="').slice(1)) {
    const view = block.slice(0, block.indexOf('"'));
    const panels = [...block.slice(0, block.indexOf('</div>')).matchAll(/data-panel="([^"]+)"/g)]
      .map(m => m[1]);
    out[view] = panels;
  }
  return out;
}
const MARKUP = tabsFromMarkup();

function page(markup = MARKUP, view = 'status') {
  const panels = {}, lists = [];
  for (const [name, ids] of Object.entries(markup)) {
    const list = new El('div', {tabs: name});
    list.children = ids.map(id => {
      const button = new El('button', {panel: id});
      panels['view' + id[0].toUpperCase() + id.slice(1)] = new El('div');
      return button;
    });
    lists.push(list);
  }
  const store = new Map();
  const timers = new Map();
  let nextTimer = 1;
  const ctx = {
    document: {
      querySelectorAll: (selector) => selector === '[data-tabs]' ? lists : [],
      getElementById: (id) => panels[id] || null,
      createElement: (tag) => new El(tag),
      body: {appendChild(){}, },
    },
    els: {views: Object.fromEntries(Object.keys(markup).map(v => [v, new El('section')])),
          statusExport: new El('button'), statusExportAs: new El('select'),
          statusStamp: new El('span')},
    currentView: view,
    feedPrefs: {poll: 5000},
    // BUILTIN_PANELS names the loaders app.js owns; the slice evaluates that table
    // at module scope, so they have to exist. They are never called here -
    // applyBuiltinPanels() is deliberately not run, so every panel starts with no
    // loader and each test registers exactly the one it is about.
    loadFeed() {}, loadQueue() {}, loadJournal() {}, loadBoard() {}, loadTickets() {},
    say: (node, text) => { node.textContent = text; },
    console,
    setInterval: (fn, ms) => { const id = nextTimer++; timers.set(id, {fn, ms}); return id; },
    // Deferred work is a legitimate thing for a view script to do - runs.js
    // delays its first background poll so it does not compete with the page's
    // own load - and without this stub the sandbox threw on registration.
    // Never fired: this harness tests that scripts REGISTER cleanly.
    setTimeout: (fn, ms) => { const id = nextTimer++; timers.set(id, {fn, ms}); return id; },
    clearTimeout: (id) => timers.delete(id),
    clearInterval: (id) => timers.delete(id),
    clearInterval: (id) => { timers.delete(id); },
    requestAnimationFrame: (fn) => fn(),
    localStorage: {
      getItem: (k) => store.has(k) ? store.get(k) : null,
      setItem: (k, v) => store.set(k, v),
    },
    URL: {createObjectURL: () => 'blob:x', revokeObjectURL() {}},
    Blob: class { constructor(parts, opts) { this.parts = parts; this.type = opts && opts.type; } },
    Date,
    JSON,
    Object,
    Array,
    Number,
  };
  ctx.els.statusExportAs.value = 'json';
  vm.createContext(ctx);
  vm.runInContext(exporter, ctx);
  vm.runInContext(tabs, ctx);
  ctx.collectTabs();
  // VIEW_TABS is a `const`, and a const in a vm script is lexically scoped rather
  // than a property of the context object - so it cannot be read as ctx.VIEW_TABS.
  // Evaluating the identifier inside the same context is how you reach it, and it
  // reads the real registry rather than a copy.
  const registry = () => vm.runInContext('VIEW_TABS', ctx);
  return {ctx, panels, timers, store, lists, registry};
}

// ── the markup and the machinery agree ──────────────────────────────────────

test('every tabbed view in the markup is collected', () => {
  const p = page();
  assert.deepEqual(Object.keys(p.registry()).sort(), Object.keys(MARKUP).sort());
  for (const [view, ids] of Object.entries(MARKUP)) {
    // Spread into this realm first: an array built inside the vm has a different
    // Array.prototype, and deepStrictEqual compares prototypes.
    assert.deepEqual([...p.registry()[view].order], ids);
  }
});

test('Status carries all four consolidated streams and Board carries Atlassian', () => {
  assert.deepEqual(MARKUP.status, ['feed', 'queue', 'journal', 'chatter']);
  assert.deepEqual(MARKUP.board, ['boardtasks', 'tickets', 'kanban']);
  assert.deepEqual(MARKUP.organization, ['agents', 'teams']);
});

test('the first tab is active until one is remembered', () => {
  const p = page();
  assert.equal(p.registry().status.active, 'feed');
  const q = page();
  q.store.set('ccc.tab.v1', JSON.stringify({status: 'journal'}));
  q.ctx.collectTabs();
  assert.equal(q.registry().status.active, 'journal');
});

test('a remembered tab that no longer exists falls back rather than breaking', () => {
  const p = page();
  p.store.set('ccc.tab.v1', JSON.stringify({status: 'gone'}));
  p.ctx.collectTabs();
  assert.equal(p.registry().status.active, 'feed');
});

// ── only the visible tab is shown, and only it polls ────────────────────────

test('showing a panel hides every sibling and marks the button selected', () => {
  const p = page();
  p.ctx.showPanel('status', 'queue');
  assert.equal(p.panels.viewQueue.hidden, false);
  for (const id of ['viewFeed', 'viewJournal', 'viewChatter']) {
    assert.equal(p.panels[id].hidden, true, id + ' should be hidden');
  }
  const buttons = p.registry().status.panels;
  assert.equal(buttons.queue.button.attrs['aria-selected'], 'true');
  assert.equal(buttons.feed.button.attrs['aria-selected'], 'false');
  assert.equal(buttons.queue.button.tabIndex, 0);
  assert.equal(buttons.feed.button.tabIndex, -1);
  assert.ok(buttons.queue.button.classes.has('active'));
});

test('switching tabs stops the outgoing tab timer and starts only the incoming one', () => {
  const p = page();
  p.ctx.registerPanel('status', 'queue', () => {}, 5000);
  p.ctx.registerPanel('status', 'chatter', () => {}, 1000);
  p.ctx.showPanel('status', 'queue');
  assert.equal(p.timers.size, 1);
  assert.equal([...p.timers.values()][0].ms, 5000);
  p.ctx.showPanel('status', 'chatter');
  assert.equal(p.timers.size, 1, 'the queue poll must not survive the switch');
  assert.equal([...p.timers.values()][0].ms, 1000);
  p.ctx.stopPanels('status');
  assert.equal(p.timers.size, 0);
});

test('a panel with no interval loads once and starts no timer', () => {
  const p = page();
  let calls = 0;
  p.ctx.registerPanel('status', 'journal', () => { calls++; }, 0);
  p.ctx.showPanel('status', 'journal');
  assert.equal(calls, 1);
  assert.equal(p.timers.size, 0);
});

test("the feed reads the operator's interval at open time, not at registration", () => {
  const p = page();
  p.ctx.registerPanel('status', 'feed', () => {}, 999999);
  p.ctx.feedPrefs.poll = 2000;
  p.ctx.showPanel('status', 'feed');
  assert.equal([...p.timers.values()][0].ms, 2000);
});

test('a tab can be shown without loading it', () => {
  const p = page();
  let calls = 0;
  p.ctx.registerPanel('status', 'queue', () => { calls++; }, 5000);
  p.ctx.showPanel('status', 'queue', {load: false});
  assert.equal(calls, 0);
  assert.equal(p.timers.size, 0);
});

test('the chosen tab is remembered per view, not globally', () => {
  const p = page();
  p.ctx.showPanel('status', 'journal');
  p.ctx.showPanel('board', 'tickets');
  assert.deepEqual(JSON.parse(p.store.get('ccc.tab.v1')),
                   {status: 'journal', board: 'tickets'});
});

test('arrow keys move along the tab strip and wrap', () => {
  const p = page();
  const buttons = p.registry().status.panels;
  buttons.feed.button.key('ArrowLeft');
  assert.equal(p.registry().status.active, 'chatter');
  buttons.chatter.button.key('ArrowRight');
  assert.equal(p.registry().status.active, 'feed');
  buttons.feed.button.key('Enter');
  assert.equal(p.registry().status.active, 'feed', 'other keys do nothing');
});

test('clicking a tab button shows it', () => {
  const p = page();
  p.registry().status.panels.chatter.button.click();
  assert.equal(p.registry().status.active, 'chatter');
});

// ── registration refuses to half-apply ──────────────────────────────────────

test('registerPanel refuses an unknown view, panel, loader or interval', () => {
  const p = page();
  assert.throws(() => p.ctx.registerPanel('nope', 'feed', () => {}), /No tabbed view/);
  assert.throws(() => p.ctx.registerPanel('status', 'nope', () => {}), /Missing panel/);
  assert.throws(() => p.ctx.registerPanel('status', 'Feed', () => {}), /Invalid panel name/);
  assert.throws(() => p.ctx.registerPanel('status', 'feed', 'nope'), /must be a function/);
  assert.throws(() => p.ctx.registerPanel('status', 'feed', () => {}, -1), /non-negative/);
  assert.equal(p.registry().status.panels.feed.loader, null, 'nothing was applied');
});

// ── cards: several per view, and they stop with the view ────────────────────

test('several scripts register cards on one view and all of them run', () => {
  const p = page();
  const ran = [];
  p.ctx.registerCard('status', () => ran.push('a'), 0);
  p.ctx.registerCard('status', () => ran.push('b'), 1000);
  p.ctx.startCards('status');
  assert.deepEqual(ran, ['a', 'b']);
  assert.equal(p.timers.size, 1, 'only the card that asked for a poll gets one');
  p.ctx.stopCards('status');
  assert.equal(p.timers.size, 0);
});

test('one card throwing does not stop the others on the same view', () => {
  const p = page();
  const ran = [];
  p.ctx.registerCard('status', () => { throw new Error('boom'); }, 0);
  p.ctx.registerCard('status', () => ran.push('b'), 0);
  const errors = [];
  p.ctx.console = {error: (...args) => errors.push(args)};
  p.ctx.startCards('status');
  assert.deepEqual(ran, ['b']);
  assert.equal(errors.length, 1);
});

test('registerCard refuses an unknown view or a bad interval', () => {
  const p = page();
  assert.throws(() => p.ctx.registerCard('nope', () => {}), /No such view/);
  assert.throws(() => p.ctx.registerCard('status', () => {}, -5), /non-negative/);
  assert.throws(() => p.ctx.registerCard('status', 'nope'), /must be a function/);
});

// ── export writes what is on screen, and only that ──────────────────────────

test('export is disabled until the active tab has rows', () => {
  const p = page();
  p.ctx.updateStatusExport();
  assert.equal(p.ctx.els.statusExport.disabled, true);
  p.ctx.publishRows('feed', [{a: 1}, {a: 2}]);
  assert.equal(p.ctx.els.statusExport.disabled, false);
  assert.equal(p.ctx.els.statusExport.textContent, 'export 2');
});

test('export follows the ACTIVE tab, not whichever published last', () => {
  const p = page();
  p.ctx.publishRows('feed', [{a: 1}]);
  p.ctx.publishRows('journal', [{a: 1}, {a: 2}, {a: 3}]);
  assert.equal(p.ctx.els.statusExport.textContent, 'export 1', 'feed is active');
  p.ctx.showPanel('status', 'journal');
  assert.equal(p.ctx.els.statusExport.textContent, 'export 3');
});

test('export is unavailable from a view that is not Status', () => {
  const p = page(MARKUP, 'board');
  p.ctx.publishRows('feed', [{a: 1}]);
  assert.equal(p.ctx.els.statusExport.disabled, true);
});

test('CSV takes the union of the columns, in first-seen order, and quotes properly', () => {
  const p = page();
  const csv = p.ctx.toCSV([
    {at: '1', text: 'plain'},
    {at: '2', text: 'has,comma', who: 'a"b'},
    {at: '3', extra: {nested: true}},
  ]);
  const lines = csv.trimEnd().split('\r\n');
  assert.equal(lines[0], 'at,text,who,extra');
  assert.equal(lines[1], '1,plain,,');
  assert.equal(lines[2], '2,"has,comma","a""b",');
  assert.equal(lines[3], '3,,,"{""nested"":true}"');
});

test('a JSON export carries the tab, a timestamp and the rows as shown', () => {
  const p = page();
  const written = [];
  p.ctx.download = (name, text, type) => written.push({name, text, type});
  p.ctx.publishRows('feed', [{at: 'x', text: 'one'}]);
  p.ctx.exportStatus();
  assert.equal(written.length, 1);
  assert.match(written[0].name, /^ccc-feed-.*\.json$/);
  assert.equal(written[0].type, 'application/json');
  const body = JSON.parse(written[0].text);
  assert.equal(body.tab, 'feed');
  assert.deepEqual(body.rows, [{at: 'x', text: 'one'}]);
  assert.ok(body.exported_at);
  assert.equal(p.ctx.els.statusStamp.textContent, 'exported 1 feed row(s)');
});

test('exporting nothing writes nothing', () => {
  const p = page();
  let calls = 0;
  p.ctx.download = () => { calls++; };
  p.ctx.exportStatus();
  assert.equal(calls, 0);
});

// ── the boot sequence, with the real view scripts ───────────────────────────
//
// WHY THIS IS HERE. Eight scripts subscribe once to a synchronous `ccc:ready` and
// register themselves into the registries above. If any one of them throws while
// doing it - a renamed id, a registration naming a view that no longer exists -
// the page does not degrade, it stops: the listeners after it never run and the
// dashboard comes up with empty views and one line in a console nobody has open.
// Nothing else in this suite would catch that, because every other test calls the
// production functions directly instead of letting the scripts find them.

function bootFixture() {
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map(m => m[1]));
  const made = new Map();
  const element = (id) => {
    if (!made.has(id)) {
      const node = new El('div');
      node.id = id;
      node.replaceChildren = () => {};
      node.appendChild = (n) => n;
      node.append = () => {};
      node.querySelector = () => null;
      made.set(id, node);
    }
    return made.get(id);
  };
  const lists = [];
  for (const [view, panels] of Object.entries(MARKUP)) {
    const list = new El('div', {tabs: view});
    list.children = panels.map(id => new El('button', {panel: id}));
    lists.push(list);
  }
  const cards = new Map();
  for (const m of html.matchAll(/data-collapse-key="([^"]+)"/g)) {
    cards.set(m[1], new El('details', {collapseKey: m[1]}));
  }
  return {ids, element, lists, cards, made};
}

test('every view script registers itself without throwing', () => {
  const fixture = bootFixture();
  const ready = [];
  const registered = {panels: [], cards: [], views: []};
  const store = new Map();

  const ctx = {
    console,
    document: {
      getElementById: (id) => fixture.ids.has(id) ? fixture.element(id) : null,
      querySelectorAll: (selector) => selector === '[data-tabs]' ? fixture.lists : [],
      querySelector: (selector) => {
        const m = /data-collapse-key="([^"]+)"/.exec(selector);
        return (m && fixture.cards.get(m[1])) || null;
      },
      createElement: (tag) => new El(tag),
      body: {appendChild() {}},
      activeElement: null,
    },
    els: {views: {}},
    currentView: 'terminals',
    feedPrefs: {poll: 5000},
    // BUILTIN_PANELS is evaluated at module scope; see the note in page().
    loadFeed() {}, loadQueue() {}, loadJournal() {}, loadBoard() {}, loadTickets() {},
    // registerView writes into these two, which live further up app.js.
    VIEW_LOADERS: {}, VIEW_POLL_MS: {},
    say: () => {},
    setInterval: () => 1,
    setTimeout: () => 1,
    clearTimeout: () => {},
    clearInterval: () => {},
    clearInterval: () => {},
    requestAnimationFrame: (fn) => fn(),
    localStorage: {getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v)},
    URL: {createObjectURL: () => '', revokeObjectURL() {}},
    Blob: class {},
    navigator: {clipboard: {writeText: async () => {}}},
    fetch: async () => ({ok: true, json: async () => ({})}),
    Date, JSON, Object, Array, Number, Promise, Map, Set, RegExp, Error, TypeError, String,
  };
  // The seven top-level view sections, as index.html declares them.
  for (const m of html.matchAll(/<section id="view([A-Za-z]+)" class="view/g)) {
    const name = m[1][0].toLowerCase() + m[1].slice(1);
    ctx.els.views[name] = new El('section');
  }
  ctx.window = {
    addEventListener: (type, fn) => { if (type === 'ccc:ready') ready.push(fn); },
  };
  vm.createContext(ctx);
  vm.runInContext(exporter, ctx);
  vm.runInContext(tabs, ctx);
  ctx.collectTabs();

  // The real registrars, wrapped so the test can see what each script asked for.
  ctx.window.CCC = {
    el: (tag, cls, text) => { const n = new El(tag); n.textContent = text; return n; },
    getJSON: async () => ({}),
    post: async () => ({}),
    say: () => {},
    collapsible: () => new El('details'),
    deleteButton: () => new El('button'),
    settingEditor: () => new El('div'),
    publishRows: () => {},
    download: () => {},
    stateChip: () => new El('span'),
    initCollapsibles: () => {},
    registerPanel: (view, name, fn, ms) => {
      registered.panels.push([view, name]);
      return ctx.registerPanel(view, name, fn, ms);
    },
    registerCard: (view, fn, ms) => {
      registered.cards.push(view);
      return ctx.registerCard(view, fn, ms);
    },
    registerView: (name, fn, ms) => {
      registered.views.push(name);
      return ctx.registerView(name, fn, ms);
    },
  };

  // IN THE ORDER index.html LOADS THEM, and `ccc:ready` fires where app.js sits -
  // which is what app.js does on its last line. The first version of this test used
  // its own array and dispatched afterwards, so it booted a page that does not
  // exist: the real page had iiot.js, mqtt.js and netscan.js BELOW app.js, where the
  // event has already fired, and four IIOT panels silently never rendered. A fixture
  // that invents its own load order cannot catch a load-order bug.
  const order = [...html.matchAll(/<script src="([A-Za-z0-9_/.+-]+\.js)"><\/script>/g)]
    .map(m => m[1]).filter(name => !name.startsWith('vendor/'));
  const scripts = order.filter(name => name !== 'app.js');
  const subscribers = scripts.filter(name => fs.readFileSync('dashboard/' + name, 'utf8').includes("'ccc:ready'"));
  let dispatched = false;
  for (const name of order) {
    if (name === 'app.js') {
      // Synchronous, exactly as app.js dispatches it: one throw stops the rest.
      for (const fn of ready) fn();
      dispatched = true;
      continue;
    }
    vm.runInContext(fs.readFileSync('dashboard/' + name, 'utf8'), ctx, {filename: name});
  }
  assert.ok(dispatched, 'app.js is in the load order');
  assert.equal(ready.length >= subscribers.length, true,
               `only ${ready.length} scripts subscribed to ccc:ready`);

  assert.deepEqual(registered.panels.sort(), [
    ['board', 'kanban'], ['organization', 'agents'], ['organization', 'teams'], ['status', 'chatter'],
  ].sort(), 'Kanban, Agents, Teams and Chatter must land as tabs');
  // Runs is a VIEW rather than a fifth Status tab, and that was a real choice: a tab
  // would have to share the Status column with the feed and cramp the per-run job
  // table, which is the thing you go there to read. The cost is one more rail entry.
  // Hub (TM-216) is a view for the same reason: three tables and a live feed.
  // Federation (EP-032) is a view too: status, quarantine, peers and one card per plugin.
  assert.deepEqual(registered.views.sort(), ['fed', 'github', 'hub', 'runs'],
                   'Federation, GitHub, Hub and Runs are the views registered by their own scripts');
  // Five IIOT field cards plus the Settings > Orchestration card, which runs.js
  // registers so that app.js and teams.js do not have to change to gain it.
  assert.deepEqual(registered.cards.slice().sort(),
                   ['iiot', 'iiot', 'iiot', 'iiot', 'iiot', 'settings'],
                   'five IIOT cards and one Settings card');
  // Superseded by the deepEqual above, which names every card and its view - a
  // strictly stronger check than 'they are all iiot', and one that does not have
  // to be relaxed each time a card lands on another view.

  // And the registries actually took them.
  const registry = vm.runInContext('VIEW_TABS', ctx);
  assert.ok(registry.board.panels.kanban.loader, 'kanban has a loader');
  assert.equal(registry.board.panels.kanban.pollMs, 0, 'kanban never polls mid-drag');
  assert.ok(registry.status.panels.chatter.loader, 'chatter has a loader');
  assert.equal(registry.status.panels.chatter.pollMs, 5000);
  assert.ok(registry.organization.panels.agents.loader);
  assert.ok(registry.organization.panels.teams.loader);
  assert.equal(vm.runInContext('VIEW_CARDS', ctx).iiot.length, 5);
});

test('server.py serves every script and stylesheet the page asks for', () => {
  // server.py serves static files from an ALLOWLIST, so a new .js or .css file is
  // a 404 until it is added there - and a 404 comes back as JSON, which the browser
  // refuses to execute under nosniff, so the panel it draws is silently blank. That
  // is a server edit you have to remember to make from a file you are not editing,
  // which is exactly the kind of thing a test should be remembering for you.
  const server = fs.readFileSync('dashboard/server.py', 'utf8');
  const wanted = [
    ...[...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map(m => m[1]),
    ...[...html.matchAll(/<link rel="stylesheet" href="([^"]+)"/g)].map(m => m[1]),
  ];
  assert.ok(wanted.length >= 10, 'found too few assets to be reading the real page');
  for (const asset of wanted) {
    assert.ok(server.includes(`"/${asset}"`),
              `index.html loads ${asset}, but server.py will not serve it`);
  }
});

test('a script that fails to load is reported instead of leaving a blank panel', () => {
  // The listener has to be installed BEFORE the scripts it watches, or it sees
  // nothing; and it has to be capture-phase, because resource errors do not bubble.
  const listenerAt = html.indexOf('CCC_SCRIPT_ERRORS = []');
  assert.ok(listenerAt > 0, 'no script-error listener in the page');
  const firstScript = html.indexOf('<script src="');
  assert.ok(listenerAt < firstScript,
            'the listener is installed after the scripts it is meant to watch');
  assert.match(html.slice(listenerAt, listenerAt + 600), /addEventListener\('error'[\s\S]*?true\)/);
  assert.match(app, /CCC_SCRIPT_ERRORS[\s\S]{0,900}?restart it/);
});

test('every script that waits for ccc:ready is loaded before app.js', () => {
  // app.js dispatches the event synchronously on its last line. Anything loaded
  // after it subscribes to an event that has already fired.
  const order = [...html.matchAll(/<script src="([A-Za-z0-9_/.+-]+\.js)"><\/script>/g)].map(m => m[1]);
  const appAt = order.indexOf('app.js');
  assert.ok(appAt > 0, 'app.js is loaded');
  for (const name of order) {
    if (name === 'app.js' || name.startsWith('vendor/')) continue;
    const source = fs.readFileSync('dashboard/' + name, 'utf8');
    if (!source.includes("'ccc:ready'")) continue;
    assert.ok(order.indexOf(name) < appAt,
              `${name} listens for ccc:ready but loads after app.js, so it never runs`);
  }
});

test('the CODESYS card does not reach a controller until it is opened', () => {
  const source = fs.readFileSync('dashboard/codesys.js', 'utf8');
  // Opening IIOT to look at Modbus must not SSH to every configured target.
  assert.match(source, /if \(!card\.open \|\| loaded\) return;/);
  assert.match(source, /registerCard\('iiot', maybe, 0\)/);
  assert.doesNotMatch(html, /data-collapse-key="iiot:codesys" open/);
});

console.log(`passed ${passed}, failed ${failed}`);
// zero tests is not a pass - see the note in test_frontend_board.sh
process.exitCode = failed || !passed ? 1 : 0;
JS
