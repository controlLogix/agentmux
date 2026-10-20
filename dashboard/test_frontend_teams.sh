#!/usr/bin/env bash
# Dependency-free DOM checks using the real shared settingEditor; no board writes.
set -euo pipefail
if ! command -v node >/dev/null 2>&1; then
  teams_node_dir=$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)
  [ -z "$teams_node_dir" ] || export PATH="$teams_node_dir:$PATH"
fi
if ! command -v node >/dev/null 2>&1; then
  echo 'FAIL: node is required for Teams frontend checks'
  echo 'passed 0, failed 1'
  exit 1
fi
if node <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const componentPaths = [...fs.readFileSync('dashboard/index.html', 'utf8').matchAll(/<script src="(src\/components\/[^"]+)"/g)].map(match => match[1]);
const source = [...componentPaths, 'src/features/teams.js', 'teams.js']
  .map(path => fs.readFileSync('dashboard/' + path, 'utf8')).join('\n');
const app = fs.readFileSync('dashboard/app.js', 'utf8');
const html = fs.readFileSync('dashboard/index.html', 'utf8');
const server = fs.readFileSync('dashboard/server.py', 'utf8');
assert.match(source, /async function loadTeams\(/);
// Teams is a TAB of Organization now, not a view of its own.
assert.match(source, /window\.CCC\.registerPanel\('organization', 'teams', loadTeams\)/);
assert.match(app, /VIEW_LOADERS\[name\] = loader/);
for (const pattern of [/src="teams.js"/, /href="teams.css"/, /id="viewTeams"/,
                       /data-panel="teams"/, /data-tabs="organization"/]) assert.match(html, pattern);
for (const path of ['/teams.js', '/teams.css']) assert.ok(server.includes('"' + path + '"'));
assert.doesNotMatch(source, /innerHTML|setInterval|setTimeout/);
class Node {
  constructor(tag, cls, text) { this.tag = tag; this.cls = cls; this.textContent = text || ''; this.children = []; this.events = {}; this.value = ''; }
  appendChild(node) { this.children.push(node); return node; }
  append(...nodes) { nodes.forEach(node => this.appendChild(node)); }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(key, fn) { this.events[key] = fn; }
}
const root = new Node('section');
const flatten = node => [node, ...node.children.flatMap(flatten)];
const text = node => flatten(node).map(n => n.textContent).join('\n');
const button = label => flatten(root).find(n => n.tag === 'button' && n.textContent === label);
const choice = label => flatten(root).find(n => n['aria-label'] === label);
let ready, loader, failRead = false, failWrite = false, reads = 0, posts = [];
let hireError = '', holdHire = null;
let board = {tasks: [{key: 'TM-051', title: '<img src=x onerror=alert(1)>', status: 'in_progress'}],
  config: {teamMaxAgents: 8, teamMaxWorkers: 0, teamRequireApproval: true, dashboardMayHire: false}};
let members = [{agent_name: 'lead', role: 'lead', status: 'proposed'}, {agent_name: 'review', role: 'reviewer', status: 'proposed'}];
const post = async (url, body) => {
  posts.push({url, body: JSON.parse(JSON.stringify(body))});
  if (failWrite) throw Error('write refused');
  if (url === 'api/board/hire') {
    if (hireError) throw Error(hireError);
    if (holdHire) await holdHire;
    members = members.map(m => m.agent_name === body.name ? {...m, status: 'hired'} : m);
  }
  if (url === 'api/board/approve') members = members.map(m => ({...m, status: body.members.includes(m.agent_name) ? 'approved' : 'rejected', approved_by: 'server-actor'}));
  if (url === 'api/board/recruit') members = members.map(m => ({...m, status: 'proposed', approved_by: null}));
  if (url === 'api/board/config') board.config[body.name] = body.value;
  return {value: body.value, note: 'saved', members: [{agent_name: 'WRONG POST DATA'}]};
};
const context = vm.createContext({
  document: {getElementById: id => { assert.equal(id, 'viewTeams'); return root; }, createElement: tag => new Node(tag)},
  el: (...args) => new Node(...args), say: (node, value) => { node.textContent = value; }, post,
  els: {authStamp: new Node('span')},
  window: {addEventListener: (event, fn, options) => { assert.equal(event, 'ccc:ready'); assert.equal(options.once, true); ready = fn; }}
});
vm.runInContext(app.slice(app.indexOf('function settingEditor('), app.indexOf('// Non-secret settings')), context);
context.window.CCC = {
  el: context.el, say: context.say, post, settingEditor: context.settingEditor,
  getJSON: async url => {
    reads++;
    if (failRead) throw Error('offline');
    if (url === 'api/board/board') return board;
    if (url === 'api/board/agents') return {agents: [{name: 'bundled-lead', role: 'lead'}, {name: 'project-lead', role: 'lead'}, {name: 'worker', role: 'worker'}]};
    assert.equal(url, 'api/board/roster?id=TM-051');
    return {members, gaps: ['Capability <img src=x onerror=alert(2)>: no definition provides it']};
  },
  markAgent: (node, name) => { if (node && name) node.dataset = {agent: name}; return node; },
  refreshLiveMarks: () => {},
  registerPanel: (view, name, fn) => {
    assert.equal(view, 'organization'); assert.equal(name, 'teams'); loader = fn;
  }
};
vm.runInContext(source, context);
(async () => {
  assert.equal(reads, 0);
  ready(); await loader();
  assert.ok(text(root).includes('<img src=x onerror=alert(1)>'));
  assert.ok(text(root).includes('Roster gap: Capability <img src=x onerror=alert(2)>: no definition provides it'));
  assert.equal(flatten(root).filter(n => n.tag === 'img').length, 0);
  members[0].definitionState = 'changed';
  members[1].definitionState = 'approval_required';
  await loader();
  assert.match(text(root), /Definition changed; this roster keeps its saved revision/);
  assert.match(text(root), /Propose and approve this roster again before hiring/);
  members[1].definitionState = 'unavailable';
  await loader();
  assert.match(text(root), /Definition unavailable; this roster keeps its saved revision/);
  assert.equal(button('Save roster decision').disabled, true);
  choice('Approve lead').events.click();
  assert.equal(button('Save roster decision').disabled, true);
  choice('Reject review').events.click();
  assert.equal(button('Save roster decision').disabled, false);
  failWrite = true;
  await button('Save roster decision').events.click();
  assert.match(text(root), /write refused/);
  assert.equal(button('Save roster decision').disabled, false);
  assert.equal(members[0].status, 'proposed');
  failWrite = false;
  const before = reads;
  await button('Save roster decision').events.click();
  assert.deepEqual(posts.at(-1), {url: 'api/board/approve', body: {id: 'TM-051', members: ['lead']}});
  assert.equal(reads, before + 3);
  assert.match(text(root), /approved/); assert.match(text(root), /rejected/);
  assert.match(text(root), /server-actor/); assert.doesNotMatch(text(root), /WRONG POST DATA/);
  assert.equal(choice('Approve lead'), undefined);
  const settings = () => root.children[1].children[0].children.slice(1);
  assert.equal(settings().length, 4);
  assert.equal(settings()[1].children[1].value, '0');
  assert.equal(settings()[3].children[1].value, 'false');
  for (const [index, key, value] of [[0, 'teamMaxAgents', 12], [1, 'teamMaxWorkers', 3], [2, 'teamRequireApproval', false], [3, 'dashboardMayHire', true]]) {
    const row = settings()[index]; row.children[1].value = String(value);
    await row.children[2].events.click();
    assert.deepEqual(posts.at(-1), {url: 'api/board/config', body: {name: key, value}});
    assert.equal(settings()[index].children[1].value, String(value));
  }
  for (const [index, value] of [[0, '33'], [1, '-1'], [1, '1.5'], [2, 'yes']]) {
    const row = settings()[index]; row.children[1].value = value;
    const count = posts.length; await row.children[2].events.click(); assert.equal(posts.length, count);
    assert.equal(row.children[2].disabled, false);
  }
  // The default auth path still works through the same implementation.
  let after = 0;
  const auth = context.settingEditor('provider', {key: 'model', value: 'old'}, async () => { after++; });
  auth.children[1].value = 'new'; await auth.children[2].events.click();
  assert.deepEqual(posts.at(-1), {url: 'api/auth/setting', body: {method: 'provider', key: 'model', value: 'new'}});
  assert.equal(after, 1);
  await button('Re-propose roster').events.click();
  choice('Reject lead').events.click(); choice('Reject review').events.click();
  failRead = true;
  await button('Save roster decision').events.click();
  assert.deepEqual(posts.at(-1).body.members, []);
  assert.match(text(root), /Saved, but refresh failed/);
  assert.equal(button('Save roster decision').disabled, true);
  await button('Refresh').events.click(); assert.match(text(root), /out of date/);
  failRead = false;
  await button('Refresh').events.click(); assert.equal(choice('Approve lead'), undefined);
  // Only approved members of open cards can be hired, and configuration gates
  // the control. Hiring needs no decision actor and sends no launch parameters.
  members = ['proposed', 'approved', 'rejected', 'hired', 'finished'].map(status => ({agent_name: status, role: 'worker', status}));
  board.config.dashboardMayHire = false;
  await loader(); assert.equal(button('Hire'), undefined);
  delete board.config.dashboardMayHire;
  await loader(); assert.equal(button('Hire'), undefined);
  board.config.dashboardMayHire = true;
  await loader();
  assert.equal(flatten(root).filter(n => n.textContent === 'Hire').length, 1);
  assert.ok(choice('Hire approved'));
  board.tasks[0].status = 'done'; await loader(); assert.equal(button('Hire'), undefined);
  board.tasks[0].status = 'in_progress'; await loader();
  // These are the server's actual refusal reasons, not fabricated status codes.
  // Posture is clamped by the server, so it does not emit a posture refusal.
  const backend = fs.readFileSync('dashboard/boardteams.py', 'utf8');
  const reasons = [
    'hire requires an approved roster row on an open card',
    'dashboardMayHire and dispatchEnabled must both be enabled',
    'dashboard hire slots exhausted',
    'approved definition snapshot is unavailable',
    'dashboard hiring requires a 127.0.0.1 listener',
    'agent spawn failed'
  ];
  const rendered = new Set();
  for (const reason of reasons) {
    assert.ok(backend.includes(reason));
    hireError = reason;
    const count = posts.length;
    await choice('Hire approved').events.click();
    assert.equal(posts.length, count + 1);
    assert.deepEqual(posts.at(-1), {url: 'api/board/hire', body: {id: 'TM-051', name: 'approved'}});
    const message = flatten(root).find(n => n.textContent.startsWith('Hire failed:')).textContent;
    assert.ok(message.includes(reason)); rendered.add(message);
    assert.equal(choice('Hire approved').disabled, undefined);
    assert.equal(members[1].status, 'approved');
  }
  assert.equal(rendered.size, reasons.length);
  hireError = '';
  let releaseHire;
  holdHire = new Promise(resolve => { releaseHire = resolve; });
  const hireButton = choice('Hire approved');
  const count = posts.length, beforeHireReads = reads;
  const pending = hireButton.events.click();
  assert.equal(hireButton.disabled, true);
  assert.equal(button('Refresh').disabled, true);
  await hireButton.events.click(); assert.equal(posts.length, count + 1);
  releaseHire(); await pending; holdHire = null;
  assert.equal(reads, beforeHireReads + 3);
  assert.equal(choice('Hire approved'), undefined);
  assert.equal(members[1].status, 'hired');
  assert.doesNotMatch(text(root), /WRONG POST DATA/);
  members[1].status = 'approved'; await loader();
  failRead = true;
  await choice('Hire approved').events.click();
  assert.match(text(root), /Hired, but refresh failed/);
  assert.equal(choice('Hire approved').disabled, true);
  failRead = false; await loader(); assert.equal(choice('Hire approved'), undefined);
  members = []; await loader(); assert.match(text(root), /No roster proposed/);
  const leadChoice = flatten(root).find(n => n['aria-label'] === 'Lead definition for TM-051');
  assert.equal(leadChoice.value, '');
  assert.equal(leadChoice.children[0].value, '');
  assert.deepEqual(leadChoice.children.slice(1).map(n => n.value), ['bundled-lead', 'project-lead']);
  leadChoice.value = 'project-lead';
  await button('Propose roster').events.click();
  assert.deepEqual(posts.at(-1), {url: 'api/board/recruit', body: {id: 'TM-051', lead: 'project-lead'}});

  assert.ok(button('Propose roster'));
  board.tasks[0].status = 'done'; await loader(); assert.equal(button('Propose roster'), undefined);
  board.tasks = []; await loader(); assert.match(text(root), /No task cards/);
  console.log('PASS: Teams loader/registry, enrolled decisions, settings, id/name-only hire, permission/status gates, six distinct API refusals, duplicate guard, server re-read and refresh failure');
})().catch(error => { console.error(error); process.exitCode = 1; });
JS
then
  echo 'passed 1, failed 0'
else
  echo 'passed 0, failed 1'
  exit 1
fi
