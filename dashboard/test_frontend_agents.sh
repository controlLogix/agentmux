#!/usr/bin/env bash
# Dependency-free registration and DOM behaviour checks; no live board writes.
set -euo pipefail
# run_tests.sh invokes this through process substitution from the repo root.
if ! command -v node >/dev/null 2>&1; then
  agents_node_dir=$(ls -d "$HOME"/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -1 || true)
  if [ -n "$agents_node_dir" ]; then
    export PATH="$agents_node_dir:$PATH"
  fi
fi
if ! command -v node >/dev/null 2>&1; then
  # NOT A PASS. This printed "passed 0, failed 0" and exited 0, which run_tests.sh
  # matches as success - so on a box without node the gate went green having checked
  # nothing. The skip line did not start with SKIP at column zero either, so the
  # runner's `grep '^SKIP '` never surfaced it. test_frontend_teams.sh, the sibling
  # doing the same job on the same dependency, has always failed loudly here.
  echo 'FAIL: node is required for Agents frontend checks'
  echo 'passed 0, failed 1'
  exit 1
fi
if node <<'JS'
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const componentPaths = [...fs.readFileSync('dashboard/index.html', 'utf8').matchAll(/<script src="(src\/components\/[^"]+)"/g)].map(match => match[1]);
const source = [...componentPaths, 'src/features/agentDefinitions.js', 'agents.js']
  .map(path => fs.readFileSync('dashboard/' + path, 'utf8')).join('\n');
const app = fs.readFileSync('dashboard/app.js', 'utf8');
const html = fs.readFileSync('dashboard/index.html', 'utf8');
assert.match(source, /async function loadAgents\(/);
// Agents is a TAB of Organization now, not a view of its own.
assert.match(source, /window\.CCC\.registerPanel\('organization', 'agents', loadAgents\)/);
assert.match(app, /VIEW_LOADERS\[name\] = loader/);
assert.match(html, /src="agents.js"/);
assert.match(html, /href="agents.css"/);
assert.match(html, /id="viewAgents"/);
assert.match(html, /data-panel="agents"/);
assert.match(html, /data-tabs="organization"/);
assert.doesNotMatch(source, /innerHTML|createElement|setInterval|VIEW_POLL_MS/);
assert.doesNotMatch(app.match(/const VIEW_POLL_MS = \{[^}]*\}/)[0], /agents/);
class Node {
  constructor(tag, cls, text) { this.tag = tag; this.cls = cls; this.textContent = text || ''; this.children = []; this.events = {}; }
  appendChild(node) { this.children.push(node); return node; }
  replaceChildren(...nodes) { this.children = nodes; }
  setAttribute(key, value) { this[key] = value; }
  addEventListener(key, fn) { this.events[key] = fn; }
}
const root = new Node('section');
const flatten = node => [node, ...node.children.flatMap(flatten)];
const text = node => flatten(node).map(n => n.textContent).join('\n');
let ready, loader, calls = 0, failure;
let confirmed = false, confirms = 0, mutationError, mutationStatus = 409, mutations = [];
const el = (...args) => new Node(...args);
const say = (node, value) => { node.textContent = value; };
const helperContext = {
  el, say, window: {confirm: message => { assert.match(message, /cannot be undone/); confirms++; return confirmed; }},
  post: async () => { throw new Error('Agent delete must not use api/delete'); }
};
vm.createContext(helperContext);
vm.runInContext(app.slice(app.indexOf('function deleteButton('), app.indexOf('// The dispatch strip:')), helperContext);
const deleteButton = helperContext.deleteButton;
let payload = {
  agents: ['repo', 'global', 'claude'].map(scope => ({name: scope + '-agent', scope,
    toolIntent: {desired: ['Read'], denied: ['Write'], hostEnforceable: [], hostEnforceableDenied: [], advisory: ['Read', 'Write']},
    description: '<img src=x onerror=alert(1)>', cli: 'codex', posture: 'read-only', role: 'reviewer', path: '/' + scope + '/agent.md', checksum: 'sha256:original'})),
  problems: [
    {path: '/repo/dup.md', scope: 'repo', error: "duplicate name 'dup'; all entries unusable: /repo/dup.md, /global/dup.md"},
    {path: '/repo/bad.md', scope: 'repo', error: "unknown key 'tool'"},
    {path: '/repo/invalid.md', scope: 'repo', error: 'posture must be valid'}
  ]
};
const context = {
  fetch: async (url, options) => {
    assert.equal(options.method, 'POST');
    assert.equal(options.headers['Content-Type'], 'application/json');
    const body = JSON.parse(options.body);
    mutations.push({url, body});
    if (mutationError) return {ok: false, status: mutationStatus, json: async () => mutationError};
    return {ok: true, json: async () => ({...body, checksum: 'sha256:saved'})};
  },
  document: {getElementById: id => { assert.equal(id, 'viewAgents'); return root; }},
  window: {
    addEventListener: (event, fn, options) => { assert.equal(event, 'ccc:ready'); assert.equal(options.once, true); ready = fn; },
    CCC: {
      el, say, deleteButton,
      post: async (url, body) => {
        body = JSON.parse(JSON.stringify(body));
        mutations.push({url, body});
        if (mutationError) {
          const hints = (mutationError.missing || []).map(item => item.hint).filter(Boolean);
          throw new Error([mutationError.error || `HTTP ${mutationStatus}`, ...hints].join(' · '));
        }
        return {...body, checksum: 'sha256:saved'};
      },
      getJSON: async url => {
        if (failure) throw failure;
        if (url.startsWith('api/board/agents?name=')) {
          const name = decodeURIComponent(url.split('=')[1]);
          return {...payload.agents.find(agent => agent.name === name), persona: 'Full persona\nsecond line',
            model: 'test-model', tools: ['Read', 'Bash'], tools_deny: ['Write'], capabilities: ['review'],
            worktree: 'none', max_instances: 2};
        }
        if (url === 'api/board/profiles') return {projectRoot: '/owned-project', profiles: [{name: '<unsafe>',
          packageId: 'example.survey', role: 'worker', scope: 'project opt-in only', appliesTo: '/owned-project',
          supportedHosts: ['macos-arm64'], client: 'codex', machinePathReviewRequired: true,
          machineReferences: ['C:/old/path'], permissions: {posture: 'unrestricted', tools: ['Read'], toolsDeny: []},
          sourceChecksum: 'sha256:source'}], problems: []};
        assert.equal(url, 'api/board/agents'); calls++; return payload;
      },
      // A definition is a file; an agent is a running process. The view tags the
      // name so the live pass can say which definitions are currently spawned.
      markAgent: (node, name) => { if (node && name) node.dataset = {agent: name}; return node; },
      refreshLiveMarks: () => {},
      registerPanel: (...args) => {
        assert.equal(args[0], 'organization'); assert.equal(args[1], 'agents');
        assert.equal(args.length, 3); loader = args[2];
      }
    }
  }
};
vm.runInNewContext(source, context);
(async () => {
  for (const [tier, name] of [['molecules', 'LabeledField'], ['molecules', 'LeadSelector'], ['molecules', 'RevisionNotice'], ['organisms', 'DefinitionEditor'], ['organisms', 'ProfilePackagePreview']]) {
    await require(process.cwd() + `/dashboard/src/components/${tier}/${name}/${name}.test.js`)({components: context.window.AgentmuxUI, el, say, flatten, assert});
  }
  assert.equal(calls, 0);
  ready();
  await loader();
  const content = root.children.find(node => node.cls === 'agents-content');
  const preview = root.children.find(node => node.cls === 'agents-profile-preview');
  preview.open = true;
  const writesBeforePreview = mutations.length;
  const previewRequest = preview.events.toggle();
  assert.match(text(preview), /Loading profile examples/);
  assert.equal(flatten(preview).find(node => node.cls === 'stamp')['aria-live'], 'polite');
  await previewRequest;
  assert.match(text(preview), /<unsafe>/);
  assert.match(text(preview), /C:\/old\/path/);
  assert.match(text(preview), /explicit local-owner command/);
  assert.match(text(preview), /Requested permissions do not establish grants/);
  assert.equal(flatten(preview).some(node => node.tag === 'button' || node.tag === 'form'), false);
  assert.equal(mutations.length, writesBeforePreview);
  assert.equal(content.children[0].cls, 'agents-problems');
  assert.equal(content.children[1].cls, 'agents-list');
  for (const value of ['/repo/dup.md', '/global/dup.md', "unknown key 'tool'", 'Remove or correct', 'Rename one', 'Correct the reported error']) assert.ok(text(content).includes(value), value);
  assert.equal(flatten(content).filter(n => n.cls === 'agents-definition').length, 3);
  assert.match(text(content), /Requested tools are advisory: Read, Write/);
  assert.match(text(content), /No host enforcement or grant is established/);
  for (const scope of ['repo', 'global', 'claude']) assert.ok(flatten(content).some(n => n.cls === 'agents-scope' && n.textContent === scope));
  for (const value of ['codex', 'read-only', 'reviewer', '<img src=x onerror=alert(1)>']) assert.ok(text(content).includes(value));
  const refresh = root.children[0].children[1];
  const cards = () => flatten(content).filter(n => n.cls === 'agents-definition');
  const open = async details => { details.open = true; await details.events.toggle(); return flatten(details).find(n => n.tag === 'form'); };
  const input = (form, name) => flatten(form).find(n => n.name === name);
  const submit = form => form.events.submit({preventDefault() {}});
  assert.equal(flatten(cards()[2]).filter(n => n.tag === 'button' || n.tag === 'form' || n.tag === 'details').length, 0);
  for (const scope of ['repo', 'global']) {
    const card = cards().find(n => text(n).includes(scope + '-agent'));
    const form = await open(flatten(card).find(n => n.tag === 'details'));
    assert.equal(input(form, 'persona').value, 'Full persona\nsecond line');
    assert.equal(input(form, 'name').disabled, true);
    assert.equal(input(form, 'scope').disabled, true);
    input(form, 'description').value = 'Updated ' + scope;
    await submit(form);
    const saved = mutations.at(-1);
    assert.equal(saved.url, 'api/board/agentdef');
    assert.equal(Object.hasOwn(saved.body, 'actor'), false);
    assert.equal(saved.body.scope, scope);
    assert.equal(saved.body.checksum, 'sha256:original');
    assert.equal(saved.body.persona, 'Full persona\nsecond line');
    assert.deepEqual(saved.body.tools, ['Read', 'Bash']);
    assert.deepEqual(saved.body.tools_deny, ['Write']);
    assert.equal(saved.body.max_instances, 2);
    const currentCard = cards().find(n => text(n).includes(scope + '-agent'));
    const remove = flatten(currentCard).find(n => n.cls === 'cbtn del');
    const before = mutations.length;
    confirmed = false;
    await remove.events.click();
    assert.equal(mutations.length, before);
    confirmed = true;
    mutationError = {error: 'definition changed', missing: [{hint: '/' + scope + '/agent.md'}]};
    await remove.events.click();
    assert.equal(remove.disabled, false);
    assert.match(text(currentCard), /definition changed/);
    mutationError = null;
    await remove.events.click();
    assert.equal(remove.disabled, true);
    assert.equal(mutations.at(-1).url, 'api/board/agentdrop');
    // Deletion preserves the same legacy surface label.
    assert.equal(Object.hasOwn(mutations.at(-1).body, 'actor'), false);
    assert.equal(mutations.at(-1).body.scope, scope);
    assert.equal(mutations.at(-1).body.checksum, 'sha256:original');
  }
  assert.equal(confirms, 6);
  const create = root.children.find(node => node.cls === 'agents-editor');
  for (const scope of ['repo', 'global']) {
    const form = await open(create);
    input(form, 'name').value = 'new-' + scope;
    input(form, 'scope').value = scope;
    input(form, 'description').value = 'New definition';
    mutationError = {error: 'agent name already taken: new-' + scope,
      missing: [{field: 'name', hint: '/other-scope/new-' + scope + '.md'}]};
    await submit(form);
    assert.ok(text(form).includes(mutationError.error));
    assert.ok(text(form).includes(mutationError.missing[0].hint));
    assert.equal(input(form, 'name').value, 'new-' + scope);
    mutationError = null;
    await submit(form);
    assert.equal(mutations.at(-1).body.scope, scope);
    assert.equal(mutations.at(-1).body.checksum, undefined);
    assert.equal(create.open, false);
  }
  const uncertainForm = await open(create);
  input(uncertainForm, 'name').value = 'uncertain-write';
  input(uncertainForm, 'scope').value = 'repo';
  input(uncertainForm, 'description').value = 'Uncertain write';
  mutationStatus = 503;
  mutationError = {error: 'definition outcome unconfirmed', outcome: 'uncertain',
    operationId: 'browser_stable_operation'};
  const beforeUncertain = mutations.length;
  await submit(uncertainForm);
  assert.equal(mutations.length, beforeUncertain + 1);
  assert.match(text(uncertainForm), /definition outcome unconfirmed/);
  const deniedForm = await open(create);
  input(deniedForm, 'name').value = 'denied-completion';
  input(deniedForm, 'scope').value = 'repo';
  mutationStatus = 409;
  mutationError = {error: 'definition completion denied', outcome: 'completion-denied',
    operationId: 'browser_denied_completion'};
  const beforeDenied = mutations.length;
  await submit(deniedForm);
  assert.equal(mutations.length, beforeDenied + 1);
  assert.match(text(deniedForm), /definition completion denied/);
  mutationStatus = 409;
  mutationError = null;
  const oldChildren = content.children;
  failure = new Error('offline');
  await refresh.events.click();
  assert.equal(content.children, oldChildren);
  assert.match(text(root), /out of date/);
  assert.equal(refresh.disabled, false);
  failure = null;
  payload = {};
  await loader();
  assert.equal(content.children, oldChildren);
  assert.match(text(root), /agents and problems arrays/);
  payload = {agents: [], problems: []};
  await refresh.events.click();
  assert.equal(content.children.length, 1);
  assert.match(text(content), /No usable agent definitions/);
  assert.ok(calls >= 8);
  assert.equal(refresh.disabled, false);
  console.log('PASS: Agents repo/global create/edit/delete, real deleteButton cancel/confirm/error/custom callback, collision paths, Claude read-only, full fields/checksums, registry, diagnostics, safe text, refresh and failure states');
})().catch(error => { console.error(error); process.exitCode = 1; });
JS
then
  echo 'passed 1, failed 0'
else
  echo 'passed 0, failed 1'
  exit 1
fi
