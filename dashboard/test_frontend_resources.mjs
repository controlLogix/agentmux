// Offline DOM fixtures for the production resource renderer and refresh handler.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const app = fs.readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const start = app.indexOf('let resourcesLoaded = false;');
const end = app.indexOf("const VIEW_KEY =", start);
assert.ok(start >= 0 && end > start, 'Resource section must be extracted from app.js');
const resourceCode = app.slice(start, end);
assert.ok(resourceCode.includes('function renderResources('));
assert.ok(resourceCode.includes('async function loadResources('));
const refreshBinding = app.split('\n').find(line => line.startsWith("els.resRefresh.addEventListener('click'"));
assert.ok(refreshBinding, 'Refresh binding must come from app.js');

class Element {
  constructor(tag) {
    this.tag = tag;
    this.className = '';
    this.children = [];
    this.events = {};
    this.disabled = false;
    this.textContent = '';
  }
  set innerHTML(_) { assert.fail('Resource data must not be parsed as HTML'); }
  insertAdjacentHTML() { assert.fail('Resource data must not be parsed as HTML'); }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  get childElementCount() { return this.children.length; }
  addEventListener(type, callback) { this.events[type] = callback; }
}

function all(node) { return [node, ...node.children.flatMap(all)]; }
function byClass(node, name) { return all(node).filter(n => n.className.split(' ').includes(name)); }
function page(response = {resources: []}) {
  const els = {resList: new Element('div'), resStamp: new Element('span'), resRefresh: new Element('button')};
  const calls = [], copies = [], timers = [];
  // No optional plugin globals, shell APIs, or client processes are available.
  const context = vm.createContext({
    els, document: {createElement: tag => new Element(tag)},
    navigator: {clipboard: {writeText: async command => { copies.push(command); }}},
    setTimeout: callback => { timers.push(callback); },
    fetch: async (url, options) => {
      calls.push({url, options});
      if (response instanceof Error) throw response;
      return {ok: true, json: async () => response};
    },
  });
  vm.runInContext(resourceCode + '\n' + refreshBinding, context);
  return {context, els, calls, copies, timers};
}

let passed = 0;
async function test(name, run) {
  await run();
  passed++;
  console.log(`PASS: ${name}`);
}

await test('resources and setup hints refresh without optional plugins', async () => {
  const p = page({resources: [{id: 'client', name: 'Client', state: 'missing', status: 'unavailable',
    actions: [{command: 'client --help', label: 'Check installation'}], notes: ['Install the client in your terminal.']}]});
  await p.context.loadResources(false);
  assert.equal(p.els.resList.children[0].tag, 'article');
  assert.equal(byClass(p.els.resList, 'act-cmd')[0].textContent, 'client --help');
  assert.equal(byClass(p.els.resList, 'res-notes')[0].children[0].textContent, 'Install the client in your terminal.');
  assert.equal(p.calls[0].url, 'api/resources');
  assert.equal(p.calls[0].options.cache, 'no-store');
  await p.els.resRefresh.events.click();
  assert.equal(p.calls[1].url, 'api/resources?refresh=1');
  assert.equal(p.els.resRefresh.disabled, false);
  assert.equal(vm.runInContext('resourcesLoaded', p.context), true);
});

await test('empty and error responses replace earlier cards with readable text', () => {
  const p = page();
  p.context.renderResources({resources: [{id: 'old'}]});
  p.context.renderResources({resources: []});
  assert.equal(p.els.resList.children.length, 1);
  assert.equal(p.els.resList.children[0].textContent, 'No resources declared in resources.json.');
  p.context.renderResources({error: 'Resource checks are running. Refresh shortly.'});
  assert.equal(p.els.resList.children.length, 1);
  assert.equal(p.els.resList.children[0].textContent, 'Resource checks are running. Refresh shortly.');
});

await test('configured, unavailable and unknown remain distinct with unknown check markers', () => {
  const p = page();
  p.context.renderResources({resources: [
    {id: 'ready', state: 'ok', status: 'configured', checks: [{ok: true, status: 'configured'}]},
    {id: 'absent', state: 'missing', status: 'unavailable', checks: [{ok: false, status: 'unavailable'}]},
    {id: 'uncertain', state: 'partial', status: 'unknown', checks: [{ok: false, status: 'unknown'}]},
  ]});
  assert.deepEqual(byClass(p.els.resList, 'res-state').map(n => n.textContent), ['configured', 'unavailable', 'unknown']);
  assert.deepEqual(byClass(p.els.resList, 'chk').map(n => n.textContent), ['✓', '✗', '?']);
});

await test('credential actions are tagged and copied without executing a request', async () => {
  const command = 'client login --interactive';
  const p = page();
  p.context.renderResources({resources: [{id: 'client', actions: [{command, secret: true}]}]});
  assert.equal(byClass(p.els.resList, 'act-secret-tag')[0].textContent, 'your terminal');
  const copy = byClass(p.els.resList, 'btn')[0];
  await copy.events.click();
  assert.deepEqual(p.copies, [command]);
  assert.deepEqual(p.calls, []);
  assert.equal(copy.textContent, 'copied');
  p.timers[0]();
  assert.equal(copy.textContent, 'copy');
});

await test('hostile resource text stays text and creates no executable elements', () => {
  const hostile = '<img src=x onerror="throw Error(1)"><script>alert(1)</script>';
  const p = page();
  p.context.renderResources({resources: [{id: 'hostile', name: hostile, summary: hostile,
    checks: [{label: hostile, detail: hostile}], notes: [hostile],
    actions: [{label: hostile, command: hostile, note: hostile}], docs: 'javascript:alert(1)'}]});
  assert.equal(byClass(p.els.resList, 'chk-detail')[0].textContent, hostile);
  assert.equal(byClass(p.els.resList, 'chk-detail')[0].title, hostile);
  assert.equal(byClass(p.els.resList, 'act-cmd')[0].textContent, hostile);
  const actionNotes = byClass(byClass(p.els.resList, 'res-actions')[0], 'res-summary');
  assert.equal(actionNotes[0].textContent, hostile);
  assert.equal(all(p.els.resList).some(n => ['img', 'script', 'a'].includes(n.tag)), false);
});

await test('failed fetch, HTTP error and invalid JSON re-enable refresh and permit retry', async () => {
  for (const failure of ['network', 'http', 'json']) {
    const p = page(new Error('fixture network failure'));
    if (failure === 'http') p.context.fetch = async () => ({ok: false, status: 503});
    if (failure === 'json') p.context.fetch = async () => ({ok: true, json: async () => { throw Error('fixture invalid JSON'); }});
    await p.els.resRefresh.events.click();
    assert.equal(p.els.resRefresh.disabled, false);
    assert.match(p.els.resStamp.textContent, /^could not load resources:/);
    assert.equal(vm.runInContext('resourcesLoaded', p.context), false);
    p.context.fetch = async () => ({ok: true, json: async () => ({resources: [{id: 'recovered'}]})});
    await p.els.resRefresh.events.click();
    assert.equal(p.els.resRefresh.disabled, false);
    assert.equal(p.els.resList.children[0].tag, 'article');
    assert.equal(p.els.resStamp.textContent, 'probed');
  }
});

await test('error payloads remain retryable and preserve earlier cards', async () => {
  const p = page({error: 'Checks unavailable', resources: []});
  await p.context.loadResources(false);
  assert.equal(vm.runInContext('resourcesLoaded', p.context), false);
  assert.equal(p.els.resStamp.textContent, 'could not load resources: Checks unavailable');
  assert.equal(p.els.resList.children[0].textContent, 'Checks unavailable');
  p.context.renderResources({resources: [{id: 'cached'}]});
  const card = p.els.resList.children[0];
  await p.context.loadResources(true);
  assert.equal(p.els.resList.children[0], card);
  assert.equal(p.els.resRefresh.disabled, false);
});

await test('refreshing responses label cached results and retain cards while checks run', async () => {
  const p = page({refreshing: true, resources: [{id: 'cached'}]});
  await p.context.loadResources(false);
  assert.equal(p.els.resList.children[0].tag, 'article');
  const card = p.els.resList.children[0];
  assert.match(p.els.resStamp.textContent, /running.*cached/);
  assert.equal(vm.runInContext('resourcesLoaded', p.context), false);
  p.context.fetch = async () => ({ok: true, json: async () => ({refreshing: true, resources: [], error: 'Checks running'})});
  await p.context.loadResources(true);
  assert.equal(p.els.resList.children[0], card);
  assert.equal(p.els.resRefresh.disabled, false);
  const empty = page({refreshing: true, resources: []});
  await empty.context.loadResources(false);
  assert.equal(empty.els.resList.children[0].textContent, 'Resource checks are running. Refresh shortly.');
});

await test('overlapping automatic and manual loads share one pending request', async () => {
  const p = page();
  let complete;
  let requests = 0;
  p.context.fetch = () => { requests++; return new Promise(resolve => { complete = resolve; }); };
  const pending = p.context.loadResources(false);
  assert.equal(p.els.resRefresh.disabled, true);
  await p.els.resRefresh.events.click();
  await p.context.loadResources(false);
  assert.equal(requests, 1);
  assert.equal(p.els.resRefresh.disabled, true);
  complete({ok: true, json: async () => ({resources: [{id: 'fresh'}]})});
  await pending;
  assert.equal(p.els.resRefresh.disabled, false);
  assert.equal(p.els.resList.children[0].tag, 'article');
  assert.equal(vm.runInContext('resourcesLoading', p.context), false);
});

console.log(`${passed} resource DOM fixture checks passed. Browser behavior was not tested.`);
