import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, resolve, sep, basename } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawn } from 'node:child_process';
import { createServer, request } from 'node:http';
import { fileURLToPath } from 'node:url';
import { manageReview, serverPaths, reviewEnvironment } from './review-server.mjs';
import { createLocalReview } from './local-review.mjs';
import { setTimeout as delay } from 'node:timers/promises';
import { acquireNotesLock } from './notes-lock.mjs';

const document = { id: 'fixture', title: 'Review fixture', version: 'sha256:' + 'a'.repeat(64), sections: [{ id: 'global', title: 'Notes', question: 'Feedback?' }] };
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'agentmux-review-server-'));
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^GIT_/i.test(key))), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: join(root, 'empty-global') };
  writeFileSync(env.GIT_CONFIG_GLOBAL, '');
  const git = args => execFileSync('git', ['-C', root, ...args], { env, encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git(['init', '-q']); git(['config', 'user.name', 'Reviewer']); git(['config', 'user.email', 'reviewer@example.test']);
  mkdirSync(join(root, 'notes')); writeFileSync(join(root, 'tracked.txt'), 'baseline'); git(['add', 'tracked.txt']); git(['commit', '-qm', 'Fixture baseline']);
  const html = '<script type="application/json" id="review-data">' + JSON.stringify({ document }) + '</script>';
  const createReview = (management, overrides = {}) => ({ ...createLocalReview({ repoRoot: root, config: { id: 'fixture', notesPath: 'notes', reviewers: [] }, document, html, gitEnv: env, management, ...overrides }), documentVersion: document.version });
  const start = options => manageReview({ repoRoot: root, reviewId: 'fixture', port: 0, createReview, ...options });
  return { root, env, git, start, createReview, paths: serverPaths(root),
    close() { const path = resolve(root); assert.ok(path.startsWith(resolve(tmpdir()) + sep) && basename(path).startsWith('agentmux-review-server-')); rmSync(path, { recursive: true, force: true }); } };
}

test('concurrent opens reuse one server', async () => {
  const h = fixture(); let owner;
  try {
    const results = await Promise.all([h.start(), h.start(), h.start()]);
    owner = results.find(item => !item.reused);
    assert.equal(results.filter(item => !item.reused).length, 1);
    assert.equal(new Set(results.map(item => item.url)).size, 1);
    assert.ok(results.every(item => !Object.hasOwn(item, 'token')));
    const state = JSON.parse(readFileSync(h.paths.state));
    assert.equal(state.instanceId, owner.instanceId);
    assert.equal((await fetch(owner.url)).status, 200);
    assert.equal((await h.start({ action: 'status' })).active, true);
    await assert.rejects(h.start({ reviewId: 'another' }), /already open/);
    await assert.rejects(h.start({ reviewId: 'another', action: 'stop' }), /owns/);
    assert.equal((await fetch(owner.url)).status, 200);
  } finally { await owner?.stop(); h.close(); }
});

test('an explicit port must match the active server without changing its ownership or settings', async () => {
  const h = fixture(); let owner;
  try {
    owner = await h.start();
    const port = Number(new URL(owner.url).port);
    const beforeRecord = readFileSync(h.paths.state, 'utf8');
    const beforeSettings = readFileSync(h.paths.settings, 'utf8');
    const reused = await h.start({ port });
    assert.equal(reused.reused, true);
    assert.equal(reused.instanceId, owner.instanceId);
    await assert.rejects(h.start({ port: port === 65535 ? 65534 : port + 1 }), /different port.*Restart it explicitly/);
    assert.equal(readFileSync(h.paths.state, 'utf8'), beforeRecord);
    assert.equal(readFileSync(h.paths.settings, 'utf8'), beforeSettings);
    assert.equal((await fetch(owner.url)).status, 200);
  } finally { await owner?.stop(); h.close(); }
});

test('an opener waiting for publication refuses a different explicit port', async () => {
  const h = fixture(); let owner, unblock, reached;
  const creating = new Promise(done => { reached = done; });
  try {
    const started = h.start({ createReview: async management => {
      reached();
      await new Promise(done => { unblock = done; }); return h.createReview(management);
    } });
    await Promise.race([creating, started]);
    // The request begins while the first owner holds the slot without a record.
    const waiting = h.start({ port: 1 });
    const refused = assert.rejects(waiting, /different port.*Restart it explicitly/);
    unblock(); owner = await started;
    await refused;
    assert.equal(JSON.parse(readFileSync(h.paths.state)).instanceId, owner.instanceId);
    assert.equal((await fetch(owner.url)).status, 200);
  } finally { unblock?.(); await owner?.stop(); h.close(); }
});

test('manager stop is private, drains requests, removes only its record and retains the port', async () => {
  const h = fixture(); let owner, restarted;
  try {
    owner = await h.start();
    const state = JSON.parse(readFileSync(h.paths.state));
    const stopUrl = new URL('_review/stop', owner.url);
    assert.equal((await fetch(stopUrl, { method: 'POST' })).status, 403);
    assert.equal((await fetch(stopUrl, { method: 'POST', headers: { 'X-Review-Manager-Token': state.token, Origin: 'https://unrelated.test' } })).status, 403);
    const response = await fetch(new URL('_review/health', owner.url), { headers: { 'X-Review-Manager-Token': state.token } });
    const info = await response.json(); assert.equal(info.instanceId, owner.instanceId); assert.ok(!Object.hasOwn(info, 'token'));
    const stopped = await h.start({ action: 'stop' }); assert.equal(stopped.stopped, true);
    assert.equal(existsSync(h.paths.state), false);
    assert.equal(JSON.parse(readFileSync(h.paths.settings)).port, Number(new URL(owner.url).port));
    restarted = await h.start({ port: undefined }); assert.equal(restarted.url, owner.url);
    assert.notEqual(restarted.instanceId, owner.instanceId);
  } finally { await restarted?.stop(); await owner?.stop(); h.close(); }
});

test('worktrees share one server slot and cannot stop another checkout’s review', async () => {
  const h = fixture(); let owner;
  try {
    const worktree = join(h.root, 'other-checkout'); h.git(['worktree', 'add', '--detach', worktree]);
    assert.equal(serverPaths(worktree).state, h.paths.state);
    owner = await h.start();
    await assert.rejects(manageReview({ repoRoot: worktree, reviewId: 'fixture', port: 0, createReview: h.createReview }), /another checkout/);
    await assert.rejects(manageReview({ repoRoot: worktree, reviewId: 'fixture', action: 'stop' }), /owns/);
    assert.equal((await fetch(owner.url)).status, 200);
    await owner.stop(); h.git(['worktree', 'remove', worktree]);
  } finally { await owner?.stop(); h.close(); }
});

test('unknown listeners are never stopped or bypassed with an automatic fallback port', async () => {
  const h = fixture(); const unknown = createServer((request, response) => { response.end('Unrelated app'); });
  await new Promise(done => unknown.listen(0, '127.0.0.1', done));
  try {
    const port = unknown.address().port;
    writeFileSync(h.paths.settings, JSON.stringify({ port }));
    await assert.rejects(h.start({ port: undefined }), /unverified process/);
    assert.equal(existsSync(h.paths.state), false);
    assert.equal(await (await fetch('http://127.0.0.1:' + port)).text(), 'Unrelated app');
  } finally { unknown.closeAllConnections(); await new Promise(done => unknown.close(done)); h.close(); }
});

test('a dead process leaves recoverable state; its PID is never used to terminate anything', async () => {
  const h = fixture(); let recovered;
  const module = fileURLToPath(new URL('./review-server.mjs', import.meta.url));
  const localModule = fileURLToPath(new URL('./local-review.mjs', import.meta.url));
  const script = `import {manageReview} from ${JSON.stringify(new URL('./review-server.mjs', import.meta.url).href)};
    import {createLocalReview} from ${JSON.stringify(new URL('./local-review.mjs', import.meta.url).href)};
    const root=process.argv[1];const document=${JSON.stringify(document)};
    const result=await manageReview({repoRoot:root,reviewId:'fixture',port:0,createReview:management=>({...createLocalReview({repoRoot:root,config:{id:'fixture',notesPath:'notes',reviewers:[]},document,html:'<script type="application/json" id="review-data">'+JSON.stringify({document})+'</script>',management}),documentVersion:document.version})});
    console.log(JSON.stringify({url:result.url}));`;
  assert.ok(existsSync(module) && existsSync(localModule));
  const child = spawn(process.execPath, ['--input-type=module', '-e', script, h.root], { env: h.env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await new Promise((done, reject) => {
      let output = ''; child.stdout.on('data', chunk => { output += chunk; if (output.includes('\n')) done(); });
      child.on('error', reject); child.on('exit', code => reject(new Error('Child stopped before ready: ' + code)));
    });
    assert.equal(existsSync(h.paths.state), true);
    const initial = JSON.parse(readFileSync(h.paths.state));
    const duplicate = execFileSync(process.execPath, ['--input-type=module', '-e', script, h.root], { env: h.env, encoding: 'utf8', windowsHide: true, timeout: 15000 });
    assert.equal(JSON.parse(duplicate.trim()).url, initial.url);
    assert.equal(JSON.parse(readFileSync(h.paths.state)).instanceId, initial.instanceId);
    const exited = new Promise(done => child.once('exit', done)); child.kill('SIGKILL'); await exited;
    const stale = JSON.parse(readFileSync(h.paths.state)); stale.pid = process.pid;
    writeFileSync(h.paths.state, JSON.stringify(stale));
    recovered = await h.start({ port: undefined });
    assert.equal(recovered.reused, false); assert.equal(process.pid, stale.pid);
    assert.equal((await fetch(recovered.url)).status, 200);
  } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await recovered?.stop(); h.close(); }
});

test('shutdown lets an already-started note save finish before releasing server ownership', async () => {
  const h = fixture(); let owner, pending;
  try {
    owner = await h.start();
    const page = await (await fetch(owner.url)).text();
    const data = JSON.parse(page.match(/id="review-data">([\s\S]*?)<\/script>/)[1]);
    const session = await (await fetch(new URL('api/session', owner.url), { headers: { 'X-Review-Token': data.bridge.token } })).json();
    const body = JSON.stringify({ identity: session.identity, revision: null, record: {
      format: 'agentmux-review-notes', schemaVersion: 1, documentId: 'fixture', documentVersion: document.version,
      reviewer: 'Reviewer', exportedAt: new Date().toISOString(), notes: { global: 'Save before shutdown' }
    } });
    let started;
    const received = new Promise((done, reject) => {
      pending = request(new URL('api/notes', owner.url), { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Review-Token': data.bridge.token } }, response => {
        response.resume(); response.once('end', () => done(response.statusCode));
      }); pending.on('error', reject);
      started = new Promise(done => owner.server.once('request', done));
      pending.write(body.slice(0, 30));
    });
    await started;
    const stopping = h.start({ action: 'stop' }); await delay(150);
    assert.equal(existsSync(h.paths.state), true);
    pending.end(body.slice(30)); assert.equal(await received, 200);
    assert.equal((await stopping).stopped, true);
    assert.match(readFileSync(join(h.root, 'notes', session.identity.filename), 'utf8'), /Save before shutdown/);
    assert.equal(existsSync(h.paths.state), false);
  } finally { pending?.destroy(); await owner?.stop(); h.close(); }
});

test('failed startup releases ownership and an explicit restart replaces rather than duplicates', async () => {
  const h = fixture(); let owner, restarted;
  try {
    await assert.rejects(h.start({ createReview: () => { throw new Error('Fixture build failed'); } }), /Fixture build failed/);
    owner = await h.start();
    const url = owner.url;
    restarted = await h.start({ action: 'restart', port: undefined });
    assert.equal(restarted.url, url); assert.notEqual(restarted.instanceId, owner.instanceId);
    assert.equal((await fetch(restarted.url)).status, 200);
    assert.equal(JSON.parse(readFileSync(h.paths.state)).instanceId, restarted.instanceId);
  } finally { await restarted?.stop(); await owner?.stop(); h.close(); }
});

test('an owner starting before state publication is unknown, never falsely stopped', async () => {
  const h = fixture(); let owner, unblock;
  try {
    const started = h.start({ createReview: async management => { await new Promise(done => { unblock = done; }); return h.createReview(management); } });
    while (!unblock) await delay(10);
    const status = await h.start({ action: 'status' });
    assert.equal(status.active, null); assert.match(status.state, /starting/);
    await assert.rejects(h.start({ action: 'stop' }), /Shutdown is not confirmed/);
    unblock(); owner = await started;
  } finally { unblock?.(); await owner?.stop(); h.close(); }
});

test('a live but unresponsive owner is not reported inactive and retains exclusion', async () => {
  const h = fixture(); let owner;
  try {
    owner = await h.start();
    const listeners = owner.server.listeners('request'); owner.server.removeAllListeners('request');
    owner.server.on('request', () => {});
    try {
      assert.equal((await h.start({ action: 'status' })).active, null);
      await assert.rejects(h.start({ action: 'stop' }), /Shutdown is not confirmed/);
      await assert.rejects(acquireNotesLock(h.paths.state), error => error.status === 423);
    } finally { owner.server.removeAllListeners('request'); listeners.forEach(listener => owner.server.on('request', listener)); }
  } finally { owner?.server.closeAllConnections(); await owner?.stop(); h.close(); }
});

test('a disconnected notes handler still drains before ownership is released', async () => {
  const h = fixture(); let owner, pending, finishLock;
  try {
    let signal;
    const paused = new Promise(done => { signal = done; });
    owner = await h.start({ createReview: management => h.createReview(management, { acquireLock: async path => {
      signal(); await new Promise(done => { finishLock = done; }); return acquireNotesLock(path);
    } }) });
    const page = await (await fetch(owner.url)).text();
    const data = JSON.parse(page.match(/id="review-data">([\s\S]*?)<\/script>/)[1]);
    const session = await (await fetch(new URL('api/session', owner.url), { headers: { 'X-Review-Token': data.bridge.token } })).json();
    pending = request(new URL('api/notes', owner.url), { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Review-Token': data.bridge.token } });
    pending.on('error', () => {});
    pending.end(JSON.stringify({ identity: session.identity, revision: null, record: {
      format: 'agentmux-review-notes', schemaVersion: 1, documentId: 'fixture', documentVersion: document.version,
      reviewer: 'Reviewer', exportedAt: new Date().toISOString(), notes: { global: 'Disconnected save still finishes' }
    } }));
    await paused; pending.destroy();
    let stopped = false;
    const closing = owner.stop().then(() => { stopped = true; }); await delay(100);
    assert.equal(stopped, false); assert.equal(existsSync(h.paths.state), true);
    await assert.rejects(acquireNotesLock(h.paths.state), error => error.status === 423);
    finishLock(); await closing;
    assert.match(readFileSync(join(h.root, 'notes', session.identity.filename), 'utf8'), /Disconnected save still finishes/);
  } finally { finishLock?.(); pending?.destroy(); await owner?.stop(); h.close(); }
});

test('shutdown acknowledges its own instance even if another opener immediately replaces the record', async () => {
  const h = fixture(); let owner, replacement;
  const originalFetch = globalThis.fetch;
  let published;
  const replacementPublished = new Promise(done => { published = done; });
  try {
    owner = await h.start();
    const originalStop = owner.stop;
    // Replace the record as soon as the old owner releases, before the caller polls.
    const state = JSON.parse(readFileSync(h.paths.state));
    owner.server.removeAllListeners('request');
    owner.server.on('request', async (request, response) => {
      const info = { ...state }; delete info.token;
      response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(info));
      if (request.url === '/_review/stop') {
        await originalStop(); replacement = await h.start(); published();
      }
    });
    globalThis.fetch = async (url, options) => {
      const response = await originalFetch(url, options);
      if (String(url).endsWith('/_review/stop')) {
        const body = await response.json();
        await replacementPublished;
        return { ok: response.ok, json: async () => body };
      }
      return response;
    };
    const stopped = await h.start({ action: 'stop' }); assert.equal(stopped.stopped, true);
    assert.equal(stopped.stoppedInstanceId, owner.instanceId);
    assert.equal(JSON.parse(readFileSync(h.paths.state)).instanceId, replacement.instanceId);
    assert.notEqual(replacement.instanceId, owner.instanceId);
    assert.equal((await h.start({ action: 'status' })).active, true);
  } finally { globalThis.fetch = originalFetch; await replacement?.stop(); await owner?.stop(); h.close(); }
});

test('port 80 is persisted from the bound socket even when URL normalization omits its port', async () => {
  const h = fixture(); let owner;
  try {
    owner = await h.start({ createReview: management => {
      const local = h.createReview(management);
      return { ...local, server: new Proxy(local.server, { get(target, name) {
        if (name === 'address') return () => ({ ...target.address(), port: 80 });
        const value = Reflect.get(target, name); return typeof value === 'function' ? value.bind(target) : value;
      } }) };
    } });
    assert.equal(JSON.parse(readFileSync(h.paths.settings)).port, 80);
  } finally { await owner?.stop(); h.close(); }
});

test('launcher environment removes case-insensitive Git redirects without changing identity configuration', () => {
  assert.deepEqual(reviewEnvironment({ PATH: 'preserved', git_dir: 'other', GIT_INDEX_FILE: 'other-index', GIT_WORK_TREE: 'other-tree', GIT_CONFIG_GLOBAL: 'effective-identity', GIT_TERMINAL_PROMPT: '0' }),
    { PATH: 'preserved', GIT_CONFIG_GLOBAL: 'effective-identity', GIT_TERMINAL_PROMPT: '0' });
});
