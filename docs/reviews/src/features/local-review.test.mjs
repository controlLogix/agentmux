import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, renameSync, symlinkSync } from 'node:fs';
import { join, resolve, basename, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { request } from 'node:http';
import { createLocalReview } from './local-review.mjs';
import { importMarkdown, MAX_FILE } from './notes-format.mjs';
import { acquireNotesLock } from './notes-lock.mjs';

const document = { id: 'fixture-review', title: 'Fixture review', version: 'sha256:' + 'a'.repeat(64),
  sections: [{ id: 'global', title: 'Overall', question: 'What changes?' }] };
const config = { id: document.id, notesPath: 'notes', reviewers: [{ id: 'nick', name: 'Nick Klute' }, { id: 'ryan', name: 'Ryan Helms' }] };
const record = note => ({ format: 'agentmux-review-notes', schemaVersion: 1, documentId: document.id,
  documentVersion: document.version, reviewer: 'Client supplied name', exportedAt: '2026-10-13T16:00:00Z', notes: { global: note } });

async function fixture(globalIdentity = false) {
  const root = mkdtempSync(join(tmpdir(), 'agentmux-review-'));
  const globalPath = join(root, 'global-config'); writeFileSync(globalPath, '');
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalPath };
  const git = args => execFileSync('git', ['-C', root, ...args], { env, encoding: 'utf8', windowsHide: true }).trim();
  git(['init', '--quiet']); git(['config', '--local', 'review.sentinel', 'preserve']);
  if (globalIdentity) { git(['config', '--file', globalPath, 'user.name', 'Ryan Helms']); git(['config', '--file', globalPath, 'user.email', 'ryan@example.test']); }
  mkdirSync(join(root, 'notes'));
  const html = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; form-action \'none\'"><script type="application/json" id="review-data">' + JSON.stringify({ document }) + '</script>';
  const local = createLocalReview({ repoRoot: root, config, document, html, gitEnv: env });
  const url = await local.listen(0);
  const call = (path, body, extra = {}) => fetch(new URL(path, url), { method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Review-Token': local.token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...extra },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { root, git, env, html, url, call, local, globalPath,
    async close() {
      local.server.closeAllConnections(); await new Promise(done => local.server.close(done));
      const target = resolve(root);
      assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('agentmux-review-'));
      rmSync(target, { recursive: true, force: true });
    } };
}

test('missing identity setup writes repo-local Git config only; direct saves use Git identity and detect conflicts', async () => {
  const h = await fixture();
  try {
    assert.equal((await (await h.call('/api/session')).json()).identity.configured, false);
    assert.equal((await h.call('/api/identity', { name: 'Nick Klute', email: 'nick@example.test' })).status, 200);
    assert.equal(h.git(['config', '--local', '--get', 'user.name']), 'Nick Klute');
    assert.equal(readFileSync(h.globalPath, 'utf8'), '');
    assert.equal(h.git(['config', '--local', '--get', 'review.sentinel']), 'preserve');
    const session = await (await h.call('/api/session')).json();
    assert.equal(session.identity.filename, 'nick.md');
    const save = await h.call('/api/notes', { identity: session.identity, revision: null, record: record('Typed note') });
    assert.equal(save.status, 200);
    const saved = await save.json();
    const file = join(h.root, 'notes/nick.md');
    const parsed = importMarkdown(readFileSync(file, 'utf8'), document);
    assert.equal(parsed.reviewer, 'Nick Klute'); assert.equal(parsed.reviewerEmail, 'nick@example.test'); assert.equal(parsed.notes.global, 'Typed note');
    assert.equal((await h.call('/api/notes', { identity: session.identity, revision: null, record: record('Stale overwrite') })).status, 409);
    assert.equal(importMarkdown(readFileSync(file, 'utf8'), document).notes.global, 'Typed note');
    assert.equal((await h.call('/api/notes', { identity: session.identity, revision: saved.revision, record: { ...record('Wrong doc'), documentId: 'other' } })).status, 400);
    h.git(['config', '--local', 'user.email', 'new@example.test']);
    assert.equal((await h.call('/api/notes', { identity: session.identity, revision: saved.revision, record: record('Changed identity') })).status, 409);
    const other = await (await h.call('/api/session')).json();
    assert.notEqual(other.identity.filename, 'nick.md');
    assert.equal(other.record, null);
    assert.equal((await h.call('/api/notes', { identity: other.identity, revision: null, record: record('Second identity') })).status, 200);
    assert.equal(importMarkdown(readFileSync(file, 'utf8'), document).notes.global, 'Typed note');
    const release = await acquireNotesLock(join(h.root, 'notes', other.identity.filename));
    try {
      const revision = (await (await h.call('/api/session')).json()).revision;
      assert.equal((await h.call('/api/notes', { identity: other.identity, revision, record: record('Locked write') })).status, 423);
    } finally { await release(); }
  } finally { await h.close(); }
});

test('effective global Git identity works without modifying configuration', async () => {
  const h = await fixture(true);
  try {
    const before = readFileSync(h.globalPath, 'utf8');
    const session = await (await h.call('/api/session')).json();
    assert.equal(session.identity.filename, 'ryan.md');
    assert.equal((await h.call('/api/identity', { name: 'Other', email: 'other@example.test' })).status, 409);
    assert.equal(readFileSync(h.globalPath, 'utf8'), before);
    assert.equal((await h.call('/api/notes', { identity: session.identity, revision: null, record: record('Ryan note') })).status, 200);
  } finally { await h.close(); }
});

test('local token, Origin and Host protect operations; served page alone enables same-origin saves', async () => {
  const h = await fixture();
  try {
    assert.equal((await h.call('/api/session', undefined, { 'X-Review-Token': 'wrong' })).status, 403);
    assert.equal((await h.call('/api/identity', { name: 'Bad', email: 'bad@example.test' }, { Origin: 'https://unrelated.test' })).status, 403);
    const hostStatus = await new Promise((done, reject) => {
      const req = request(h.url, { headers: { Host: 'unrelated.test' } }, response => { response.resume(); done(response.statusCode); });
      req.on('error', reject); req.end();
    });
    assert.equal(hostStatus, 403);
    const response = await fetch(h.url); const html = await response.text();
    assert.match(html, /connect-src 'self'/);
    assert.ok(!h.html.includes('connect-src'));
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.equal(h.local.server.address().address, '127.0.0.1');
    const data = JSON.parse(html.match(/id="review-data">([\s\S]*?)<\/script>/)[1]);
    assert.equal(data.bridge.token, h.local.token);
    assert.throws(() => createLocalReview({ repoRoot: h.root, config: { ...config, notesPath: '../outside' }, document, html: h.html, gitEnv: h.env }), /leaves/);
    assert.throws(() => createLocalReview({ repoRoot: h.root, config: { ...config, reviewers: [{ id: '../other', name: 'Nick Klute' }] }, document, html: h.html, gitEnv: h.env }), /Invalid review/);
  } finally { await h.close(); }
});

test('malformed and oversized HTTP writes leave existing notes and Git settings intact', async () => {
  const h = await fixture(true);
  try {
    const session = await (await h.call('/api/session')).json();
    const saved = await h.call('/api/notes', { identity: session.identity, revision: null, record: record('Keep this note') });
    assert.equal(saved.status, 200);
    const revision = (await saved.json()).revision;
    const file = join(h.root, 'notes/ryan.md');
    const before = readFileSync(file);
    const gitBefore = readFileSync(join(h.root, '.git/config'));
    for (const [body, type, status] of [
      ['{', 'application/json', 400], ['[]', 'application/json', 400],
      ['null', 'application/json', 400], ['{}', 'text/plain', 415],
      [' '.repeat(MAX_FILE + 1), 'application/json', 413]
    ]) {
      const response = await fetch(new URL('/api/notes', h.url), { method: 'POST',
        headers: { 'X-Review-Token': h.local.token, 'Content-Type': type }, body });
      assert.equal(response.status, status); await response.text();
      assert.deepEqual(readFileSync(file), before);
      assert.deepEqual(readFileSync(join(h.root, '.git/config')), gitBefore);
    }
    const invalid = { ...record('Invalid replacement'), notes: { global: 'x'.repeat(20001) } };
    assert.equal((await h.call('/api/notes', { identity: session.identity, revision, record: invalid })).status, 400);
    assert.deepEqual(readFileSync(file), before);
  } finally { await h.close(); }
});

test('configured traversal and a directory link outside the repository are rejected', async () => {
  const h = await fixture();
  const outside = mkdtempSync(join(tmpdir(), 'agentmux-review-outside-'));
  try {
    const linked = join(h.root, 'linked-notes');
    symlinkSync(outside, linked, process.platform === 'win32' ? 'junction' : 'dir');
    for (const notesPath of ['../outside', outside, 'linked-notes']) {
      assert.throws(() => createLocalReview({ repoRoot: h.root, config: { ...config, notesPath },
        document, html: h.html, gitEnv: h.env }), /leaves|outside/);
    }
  } finally {
    await h.close();
    const target = resolve(outside);
    assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('agentmux-review-outside-'));
    rmSync(target, { recursive: true, force: true });
  }
});

test('replacing the notes folder with a link cannot expose or overwrite another folder', async () => {
  const h = await fixture(true);
  try {
    const session = await (await h.call('/api/session')).json();
    const saved = await h.call('/api/notes', { identity: session.identity, revision: null, record: record('Original notes') });
    assert.equal(saved.status, 200); const revision = (await saved.json()).revision;
    const original = readFileSync(join(h.root, 'notes/ryan.md'));
    const other = join(h.root, 'other-notes'); mkdirSync(other);
    writeFileSync(join(other, 'ryan.md'), original);
    renameSync(join(h.root, 'notes'), join(h.root, 'original-notes'));
    symlinkSync(other, join(h.root, 'notes'), process.platform === 'win32' ? 'junction' : 'dir');
    assert.equal((await h.call('/api/session')).status, 400);
    assert.equal((await h.call('/api/notes', { identity: session.identity, revision, record: record('Unwanted replacement') })).status, 400);
    assert.deepEqual(readFileSync(join(other, 'ryan.md')), original);
    assert.deepEqual(readFileSync(join(h.root, 'original-notes/ryan.md')), original);
  } finally { await h.close(); }
});

async function sharingFixture() {
  const h = await fixture(true);
  h.git(['switch', '-c', 'feat/agentmux-platform-rearchitecture']);
  writeFileSync(join(h.root, 'baseline.txt'), 'baseline');
  h.git(['add', 'baseline.txt']); h.git(['commit', '-qm', 'Baseline']);
  const remote = join(h.root, 'remote.git');
  h.git(['init', '--bare', '--quiet', remote]); h.git(['remote', 'add', 'origin', remote]);
  h.git(['push', '--quiet', '-u', 'origin', 'feat/agentmux-platform-rearchitecture']);
  const session = await (await h.call('/api/session')).json();
  const saved = await (await h.call('/api/notes', { identity: session.identity, revision: null, record: record('Share this feedback') })).json();
  return Object.assign(h, { share: () => h.call('/api/share', { identity: session.identity, revision: saved.revision }), remote });
}

test('sharing commits and pushes only own notes, preserves unrelated staging, and is repeatable', async () => {
  const h = await sharingFixture();
  try {
    writeFileSync(join(h.root, 'unrelated.txt'), 'Keep staged'); h.git(['add', 'unrelated.txt']);
    writeFileSync(join(h.root, 'notes/nick.md'), 'Do not commit Nick');
    const response = await h.share(); assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
    const result = await response.json();
    assert.equal(h.git(['diff-tree', '--no-commit-id', '--name-only', '-r', result.commit]), 'notes/ryan.md');
    assert.equal(h.git(['diff', '--cached', '--name-only']), 'unrelated.txt');
    assert.equal(h.git(['ls-remote', '--heads', 'origin', 'refs/heads/feat/agentmux-platform-rearchitecture']).split(/\s/)[0], result.commit);
    const again = await h.share(); assert.equal(again.status, 200);
    assert.match((await again.json()).message, /already shared/);
    assert.equal(h.git(['rev-parse', 'HEAD']), result.commit);
  } finally { await h.close(); }
});

test('sharing refuses unrelated outgoing commits and the wrong branch before committing', async () => {
  const h = await sharingFixture();
  try {
    writeFileSync(join(h.root, 'other.txt'), 'Other work'); h.git(['add', 'other.txt']); h.git(['commit', '-qm', 'Other work']);
    const before = h.git(['rev-parse', 'HEAD']);
    const remoteBefore = h.git(['ls-remote', '--heads', 'origin']);
    const response = await h.share(); assert.equal(response.status, 409); assert.match((await response.json()).error, /other work/);
    assert.equal(h.git(['rev-parse', 'HEAD']), before); assert.equal(h.git(['ls-remote', '--heads', 'origin']), remoteBefore);
    h.git(['switch', '-c', 'other-branch']); assert.equal((await h.share()).status, 409);
  } finally { await h.close(); }
});

test('a failed push leaves an own-only commit that Share notes can retry without another commit', async () => {
  const h = await sharingFixture();
  try {
    const hook = join(h.remote, 'hooks/pre-receive'); writeFileSync(hook, '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const response = await h.share(); assert.equal(response.status, 502);
    assert.match((await response.json()).error, /committed locally/);
    const candidate = h.git(['rev-parse', 'HEAD']);
    rmSync(hook);
    const retry = await h.share(); assert.equal(retry.status, 200);
    assert.equal((await retry.json()).commit, candidate); assert.equal(h.git(['rev-parse', 'HEAD']), candidate);
  } finally { await h.close(); }
});

test('sharing refuses a stale note revision and remote changes without committing or merging', async () => {
  const h = await sharingFixture();
  try {
    const before = h.git(['rev-parse', 'HEAD']);
    const session = await (await h.call('/api/session')).json();
    assert.equal((await h.call('/api/share', { identity: session.identity, revision: 'stale' })).status, 409);
    // Advance the disposable remote, then return the local branch to its original head.
    writeFileSync(join(h.root, 'remote-change.txt'), 'Remote changed');
    h.git(['add', 'remote-change.txt']); h.git(['commit', '-qm', 'Remote work']);
    h.git(['push', '--quiet', 'origin', 'feat/agentmux-platform-rearchitecture']);
    h.git(['reset', '--soft', before]);
    const staged = h.git(['diff', '--cached', '--name-only']);
    const response = await h.share(); assert.equal(response.status, 409);
    assert.match((await response.json()).error, /changes you do not have/);
    assert.equal(h.git(['rev-parse', 'HEAD']), before); assert.equal(h.git(['diff', '--cached', '--name-only']), staged);
  } finally { await h.close(); }
});

test('commit hooks remain active and rejected commits do not push', async () => {
  const h = await sharingFixture();
  try {
    const before = h.git(['rev-parse', 'HEAD']);
    writeFileSync(join(h.root, '.git/hooks/pre-commit'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const response = await h.share(); assert.equal(response.status, 409);
    assert.match((await response.json()).error, /hook or signing/);
    assert.equal(h.git(['rev-parse', 'HEAD']), before);
    assert.equal(h.git(['ls-remote', '--heads', 'origin', 'refs/heads/feat/agentmux-platform-rearchitecture']).split(/\s/)[0], before);
  } finally { await h.close(); }
});

test('different or multiple push destinations are rejected without committing', async () => {
  const h = await sharingFixture();
  try {
    const before = h.git(['rev-parse', 'HEAD']);
    h.git(['config', 'remote.origin.pushurl', join(h.root, 'different.git')]);
    assert.equal((await h.share()).status, 409);
    h.git(['config', '--replace-all', 'remote.origin.pushurl', h.remote]);
    h.git(['config', '--add', 'remote.origin.pushurl', h.remote]);
    assert.equal((await h.share()).status, 409);
    assert.equal(h.git(['rev-parse', 'HEAD']), before);
  } finally { await h.close(); }
});

test('a hook that replaces only staged notes cannot publish different feedback', async () => {
  const h = await sharingFixture();
  try {
    const remoteBefore = h.git(['ls-remote', '--heads', 'origin']);
    writeFileSync(join(h.root, '.git/hooks/pre-commit'), '#!/bin/sh\nblob=$(printf "Hook replacement" | git hash-object -w --stdin)\ngit update-index --cacheinfo 100644,$blob,notes/ryan.md\n', { mode: 0o755 });
    const response = await h.share(); assert.equal(response.status, 409);
    assert.match((await response.json()).error, /differ from your confirmed save/);
    assert.equal(h.git(['ls-remote', '--heads', 'origin']), remoteBefore);
    assert.match(readFileSync(join(h.root, 'notes/ryan.md'), 'utf8'), /Share this feedback/);
  } finally { await h.close(); }
});

test('Git URL rewrite rules cannot redirect the explicit share destination', async () => {
  const h = await sharingFixture();
  try {
    const before = h.git(['rev-parse', 'HEAD']);
    h.git(['config', 'url.' + h.remote + '.insteadOf', 'review-alias:']);
    h.git(['config', 'url.' + join(h.root, 'wrong.git') + '.pushInsteadOf', h.remote]);
    h.git(['remote', 'set-url', 'origin', 'review-alias:']);
    const response = await h.share(); assert.equal(response.status, 409);
    assert.match((await response.json()).error, /URL rewrite rules/);
    assert.equal(h.git(['rev-parse', 'HEAD']), before);
  } finally { await h.close(); }
});

test('a hook cannot replace valid Unicode notes with invalid UTF-8 bytes', async () => {
  const h = await sharingFixture();
  try {
    const session = await (await h.call('/api/session')).json();
    const saved = await (await h.call('/api/notes', { identity: session.identity, revision: session.revision, record: record('Valid replacement character: \uFFFD') })).json();
    const bytes = readFileSync(join(h.root, 'notes/ryan.md'));
    const index = bytes.indexOf(Buffer.from('\uFFFD'));
    const invalid = Buffer.concat([bytes.subarray(0, index), Buffer.from([0xff]), bytes.subarray(index + 3)]);
    const blob = execFileSync('git', ['-C', h.root, 'hash-object', '-w', '--stdin'], { input: invalid, env: h.env, encoding: 'utf8' }).trim();
    writeFileSync(join(h.root, '.git/hooks/pre-commit'), '#!/bin/sh\ngit update-index --cacheinfo 100644,' + blob + ',notes/ryan.md\n', { mode: 0o755 });
    const remoteBefore = h.git(['ls-remote', '--heads', 'origin']);
    const response = await h.call('/api/share', { identity: session.identity, revision: saved.revision });
    assert.equal(response.status, 409); assert.match((await response.json()).error, /differ from your confirmed save/);
    assert.equal(h.git(['ls-remote', '--heads', 'origin']), remoteBefore);
  } finally { await h.close(); }
});
