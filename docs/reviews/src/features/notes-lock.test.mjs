import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, realpathSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep, basename, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { acquireNotesLock } from './notes-lock.mjs';

test('write lock excludes a second process and is released automatically when the owner exits', async () => {
  const root = mkdtempSync(join(tmpdir(), 'agentmux-review-lock-'));
  const path = join(root, 'notes.md');
  const source = 'import { acquireNotesLock } from ' + JSON.stringify(new URL('./notes-lock.mjs', import.meta.url).href) +
    '; await acquireNotesLock(process.argv[1]); process.stdout.write("READY\\n");';
  const child = spawn(process.execPath, ['--input-type=module', '-e', source, path], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await new Promise((done, reject) => {
      let text = ''; child.stdout.on('data', bytes => { text += bytes; if (text.includes('READY')) done(); });
      child.once('error', reject); child.once('exit', code => { if (!text.includes('READY')) reject(new Error('Lock fixture exited: ' + code)); });
    });
    await assert.rejects(acquireNotesLock(path), error => error.status === 423);
    const exited = new Promise(done => child.once('exit', done)); child.kill(); await exited;
    const release = await acquireNotesLock(path); await release();
  } finally {
    if (child.exitCode === null && child.signalCode === null) { const exited = new Promise(done => child.once('exit', done)); child.kill(); await exited; }
    const target = resolve(root);
    assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('agentmux-review-lock-'));
    rmSync(target, { recursive: true, force: true });
  }
});
test('resetting an accepted lock connection has an error handler', async () => {
  let accept;
  const source = readFileSync(new URL('./notes-lock.mjs', import.meta.url), 'utf8').replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '') + '\nacquireNotesLock;';
  const acquire = runInNewContext(source, { process, resolve, dirname, basename, join, realpathSync, existsSync, createHash,
    createServer: callback => { accept = callback; return { once() {}, listen(address, done) { done(); }, close(done) { done(); } }; } });
  const release = await acquire(join(tmpdir(), 'fixture-lock-reset.md'));
  const handlers = new Map(); let ended = false;
  accept({ on: (type, handler) => handlers.set(type, handler), end: () => { ended = true; } });
  assert.equal(ended, true); assert.ok(handlers.has('error'));
  assert.doesNotThrow(() => handlers.get('error')(Object.assign(new Error('Connection reset'), { code: 'ECONNRESET' })));
  await release();
});
