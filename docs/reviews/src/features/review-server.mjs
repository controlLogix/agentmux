// One owned HTTP review server per Git repository, shared by its worktrees.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, realpathSync, lstatSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { acquireNotesLock } from './notes-lock.mjs';

const protocol = 'agentmux-review-server-v1';
export function reviewEnvironment(source = process.env) {
  const redirect = /^(GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_COMMON_DIR|GIT_NAMESPACE|GIT_OBJECT_DIRECTORY|GIT_ALTERNATE_OBJECT_DIRECTORIES)$/i;
  return Object.fromEntries(Object.entries(source).filter(([key]) => !redirect.test(key)));
}
export function serverPaths(repoRoot) {
  const checkout = realpathSync.native(repoRoot);
  const env = reviewEnvironment();
  const git = args => execFileSync('git', ['--no-optional-locks', '-C', checkout, ...args], { env, encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  if (relative(checkout, realpathSync.native(git(['rev-parse', '--show-toplevel']))) !== '') throw new Error('Use the repository checkout root.');
  const common = realpathSync.native(resolve(checkout, git(['rev-parse', '--git-common-dir'])));
  const directory = resolve(common, 'agentmux-review');
  if (existsSync(directory) && lstatSync(directory).isSymbolicLink()) throw new Error('Review server state cannot be a linked directory.');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  return { checkout, state: resolve(directory, 'server.json'), settings: resolve(directory, 'settings.json') };
}

function readRecord(path) {
  if (!existsSync(path)) return null;
  if (lstatSync(path).isSymbolicLink()) throw new Error('Review server records cannot be links.');
  const bytes = readFileSync(path); if (bytes.length > 16384) throw new Error('Review server record is too large.');
  try { return JSON.parse(bytes.toString('utf8')); } catch { return null; }
}
function store(path, data) {
  const temp = path + '.' + randomBytes(8).toString('hex') + '.tmp';
  try { writeFileSync(temp, JSON.stringify(data) + '\n', { mode: 0o600, flag: 'wx' }); renameSync(temp, path); }
  finally { if (existsSync(temp)) unlinkSync(temp); }
}
function valid(record) {
  const url = typeof record?.url === 'string' && record.url.match(/^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/$/);
  return record?.protocol === protocol && /^[a-f0-9]{64}$/.test(record.token) && /^[a-f0-9]{32}$/.test(record.instanceId) &&
    url && Number(url[1]) <= 65535 &&
    typeof record.checkout === 'string' && typeof record.reviewId === 'string';
}
async function probe(record, operation = 'health') {
  if (!valid(record)) return null;
  try {
    const response = await fetch(new URL('_review/' + operation, record.url), {
      method: operation === 'stop' ? 'POST' : 'GET', redirect: 'error',
      headers: { 'X-Review-Manager-Token': record.token }, signal: AbortSignal.timeout(2500)
    });
    if (!response.ok) return null;
    const info = await response.json();
    return info.protocol === protocol && info.instanceId === record.instanceId && info.checkout === record.checkout && info.reviewId === record.reviewId ? info : null;
  } catch { return null; }
}

export async function manageReview({ repoRoot, reviewId, port, action = 'open', createReview }) {
  if (!['open', 'status', 'stop', 'restart'].includes(action) || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(reviewId) ||
    (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535))) throw new Error('Invalid review server operation.');
  const paths = serverPaths(repoRoot);
  let record = readRecord(paths.state), active = await probe(record);
  async function confirmAbsent() {
    try { const release = await acquireNotesLock(paths.state); await release(); return true; }
    catch (error) { if (error.status === 423) return false; throw error; }
  }
  if (action === 'status') {
    if (active) return { active: true, state: 'running', ...active };
    const absent = await confirmAbsent();
    return { active: absent ? false : null, state: absent ? 'inactive' : 'starting-stopping-or-unreachable' };
  }
  if (action === 'stop' || action === 'restart') {
    if (active) {
      if (record.checkout !== paths.checkout || record.reviewId !== reviewId) throw new Error('Another checkout or document owns the review server. Close that review explicitly from its checkout first.');
      if (!await probe(record, 'stop')) throw new Error('Review shutdown was not confirmed. Do not start another server.');
    } else if (action === 'stop') {
      if (!await confirmAbsent()) throw new Error('The review owner is starting, stopping or unreachable. Shutdown is not confirmed; do not start another server.');
      return { active: false, stopped: false };
    }
    if (action === 'stop') {
      for (let attempt = 0; attempt < 100; attempt++) {
        if (readRecord(paths.state)?.instanceId !== record.instanceId) return { stopped: true, stoppedInstanceId: record.instanceId };
        await delay(100);
      }
      throw new Error('The server is still draining requests. Wait before opening it again.');
    }
  }
  if (action === 'open' && active) return reuse(record);
  let release;
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    try { release = await acquireNotesLock(paths.state); break; }
    catch (error) {
      if (error.status !== 423) throw error;
      record = readRecord(paths.state); active = await probe(record);
      if (action === 'open' && active) return reuse(record);
      await delay(100);
    }
  }
  if (!release) throw new Error('The existing server is starting, stopping or unreachable. No second server was started.');
  let released = false;
  const unlock = async () => { if (!released) { released = true; await release(); } };
  let local, stopping;
  const owned = { protocol, instanceId: randomBytes(16).toString('hex'), token: randomBytes(32).toString('hex'),
    checkout: paths.checkout, reviewId, pid: process.pid };
  const info = () => { const { token, ...publicInfo } = owned; return publicInfo; };
  const stop = () => {
    if (stopping) return stopping;
    stopping = (async () => {
      if (local?.server.listening) {
        await new Promise((done, reject) => { local.server.close(error => error ? reject(error) : done()); local.server.closeIdleConnections?.(); });
      }
      await local?.drain?.();
      try { if (readRecord(paths.state)?.instanceId === owned.instanceId) unlinkSync(paths.state); }
      finally { await unlock(); }
    })();
    return stopping;
  };
  try {
    record = readRecord(paths.state); active = await probe(record);
    if (active) { await unlock(); return reuse(record); }
    const settings = readRecord(paths.settings);
    const selectedPort = port === undefined ? (Number.isInteger(settings?.port) && settings.port > 0 && settings.port <= 65535 ? settings.port : 4317) : port;
    local = await createReview({ token: owned.token, info, stop });
    owned.version = local.documentVersion;
    owned.url = await local.listen(selectedPort);
    store(paths.settings, { port: local.server.address().port });
    store(paths.state, owned);
    return { ...info(), reused: false, stop, server: local.server };
  } catch (error) {
    await stop();
    if (error.code === 'EADDRINUSE' || error.code === 'EACCES') throw new Error('The saved review port is occupied by an unverified process. No extra server was started. Stop the known old review, or explicitly choose a free port.');
    throw error;
  }
  function reuse(existing) {
    if (existing.checkout !== paths.checkout || existing.reviewId !== reviewId) throw new Error('One review server is already open from another checkout or document. Close that review explicitly before switching.');
    if (port !== undefined && port !== 0 && Number(new URL(existing.url).port || 80) !== port) {
      throw new Error('The review server is already open on a different port. Restart it explicitly to use the requested port.');
    }
    const { token, ...publicInfo } = existing;
    return { ...publicInfo, reused: true };
  }
}
