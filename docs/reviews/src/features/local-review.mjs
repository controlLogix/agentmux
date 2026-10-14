// Local repository access. Sharing requires an explicit request from the review page.
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, renameSync, unlinkSync, existsSync, realpathSync } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { importMarkdown, exportMarkdown, reviewerSlug, MAX_FILE } from './notes-format.mjs';
import { acquireNotesLock } from './notes-lock.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = (status, message) => Object.assign(new Error(message), { status });
const jsonEscape = data => JSON.stringify(data).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

export function createLocalReview({ repoRoot, config, document, html, gitEnv = process.env, management = null, acquireLock = acquireNotesLock }) {
  if (config.id !== document.id || !Array.isArray(config.reviewers) || config.reviewers.some(person =>
    typeof person.id !== 'string' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(person.id) || typeof person.name !== 'string')) throw new Error('Invalid review configuration.');
  const canonical = path => realpathSync.native(path);
  const root = canonical(repoRoot);
  const git = args => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', env: { ...gitEnv, GIT_TERMINAL_PROMPT: '0' }, timeout: 30000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  if (relative(root, canonical(git(['rev-parse', '--show-toplevel']))) !== '') throw new Error('Use the Git repository root.');
  function inside(path) {
    const target = resolve(root, path);
    const rel = relative(root, target);
    if (isAbsolute(path) || rel.startsWith('..') || isAbsolute(rel)) throw new Error('Review path leaves the repository.');
    const checked = canonical(existsSync(target) ? target : resolve(target, '..'));
    const realRel = relative(root, checked);
    if (realRel.startsWith('..') || isAbsolute(realRel)) throw new Error('Review path follows a link outside the repository.');
    return target;
  }
  const notesRoot = canonical(inside(config.notesPath));
  function setting(key) {
    try { return git(['config', '--get', key]); } catch (error) { if (error.status === 1) return ''; throw error; }
  }
  function identity() {
    const name = setting('user.name'), email = setting('user.email');
    const configured = Boolean(name.trim() && name.length <= 120 && !/[\r\n\0]/.test(name) &&
      email.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(email));
    if (!configured) return { name, email, configured: false };
    const compact = value => value.toLowerCase().replace(/[^a-z0-9]/g, '');
    const known = config.reviewers.find(person => (person.emails || []).some(value => value.toLowerCase() === email.toLowerCase()) ||
      [person.id, person.name].some(value => compact(value) === compact(name)));
    let slug; try { slug = reviewerSlug(name); } catch { slug = 'reviewer'; }
    const fallback = slug + '-' + hash(email.toLowerCase()).slice(0, 8);
    let id = known ? known.id : fallback;
    // An existing named file binds to its recorded email, not just its display name.
    const existing = inside(relative(root, resolve(notesRoot, id + '.md')));
    if (existsSync(existing)) {
      const bytes = readFileSync(existing);
      if (bytes.length > MAX_FILE) throw fail(400, 'Existing notes exceed 2 MB.');
      const owner = importMarkdown(bytes.toString('utf8'), document);
      if (owner.reviewerEmail && owner.reviewerEmail.toLowerCase() !== email.toLowerCase()) id = fallback;
    }
    return { name, email, configured: true, id, filename: id + '.md' };
  }
  function current(person) {
    const path = inside(relative(root, resolve(notesRoot, person.filename)));
    const actual = canonical(existsSync(path) ? path : notesRoot);
    if (relative(notesRoot, actual).startsWith('..')) throw fail(400, 'Notes must stay inside this review’s notes folder.');
    const bytes = existsSync(path) ? readFileSync(path) : null;
    if (bytes && bytes.length > MAX_FILE) throw fail(400, 'Existing notes exceed 2 MB.');
    return { path, revision: bytes ? hash(bytes) : null, record: bytes ? importMarkdown(bytes.toString('utf8'), document) : null };
  }
  async function share(person, body) {
    const branch = config.shareBranch || 'feat/agentmux-platform-rearchitecture';
    const remote = config.shareRemote || 'origin';
    if (!/^[a-zA-Z0-9][a-zA-Z0-9/._-]*$/.test(branch) || !/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(remote)) throw fail(400, 'Invalid sharing configuration.');
    const state = current(person);
    const releaseFile = await acquireLock(state.path);
    let releaseRepo;
    let committed = false;
    try {
      releaseRepo = await acquireLock(resolve(root, git(['rev-parse', '--git-common-dir'])));
      const path = relative(root, state.path).replaceAll('\\', '/');
      const check = () => {
        const latest = identity();
        if (latest.email !== person.email || latest.name !== person.name || latest.id !== person.id || current(person).revision !== body.revision || !state.record) throw fail(409, 'Your notes or Git identity changed. Reload before sharing.');
        if (git(['symbolic-ref', '--quiet', '--short', 'HEAD']) !== branch) throw fail(409, 'Open the review on ' + branch + ' before sharing.');
        for (const name of ['MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'rebase-merge', 'rebase-apply']) {
          if (existsSync(resolve(root, git(['rev-parse', '--git-path', name])))) throw fail(409, 'Finish the current Git merge or rebase before sharing.');
        }
        if (git(['ls-files', '--unmerged'])) throw fail(409, 'Resolve Git conflicts before sharing.');
      };
      check();
      const before = git(['rev-parse', 'HEAD']);
      let destination;
      let rewrites = '';
      try { rewrites = git(['config', '--name-only', '--get-regexp', '^url\\..*\\.(insteadof|pushinsteadof)$']); }
      catch (error) { if (error.status !== 1) throw error; }
      // Passing a resolved URL back to Git can apply another rewrite, including push-only rules.
      if (rewrites) throw fail(409, 'Sharing does not support Git URL rewrite rules. Ask Codex to configure a direct, matching fetch and push destination.');
      try {
        const fetchUrls = git(['remote', 'get-url', '--all', remote]).split('\n');
        const pushUrls = git(['remote', 'get-url', '--push', '--all', remote]).split('\n');
        if (fetchUrls.length !== 1 || pushUrls.length !== 1 || fetchUrls[0] !== pushUrls[0] || !pushUrls[0] || pushUrls[0].startsWith('-')) throw new Error('Ambiguous destination');
        destination = pushUrls[0];
      } catch { throw fail(409, 'Sharing needs one matching Git fetch and push destination. Ask Codex to check this repository’s remote configuration.'); }
      try { git(['fetch', '--no-tags', '--no-recurse-submodules', destination, 'refs/heads/' + branch]); }
      catch { throw fail(502, 'Could not read the shared branch. Check your Git connection and sign-in, then try Share notes again.'); }
      const base = git(['rev-parse', 'FETCH_HEAD']);
      const outgoing = head => {
        try { git(['merge-base', '--is-ancestor', base, head]); }
        catch { throw fail(409, 'The shared branch has changes you do not have. Update the repository before sharing; your notes remain saved.'); }
        for (const commit of git(['rev-list', base + '..' + head]).split('\n').filter(Boolean)) {
          const parents = git(['rev-list', '--parents', '-n', '1', commit]).split(' ');
          const paths = git(['diff-tree', '--no-commit-id', '--name-only', '-r', '-z', commit]).split('\0').filter(Boolean);
          if (parents.length !== 2 || paths.length !== 1 || paths[0] !== path || git(['show', '-s', '--format=%ae', commit]).toLowerCase() !== person.email.toLowerCase()) throw fail(409, 'Sharing would also push other work. Share notes stopped without pushing. Ask Codex to publish or reconcile that work first.');
        }
      };
      outgoing(before); check();
      if (git(['rev-parse', 'HEAD']) !== before) throw fail(409, 'The branch changed while sharing. Try again.');
      const dirty = git(['status', '--porcelain', '--', path]);
      if (dirty) {
        if (!git(['ls-files', '--', path])) git(['add', '--', path]);
        try { git(['commit', '--only', '-m', 'Review notes: ' + config.id + ' by ' + person.name, '--', path]); committed = true; }
        catch { throw fail(409, 'Git did not confirm the notes commit. A hook or signing check may have blocked it. Notes remain saved; check the repository before trying again.'); }
      }
      const candidate = git(['rev-parse', 'HEAD']);
      outgoing(candidate); check();
      const blob = execFileSync('git', ['-C', root, 'show', candidate + ':' + path], { env: gitEnv, windowsHide: true, timeout: 30000, maxBuffer: MAX_FILE * 2, stdio: ['ignore', 'pipe', 'pipe'] });
      // Git may normalize Windows line endings; all other saved bytes must match.
      const normalized = bytes => Buffer.from(Array.from(bytes).filter((byte, index) => byte !== 13 || bytes[index + 1] !== 10));
      if (!normalized(blob).equals(normalized(readFileSync(state.path)))) throw fail(409, 'The committed notes differ from your confirmed save. Nothing was pushed. Ask Codex to check Git hooks or file filters before sharing.');
      if (candidate !== base) {
        try { git(['-c', 'push.followTags=false', '-c', 'remote.' + remote + '.mirror=false', 'push', '--no-mirror', '--no-follow-tags', '--recurse-submodules=no', destination, candidate + ':refs/heads/' + branch]); }
        catch { throw fail(502, 'Notes are committed locally, but the push was not confirmed. Check your connection or whether the shared branch changed, then try Share notes again.'); }
      }
      const published = git(['ls-remote', '--heads', destination, 'refs/heads/' + branch]).split(/\s/)[0];
      if (published !== candidate) throw fail(502, 'The remote did not confirm this notes commit. Notes remain saved locally. Try Share notes again.');
      return { commit: candidate, filename: person.filename, message: candidate === base ? 'Your notes are already shared.' : 'Your notes were committed and pushed.', committed };
    } finally { if (releaseRepo) await releaseRepo(); await releaseFile(); }
  }
  const token = randomBytes(32).toString('hex');
  let origin;
  let activeHandlers = 0;
  const drainWaiters = [];
  const server = createServer(async (request, response) => {
    activeHandlers++;
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    const send = (status, data) => { response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); response.end(JSON.stringify(data)); };
    try {
      if (request.headers.host !== origin.slice(7) || (request.headers.origin && request.headers.origin !== origin) ||
          request.headers['sec-fetch-site'] === 'cross-site') throw fail(403, 'Use the local review URL printed by the launcher.');
      if (management && ['/_review/health', '/_review/stop'].includes(request.url)) {
        if (request.headers['x-review-manager-token'] !== management.token) throw fail(403, 'Review server management requires its local owner token.');
        if (request.url === '/_review/health' && request.method === 'GET') { send(200, management.info()); return; }
        if (request.url === '/_review/stop' && request.method === 'POST') {
          send(200, management.info());
          setImmediate(() => { management.stop().catch(() => { console.error('Review shutdown did not finish. Check the launcher before reopening.'); }); });
          return;
        }
        throw fail(405, 'Unsupported review server management method.');
      }
      if (request.method === 'GET' && request.url === '/') {
        const marker = /(<script type="application\/json" id="review-data">)([\s\S]*?)(<\/script>)/;
        const data = JSON.parse(html.match(marker)?.[2] || 'null');
        if (!data || data.document.version !== document.version) throw fail(500, 'Rebuild the review before launching.');
        const page = html.replace(marker, (_, start, contents, end) => start + jsonEscape({ ...data, bridge: { token } }) + end)
          .replace("form-action 'none'", "form-action 'none'; connect-src 'self'");
        response.setHeader('Content-Security-Policy', "frame-ancestors 'none'; connect-src 'self'");
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); response.end(page); return;
      }
      if (request.headers['x-review-token'] !== token) throw fail(403, 'The local review session is missing or expired. Reload the page.');
      if (request.method === 'GET' && request.url === '/api/session') {
        const person = identity();
        const notes = person.configured ? current(person) : { revision: null, record: null };
        send(200, { identity: person, revision: notes.revision, record: notes.record }); return;
      }
      if (request.method !== 'POST' || !['/api/identity', '/api/notes', '/api/share'].includes(request.url)) throw fail(404, 'Unknown review operation.');
      if (!request.headers['content-type']?.startsWith('application/json')) throw fail(415, 'Send JSON.');
      let bytes = 0; const chunks = [];
      for await (const chunk of request) { bytes += chunk.length; if (bytes > MAX_FILE) throw fail(413, 'Notes exceed 2 MB.'); chunks.push(chunk); }
      let body; try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw fail(400, 'Invalid JSON.'); }
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw fail(400, 'Send a JSON object.');
      if (request.url === '/api/identity') {
        // Existing effective identity is authoritative. Setup changes only missing/invalid identity.
        if (identity().configured) throw fail(409, 'Git identity is already configured. Reload to use it.');
        if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 120 || /[\r\n\0]/.test(body.name) ||
            typeof body.email !== 'string' || body.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(body.email)) throw fail(400, 'Enter a name and email address.');
        git(['config', '--local', '--replace-all', 'user.name', body.name.trim()]);
        git(['config', '--local', '--replace-all', 'user.email', body.email.trim()]);
        send(200, { configured: true }); return;
      }
      const person = identity();
      if (!person.configured) throw fail(409, 'Set your Git name and email first.');
      if (body.identity?.email !== person.email || body.identity?.name !== person.name) throw fail(409, 'Git identity changed. Reload before saving notes.');
      if (request.url === '/api/share') { send(200, await share(person, body)); return; }
      const record = { ...body.record, reviewer: person.name, reviewerEmail: person.email, reviewerId: person.id };
      let text; try { text = exportMarkdown(record, document); } catch (error) { throw fail(400, error.message); }
      const state = current(person);
      const release = await acquireLock(state.path);
      const temp = state.path + '.' + randomBytes(8).toString('hex') + '.tmp';
      try {
        const latestIdentity = identity();
        if (latestIdentity.email !== person.email || latestIdentity.name !== person.name || latestIdentity.id !== person.id) throw fail(409, 'Git identity or note ownership changed. Reload before saving.');
        if (current(person).revision !== body.revision) throw fail(409, 'Your notes file changed outside this page. Reload and review those changes; your browser draft is preserved.');
        writeFileSync(temp, text, { flag: 'wx', mode: 0o600 });
        if (current(person).revision !== state.revision) throw fail(409, 'Your notes changed while saving. Reload to reconcile them.');
        renameSync(temp, state.path);
      } finally { try { if (existsSync(temp)) unlinkSync(temp); } finally { await release(); } }
      send(200, { revision: hash(text), filename: person.filename });
    } catch (error) { send(error.status || 500, { error: error.status ? error.message : 'The local helper could not complete the operation. Check its terminal output.' }); }
    finally { activeHandlers--; if (!activeHandlers) drainWaiters.splice(0).forEach(done => done()); }
  });
  return {
    server, token,
    async drain() { if (activeHandlers) await new Promise(done => drainWaiters.push(done)); },
    async listen(port = 4317) {
      await new Promise((done, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', done); });
      origin = 'http://127.0.0.1:' + server.address().port;
      return origin + '/';
    }
  };
}
