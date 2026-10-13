import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep, basename } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scanInbox } from './inbox.mjs';

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'agentmux-inbox-'));
  const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^GIT_/i.test(key)));
  const git = (args, overrides = {}) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', windowsHide: true,
    env: { ...cleanEnv, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: join(root, 'empty-global'), ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  writeFileSync(join(root, 'empty-global'), '');
  git(['init', '-q']); git(['config', 'user.name', 'Ryan Helms']); git(['config', 'user.email', 'ryan@example.test']);
  mkdirSync(join(root, 'docs/reviews/demo/notes'), { recursive: true });
  const config = { id: 'demo', title: 'Demo review', artifactPath: 'docs/demo.html', notesPath: 'docs/reviews/demo/notes', workPaths: ['requests'], shareBranch: 'feat/review' };
  writeFileSync(join(root, 'docs/reviews/demo/review.json'), JSON.stringify(config));
  writeFileSync(join(root, 'docs/reviews/demo/document-version.json'), JSON.stringify({ version: 'sha256:' + 'a'.repeat(64) }));
  writeFileSync(join(root, 'docs/demo.html'), '<!doctype html><title>Demo</title>');
  const note = (name, text) => '# Review\n\n```review-metadata\n' + JSON.stringify({ format: 'agentmux-review-notes', schemaVersion: 1, documentId: 'demo', documentVersion: 'sha256:' + 'a'.repeat(64), reviewer: name }) + '\n```\n\n```review-note global\n' + text + '\n```\n';
  writeFileSync(join(root, 'docs/reviews/demo/notes/ryan.md'), note('Ryan Helms', ''));
  git(['add', 'docs']); git(['commit', '-qm', 'Document with empty placeholder']); git(['branch', '-m', 'feat/review']);
  return { root, git, config, note,
    scan: () => scanInbox({ repoRoot: root }),
    close() {
      const target = resolve(root); assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('agentmux-inbox-'));
      rmSync(target, { recursive: true, force: true });
    } };
}

test('discovery groups duplicate refs, omits placeholders, lists multiple submissions and preserves Git state', () => {
  const h = fixture();
  try {
    assert.equal(h.scan().submissions.length, 0);
    h.git(['config', 'user.name', 'Nick Klute']); h.git(['config', 'user.email', 'nick@example.test']);
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/nick.md'), h.note('Nick Klute', 'Which action owns acceptance?'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Nick questions']);
    const nick = h.git(['rev-parse', 'HEAD']);
    writeFileSync(join(h.root, 'requests'), 'Please review work'); h.git(['add', 'requests']); h.git(['commit', '-qm', 'Work submission']);
    h.git(['update-ref', 'refs/remotes/origin/feat/review', 'HEAD']);
    h.git(['config', 'user.name', 'Ryan Helms']); h.git(['config', 'user.email', 'ryan@example.test']);
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/ryan.md'), h.note('Ryan Helms', 'Unshared local draft'));
    const before = h.git(['status', '--porcelain=v1']); const head = h.git(['rev-parse', 'HEAD']); const config = readFileSync(join(h.root, '.git/config'));
    const result = h.scan(); assert.equal(result.submissions.length, 2);
    const item = result.submissions.find(item => item.kind === 'notes');
    assert.equal(item.commit, nick); assert.equal(item.author, 'Nick Klute'); assert.equal(item.fromCurrentIdentity, false);
    assert.equal(item.refs.length, 2); assert.equal(item.replyStatus, 'unknown');
    assert.equal(result.localDrafts[0].path, 'docs/reviews/demo/notes/ryan.md');
    assert.equal(h.git(['status', '--porcelain=v1']), before); assert.equal(h.git(['rev-parse', 'HEAD']), head);
    assert.deepEqual(readFileSync(join(h.root, '.git/config')), config);
  } finally { h.close(); }
});

test('explicit reply receipts apply only to their exact submission and require a present response', () => {
  const h = fixture();
  try {
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/nick.md'), h.note('Nick Klute', 'Question one'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Questions']); const submission = h.git(['rev-parse', 'HEAD']);
    mkdirSync(join(h.root, 'docs/reviews/demo/responses'));
    const receipt = { schemaVersion: 1, documentId: 'demo', submissionCommit: submission, status: 'answered', responderEmail: 'ryan@example.test', answeredAt: new Date().toISOString(), responsePath: 'docs/reviews/demo/notes/ryan.md' };
    const file = join(h.root, 'docs/reviews/demo/responses', submission + '.json');
    writeFileSync(file, JSON.stringify({ ...receipt, responsePath: 'missing.md' }));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Invalid receipt']); assert.equal(h.scan().submissions[0].replyStatus, 'unknown');
    writeFileSync(join(h.root, receipt.responsePath), h.note('Ryan Helms', 'Here is my answer'));
    writeFileSync(file, JSON.stringify(receipt)); h.git(['add', 'docs']); h.git(['commit', '-qm', 'Recorded reply']);
    assert.equal(h.scan().submissions.find(item => item.commit === submission).replyStatus, 'answered');
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/nick.md'), h.note('Nick Klute', 'New question'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'New submission']);
    assert.equal(h.scan().submissions.find(item => item.path.endsWith('nick.md')).replyStatus, 'unknown');
  } finally { h.close(); }
});

test('invalid paths are not executed or followed and old submissions stay outside the window', () => {
  const h = fixture();
  try {
    writeFileSync(join(h.root, 'docs/reviews/demo/review.json'), JSON.stringify({ ...h.config, workPaths: ['../outside'] }));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Invalid path']);
    const result = h.scan(); assert.equal(result.submissions.length, 0); assert.match(result.warnings[0], /Invalid work paths/);
    assert.throws(() => scanInbox({ repoRoot: h.root, reviewsDir: '../outside' }));
    assert.throws(() => scanInbox({ repoRoot: h.root, days: 0 }));
    writeFileSync(join(h.root, 'docs/reviews/demo/review.json'), JSON.stringify(h.config));
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/nick.md'), h.note('Nick Klute', 'Older questions'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Questions']);
    assert.equal(scanInbox({ repoRoot: h.root, now: new Date(Date.now() + 60 * 86400000) }).submissions.length, 0);
  } finally { h.close(); }
});

test('duplicate submissions retain branch-specific document versions instead of claiming one latest version', () => {
  const h = fixture();
  try {
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/nick.md'), h.note('Nick Klute', 'Version question'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Notes']);
    h.git(['update-ref', 'refs/remotes/origin/feat/review', 'HEAD']);
    writeFileSync(join(h.root, 'docs/reviews/demo/document-version.json'), JSON.stringify({ version: 'sha256:' + 'b'.repeat(64) }));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'New document version']);
    const item = h.scan().submissions[0]; assert.equal(item.refs.length, 2);
    assert.equal(item.currentVersion, null); assert.equal(item.versionMatches, null);
    assert.equal(item.versionsByRef['refs/heads/feat/review'], 'sha256:' + 'b'.repeat(64));
    assert.equal(item.versionsByRef['refs/remotes/origin/feat/review'], 'sha256:' + 'a'.repeat(64));
  } finally { h.close(); }
});

test('commit dates order submissions across timezone offsets and preserve older author dates', () => {
  const h = fixture();
  try {
    const first = Date.now() - 3600000;
    const olderOffset = new Date(first + 14 * 3600000).toISOString().slice(0, 19) + '+14:00';
    const newerUTC = new Date(first + 60000).toISOString();
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/nick.md'), h.note('Nick Klute', 'Older submission'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Older commit'], { GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z', GIT_COMMITTER_DATE: olderOffset });
    writeFileSync(join(h.root, 'docs/reviews/demo/notes/sam.md'), h.note('Sam', 'Newer submission'));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Newer commit'], { GIT_COMMITTER_DATE: newerUTC });
    const items = h.scan().submissions; assert.equal(items.length, 2);
    assert.ok(items[0].path.endsWith('sam.md')); assert.ok(items[1].path.endsWith('nick.md'));
    assert.equal(Date.parse(items[1].authoredAt), Date.parse('2000-01-01T00:00:00Z'));
    assert.equal(Date.parse(items[1].submittedAt), Date.parse(olderOffset));
  } finally { h.close(); }
});

test('malformed workPaths are reported rather than silently hiding work', () => {
  const h = fixture();
  try {
    writeFileSync(join(h.root, 'docs/reviews/demo/review.json'), JSON.stringify({ ...h.config, workPaths: 'requests' }));
    h.git(['add', 'docs']); h.git(['commit', '-qm', 'Malformed work configuration']);
    assert.match(h.scan().warnings[0], /expected an array/);
  } finally { h.close(); }
});

test('inherited Git repository and index overrides do not redirect discovery', () => {
  const h = fixture(); const other = fixture();
  const keys = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'];
  const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  try {
    process.env.GIT_DIR = join(other.root, '.git'); process.env.GIT_WORK_TREE = other.root;
    process.env.GIT_INDEX_FILE = join(other.root, '.git/index');
    const before = readFileSync(process.env.GIT_INDEX_FILE);
    assert.equal(realpathSync.native(h.scan().repository), realpathSync.native(h.root));
    assert.deepEqual(readFileSync(process.env.GIT_INDEX_FILE), before);
    const redirectedFixture = fixture();
    try { assert.equal(realpathSync.native(redirectedFixture.git(['rev-parse', '--show-toplevel'])), realpathSync.native(redirectedFixture.root)); }
    finally { redirectedFixture.close(); }
    const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^GIT_/i.test(key)));
    const output = execFileSync(process.execPath, [fileURLToPath(new URL('./inbox.mjs', import.meta.url)), '--repo', h.root], {
      encoding: 'utf8', windowsHide: true,
      env: { ...cleanEnv, git_dir: join(other.root, '.git'), git_work_tree: other.root, git_index_file: join(other.root, '.git/index') }
    });
    assert.equal(realpathSync.native(JSON.parse(output).repository), realpathSync.native(h.root));
    assert.deepEqual(readFileSync(join(other.root, '.git/index')), before);
  } finally {
    for (const key of keys) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; }
    h.close(); other.close();
  }
});
