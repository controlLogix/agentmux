import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, utimesSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep, basename } from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanInbox } from './inbox.mjs';

function fixture({ notesPath = 'docs/reviews/demo/notes', workPaths = [] } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'agentmux-inbox-boundary-'));
  const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^GIT_/i.test(key)));
  const git = args => execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...cleanEnv, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: join(root, 'empty-global'), GIT_OPTIONAL_LOCKS: '1' }
  }).trim();
  const write = (path, text) => { mkdirSync(join(root, path, '..'), { recursive: true }); writeFileSync(join(root, path), text); };
  write('empty-global', ''); git(['init', '-q']);
  git(['config', 'user.name', 'Boundary Reviewer']); git(['config', 'user.email', 'boundary@example.test']);
  const config = { id: 'demo', title: 'Boundary review', notesPath, artifactPath: 'docs/demo.html', workPaths };
  write('docs/reviews/demo/review.json', JSON.stringify(config));
  write('docs/reviews/demo/document-version.json', JSON.stringify({ version: 'fixture-version' }));
  write('docs/demo.html', '<!doctype html><title>Fixture</title>');
  const note = text => '```review-metadata\n' + JSON.stringify({ format: 'agentmux-review-notes', schemaVersion: 1,
    documentId: 'demo', documentVersion: 'fixture-version', reviewer: 'Boundary Reviewer' }) +
    '\n```\n\n```review-note global\n' + text + '\n```\n';
  const commit = () => { git(['add', '.']); git(['commit', '-qm', 'Offline boundary fixture']); };
  return { root, git, write, note, commit, config,
    close() {
      const target = resolve(root);
      assert.ok(target.startsWith(resolve(tmpdir()) + sep) && basename(target).startsWith('agentmux-inbox-boundary-'));
      rmSync(target, { recursive: true, force: true });
    }
  };
}

test('discovery does not refresh the index when clean tracked-file metadata changes', () => {
  const h = fixture();
  try {
    h.write('tracked.txt', 'Unchanged bytes'); h.commit();
    const file = join(h.root, 'tracked.txt'), metadata = statSync(file);
    utimesSync(file, metadata.atime, new Date(metadata.mtimeMs + 10000));
    const before = readFileSync(join(h.root, '.git/index'));
    scanInbox({ repoRoot: h.root });
    assert.deepEqual(readFileSync(join(h.root, '.git/index')), before);
    // The fixture would expose an ordinary status refresh, rather than merely comparing a stable index.
    h.git(['status', '--porcelain=v1']);
    assert.notDeepEqual(readFileSync(join(h.root, '.git/index')), before);
  } finally { h.close(); }
});

test('work paths and review directories keep literal wildcard characters', () => {
  const h = fixture({ workPaths: ['requests/*.txt'] });
  try {
    h.write('requests/unrelated.txt', 'This is not the configured literal path'); h.commit();
    const result = scanInbox({ repoRoot: h.root });
    assert.equal(result.submissions.length, 0);
    assert.equal(scanInbox({ repoRoot: h.root, reviewsDir: 'docs/rev*' }).submissions.length, 0);
  } finally { h.close(); }
});

test('a manifest outside its notes directory discovers committed notes and local drafts', () => {
  const h = fixture({ notesPath: 'feedback/review-notes' });
  try {
    h.write('feedback/review-notes/reviewer.md', h.note('Review the boundary')); h.commit();
    h.write('feedback/review-notes/reviewer.md', h.note('Unshared local change'));
    const result = scanInbox({ repoRoot: h.root });
    assert.equal(result.submissions.length, 1);
    assert.equal(result.submissions[0].path, 'feedback/review-notes/reviewer.md');
    assert.equal(result.submissions[0].versionMatches, true);
    assert.equal(result.localDrafts.length, 1);
    assert.equal(result.localDrafts[0].path, 'feedback/review-notes/reviewer.md');
  } finally { h.close(); }
});

test('manifest truncation reports incomplete coverage without widening discovery', () => {
  const h = fixture();
  try {
    for (let index = 0; index < 100; index++) {
      const id = 'extra-' + index;
      h.write('docs/reviews/' + id + '/review.json', JSON.stringify({ ...h.config, id, notesPath: 'feedback/' + id }));
    }
    h.commit();
    const result = scanInbox({ repoRoot: h.root });
    assert.equal(result.submissions.length, 0);
    assert.ok(result.warnings.some(value => value.startsWith('Only the first 100 review manifests')));
    assert.equal(result.limits.manifestsPerHead, 100);
  } finally { h.close(); }
});

test('non-string manifest identifiers are rejected rather than coerced into valid IDs', () => {
  const h = fixture();
  try {
    for (const id of [undefined, null, 42]) {
      h.write('docs/reviews/demo/review.json', JSON.stringify({ ...h.config, id })); h.commit();
      const result = scanInbox({ repoRoot: h.root });
      assert.equal(result.submissions.length, 0);
      assert.ok(result.warnings.some(value => value.startsWith('Invalid review manifest:')));
    }
  } finally { h.close(); }
});

test('reply disagreement across refs stays mixed with exact pending and answered receipts', () => {
  const h = fixture();
  try {
    const submittedPath = 'docs/reviews/demo/notes/submitter.md';
    h.write(submittedPath, h.note('Question')); h.commit();
    const submission = h.git(['rev-parse', 'HEAD']);
    const receiptPath = 'docs/reviews/demo/responses/' + submission + '.json';
    const receipt = { schemaVersion: 1, documentId: 'demo', submissionCommit: submission, status: 'pending' };
    h.write(receiptPath, JSON.stringify(receipt)); h.commit();
    h.git(['update-ref', 'refs/remotes/origin/pending', 'HEAD']);
    const responsePath = 'docs/reviews/demo/notes/responder.md';
    h.write(responsePath, h.note('Answer'));
    h.write(receiptPath, JSON.stringify({ ...receipt, status: 'answered', responderEmail: 'reply@example.test',
      answeredAt: new Date().toISOString(), responsePath })); h.commit();
    const item = scanInbox({ repoRoot: h.root }).submissions.find(value => value.path === submittedPath);
    assert.equal(item.commit, submission);
    assert.equal(item.replyStatus, 'mixed');
    assert.deepEqual(new Set(Object.values(item.replyByRef)), new Set(['pending', 'answered']));
    assert.equal(item.refs.length, 2);
  } finally { h.close(); }
});
