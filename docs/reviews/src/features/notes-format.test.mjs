import test from 'node:test';
import assert from 'node:assert/strict';
import { exportMarkdown, importMarkdown, reviewerSlug, draftKey } from './notes-format.mjs';

const document = { id: 'test-review', title: 'Test review', version: 'sha256:' + 'a'.repeat(64),
  sections: [{ id: 'scene', title: 'Scene', question: 'What changes?' }, { id: 'global', title: 'Overall', question: 'Other notes?' }] };
const make = (notes = { scene: '', global: '' }) => ({ format: 'agentmux-review-notes', schemaVersion: 1,
  documentId: document.id, documentVersion: document.version, reviewer: 'Nick', exportedAt: '2026-10-13T14:00:00Z', notes });

test('Markdown round trip preserves Unicode, code fences, headings, whitespace and empty notes', () => {
  const record = make({ scene: '  Hello Nick 👋\n## Heading\n```js\nconst x = "</script>";\n```\n```review-metadata\n{}\n```\n```review-note global\nNested example\n```\n\n', global: '' });
  const result = importMarkdown(exportMarkdown(record, document), document);
  assert.deepEqual({ ...result.notes }, record.notes);
  assert.equal(result.documentVersion, record.documentVersion);
});
test('old document versions remain attributed and other documents are rejected', () => {
  const record = { ...make(), documentVersion: 'sha256:' + 'b'.repeat(64) };
  assert.equal(importMarkdown(exportMarkdown(record, document), document).documentVersion, record.documentVersion);
  assert.throws(() => importMarkdown(exportMarkdown(make(), document), { ...document, id: 'other' }), /different document/);
});
test('rejects unsupported format, duplicate, missing, unknown and overlong sections before import', () => {
  const markdown = exportMarkdown(make(), document);
  assert.throws(() => importMarkdown(markdown.replace('"schemaVersion": 1', '"schemaVersion": 2'), document), /Unsupported/);
  assert.throws(() => exportMarkdown({ ...make(), documentVersion: [document.version] }, document), /document version/);
  assert.throws(() => importMarkdown(markdown + '\n```review-note scene\nDuplicate\n```\n', document), /Duplicate/);
  assert.throws(() => importMarkdown(markdown.replace('review-note scene', 'review-note unknown'), document), /sections/);
  assert.throws(() => importMarkdown(markdown.replace('```review-note scene\n\n```', 'removed'), document), /sections/);
  assert.throws(() => exportMarkdown(make({ scene: 'x'.repeat(20001), global: '' }), document), /20,000/);
  assert.throws(() => importMarkdown(markdown + '\n```review-note scene\nUnclosed', document), /incomplete/);
});
test('safe filenames and distinct document draft keys', () => {
  const reviewers = [{ id: 'nick', name: 'Nick Klute' }, { id: 'ryan', name: 'Ryan Helms' }];
  assert.equal(reviewerSlug('Nick Klute', reviewers), 'nick');
  assert.equal(reviewerSlug('RYAN', reviewers), 'ryan');
  assert.equal(reviewerSlug('../../Other Reviewer'), 'other-reviewer');
  assert.equal(reviewerSlug('CON'), 'reviewer-con');
  assert.throws(() => reviewerSlug('  '));
  assert.notEqual(draftKey('first'), draftKey('second'));
});
