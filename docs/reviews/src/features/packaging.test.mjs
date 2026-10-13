import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { Script, runInNewContext } from 'node:vm';
import { renderScene } from '../../../planning/2026-10-09/review-site/src/components/organisms/index.mjs';
import { importMarkdown, exportMarkdown, reviewerSlug } from './notes-format.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const builder = resolve(repo, 'docs/planning/2026-10-09/review-site/src/pages/build.mjs');
const notePath = resolve(repo, 'docs/reviews/agentmux-visual-review/notes/nick.md');
const templatePath = resolve(repo, 'docs/planning/2026-10-09/review-site/src/pages/review.template.html');
const documentData = JSON.parse(readFileSync(resolve(repo, 'docs/reviews/agentmux-visual-review/document-version.json')));

function build(overrides = new Map()) {
  const outputs = new Map();
  const source = readFileSync(builder, 'utf8').replace(/^import .*;\r?\n/gm, '')
    .replaceAll('import.meta.url', JSON.stringify(pathToFileURL(builder).href));
  runInNewContext(source, {
    readFileSync: path => overrides.has(resolve(path)) ? Buffer.from(overrides.get(resolve(path))) : readFileSync(path),
    writeFileSync: (path, content) => outputs.set(path, String(content)),
    existsSync, readdirSync, resolve, dirname, fileURLToPath, createHash,
    renderScene, importMarkdown, reviewerSlug, Buffer, console: { log() {} }
  });
  return { html: outputs.get(resolve(repo, 'docs/planning/2026-10-09/agentmux-visual-review.html')),
    report: JSON.parse(outputs.get(resolve(repo, 'docs/planning/2026-10-09/review-site/build-report.json'))) };
}

test('literal template markers and script tags in feedback survive packaging without becoming scripts', () => {
  const record = importMarkdown(readFileSync(notePath, 'utf8'), documentData);
  record.notes.global = '{{NOTES_RUNTIME}} {{REVIEW_DATA}} </script><script>globalThis.injected = true</script> & < >';
  const { html } = build(new Map([[notePath, exportMarkdown(record, documentData)]]));
  const dataText = html.match(/<script type="application\/json" id="review-data">([\s\S]*?)<\/script>/)[1];
  const payload = JSON.parse(dataText);
  assert.equal(payload.committedNotes[0].notes.global, record.notes.global);
  assert.ok(!dataText.includes('</script>'));
  const scripts = Array.from(html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g));
  for (const [, attributes, source] of scripts) if (!attributes.includes('application/json')) new Script(source);
  assert.equal(scripts.length, 3);
});

test('feedback-only changes retain document version; layout source changes create a new version', () => {
  const baseline = build();
  const record = importMarkdown(readFileSync(notePath, 'utf8'), documentData);
  record.notes.global = 'New feedback';
  const notesChanged = build(new Map([[notePath, exportMarkdown(record, documentData)]]));
  assert.equal(notesChanged.report.documentVersion, baseline.report.documentVersion);
  assert.notEqual(notesChanged.report.sha256, baseline.report.sha256);
  const template = readFileSync(templatePath, 'utf8');
  const layoutChanged = build(new Map([[templatePath, template.replace('Your review notes', 'Review feedback')]]));
  assert.notEqual(layoutChanged.report.documentVersion, baseline.report.documentVersion);
});

test('package has exact original images, logo and source plan with no external resources', () => {
  const { html } = build();
  const root = 'docs/planning/2026-10-09/';
  const manifest = JSON.parse(readFileSync(resolve(repo, root + 'concept-images/prompts.json')));
  const hash = value => createHash('sha256').update(value).digest('hex');
  const images = Array.from(html.matchAll(/class="scene__image"[^>]+src="data:image\/png;base64,([^"]+)"/g));
  assert.equal(images.length, 6);
  images.forEach((match, index) => assert.equal(hash(Buffer.from(match[1], 'base64')), manifest.images[index].sha256));
  const plan = html.match(/href="data:text\/markdown;charset=utf-8;base64,([^"]+)"/)[1];
  assert.ok(Buffer.from(plan, 'base64').equals(readFileSync(resolve(repo, root + 'implementation-plan.md'))));
  const logos = Array.from(html.matchAll(/(?:src|href)="data:image\/svg\+xml;base64,([^"]+)"/g));
  assert.equal(logos.length, 3);
  logos.forEach(match => assert.ok(Buffer.from(match[1], 'base64').equals(readFileSync(resolve(repo, 'dashboard/assets/logo-ccc.svg')))));
  assert.ok(!/\b(?:src|href)="(?:https?:)?\/\//.test(html));
  const ids = Array.from(html.matchAll(/\bid="([^"]+)"/g), match => match[1]);
  assert.equal(new Set(ids).size, ids.length);
  for (const match of html.matchAll(/\b(?:href="#|for=")([^"]+)"/g)) assert.ok(ids.includes(match[1]), match[1]);
});
