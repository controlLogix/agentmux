// Package the reviewed Claude Opus design without external runtime dependencies.
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { renderScene } from '../components/organisms/index.mjs';
import { importMarkdown, notesFilename } from '../../../../../reviews/src/features/notes-format.mjs';

const siteRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const planRoot = resolve(siteRoot, '..');
const repoRoot = resolve(planRoot, '../../..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const read = path => readFileSync(path);
const imageManifest = JSON.parse(read(resolve(planRoot, 'concept-images/prompts.json')));
const scenes = JSON.parse(read(resolve(siteRoot, 'scenes.json')));
if (scenes.length !== 6) throw new Error('The review requires exactly six scenes.');
const sourceHashes = {};
const rendered = scenes.map(scene => {
  const record = imageManifest.images.find(item => item.id === scene.id);
  if (!record) throw new Error(`Unknown scene: ${scene.id}`);
  const bytes = read(resolve(planRoot, 'concept-images', record.file));
  if (sha(bytes) !== record.sha256) throw new Error(`Image changed: ${record.file}`);
  sourceHashes[record.file] = sha(bytes);
  return renderScene({...scene, imageSrc:`data:image/png;base64,${bytes.toString('base64')}`});
}).join('\n');
const plan = read(resolve(planRoot, 'implementation-plan.md'));
const logo = read(resolve(repoRoot, 'dashboard/assets/logo-ccc.svg'));
const css = read(resolve(siteRoot, 'src/components/organisms/Scene/scene.css')).toString('utf8');
const script = read(resolve(siteRoot, 'src/features/review.js')).toString('utf8');
let html = read(resolve(siteRoot, 'src/pages/review.template.html')).toString('utf8');
const reviewRoot = resolve(repoRoot, 'docs/reviews/agentmux-visual-review');
const config = JSON.parse(read(resolve(reviewRoot, 'review.json')));
const formatSource = read(resolve(repoRoot, 'docs/reviews/src/features/notes-format.mjs')).toString('utf8');
const controllerSource = read(resolve(repoRoot, 'docs/reviews/src/features/notes-controller.mjs')).toString('utf8');
const localSource = read(resolve(repoRoot, 'docs/reviews/src/features/notes-local.mjs')).toString('utf8');
const inputs = {
  'implementation-plan.md': sha(plan), 'logo-ccc.svg': sha(logo), 'scene.css': sha(css),
  'review.js': sha(script), 'review.template.html': sha(html), 'notes-format.mjs': sha(formatSource),
  'notes-controller.mjs': sha(controllerSource),
  'notes-local.mjs': sha(localSource),
  'local-review.mjs': sha(read(resolve(repoRoot, 'docs/reviews/src/features/local-review.mjs'))),
  'notes-lock.mjs': sha(read(resolve(repoRoot, 'docs/reviews/src/features/notes-lock.mjs'))),
  'review-server.mjs': sha(read(resolve(repoRoot, 'docs/reviews/src/features/review-server.mjs'))),
  'open.mjs': sha(read(resolve(repoRoot, 'docs/reviews/open.mjs'))),
  'build.mjs': sha(read(fileURLToPath(import.meta.url))),
  'review.json': sha(read(resolve(reviewRoot, 'review.json'))),
  'scenes.json': sha(read(resolve(siteRoot, 'scenes.json'))),
  'Scene.mjs': sha(read(resolve(siteRoot, 'src/components/organisms/Scene/Scene.mjs'))),
  ...sourceHashes
};
// Feedback files do not change the document version they refer to.
const version = 'sha256:' + sha(JSON.stringify(Object.entries(inputs).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)));
const globalQuestion = html.match(/<label[^>]+for="global-note"[^>]*>([^<]+)<\/label>/)?.[1];
if (!globalQuestion) throw new Error('Overall review question is missing.');
const document = { id: config.id, title: config.title, version,
  sections: scenes.map(scene => ({ id: scene.id, title: `${scene.number} · ${scene.title}`, question: scene.question }))
    .concat({ id: 'global', title: 'Overall notes', question: globalQuestion }) };
const notesRoot = resolve(reviewRoot, 'notes');
const committedNotes = (existsSync(notesRoot) ? readdirSync(notesRoot).filter(file => file.endsWith('.md')).sort() : []).map(file => {
  const record = importMarkdown(read(resolve(notesRoot, file)).toString('utf8'), document);
  if (file !== notesFilename(record, config.reviewers)) throw new Error(`Reviewer and notes filename differ: ${file}`);
  return record;
});
const reviewData = JSON.stringify({ document, reviewers: config.reviewers, notesPath: config.notesPath,
  legacyDraftKey: config.legacyDraftKey, legacyReviewId: config.legacyReviewId, committedNotes }).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');
// This dependency-free feature is the same code tested as an ES module.
const notesRuntime = 'const ReviewNotes = (() => {\n' + formatSource.replace(/^export /gm, '') +
  '\nreturn { MAX_FILE, MAX_NOTE, draftKey, reviewerSlug, notesFilename, validateNotes, exportMarkdown, importMarkdown };\n})();\n' +
  localSource.replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '') + '\n' +
  controllerSource.replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');
const replacements = {
  '{{LOGO_DATA_URI}}': `data:image/svg+xml;base64,${logo.toString('base64')}`,
  '{{SCENES}}': rendered,
  '{{PLAN_DATA_URI}}': `data:text/markdown;charset=utf-8;base64,${plan.toString('base64')}`,
  '{{SCENE_CSS}}': css,
  '{{REVIEW_SCRIPT}}': script,
  '{{REVIEW_DATA}}': reviewData,
  '{{NOTES_RUNTIME}}': notesRuntime
};
for (const marker of Object.keys(replacements)) {
  if (!html.includes(marker)) throw new Error(`Missing template marker: ${marker}`);
}
// Insert once: text supplied by a reviewer can contain literal template markers.
html = html.replace(/\{\{[A-Z_]+\}\}/g, marker => {
  if (!Object.hasOwn(replacements, marker)) throw new Error('Unknown template marker: ' + marker);
  return replacements[marker];
});
const output = resolve(planRoot, 'agentmux-visual-review.html');
writeFileSync(output, html, 'utf8');
const report = {
  file: 'agentmux-visual-review.html',
  bytes: Buffer.byteLength(html),
  sha256: sha(html),
  imageCount: scenes.length,
  documentId: document.id,
  documentVersion: version,
  committedReviewers: committedNotes.map(record => record.reviewer),
  planSha256: sha(plan),
  logoSha256: sha(logo),
  imageHashes: sourceHashes,
  designAuthor: 'Claude Opus via the user-requested WSL terminal',
  packaging: 'Codex; all images, styles, scripts and source-plan download are embedded',
  productImplementation: false
};
writeFileSync(resolve(siteRoot, 'build-report.json'), JSON.stringify(report, null, 2)+'\n');
writeFileSync(resolve(reviewRoot, 'document-version.json'), JSON.stringify({ ...document, sourceHashes: inputs }, null, 2)+'\n');
console.log(JSON.stringify(report, null, 2));
