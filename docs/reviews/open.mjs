// Launch one review with repository identity and automatic local note saving.
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createLocalReview } from './src/features/local-review.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const id = process.argv[2] || 'agentmux-visual-review';
const port = process.argv[3] === undefined ? 4317 : Number(process.argv[3]);
if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Usage: node docs/reviews/open.mjs [document-id] [port]');
const reviewRoot = resolve(repoRoot, 'docs/reviews', id);
const config = JSON.parse(readFileSync(resolve(reviewRoot, 'review.json')));
function source(path) {
  if (typeof path !== 'string' || isAbsolute(path)) throw new Error('Use repository-relative review paths.');
  const resolved = realpathSync(resolve(repoRoot, path));
  const rel = relative(repoRoot, resolved);
  if (rel.startsWith('..') || isAbsolute(rel)) throw new Error('Review source must stay inside the repository.');
  return resolved;
}
if (config.buildScript) execFileSync(process.execPath, [source(config.buildScript)], { cwd: repoRoot, stdio: 'inherit', windowsHide: true });
const document = JSON.parse(readFileSync(resolve(reviewRoot, 'document-version.json')));
const local = createLocalReview({ repoRoot, config, document, html: readFileSync(source(config.artifactPath), 'utf8') });
const url = await local.listen(port);
console.log('\nOpen your live review: ' + url + '\nNotes save directly into this repository. Leave this process running. Ctrl+C stops it.');
