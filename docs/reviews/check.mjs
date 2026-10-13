// Validate Git note files without writing files or running Git commands.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importMarkdown, reviewerSlug, MAX_FILE } from './src/features/notes-format.mjs';

const reviewsRoot = dirname(fileURLToPath(import.meta.url));
const requested = process.argv[2];
if (requested && !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(requested)) throw new Error('Pass a review directory name, such as agentmux-visual-review.');
const names = requested ? [requested] : readdirSync(reviewsRoot, { withFileTypes: true })
  .filter(item => item.isDirectory() && item.name !== 'src').map(item => item.name);
let count = 0;
for (const name of names.sort()) {
  const root = resolve(reviewsRoot, name);
  const config = JSON.parse(readFileSync(resolve(root, 'review.json'), 'utf8'));
  const document = JSON.parse(readFileSync(resolve(root, 'document-version.json'), 'utf8'));
  if (config.id !== name || document.id !== config.id) throw new Error('Review directory and document IDs differ: ' + name);
  for (const file of readdirSync(resolve(root, 'notes')).filter(file => file.endsWith('.md')).sort()) {
    const bytes = readFileSync(resolve(root, 'notes', file));
    if (bytes.length > MAX_FILE) throw new Error('Notes file exceeds 2 MB: ' + file);
    const record = importMarkdown(bytes.toString('utf8'), document);
    if (file !== reviewerSlug(record.reviewer, config.reviewers) + '.md') throw new Error('Reviewer and filename differ: ' + file);
    console.log(name + '/' + file + ': valid' + (record.documentVersion === document.version ? '' : ' (earlier or unknown document version retained)'));
    count++;
  }
  for (const person of config.reviewers) {
    if (!readdirSync(resolve(root, 'notes')).includes(person.id + '.md')) throw new Error('Missing reviewer file: ' + person.id + '.md');
  }
}
console.log('Checked ' + count + ' reviewer files. Notes are feedback, not delivery acceptance.');
