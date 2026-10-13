// Shared offline notes format. File access and page state belong to its callers.
export const MAX_NOTE = 20000;
export const MAX_FILE = 2 * 1024 * 1024;
const ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VERSION = /^(?:sha256:[a-f0-9]{64}|legacy-unversioned)$/;

export function validateDocument(document) {
  if (!document || typeof document.id !== 'string' || !ID.test(document.id) ||
      typeof document.version !== 'string' || !VERSION.test(document.version) ||
      typeof document.title !== 'string' || !document.title.trim() || !Array.isArray(document.sections) ||
      document.sections.length < 1 || document.sections.length > 100) throw new Error('Invalid review document metadata.');
  const ids = new Set();
  for (const section of document.sections) {
    if (!section || typeof section.id !== 'string' || !ID.test(section.id) || ids.has(section.id) || typeof section.title !== 'string' ||
        typeof section.question !== 'string') throw new Error('Invalid or duplicate review section.');
    ids.add(section.id);
  }
  return document;
}

export function reviewerSlug(name, reviewers = []) {
  if (typeof name !== 'string' || !name.trim() || name.length > 120) throw new Error('Enter your name before exporting notes.');
  const normalized = name.trim().toLowerCase();
  const known = reviewers.find(person => [person.id, person.name].some(value => value.toLowerCase() === normalized));
  const slug = known ? known.id : normalized.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 64).replace(/-$/g, '');
  if (!ID.test(slug)) throw new Error('Use a name containing letters or numbers for the export filename.');
  // Windows reserves these names, even with an extension.
  return /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/.test(slug) ? 'reviewer-' + slug : slug;
}

export function draftKey(documentId) {
  if (!ID.test(documentId)) throw new Error('Invalid document ID.');
  return 'agentmux.review-notes.v1.' + documentId;
}

export function validateNotes(record, document, { allowEmptyReviewer = false } = {}) {
  validateDocument(document);
  if (!record || record.format !== 'agentmux-review-notes' || record.schemaVersion !== 1) throw new Error('Unsupported review notes format.');
  if (record.documentId !== document.id) throw new Error('These notes belong to a different document.');
  if (typeof record.documentVersion !== 'string' || !VERSION.test(record.documentVersion)) throw new Error('Invalid document version in notes.');
  if (typeof record.reviewer !== 'string' || record.reviewer.length > 120 || (!allowEmptyReviewer && !record.reviewer.trim())) throw new Error('Notes must include a reviewer name.');
  if (typeof record.exportedAt !== 'string' || !Number.isFinite(Date.parse(record.exportedAt))) throw new Error('Invalid notes date.');
  if (!record.notes || typeof record.notes !== 'object' || Array.isArray(record.notes)) throw new Error('Invalid note fields.');
  const ids = document.sections.map(section => section.id);
  if (Object.keys(record.notes).length !== ids.length || ids.some(id => !Object.hasOwn(record.notes, id))) throw new Error('The note sections do not match this document.');
  for (const value of Object.values(record.notes)) {
    if (typeof value !== 'string' || value.length > MAX_NOTE) throw new Error('A note is invalid or exceeds 20,000 characters.');
  }
  return record;
}

export function exportMarkdown(record, document) {
  validateNotes(record, document);
  const { notes, ...metadata } = record;
  const line = value => value.replace(/[\r\n]/g, ' ');
  const parts = ['# ' + line(document.title) + ' — review notes', '',
    '> Feedback only. These notes do not pass a delivery gate or authorize a merge or release.', '',
    '```review-metadata', JSON.stringify(metadata, null, 2), '```', ''];
  for (const section of document.sections) {
    const value = notes[section.id];
    const longest = Math.max(2, ...Array.from(value.matchAll(/`+/g), match => match[0].length));
    const fence = '`'.repeat(longest + 1);
    parts.push('## ' + line(section.title), '', '**Question:** ' + line(section.question), '',
      fence + 'review-note ' + section.id, value, fence, '');
  }
  return parts.join('\n');
}

export function importMarkdown(markdown, document) {
  validateDocument(document);
  if (typeof markdown !== 'string' || markdown.length > MAX_FILE) throw new Error('Choose a review notes Markdown file smaller than 2 MB.');
  const text = markdown.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n');
  const metadata = text.match(/^```review-metadata\n([\s\S]*?)\n```(?:\n|$)/m);
  if (!metadata) throw new Error('Missing review metadata. Use a notes export from this workflow.');
  let record;
  try { record = JSON.parse(metadata[1]); } catch { throw new Error('The review metadata is not valid JSON.'); }
  // Only parse note blocks after metadata. Variable fences preserve embedded code and headings.
  const body = text.slice(metadata.index + metadata[0].length);
  const notes = Object.create(null);
  const blocks = /^(`{3,})review-note ([a-z0-9-]+)\n([\s\S]*?)\n\1(?=\n|$)/gm;
  for (const match of body.matchAll(blocks)) {
    if (Object.hasOwn(notes, match[2])) throw new Error('Duplicate note section: ' + match[2]);
    notes[match[2]] = match[3];
  }
  // Unterminated or extra blocks must not be silently discarded.
  const remainder = body.replace(blocks, '');
  if (/^```review-metadata$/m.test(remainder)) throw new Error('Duplicate review metadata.');
  if (/^`{3,}review-note\b/m.test(remainder)) throw new Error('A note block is incomplete. Keep its opening and closing fences.');
  return validateNotes({ ...record, notes }, document);
}
