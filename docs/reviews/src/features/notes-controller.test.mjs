import test from 'node:test';
import assert from 'node:assert/strict';
import { attachReviewNotes } from './notes-controller.mjs';
import { exportMarkdown, importMarkdown, draftKey } from './notes-format.mjs';

// A source-level fixture for notes state and event handlers; it does not render a browser.
class Element {
  constructor(id = '') { this.id = id; this.value = ''; this.textContent = ''; this.dataset = {}; this.listeners = new Map(); this.hidden = false; this.files = []; this.children = []; }
  addEventListener(type, fn) { this.listeners.set(type, fn); }
  async fire(type) { await this.listeners.get(type)?.({ target: this }); }
  appendChild(element) { this.children.push(element); }
  focus() { this.focused = true; }
  select() { this.selected = true; }
  remove() {}
  click() { this.clicked = true; }
}

const documentData = { id: 'another-review', title: 'Another document', version: 'sha256:' + 'a'.repeat(64),
  sections: [{ id: 'first', title: 'First section', question: 'What changed?' }, { id: 'global', title: 'Overall', question: 'Other notes?' }] };
const record = (version = documentData.version) => ({ format: 'agentmux-review-notes', schemaVersion: 1,
  documentId: documentData.id, documentVersion: version, reviewer: 'Nick', exportedAt: '2026-10-13T15:00:00Z',
  notes: { first: '<script>literal text</script>\n```example\n```', global: 'Overall note' } });

function setup({ initial = new Map(), blocked = false, confirm = true } = {}) {
  const previous = { document: globalThis.document, window: globalThis.window, URL: globalThis.URL };
  const elements = new Map(['reviewer-name', 'notes-status', 'notes-saved', 'notes-export', 'notes-export-text',
    'notes-version', 'document-version', 'notes-git-path', 'shared-reviewer', 'shared-notes', 'notes-import']
    .map(id => [id, new Element(id)]));
  const fields = documentData.sections.map(section => {
    const element = new Element(section.id + '-note'); element.dataset.note = section.id; elements.set(element.id, element); return element;
  });
  const buttons = ['download', 'save', 'show', 'clear', 'load-shared', 'version'].map(action => {
    const element = new Element(); element.dataset.action = action; return element;
  });
  const timers = new Map(); let tick = 0; const blobs = []; const prompts = [];
  const root = { documentElement: { classList: { add() {}, remove() {} } }, body: new Element(),
    querySelector: selector => elements.get(selector.slice(1)) || null,
    querySelectorAll: selector => selector === 'textarea[data-note]' ? fields : selector === '[data-action]' ? buttons : [],
    createElement: () => new Element() };
  const storage = {
    getItem(key) { if (blocked) throw new Error('blocked'); return initial.get(key) ?? null; },
    setItem(key, value) { if (blocked) throw new Error('blocked'); initial.set(key, value); },
    removeItem(key) { if (blocked) throw new Error('blocked'); initial.delete(key); }
  };
  globalThis.document = root;
  globalThis.window = { localStorage: storage, setTimeout: fn => { timers.set(++tick, fn); return tick; },
    clearTimeout: id => timers.delete(id), addEventListener() {}, confirm: message => { prompts.push(message); return confirm; } };
  globalThis.URL = { createObjectURL(blob) { blobs.push(blob); return 'blob:fixture'; }, revokeObjectURL() {} };
  attachReviewNotes({ document: documentData, reviewers: [{ id: 'nick', name: 'Nick Klute' }],
    notesPath: 'docs/reviews/another-review/notes', committedNotes: [record()], legacyDraftKey: 'legacy', legacyReviewId: 'old-id' }, root);
  return { elements, fields, timers, blobs, initial, prompts, root,
    action: action => buttons.find(button => button.dataset.action === action).fire('click'),
    import: async (text, size = text.length) => { const input = elements.get('notes-import'); input.files = [{ size, text: async () => text }]; await input.fire('change'); },
    close() { Object.assign(globalThis, previous); } };
}

test('new export uses reviewer filename, metadata and exact note values; draft survives attachment again', async () => {
  const h = setup();
  try {
    h.elements.get('reviewer-name').value = 'Nick Klute'; h.fields[0].value = 'New note\n';
    await h.fields[0].fire('input'); await h.action('download');
    assert.equal(h.root.body.children[0].download, 'nick.md');
    assert.equal(importMarkdown(await h.blobs[0].text(), documentData).notes.first, 'New note\n');
    assert.equal(JSON.parse(h.initial.get(draftKey(documentData.id))).notes.first, 'New note\n');
    const saved = h.initial; h.close();
    const reload = setup({ initial: saved });
    try { assert.equal(reload.fields[0].value, 'New note\n'); } finally { reload.close(); }
  } finally { h.close(); }
});

test('invalid or cancelled imports do not change draft; earlier versions retain attribution', async () => {
  const h = setup();
  try {
    h.fields[0].value = 'Keep this draft';
    await h.import('not a review'); assert.equal(h.fields[0].value, 'Keep this draft');
    assert.match(h.elements.get('notes-status').textContent, /unchanged/);
    const older = record('sha256:' + 'b'.repeat(64));
    await h.import(exportMarkdown(older, documentData));
    assert.equal(h.fields[0].value, older.notes.first);
    assert.equal(JSON.parse(h.initial.get(draftKey(documentData.id))).documentVersion, older.documentVersion);
    await h.action('version');
    assert.equal(JSON.parse(h.initial.get(draftKey(documentData.id))).documentVersion, documentData.version);
  } finally { h.close(); }
  const cancelled = setup({ confirm: false });
  try { cancelled.fields[0].value = 'Keep'; await cancelled.import(exportMarkdown(record(), documentData)); assert.equal(cancelled.fields[0].value, 'Keep'); }
  finally { cancelled.close(); }
});

test('reads shared feedback as literal text without replacing a draft until requested', async () => {
  const h = setup();
  try {
    h.fields[0].value = 'My draft'; h.elements.get('shared-reviewer').value = '0';
    await h.elements.get('shared-reviewer').fire('change');
    assert.match(h.elements.get('shared-notes').textContent, /<script>literal text<\/script>/);
    assert.equal(h.fields[0].value, 'My draft');
    await h.action('load-shared'); assert.equal(h.fields[0].value, record().notes.first);
  } finally { h.close(); }
});

test('legacy drafts are preserved with unknown version; blocked storage still permits file import and export', async () => {
  const initial = new Map([['legacy', JSON.stringify({ version: 1, review: 'old-id', savedAt: '2026-10-13T14:00:00Z', reviewer: 'Nick', notes: { first: 'Old draft', global: '' } })]]);
  const old = setup({ initial });
  try { assert.equal(old.fields[0].value, 'Old draft'); assert.match(old.elements.get('notes-version').textContent, /unknown/); assert.ok(initial.has('legacy')); }
  finally { old.close(); }
  const blocked = setup({ blocked: true });
  try {
    assert.match(blocked.elements.get('notes-status').textContent, /does not allow/);
    await blocked.import(exportMarkdown(record(), documentData));
    assert.match(blocked.elements.get('notes-status').textContent, /saving is unavailable/);
    await blocked.action('download'); assert.equal(blocked.blobs.length, 1);
  } finally { blocked.close(); }
});
