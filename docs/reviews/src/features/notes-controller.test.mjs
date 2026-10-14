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

function setup({ initial = new Map(), blocked = false, confirm = true, live = null } = {}) {
  const previous = { document: globalThis.document, window: globalThis.window, URL: globalThis.URL, fetch: globalThis.fetch };
  const elements = new Map(['reviewer-name', 'notes-status', 'notes-saved', 'notes-export', 'notes-export-text',
    'notes-version', 'document-version', 'notes-git-path', 'shared-reviewer', 'shared-notes', 'notes-import',
    'git-identity-panel', 'reviewer-name-label', 'git-name', 'git-email', 'git-identity-current',
    'git-identity-save', 'notes-local-fact', 'lede']
    .map(id => [id, new Element(id)]));
  const fields = documentData.sections.map(section => {
    const element = new Element(section.id + '-note'); element.dataset.note = section.id; elements.set(element.id, element); return element;
  });
  const buttons = ['download', 'save', 'show', 'clear', 'load-shared', 'version'].map(action => {
    const element = new Element(); element.dataset.action = action; return element;
  });
  const timers = new Map(), deadlines = new Map(), events = new Map(), calls = [];
  let tick = 0, now = 0, releaseWrite; const blobs = []; const prompts = [];
  const root = { documentElement: { classList: { add() {}, remove() {} } }, body: new Element(),
    querySelector: selector => {
      if (selector === '.notes__lede') return elements.get('lede');
      const action = selector.match(/data-action="([^"]+)"/);
      return action ? buttons.find(button => button.dataset.action === action[1]) : elements.get(selector.slice(1)) || null;
    },
    querySelectorAll: selector => selector === 'textarea[data-note]' ? fields : selector === '[data-action]' ? buttons : [],
    createElement: () => new Element() };
  const storage = {
    getItem(key) { if (blocked) throw new Error('blocked'); return initial.get(key) ?? null; },
    setItem(key, value) { if (blocked) throw new Error('blocked'); initial.set(key, value); },
    removeItem(key) { if (blocked) throw new Error('blocked'); initial.delete(key); }
  };
  globalThis.document = root;
  globalThis.window = { localStorage: storage, setTimeout: (fn, delay = 0) => {
    timers.set(++tick, fn); deadlines.set(tick, now + delay); return tick;
  }, clearTimeout: id => { timers.delete(id); deadlines.delete(id); },
  addEventListener(type, fn) { events.set(type, [...(events.get(type) || []), fn]); },
  confirm: message => { prompts.push(message); return confirm; } };
  globalThis.URL = { createObjectURL(blob) { blobs.push(blob); return 'blob:fixture'; }, revokeObjectURL() {} };
  if (live) {
    const response = body => ({ ok: true, json: async () => body });
    globalThis.fetch = async (path, options) => {
      if (path === '/api/session') return response({ identity: live.identity, revision: 'original', record: live.record || null });
      calls.push({ path, body: JSON.parse(options.body) });
      if (live.hold && calls.length === 1) return await new Promise(done => {
        releaseWrite = () => done(response({ revision: 'saved-1', filename: live.identity.filename }));
      });
      return response({ revision: 'saved-' + calls.length, filename: live.identity.filename });
    };
  }
  attachReviewNotes({ document: documentData, ...(live ? { bridge: { token: 'synthetic' } } : {}), reviewers: [{ id: 'nick', name: 'Nick Klute' }],
    notesPath: 'docs/reviews/another-review/notes', committedNotes: [record()], legacyDraftKey: 'legacy', legacyReviewId: 'old-id' }, root);
  return { elements, fields, timers, blobs, initial, prompts, root, calls,
    async ready() { await new Promise(setImmediate); },
    async advance(ms) {
      const until = now + ms;
      while (true) {
        const next = [...deadlines].sort((a, b) => a[1] - b[1])[0];
        if (!next || next[1] > until) break;
        const [id, at] = next, fn = timers.get(id); now = at; timers.delete(id); deadlines.delete(id);
        void fn(); await new Promise(setImmediate);
      }
      now = until;
    },
    warnsBeforeLeaving() {
      let warned = false;
      for (const fn of events.get('beforeunload') || []) fn({ preventDefault() { warned = true; } });
      return warned;
    },
    releaseWrite: () => releaseWrite(),
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

test('imported reviewer identity survives edits, draft restoration and export', async () => {
  const imported = { ...record(), reviewer: 'Other Reviewer',
    reviewerId: 'other-reviewer-12345678', reviewerEmail: 'other@example.test' };
  const h = setup();
  let saved;
  try {
    await h.import(exportMarkdown(imported, documentData));
    h.fields[0].value += ' edited'; await h.fields[0].fire('input');
    await h.action('download');
    const exported = importMarkdown(await h.blobs[0].text(), documentData);
    assert.equal(exported.reviewerId, imported.reviewerId);
    assert.equal(exported.reviewerEmail, imported.reviewerEmail);
    assert.equal(h.root.body.children[0].download, imported.reviewerId + '.md');
    saved = h.initial;
  } finally { h.close(); }
  const restored = setup({ initial: saved });
  try {
    await restored.action('download');
    const exported = importMarkdown(await restored.blobs[0].text(), documentData);
    assert.equal(exported.reviewerId, imported.reviewerId);
    assert.equal(exported.reviewerEmail, imported.reviewerEmail);
    assert.equal(exported.notes.first, imported.notes.first + ' edited');
    assert.equal(restored.root.body.children[0].download, imported.reviewerId + '.md');
  } finally { restored.close(); }
});

test('an explicit reviewer switch clears imported identity and uses the new reviewer filename', async () => {
  const h = setup();
  try {
    await h.import(exportMarkdown({ ...record(), reviewer: 'Other Reviewer',
      reviewerId: 'other-reviewer-12345678', reviewerEmail: 'other@example.test' }, documentData));
    h.elements.get('reviewer-name').value = 'Nick Klute';
    await h.elements.get('reviewer-name').fire('input'); await h.action('download');
    const exported = importMarkdown(await h.blobs[0].text(), documentData);
    assert.equal(exported.reviewer, 'Nick Klute');
    assert.equal(exported.reviewerId, undefined); assert.equal(exported.reviewerEmail, undefined);
    assert.equal(h.root.body.children[0].download, 'nick.md');
  } finally { h.close(); }
});

test('combined controllers warn through debounce and pending writes, then save newer edits with Git identity', async () => {
  const identity = { configured: true, name: 'Ryan Helms', email: 'ryan@example.test', id: 'ryan', filename: 'ryan.md' };
  const h = setup({ live: { identity, hold: true, record: { ...record(), reviewer: 'Old display name',
    reviewerId: 'ryan', reviewerEmail: identity.email } } });
  try {
    await h.ready();
    assert.equal(h.fields[0].disabled, false); assert.equal(h.elements.get('reviewer-name').readOnly, true);
    assert.equal(h.warnsBeforeLeaving(), false);
    h.fields[0].value = 'First edit'; await h.fields[0].fire('input');
    assert.equal(h.warnsBeforeLeaving(), true); assert.equal(h.calls.length, 0);
    await h.advance(750); assert.equal(h.calls.length, 1); assert.equal(h.warnsBeforeLeaving(), true);
    h.fields[0].value = 'Latest edit'; await h.fields[0].fire('input'); await h.advance(750);
    assert.equal(h.calls.length, 1); assert.equal(h.fields[0].value, 'Latest edit');
    h.releaseWrite(); await h.ready();
    assert.equal(h.calls.length, 2); assert.equal(h.calls[1].body.revision, 'saved-1');
    assert.equal(h.calls[1].body.record.notes.first, 'Latest edit');
    assert.equal(h.calls[1].body.record.reviewer, identity.name);
    assert.equal(h.calls[1].body.record.reviewerId, identity.id);
    assert.equal(h.calls[1].body.record.reviewerEmail, identity.email);
    assert.equal(h.warnsBeforeLeaving(), false);
  } finally { h.close(); }
});

test('marking notes reviewed saves the version without changing text, even when browser storage is blocked', async () => {
  const identity = { configured: true, name: 'Ryan Helms', email: 'ryan@example.test', id: 'ryan', filename: 'ryan.md' };
  const older = { ...record('sha256:' + 'b'.repeat(64)), reviewerId: identity.id, reviewerEmail: identity.email };
  for (const blocked of [false, true]) {
    const h = setup({ blocked, live: { identity, record: older } });
    try {
      await h.ready();
      assert.equal(h.elements.get('notes-version').title, older.documentVersion);
      await h.action('version');
      assert.equal(h.warnsBeforeLeaving(), true);
      assert.equal(h.calls.length, 0);
      await h.advance(450);
      assert.equal(h.calls.length, 1);
      const saved = h.calls[0].body;
      assert.equal(h.calls[0].path, '/api/notes');
      assert.equal(saved.record.documentVersion, documentData.version);
      assert.deepEqual(saved.record.notes, older.notes);
      assert.equal(saved.record.reviewerId, identity.id);
      assert.equal(saved.record.reviewerEmail, identity.email);
      assert.equal(saved.revision, 'original');
      assert.equal(h.warnsBeforeLeaving(), false);
      assert.match(h.elements.get('notes-saved').textContent, /ryan\.md/);
    } finally { h.close(); }
  }
});

test('marking reviewed during a pending save queues the current version using the acknowledged revision', async () => {
  const identity = { configured: true, name: 'Ryan Helms', email: 'ryan@example.test', id: 'ryan', filename: 'ryan.md' };
  const older = record('sha256:' + 'b'.repeat(64));
  const h = setup({ live: { identity, hold: true, record: older } });
  try {
    await h.ready();
    h.fields[0].value += '\nNew feedback'; await h.fields[0].fire('input');
    await h.advance(750);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0].body.record.documentVersion, older.documentVersion);
    await h.action('version'); await h.advance(450);
    assert.equal(h.calls.length, 1);
    assert.equal(h.warnsBeforeLeaving(), true);
    h.releaseWrite(); await h.ready();
    assert.equal(h.calls.length, 2);
    assert.equal(h.calls[1].body.revision, 'saved-1');
    assert.equal(h.calls[1].body.record.documentVersion, documentData.version);
    assert.equal(h.calls[1].body.record.notes.first, older.notes.first + '\nNew feedback');
    assert.equal(h.warnsBeforeLeaving(), false);
  } finally { h.close(); }
});

test('cancelling the reviewed marker preserves the source version and does not save or share', async () => {
  const identity = { configured: true, name: 'Ryan Helms', email: 'ryan@example.test', id: 'ryan', filename: 'ryan.md' };
  const older = record('sha256:' + 'b'.repeat(64));
  const h = setup({ confirm: false, live: { identity, record: older } });
  try {
    await h.ready(); await h.action('version'); await h.advance(1000);
    assert.equal(h.calls.length, 0);
    assert.equal(h.elements.get('notes-version').title, older.documentVersion);
    assert.equal(h.warnsBeforeLeaving(), false);
    assert.equal(h.fields[0].value, older.notes.first);
  } finally { h.close(); }
});
