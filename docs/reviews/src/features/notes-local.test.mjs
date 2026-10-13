import test from 'node:test';
import assert from 'node:assert/strict';
import { attachLocalReview } from './notes-local.mjs';

const documentData = { id: 'live-test', title: 'Live test', version: 'sha256:' + 'a'.repeat(64),
  sections: [{ id: 'global', title: 'Overall', question: 'Feedback?' }] };
class Element {
  constructor() { this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false; this.listeners = new Map(); }
  addEventListener(type, fn) { this.listeners.set(type, fn); }
  async click() { await this.listeners.get('click')?.(); }
}
function setup({ configured = true, conflict = false, hold = false, transient = false, draft = null, recover = false } = {}) {
  const previous = { window: globalThis.window, fetch: globalThis.fetch };
  const elements = new Map(['git-identity-panel', 'reviewer-name', 'notes-local-fact', 'git-name', 'git-email',
    'git-identity-current', 'notes-git-path', 'git-identity-save', 'notes-share', 'lede', 'save', 'download', 'show'].map(id => [id, new Element()]));
  const field = new Element(); const timers = new Map(), events = new Map(), calls = []; let next = 0, release;
  const identity = { configured, name: configured ? 'Ryan Helms' : '', email: configured ? 'ryan@example.test' : '', filename: 'ryan.md' };
  const state = { version: documentData.version, name: '', saved: '', status: '' };
  const response = (body, status = 200) => ({ ok: status === 200, status, json: async () => body });
  globalThis.window = { clearTimeout: id => timers.delete(id), setTimeout: fn => { timers.set(++next, fn); return next; },
    localStorage: { getItem: () => draft ? JSON.stringify(draft) : null }, addEventListener: (type, fn) => events.set(type, fn), confirm: () => recover };
  globalThis.fetch = async (path, options) => {
    if (path === '/api/session') return response({ identity, revision: 'start', record: null });
    const body = JSON.parse(options.body); calls.push({ path, body });
    if (path === '/api/identity') { Object.assign(identity, { configured: true, ...body }); return response({ configured: true }); }
    if (path === '/api/share') return response({ commit: 'a'.repeat(40), message: 'Your notes were committed and pushed.' });
    if (conflict) return response({ error: 'File changed' }, 409);
    if (transient && calls.filter(call => call.path === '/api/notes').length === 1) return response({ error: 'Temporary failure' }, 503);
    if (hold && calls.filter(call => call.path === '/api/notes').length === 1) return await new Promise(done => { release = () => done(response({ revision: 'next-1', filename: 'ryan.md' })); });
    return response({ revision: 'next-' + calls.length, filename: 'ryan.md' });
  };
  const root = { querySelector: selector => {
    if (selector === '.notes__lede') return elements.get('lede');
    const action = selector.match(/data-action="([^"]+)"/);
    return elements.get(action ? action[1] : selector.slice(1));
  }, querySelectorAll: () => [field] };
  const changed = attachLocalReview({ document: documentData, notesPath: 'notes', bridge: { token: 'fixture-token' } }, {
    snapshot: () => ({ format: 'agentmux-review-notes', schemaVersion: 1, documentId: documentData.id,
      documentVersion: state.version, reviewer: state.name, exportedAt: '2026-10-13T16:00:00Z', notes: { global: field.value } }),
    setSaved: message => { state.saved = message; }, setStatus: message => { state.status = message; },
    storageKey: () => 'fixture', setIdentity: person => { state.name = person.name; },
    loadRecord: record => { state.version = record.documentVersion; field.value = record.notes.global; }
  }, root);
  return { changed, field, elements, state, calls, events, release: () => release(),
    async tick() { const queued = [...timers.values()]; timers.clear(); await Promise.all(queued.map(fn => fn())); },
    async ready() { await new Promise(setImmediate); },
    close() { Object.assign(globalThis, previous); } };
}

test('Git identity initializes readonly UI and saves notes without an export', async () => {
  const h = setup();
  try {
    await h.ready(); assert.equal(h.field.disabled, false); assert.equal(h.elements.get('reviewer-name').readOnly, true);
    assert.equal(h.elements.get('download').hidden, true);
    h.field.value = 'Typed directly'; h.changed(); await h.tick();
    assert.equal(h.calls[0].path, '/api/notes'); assert.equal(h.calls[0].body.record.notes.global, 'Typed directly');
    assert.equal(h.calls[0].body.identity.email, 'ryan@example.test'); assert.match(h.state.saved, /notes\/ryan.md/);
  } finally { h.close(); }
});
test('missing Git identity locks editing and sets repository identity through the helper', async () => {
  const h = setup({ configured: false });
  try {
    await h.ready(); assert.equal(h.field.disabled, true); assert.equal(h.elements.get('git-identity-panel').hidden, false);
    h.elements.get('git-name').value = 'Ryan Helms'; h.elements.get('git-email').value = 'ryan@example.test';
    await h.elements.get('git-identity-save').click(); assert.equal(h.field.disabled, false);
    assert.equal(h.calls[0].path, '/api/identity'); assert.equal(h.calls[0].body.email, 'ryan@example.test');
  } finally { h.close(); }
});
test('edits during an in-flight write are serialized after its acknowledgment; unsaved edits warn before leaving', async () => {
  const h = setup({ hold: true });
  try {
    await h.ready(); h.field.value = 'First'; h.changed();
    let warned = false; h.events.get('beforeunload')({ preventDefault() { warned = true; } }); assert.equal(warned, true);
    const pending = h.tick(); await h.ready(); h.field.value = 'Second'; h.changed(); await h.tick();
    h.release(); await pending; await h.ready();
    assert.equal(h.calls.length, 2); assert.equal(h.calls[1].body.revision, 'next-1'); assert.equal(h.calls[1].body.record.notes.global, 'Second');
  } finally { h.close(); }
});
test('a revision conflict keeps draft text and stops further automatic overwrites', async () => {
  const h = setup({ conflict: true });
  try {
    await h.ready(); h.field.value = 'Keep my text'; h.changed(); await h.tick(); assert.match(h.state.status, /File changed/);
    h.field.value = 'Still here'; h.changed(); await h.tick(); assert.equal(h.calls.length, 1); assert.equal(h.field.value, 'Still here');
  } finally { h.close(); }
});
test('temporary failures retry without another edit or export', async () => {
  const h = setup({ transient: true });
  try {
    await h.ready(); h.field.value = 'Save this automatically'; h.changed(); await h.tick();
    assert.match(h.state.status, /retrying automatically/); await h.tick();
    assert.equal(h.calls.length, 2); assert.match(h.state.saved, /Saved to/);
  } finally { h.close(); }
});
test('a version-only browser change is recoverable even when note text is identical', async () => {
  const oldVersion = 'sha256:' + 'b'.repeat(64);
  const draft = { format: 'agentmux-review-notes', schemaVersion: 1, documentId: documentData.id,
    documentVersion: oldVersion, reviewer: 'Ryan Helms', exportedAt: '2026-10-13T16:00:00Z', notes: { global: '' } };
  const h = setup({ draft, recover: true });
  try { await h.ready(); assert.equal(h.state.version, oldVersion); assert.equal(h.calls[0].body.record.documentVersion, oldVersion); }
  finally { h.close(); }
});

test('Share notes saves pending text first and shares only the acknowledged revision', async () => {
  const h = setup();
  try {
    await h.ready(); h.field.value = 'Latest feedback'; h.changed();
    await h.elements.get('notes-share').click();
    assert.deepEqual(h.calls.map(call => call.path), ['/api/notes', '/api/share']);
    assert.equal(h.calls[1].body.revision, 'next-1');
    assert.match(h.state.status, /committed and pushed/);
    await h.elements.get('notes-share').click();
    assert.equal(h.calls.filter(call => call.path === '/api/notes').length, 1);
  } finally { h.close(); }
});

test('Share notes never sends a failed or conflicted save', async () => {
  const h = setup({ conflict: true });
  try {
    await h.ready(); h.field.value = 'Keep this'; h.changed();
    await h.elements.get('notes-share').click();
    assert.deepEqual(h.calls.map(call => call.path), ['/api/notes']);
    assert.equal(h.field.value, 'Keep this'); assert.equal(h.field.disabled, false);
  } finally { h.close(); }
});

test('Share notes waits for an in-flight save and freezes editing until sharing finishes', async () => {
  const h = setup({ hold: true });
  try {
    await h.ready(); h.field.value = 'First'; h.changed();
    const pending = h.tick(); await h.ready();
    h.field.value = 'Latest'; h.changed();
    const sharing = h.elements.get('notes-share').click(); await h.ready();
    assert.equal(h.field.disabled, true);
    assert.equal(h.calls.filter(call => call.path === '/api/share').length, 0);
    h.release(); await pending; await sharing;
    assert.equal(h.calls.filter(call => call.path === '/api/notes').length, 2);
    assert.equal(h.calls.at(-1).path, '/api/share');
    assert.equal(h.calls.at(-1).body.revision, 'next-2');
    assert.equal(h.field.disabled, false);
  } finally { h.close(); }
});

test('a temporary save failure during Share notes retains the automatic retry', async () => {
  const h = setup({ transient: true });
  try {
    await h.ready(); h.field.value = 'Retry me'; h.changed();
    await h.elements.get('notes-share').click();
    assert.equal(h.calls.length, 1); assert.equal(h.calls[0].path, '/api/notes');
    await h.tick(); assert.equal(h.calls.length, 2);
    assert.equal(h.calls[1].path, '/api/notes'); assert.match(h.state.saved, /Saved to/);
  } finally { h.close(); }
});
