import * as ReviewNotes from './notes-format.mjs';

// Connect notes controls to the launcher on this computer only.
export function attachLocalReview(data, hooks, root = document) {
  const $ = selector => root.querySelector(selector);
  let ready = false, revision = null, identity, sequence = 0, savedSequence = 0;
  let timer, writing = false, stopped = false, failures = 0;
  let sharing = false;
  const waiting = [];
  const shareButton = $('#notes-share');
  if (shareButton) { shareButton.hidden = false; shareButton.disabled = true; }
  const fields = Array.from(root.querySelectorAll('textarea[data-note]'));
  const panel = $('#git-identity-panel');
  const lock = value => fields.forEach(field => { field.disabled = value; });
  lock(true);
  $('#reviewer-name').readOnly = true;
  const identityLabel = $('#reviewer-name-label');
  if (identityLabel) identityLabel.textContent = 'Git name (detected automatically)';
  for (const action of ['download', 'show']) {
    const button = root.querySelector('[data-action="' + action + '"]');
    if (button) button.hidden = true;
  }
  root.querySelector('[data-action="save"]').textContent = 'Save notes now';
  $('#notes-local-fact').textContent = 'Notes save locally as you type. Share notes sends only your notes to this repository’s Git remote. Feedback is not approval to implement or merge.';
  root.querySelector('.notes__lede').textContent = 'Your Git identity is used automatically. Notes save into your own repository file as you type. Choose Share notes to commit and push them.';

  async function api(path, body) {
    const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST',
      headers: { 'X-Review-Token': data.bridge.token, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const result = await response.json();
    if (!response.ok) { const error = new Error(result.error || 'Local save failed.'); error.status = response.status; throw error; }
    return result;
  }
  async function flush() {
    if (!ready || stopped || writing || savedSequence === sequence) return;
    writing = true;
    const attempt = sequence;
    const record = hooks.snapshot();
    hooks.setSaved('Saving notes to the repository…');
    try {
      const result = await api('/api/notes', { revision, record, identity: { name: identity.name, email: identity.email } });
      revision = result.revision;
      savedSequence = attempt;
      failures = 0;
      hooks.setSaved('Saved to ' + data.notesPath + '/' + result.filename + ' at ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + '.');
      hooks.setStatus('Notes saved automatically. Choose Share notes when you want to send them.', 'ok');
    } catch (error) {
      const transient = !error.status || error.status >= 500 || [408, 423, 429].includes(error.status);
      failures++;
      stopped = !transient || failures > 5;
      hooks.setSaved('Repository save failed. Your draft remains in this page.');
      hooks.setStatus(error.message + (stopped ? ' Save was not confirmed. Reload after resolving the issue.' : ' Save was not confirmed; retrying automatically.'), 'warn');
      if (!stopped) timer = window.setTimeout(flush, Math.min(1000 * 2 ** (failures - 1), 10000));
    } finally {
      writing = false;
      waiting.splice(0).forEach(done => done());
      // Queue newer edits only after this write acknowledges its file revision.
      if (!stopped && savedSequence !== sequence && savedSequence === attempt) void flush();
    }
  }
  function changed() {
    if (!ready || sharing) return;
    hooks.setIdentity(identity);
    failures = 0;
    sequence++;
    window.clearTimeout(timer);
    hooks.setSaved('Repository save pending…');
    timer = window.setTimeout(flush, 450);
  }
  async function initialize() {
    try {
      const session = await api('/api/session');
      identity = session.identity;
      if (!identity.configured) {
        panel.hidden = false;
        $('#git-name').value = identity.name;
        $('#git-email').value = identity.email;
        hooks.setStatus('Git name or email is missing or invalid. Set it below for this repository.', 'warn');
        return;
      }
      panel.hidden = true;
      revision = session.revision;
      hooks.setIdentity(identity);
      $('#git-identity-current').textContent = 'Git identity: ' + identity.name + ' <' + identity.email + '>';
      $('#notes-git-path').textContent = 'Automatically saved to ' + data.notesPath + '/' + identity.filename + '. Share notes commits and pushes only this file.';
      const empty = { format: 'agentmux-review-notes', schemaVersion: 1, documentId: data.document.id,
        documentVersion: data.document.version, reviewer: identity.name, exportedAt: new Date().toISOString(),
        notes: Object.fromEntries(data.document.sections.map(section => [section.id, ''])) };
      const loaded = session.record && Object.values(session.record.notes).some(text => text.trim()) ? session.record : empty;
      hooks.loadRecord(loaded);
      // Different origins cannot read file:// drafts. Recover only this launcher's own identity-scoped draft.
      try {
        const raw = window.localStorage.getItem(hooks.storageKey());
        if (raw) {
          const draft = ReviewNotes.validateNotes(JSON.parse(raw), data.document);
          if ((JSON.stringify(draft.notes) !== JSON.stringify(hooks.snapshot().notes) || draft.documentVersion !== hooks.snapshot().documentVersion) &&
              window.confirm('A browser draft differs from your repository file. Recover that draft and save it to your file? Cancel keeps the repository notes.')) {
            hooks.loadRecord(draft); sequence++;
          }
        }
      } catch { /* Repository saving still works when browser draft storage is unavailable. */ }
      hooks.setIdentity(identity);
      ready = true;
      if (shareButton) shareButton.disabled = false;
      lock(false);
      hooks.setStatus('Git identity detected. Your notes will save automatically to the repository.', 'ok');
      hooks.setSaved('Repository notes loaded.');
      if (sequence) void flush();
    } catch (error) { hooks.setStatus(error.message + ' Keep the local launcher running and reload.', 'warn'); }
  }
  $('#git-identity-save').addEventListener('click', async () => {
    try {
      await api('/api/identity', { name: $('#git-name').value, email: $('#git-email').value });
      await initialize();
    } catch (error) { hooks.setStatus(error.message, 'warn'); }
  });
  shareButton?.addEventListener('click', async () => {
    if (!ready || sharing) return;
    sharing = true;
    const controls = Array.from(root.querySelectorAll('#notes button, #notes input, textarea[data-note]'));
    const disabled = controls.map(control => control.disabled);
    controls.forEach(control => { control.disabled = true; });
    shareButton.disabled = true;
    window.clearTimeout(timer);
    try {
      while (writing) await new Promise(done => waiting.push(done));
      if (stopped) throw new Error('Resolve the save error and reload before sharing. Your draft is preserved.');
      // Save even an untouched draft so the server has a file and a confirmed revision.
      if (revision === null && savedSequence === sequence) sequence++;
      await flush();
      if (writing || savedSequence !== sequence) throw new Error('Your latest notes were not saved. Nothing was shared; retry after the save succeeds.');
      window.clearTimeout(timer);
      hooks.setStatus('Sharing your notes…', 'ok');
      const result = await api('/api/share', { revision, identity: { name: identity.name, email: identity.email } });
      hooks.setStatus(result.message + ' Commit ' + result.commit.slice(0, 12) + '. Feedback is not implementation or merge approval.', 'ok');
    } catch (error) { hooks.setStatus(error.message, 'warn'); }
    finally {
      sharing = false;
      controls.forEach((control, index) => { control.disabled = disabled[index]; });
      shareButton.disabled = false;
    }
  });
  window.addEventListener('beforeunload', event => {
    if (!sharing && savedSequence === sequence) return;
    event.preventDefault(); event.returnValue = '';
  });
  void initialize();
  return changed;
}
