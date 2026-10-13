import * as ReviewNotes from './notes-format.mjs';

// Attach offline notes controls to a page using the documented element IDs.
export function attachReviewNotes(reviewData, root = document) {

  const reviewDocument = reviewData.document;
  const STORAGE_KEY = ReviewNotes.draftKey(reviewDocument.id);
  const BLOCKED = 'This browser does not allow this page to save drafts. That often happens with files opened from disk or in private windows. Your notes stay here only until you close or reload the page, so download them to keep a copy.';

  const $ = (selector, scope = root) => scope.querySelector(selector);
  const $$ = (selector, scope = root) => Array.from(scope.querySelectorAll(selector));

  document.documentElement.classList.remove('no-js');
  document.documentElement.classList.add('js');
  $$('[data-js-only]').forEach(element => { element.hidden = false; });

  /* Review notes: local draft, print copy and Markdown export. No network use. */
  const nameInput = $('#reviewer-name');
  const fields = $$('textarea[data-note]');
  const inputs = nameInput ? fields.concat(nameInput) : fields;
  const statusEl = $('#notes-status');
  const savedEl = $('#notes-saved');
  const exportBox = $('#notes-export');
  const exportText = $('#notes-export-text');
  const mirrors = new Map($$('[data-print-for]').map(element => [element.dataset.printFor, element]));
  const navLinks = new Map($$('[data-nav]').map(link => [link.dataset.nav, link]));
  const notesVersionEl = $('#notes-version');
  const sharedSelect = $('#shared-reviewer');
  const sharedText = $('#shared-notes');
  const importInput = $('#notes-import');

  let canStore = probeStorage();
  let saveTimer = 0;
  let unsharedChanges = false;
  let noteVersion = reviewDocument.version;
  let importSequence = 0;

  const versionLabel = version => version === 'legacy-unversioned' ? 'unknown (older export or draft)' : version.slice(0, 23);
  $('#document-version').textContent = 'Document: ' + reviewDocument.id + ' · ' + versionLabel(reviewDocument.version);
  $('#document-version').title = reviewDocument.version;
  const reviewerFiles = reviewData.reviewers.map(person => person.id + '.md').join(' or ');
  $('#notes-git-path').textContent = 'Save your export in ' + reviewData.notesPath + ' (' + reviewerFiles + '), then commit and push your file. This page does not run Git commands.';

  function reflectVersion() {
    notesVersionEl.textContent = 'Notes refer to: ' + versionLabel(noteVersion) +
      (noteVersion === reviewDocument.version ? ' · current document.' : ' · a different or unknown version. Review the changes before marking these notes current.');
    notesVersionEl.title = noteVersion;
  }

  function probeStorage() {
    try {
      const probe = STORAGE_KEY + '.probe';
      window.localStorage.setItem(probe, '1');
      window.localStorage.removeItem(probe);
      return true;
    } catch (error) {
      return false;
    }
  }

  function setStatus(message, tone) {
    if (!statusEl) return;
    statusEl.textContent = message;
    statusEl.dataset.tone = tone || 'info';
  }

  function setSaved(message) {
    if (savedEl) savedEl.textContent = message;
  }

  function clock() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function hasText() {
    return inputs.some(input => input.value.trim() !== '');
  }

  function reflect(input) {
    const empty = input.value.trim() === '';
    const mirror = mirrors.get(input.id);
    if (mirror) mirror.textContent = empty ? (input === nameInput ? 'Not given.' : 'No note written.') : input.value;
    if (input === nameInput) return;
    const link = navLinks.get(input.dataset.note === 'global' ? 'notes' : input.dataset.note);
    if (!link) return;
    link.toggleAttribute('data-noted', !empty);
    const flag = $('.scene-nav__flag', link);
    if (flag) flag.textContent = empty ? '' : ' (note written)';
  }

  function snapshot() {
    const notes = {};
    fields.forEach(field => { notes[field.dataset.note] = field.value; });
    return { format: 'agentmux-review-notes', schemaVersion: 1, documentId: reviewDocument.id,
      documentVersion: noteVersion, exportedAt: new Date().toISOString(), reviewer: nameInput ? nameInput.value : '', notes };
  }

  function saveDraft(manual) {
    window.clearTimeout(saveTimer);
    if (!canStore) {
      if (manual) setStatus(BLOCKED, 'warn');
      return;
    }
    try {
      if (hasText()) {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot()));
        setSaved('Draft saved in this browser at ' + clock() + '.');
        if (manual) setStatus('Draft saved in this browser at ' + clock() + '. Download your notes to share them.', 'ok');
      } else {
        window.localStorage.removeItem(STORAGE_KEY);
        setSaved('No notes written yet.');
        if (manual) setStatus('There are no notes to save yet.', 'info');
      }
    } catch (error) {
      canStore = false;
      setSaved('Draft not saved.');
      setStatus(BLOCKED, 'warn');
    }
  }

  function restore() {
    if (!canStore) {
      setSaved('Draft saving is not available here.');
      setStatus(BLOCKED, 'warn');
      return;
    }
    let raw = null;
    try {
      raw = window.localStorage.getItem(STORAGE_KEY);
      if (!raw && reviewData.legacyDraftKey) raw = window.localStorage.getItem(reviewData.legacyDraftKey);
    } catch (error) {
      canStore = false;
      setSaved('Draft saving is not available here.');
      setStatus(BLOCKED, 'warn');
      return;
    }
    if (!raw) {
      setSaved('No notes written yet.');
      setStatus('Your notes save in this browser as you type. Nothing is sent anywhere.', 'info');
      return;
    }
    try {
      let data = JSON.parse(raw);
      if (data && data.version === 1 && data.review === reviewData.legacyReviewId && reviewData.legacyDraftKey) {
        data = { format: 'agentmux-review-notes', schemaVersion: 1, documentId: reviewDocument.id,
          documentVersion: 'legacy-unversioned', exportedAt: data.savedAt, reviewer: data.reviewer, notes: data.notes };
      }
      ReviewNotes.validateNotes(data, reviewDocument, { allowEmptyReviewer: true });
      noteVersion = data.documentVersion;
      fields.forEach(field => {
        const value = data.notes[field.dataset.note];
        field.value = value;
      });
      if (nameInput) nameInput.value = data.reviewer;
      const when = new Date(data.exportedAt);
      const stamp = Number.isNaN(when.getTime()) ? '' : ' from ' + when.toLocaleString();
      setSaved('Draft restored' + stamp + '.');
      setStatus('Restored your draft' + stamp + '. Download your notes when you finish.', 'ok');
    } catch (error) {
      setSaved('Saved draft unreadable.');
      setStatus('A saved draft could not be read, so the boxes start empty. Typing here will replace that draft.', 'warn');
    }
  }

  function buildMarkdown() {
    return ReviewNotes.exportMarkdown(snapshot(), reviewDocument);
  }

  function showExport(text) {
    if (!exportBox || !exportText) return;
    exportText.value = text;
    exportBox.hidden = false;
    exportText.focus();
    exportText.select();
  }

  function download() {
    if (canStore) saveDraft(false);
    const filename = ReviewNotes.reviewerSlug(nameInput.value, reviewData.reviewers) + '.md';
    const text = buildMarkdown();
    try {
      const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.hidden = true;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 10000);
      // A download request can be canceled silently; keep the unload warning active.
      setStatus('Download requested: ' + filename + '. Save it in ' + reviewData.notesPath + ', then commit and push your file. If no file appears, choose Show notes as text.', 'ok');
    } catch (error) {
      showExport(text);
      setStatus('This browser blocked the download. Copy the text below into ' + filename + ' in the Git notes folder.', 'warn');
    }
  }

  function applyImported(record) {
    ReviewNotes.validateNotes(record, reviewDocument);
    const mismatch = record.documentVersion !== reviewDocument.version;
    const message = 'Load notes from ' + record.reviewer + '? This replaces every note in the current browser draft.' +
      (mismatch ? ' These notes refer to a different or unknown document version; their original version will be kept.' : '');
    if (!window.confirm(message)) return;
    window.clearTimeout(saveTimer);
    fields.forEach(field => { field.value = record.notes[field.dataset.note]; reflect(field); });
    nameInput.value = record.reviewer;
    reflect(nameInput);
    noteVersion = record.documentVersion;
    reflectVersion();
    unsharedChanges = true;
    if (exportBox) exportBox.hidden = true;
    saveDraft(false);
    setStatus('Loaded notes from ' + record.reviewer + '.' + (mismatch ? ' Their source version remains recorded.' : '') +
      (canStore ? ' Draft saved locally.' : ' Draft saving is unavailable; download to keep your changes.'), mismatch || !canStore ? 'warn' : 'ok');
  }

  (reviewData.committedNotes || []).forEach((record, index) => {
    const option = document.createElement('option');
    option.value = String(index);
    option.textContent = record.reviewer + ' · ' + versionLabel(record.documentVersion);
    sharedSelect.appendChild(option);
  });
  sharedSelect.addEventListener('change', () => {
    const record = sharedSelect.value === '' ? null : reviewData.committedNotes[Number(sharedSelect.value)];
    sharedText.textContent = record ? ReviewNotes.exportMarkdown(record, reviewDocument) : '';
  });
  importInput.addEventListener('change', async () => {
    const sequence = ++importSequence;
    const file = importInput.files[0];
    if (!file) return;
    try {
      if (file.size > ReviewNotes.MAX_FILE) throw new Error('Choose a notes file smaller than 2 MB.');
      const text = await file.text();
      if (sequence !== importSequence) return;
      applyImported(ReviewNotes.importMarkdown(text, reviewDocument));
    } catch (error) {
      setStatus('Notes were not imported: ' + error.message + ' Your draft is unchanged.', 'warn');
    } finally {
      if (sequence === importSequence) importInput.value = '';
    }
  });

  const actions = {
    download,
    save: () => saveDraft(true),
    'load-shared': () => {
      if (sharedSelect.value === '') throw new Error('Choose a reviewer from the Git notes list first.');
      applyImported(reviewData.committedNotes[Number(sharedSelect.value)]);
    },
    version: () => {
      if (!window.confirm('Have you reviewed these notes against the document currently open? This updates their version label only; it does not approve implementation.')) return;
      noteVersion = reviewDocument.version;
      reflectVersion();
      unsharedChanges = true;
      saveDraft(false);
      setStatus('Notes now refer to this document version.' + (canStore ? '' : ' Download them to keep a copy.'), canStore ? 'ok' : 'warn');
    },
    show: () => {
      showExport(buildMarkdown());
      setStatus('Your notes are shown as text below. Select all and copy them.', 'info');
    },
    clear: () => {
      if (!window.confirm('Clear every note on this page and the draft saved in this browser? Download your notes first if you need a copy.')) return;
      inputs.forEach(input => { input.value = ''; reflect(input); });
      noteVersion = reviewDocument.version;
      reflectVersion();
      if (exportBox) exportBox.hidden = true;
      unsharedChanges = false;
      if (canStore) {
        try {
          window.localStorage.removeItem(STORAGE_KEY);
          if (reviewData.legacyDraftKey) window.localStorage.removeItem(reviewData.legacyDraftKey);
        } catch (error) { canStore = false; }
      }
      setSaved('No notes written yet.');
      setStatus(canStore ? 'All notes cleared, including the saved draft.' : 'All notes on this page cleared.', 'info');
    }
  };

  $$('[data-action]').forEach(button => {
    button.addEventListener('click', () => {
      const run = actions[button.dataset.action];
      try { if (run) run(); } catch (error) {
        setStatus(error.message, 'warn');
        if (!nameInput.value.trim()) nameInput.focus();
      }
    });
  });

  inputs.forEach(input => {
    input.addEventListener('input', () => {
      unsharedChanges = true;
      reflect(input);
      window.clearTimeout(saveTimer);
      if (canStore) saveTimer = window.setTimeout(() => saveDraft(false), 700);
    });
  });

  window.addEventListener('beforeprint', () => inputs.forEach(input => reflect(input)));
  window.addEventListener('pagehide', () => { if (canStore && unsharedChanges) saveDraft(false); });
  window.addEventListener('beforeunload', event => {
    if (canStore || !unsharedChanges || !hasText()) return;
    event.preventDefault();
    event.returnValue = '';
  });

  restore();
  reflectVersion();
  inputs.forEach(input => reflect(input));

}

