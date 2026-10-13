(() => {
  'use strict';

  const STORAGE_KEY = 'agentmux.visual-review.2026-10-09.notes.v1';
  const NOTES_FILE = 'agentmux-visual-review-notes-2026-10-09.md';
  const MAX_NOTE = 20000;
  const NL = '\n';
  const BLOCKED = 'This browser does not allow this page to save drafts. That often happens with files opened from disk or in private windows. Your notes stay here only until you close or reload the page, so download them to keep a copy.';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

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

  let canStore = probeStorage();
  let saveTimer = 0;
  let unsharedChanges = false;

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
    return { version: 1, review: 'agentmux-visual-review-2026-10-09', savedAt: new Date().toISOString(), reviewer: nameInput ? nameInput.value : '', notes };
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
      const data = JSON.parse(raw);
      if (!data || data.version !== 1 || typeof data.notes !== 'object' || data.notes === null) throw new Error('Unknown draft format');
      fields.forEach(field => {
        const value = data.notes[field.dataset.note];
        if (typeof value === 'string') field.value = value.slice(0, MAX_NOTE);
      });
      if (nameInput && typeof data.reviewer === 'string') nameInput.value = data.reviewer.slice(0, 120);
      const when = new Date(data.savedAt);
      const stamp = Number.isNaN(when.getTime()) ? '' : ' from ' + when.toLocaleString();
      setSaved('Draft restored' + stamp + '.');
      setStatus('Restored your draft' + stamp + '. Download your notes when you finish.', 'ok');
    } catch (error) {
      setSaved('Saved draft unreadable.');
      setStatus('A saved draft could not be read, so the boxes start empty. Typing here will replace that draft.', 'warn');
    }
  }

  function questionFor(field) {
    const label = field.labels && field.labels[0];
    return label ? label.textContent.replace(/\s+/g, ' ').trim() : '';
  }

  function buildMarkdown() {
    const reviewer = nameInput && nameInput.value.trim() ? nameInput.value.trim() : 'Not given';
    const lines = [
      '# Agentmux visual review notes',
      '',
      '- Review: six proposed interfaces with fictional sample data, October 9, 2026',
      '- Reviewer: ' + reviewer,
      '- Exported: ' + new Date().toLocaleString(),
      '',
      '> These notes are review feedback. They do not pass a delivery gate. Codex reviews phase evidence and final feature-branch acceptance. No merge or release is authorized.',
      ''
    ];
    fields.forEach(field => {
      const heading = field.dataset.note === 'global' ? 'Overall notes' : field.dataset.number + ' · ' + field.dataset.title;
      const note = field.value.trim();
      lines.push('## ' + heading, '', '**Question:** ' + questionFor(field), '', note || '_No note written._', '');
    });
    return lines.join(NL);
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
    const text = buildMarkdown();
    try {
      const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = NOTES_FILE;
      link.hidden = true;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 10000);
      // A download request can be canceled silently; keep the unload warning active.
      setStatus('Your browser is saving ' + NOTES_FILE + '. Send that file to Ryan. If no file appears, choose Show notes as text and copy them instead.', 'ok');
    } catch (error) {
      showExport(text);
      setStatus('This browser blocked the download. Your notes are shown as text below. Select all and copy them into an email to Ryan.', 'warn');
    }
  }

  const actions = {
    download,
    save: () => saveDraft(true),
    show: () => {
      showExport(buildMarkdown());
      setStatus('Your notes are shown as text below. Select all and copy them.', 'info');
    },
    clear: () => {
      if (!window.confirm('Clear every note on this page and the draft saved in this browser? Download your notes first if you need a copy.')) return;
      inputs.forEach(input => { input.value = ''; reflect(input); });
      if (exportBox) exportBox.hidden = true;
      unsharedChanges = false;
      if (canStore) {
        try { window.localStorage.removeItem(STORAGE_KEY); } catch (error) { canStore = false; }
      }
      setSaved('No notes written yet.');
      setStatus(canStore ? 'All notes cleared, including the saved draft.' : 'All notes on this page cleared.', 'info');
    }
  };

  $$('[data-action]').forEach(button => {
    button.addEventListener('click', () => {
      const run = actions[button.dataset.action];
      if (run) run();
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
  inputs.forEach(input => reflect(input));

  /* Sticky navigation: mark the section in view and keep its link visible. */
  const nav = $('.scene-nav');
  const reduceMotion = Boolean(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  function setCurrent(id) {
    navLinks.forEach((link, key) => {
      if (key === id) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    });
    const link = navLinks.get(id);
    if (!nav || !link || nav.scrollWidth <= nav.clientWidth) return;
    const left = link.offsetLeft - (nav.clientWidth - link.offsetWidth) / 2;
    nav.scrollTo({ left: Math.max(0, left), behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => { if (entry.isIntersecting) setCurrent(entry.target.id); });
    }, { rootMargin: '-35% 0px -60% 0px' });
    $$('[data-nav-section]').forEach(section => observer.observe(section));
  }

  /* Image viewer: native modal dialog with fit and fixed zoom levels. */
  const viewer = $('#viewer');
  const scenes = $$('.scene[id]');
  if (!viewer || typeof viewer.showModal !== 'function' || scenes.length === 0) return;

  const stage = $('.viewer__stage', viewer);
  const image = $('.viewer__img', viewer);
  const title = $('#viewer-title');
  const caption = $('#viewer-caption');
  const zoomButtons = $$('[data-zoom]', viewer);
  const prevButton = $('.viewer__prev', viewer);
  const nextButton = $('.viewer__next', viewer);
  const closeButton = $('.viewer__close', viewer);
  const LEVELS = ['fit', 1, 1.5, 2];
  const total = String(scenes.length).padStart(2, '0');
  const clamp = value => Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0.5));

  let index = 0;
  let openedAt = 0;
  let level = 'fit';
  let drag = null;

  function sceneImage(i) {
    return $('.scene__image', scenes[i]);
  }

  function applyZoom(next, anchorX, anchorY) {
    const rx = typeof anchorX === 'number' ? anchorX : (stage.scrollLeft + stage.clientWidth / 2 - image.offsetLeft) / Math.max(1, image.offsetWidth);
    const ry = typeof anchorY === 'number' ? anchorY : (stage.scrollTop + stage.clientHeight / 2 - image.offsetTop) / Math.max(1, image.offsetHeight);
    level = next;
    const fit = next === 'fit';
    image.classList.toggle('is-fit', fit);
    image.style.width = fit ? '' : Math.round((image.naturalWidth || 1672) * next) + 'px';
    stage.classList.toggle('is-zoomed', !fit);
    zoomButtons.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.zoom === String(next))));
    if (fit) return;
    stage.scrollLeft = image.offsetLeft + clamp(rx) * image.offsetWidth - stage.clientWidth / 2;
    stage.scrollTop = image.offsetTop + clamp(ry) * image.offsetHeight - stage.clientHeight / 2;
  }

  function show(i) {
    index = Math.min(scenes.length - 1, Math.max(0, i));
    const scene = scenes[index];
    const source = sceneImage(index);
    const sceneTitle = $('.scene__title', scene);
    const phase = $('.scene__phase', scene);
    const summary = $('.scene__caption-text', scene);
    image.src = source ? (source.currentSrc || source.src) : '';
    image.alt = source ? source.alt : '';
    title.textContent = (scene.dataset.number || '') + ' · ' + (sceneTitle ? sceneTitle.textContent.trim() : '');
    caption.textContent = ['Scene ' + (scene.dataset.number || '') + ' of ' + total, phase ? phase.textContent.trim() : '', summary ? summary.textContent.trim() : ''].filter(Boolean).join(' · ');
    prevButton.disabled = index === 0;
    nextButton.disabled = index === scenes.length - 1;
    stage.scrollTop = 0;
    stage.scrollLeft = 0;
    applyZoom(window.innerWidth >= 1100 ? 'fit' : 1, 0, 0);
  }

  function open(i) {
    if (i < 0) return;
    openedAt = i;
    viewer.showModal();
    document.documentElement.classList.add('is-viewing');
    show(i);
    stage.focus({ preventScroll: true });
  }

  function step(delta) {
    show(index + delta);
    const button = delta < 0 ? prevButton : nextButton;
    if (button.disabled) stage.focus({ preventScroll: true });
  }

  $$('[data-enlarge]').forEach(button => {
    button.hidden = false;
    button.addEventListener('click', () => open(scenes.findIndex(scene => scene.id === button.dataset.enlarge)));
  });

  scenes.forEach((scene, i) => {
    const img = sceneImage(i);
    if (!img) return;
    img.classList.add('is-zoomable');
    img.addEventListener('click', () => open(i));
  });

  zoomButtons.forEach(button => {
    button.addEventListener('click', () => applyZoom(button.dataset.zoom === 'fit' ? 'fit' : Number(button.dataset.zoom)));
  });
  prevButton.addEventListener('click', () => step(-1));
  nextButton.addEventListener('click', () => step(1));
  closeButton.addEventListener('click', () => viewer.close());

  viewer.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      event.preventDefault();
      viewer.close();
      return;
    }
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    const at = LEVELS.indexOf(level);
    if (event.key === '+' || event.key === '=') {
      event.preventDefault();
      applyZoom(LEVELS[Math.min(LEVELS.length - 1, at + 1)]);
    } else if (event.key === '-' || event.key === '_') {
      event.preventDefault();
      applyZoom(LEVELS[Math.max(0, at - 1)]);
    } else if (event.key === '0') {
      event.preventDefault();
      applyZoom('fit');
    }
  });

  viewer.addEventListener('close', () => {
    document.documentElement.classList.remove('is-viewing');
    drag = null;
    stage.classList.remove('is-dragging');
    const back = $('[data-enlarge]', scenes[index]);
    if (back) back.focus({ preventScroll: index === openedAt });
  });

  stage.addEventListener('click', event => {
    if (level !== 'fit' || event.target !== image) return;
    const rect = image.getBoundingClientRect();
    applyZoom(1, (event.clientX - rect.left) / rect.width, (event.clientY - rect.top) / rect.height);
  });

  stage.addEventListener('dblclick', event => {
    if (level === 'fit') return;
    event.preventDefault();
    applyZoom('fit');
  });

  stage.addEventListener('pointerdown', event => {
    if (level === 'fit' || event.pointerType !== 'mouse' || event.button !== 0) return;
    drag = { x: event.clientX, y: event.clientY, left: stage.scrollLeft, top: stage.scrollTop };
    stage.setPointerCapture(event.pointerId);
    stage.classList.add('is-dragging');
    event.preventDefault();
  });
  stage.addEventListener('pointermove', event => {
    if (!drag) return;
    stage.scrollLeft = drag.left - (event.clientX - drag.x);
    stage.scrollTop = drag.top - (event.clientY - drag.y);
  });
  const endDrag = () => {
    drag = null;
    stage.classList.remove('is-dragging');
  };
  stage.addEventListener('pointerup', endDrag);
  stage.addEventListener('pointercancel', endDrag);
})();
