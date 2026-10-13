(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const navLinks = new Map($$('[data-nav]').map(link => [link.dataset.nav, link]));
  attachReviewNotes(JSON.parse(document.getElementById('review-data').textContent));

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
