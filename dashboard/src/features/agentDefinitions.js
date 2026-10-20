/* File definition registry with inline, checksum-guarded editing. */
(() => {
  'use strict';

  let ui;
  let loading = false;
  let browserCSRF = null;
  let pairing = null;

  function pairingCode() {
    const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    const bytes = crypto.getRandomValues(new Uint8Array(13));
    let value = 0, bits = 0, text = '';
    for (const byte of bytes) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5 && text.length < 20) {
        bits -= 5;
        text += alphabet[(value >>> bits) & 31];
        value &= (1 << bits) - 1;
      }
    }
    return text.match(/.{4}/g).join('-');
  }

  async function pairBrowser() {
    if (pairing) return pairing;
    pairing = (async () => {
      let challenge = pairingCode();
      const dialog = window.CCC.el('dialog', 'agents-pairing');
      const title = window.CCC.el('h3', '', 'Sign in to make changes');
      const instruction = window.CCC.el('p', '',
        'Enter this code in the Agentmux owner prompt. It expires in 30 seconds.');
      const code = window.CCC.el('code', '', challenge);
      const status = window.CCC.el('p', '', 'Waiting for approval…');
      status.setAttribute('aria-live', 'polite');
      dialog.append(title, instruction, code, status);
      document.body.appendChild(dialog);
      dialog.showModal();
      try {
        const response = await fetch('/api/local-auth/pair', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({challenge})
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || typeof data.csrfToken !== 'string') {
          throw new Error(data.error || `HTTP ${response.status}`);
        }
        browserCSRF = data.csrfToken;
      } finally {
        challenge = '';
        code.textContent = '';
        dialog.close();
        dialog.remove();
      }
    })();
    try { await pairing; }
    finally { pairing = null; }
  }

  async function hostedBrowser() {
    const popup = window.open('about:blank', 'agentmux-oidc',
      'popup,width=520,height=720');
    if (!popup) throw new Error('Allow the sign-in window, then try again.');
    const channel = new BroadcastChannel('agentmux-local-auth');
    let timer, receive;
    try {
      const completed = new Promise((resolve, reject) => {
        const finish = data => {
          if (!data || data.kind !== 'agentmux-oidc-login' ||
              typeof data.csrfToken !== 'string') return;
          browserCSRF = data.csrfToken;
          resolve();
        };
        channel.onmessage = event => finish(event.data);
        receive = event => {
          if (event.origin === window.location.origin && event.source === popup) {
            finish(event.data);
          }
        };
        window.addEventListener('message', receive);
        timer = window.setTimeout(() => reject(new Error('Sign-in expired. Try again.')), 300000);
      });
      const response = await fetch('/api/local-auth/oidc/start', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || typeof data.authorizationUrl !== 'string') {
        throw new Error(data.error || 'Hosted sign-in is unavailable.');
      }
      const target = new URL(data.authorizationUrl);
      if (target.protocol !== 'https:') throw new Error('Hosted sign-in is unavailable.');
      popup.location.replace(target.href);
      await completed;
    } finally {
      window.clearTimeout(timer);
      if (receive) window.removeEventListener('message', receive);
      channel.close();
      if (!popup.closed) popup.close();
    }
  }

  async function signInBrowser() {
    const dialog = window.CCC.el('dialog', 'agents-pairing');
    const title = window.CCC.el('h3', '', 'Sign in to make changes');
    const instruction = window.CCC.el('p', '',
      'Use your configured identity provider, or approve this browser from the Agentmux owner.');
    const hosted = window.CCC.el('button', 'btn', 'Sign in with identity provider');
    const local = window.CCC.el('button', 'btn', 'Use owner approval code');
    const cancel = window.CCC.el('button', 'btn', 'Cancel');
    for (const button of [hosted, local, cancel]) button.type = 'button';
    dialog.append(title, instruction, hosted, local, cancel);
    document.body.appendChild(dialog);
    dialog.showModal();
    try {
      await new Promise((resolve, reject) => {
        const run = action => async () => {
          for (const button of [hosted, local, cancel]) button.disabled = true;
          dialog.close();
          try { await action(); resolve(); }
          catch (error) { reject(error); }
        };
        hosted.addEventListener('click', run(hostedBrowser), {once: true});
        local.addEventListener('click', run(pairBrowser), {once: true});
        cancel.addEventListener('click', () => reject(new Error('Sign-in cancelled.')),
          {once: true});
      });
    } finally {
      if (dialog.open) dialog.close();
      dialog.remove();
    }
  }

  window.AgentmuxBrowserAuth = {
    headers: () => browserCSRF ? {'X-Agentmux-CSRF': browserCSRF} : {},
    clear: () => { browserCSRF = null; },
    signIn: signInBrowser
  };

  async function writeDefinition(op, body) {
    return window.CCC.post(`api/board/${op}`, body);
  }

  function editor(agent) {
    const { el, getJSON, say } = window.CCC;
    const details = el('details', 'agents-editor');
    details.appendChild(el('summary', '', agent ? 'Edit definition' : 'Create definition'));
    const host = el('div');
    details.appendChild(host);
    let initialized = false;
    let fetching = false;
    async function initialize() {
      if (!details.open || initialized || fetching) return;
      fetching = true;
      try {
        const value = agent ? await getJSON(`api/board/agents?name=${encodeURIComponent(agent.name)}`) : {};
        if (agent && (value.scope === 'claude' || value.editable === false)) {
          throw new Error('This definition is read-only. Refresh the list.');
        }
        const form = window.AgentmuxUI.organisms.DefinitionEditor.create({
          el, say, value, isEditing: !!agent,
          onSubmit: async body => {
            if (agent) Object.assign(body, {name: value.name, scope: value.scope,
              path: value.path, checksum: value.checksum});
            const saved = await writeDefinition('agentdef', body);
            Object.assign(value, saved);
            if (!agent) { initialized = false; host.replaceChildren(); details.open = false; }
            await loadAgents();
          }
        });
        host.replaceChildren(form);
        initialized = true;
      } catch (err) {
        host.replaceChildren(el('p', 'agents-error', `${err.message} Close and reopen to retry.`));
      } finally { fetching = false; }
    }
    details.addEventListener('toggle', initialize);
    return details;
  }

  function remedy(error) {
    if (error.includes('duplicate name')) {
      return 'Rename one definition file and its name field, or remove a duplicate, then refresh.';
    }
    if (error.includes('unknown key')) {
      return 'Remove or correct the unknown frontmatter key, then refresh.';
    }
    return 'Correct the reported error in the source file, then refresh.';
  }

  function profilePreview() {
    const {el, getJSON} = window.CCC;
    const details = el('details', 'agents-profile-preview');
    details.appendChild(el('summary', '', 'Review bundled profile packages'));
    const content = el('div');
    details.appendChild(content);
    let loading = false;
    details.addEventListener('toggle', async () => {
      if (!details.open || loading) return;
      loading = true;
      const status = el('p', 'stamp', 'Loading profile examples…');
      status.setAttribute('aria-live', 'polite');
      content.replaceChildren(status);
      try {
        const value = await getJSON('api/board/profiles');
        if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.problems)) {
          throw new Error('profile preview response is invalid');
        }
        content.replaceChildren(window.AgentmuxUI.organisms.ProfilePackagePreview.create({el, value}));
      } catch (err) {
        content.replaceChildren(el('p', 'agents-error', `${err.message} Close and reopen to retry.`));
      } finally { loading = false; }
    });
    return details;
  }

  function setup() {
    if (ui) return ui;
    const { el } = window.CCC;
    const section = document.getElementById('viewAgents');
    const header = el('div', 'agents-header');
    header.appendChild(el('h2', '', 'Agents'));
    const refresh = el('button', 'btn', 'Refresh');
    refresh.type = 'button';
    refresh.addEventListener('click', loadAgents);
    const stamp = el('span', 'stamp');
    stamp.setAttribute('aria-live', 'polite');
    header.appendChild(refresh);
    header.appendChild(stamp);
    const content = el('div', 'agents-content');
    section.replaceChildren(header,
      el('p', 'hint', 'Create and edit repo or global definitions here. Claude definitions are read-only.'),
      profilePreview(), content, editor(null));
    ui = { refresh, stamp, content };
    return ui;
  }

  async function loadAgents() {
    const { el, getJSON, say } = window.CCC;
    const { refresh, stamp, content } = setup();
    if (loading) return;
    loading = true;
    refresh.disabled = true;
    say(stamp, 'Loading definitions…');
    try {
      const data = await getJSON('api/board/agents');
      if (!data || !Array.isArray(data.agents) || !Array.isArray(data.problems)) {
        throw new Error('response must include agents and problems arrays');
      }
      const nodes = [];
      if (data.problems.length) {
        const problems = el('section', 'agents-problems');
        problems.setAttribute('aria-label', 'Definition problems');
        problems.appendChild(el('h3', '', 'Definition problems'));
        for (const problem of data.problems) {
          const row = el('article', 'agents-problem');
          row.appendChild(el('strong', 'agents-path', problem.path));
          row.appendChild(el('span', 'agents-scope', problem.scope));
          // Keep the complete backend diagnostic: collisions include every path.
          row.appendChild(el('p', 'agents-error', problem.error));
          row.appendChild(el('p', 'agents-remedy', remedy(String(problem.error))));
          problems.appendChild(row);
        }
        nodes.push(problems);
      }
      const list = el('section', 'agents-list');
      list.setAttribute('aria-label', 'Agent definitions');
      list.appendChild(el('h3', '', 'Definitions'));
      if (!data.agents.length) list.appendChild(el('p', 'empty', 'No usable agent definitions found.'));
      for (const agent of data.agents) {
        const card = el('article', 'agents-definition');
        const title = el('div', 'agents-title');
        // A definition is a file; an AGENT is a running process. Marking the name
        // here is what tells you which of these definitions is currently spawned.
        title.appendChild(window.CCC.markAgent(el('h4', '', agent.name), agent.name));
        title.appendChild(el('span', 'agents-scope', agent.scope));
        card.appendChild(title);
        if (agent.description) card.appendChild(el('p', '', agent.description));
        const fields = el('dl', 'agents-fields');
        for (const [label, value] of [['CLI', agent.cli], ['Posture', agent.posture], ['Role', agent.role]]) {
          fields.appendChild(el('dt', '', label));
          fields.appendChild(el('dd', '', value || '—'));
        }
        card.appendChild(fields);
        if (agent.profileMembership) {
          const membership = agent.profileMembership;
          card.appendChild(el('p', 'hint', `Adopted profile package: ${membership.package_id} · ${membership.relationship}` +
            (membership.parent_package ? ` · parent: ${membership.parent_package}` : '') +
            '. Local owner adoption does not grant team approval.'));
          card.appendChild(el('p', 'agents-path', `Derived revision: ${membership.derived_checksum}`));
        }
        if (Array.isArray(agent.toolIntent?.advisory) && agent.toolIntent.advisory.length) {
          card.appendChild(el('p', 'hint', 'Requested tools are advisory: ' +
            agent.toolIntent.advisory.join(', ') + '. No host enforcement or grant is established.'));
        }
        card.appendChild(el('p', 'agents-path', agent.path));
        if (['repo', 'global'].includes(agent.scope) && agent.editable !== false) {
          card.appendChild(editor(agent));
          const stamp = el('p', 'stamp');
          stamp.setAttribute('aria-live', 'polite');
          card.appendChild(window.CCC.deleteButton('agent definition', agent.name, agent.name,
            loadAgents, stamp, () => writeDefinition('agentdrop', {
              name: agent.name, scope: agent.scope, path: agent.path, checksum: agent.checksum
            })));
          card.appendChild(stamp);
        } else card.appendChild(el('p', 'hint', 'Read-only definition'));
        list.appendChild(card);
      }
      nodes.push(list);
      content.replaceChildren(...nodes);
      window.CCC.refreshLiveMarks(document.getElementById('viewAgents'));
      say(stamp, `${data.agents.length} definitions · ${data.problems.length} problems`);
    } catch (err) {
      // Retain the last successful result, but clearly mark it as stale.
      say(stamp, `Definitions unavailable: ${err.message}. Displayed results may be out of date; refresh to retry.`);
    } finally {
      loading = false;
      refresh.disabled = false;
    }
  }

  window.AgentmuxFeatures = window.AgentmuxFeatures || {};
  window.AgentmuxFeatures.registerAgentDefinitions = () => {
    window.CCC.registerPanel('organization', 'agents', loadAgents);
  };
})();
