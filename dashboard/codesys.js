/* Remote Linux SL targets. No automatic retries or background SSH polling. */
(() => {
  'use strict';
  let busy = false;
  let notice = '';
  const warning = 'apt purge does NOT clear the runtime password. Device user management under /var/opt/codesys survives package removal and reinstall.';
  const labels = {start: 'Start', stop: 'Stop', reset: 'Reset', boot: 'Create boot application', install: 'Install runtime', update: 'Update runtime'};
  function base(root) {
    const {el} = window.CCC;
    root.replaceChildren();
    // No heading: this is a card inside IIOT now, and the card's own <summary>
    // already names it. A second title inside the body just reads as a repeat.
    root.appendChild(el('p', 'warn', warning));
    root.appendChild(el('p', 'muted', 'CODESYS Control for Linux SL only. Installed versions are verified per box. Every state change requires confirmation and records target, action and actor in the journal.'));
    const refresh = el('button', 'btn', 'Refresh targets');
    refresh.disabled = busy;
    refresh.addEventListener('click', load);
    root.appendChild(refresh);
    if (notice) root.appendChild(el('p', '', notice));
  }
  async function act(target, action, resetType) {
    if (busy) return;
    busy = true;
    const root = document.getElementById('viewCodesys');
    base(root);
    root.appendChild(window.CCC.el('p', '', 'Preparing action; verifying target identity and version…'));
    const path = action === 'boot' ? '/api/board/bootapp' : '/api/board/plcstate';
    const body = {target: target.id, action, phase: 'prepare'};
    if (action === 'reset') body.reset_type = resetType;
    try {
      const prepared = await window.CCC.post(path, body);
      if (!prepared.token || !prepared.confirmation) throw Error('No valid confirmation returned; action not sent.');
      if (!window.confirm(prepared.confirmation)) {
        notice = 'Cancelled; no runtime change requested.';
      } else {
        root.appendChild(window.CCC.el('p', '', 'Executing confirmed operation. Do not retry if the connection is interrupted.'));
        const result = await window.CCC.post(path, {...body, phase: 'execute', token: prepared.token, confirm: true});
        notice = result.message || 'Operation completed; refresh target state.';
      }
    } catch (err) {
      notice = `${err.message} No automatic retry was made. Refresh before attempting another operation.`;
    } finally {
      busy = false;
      // Do not make another SSH connection after failure or cancellation. Discard
      // pre-action states, and let the operator explicitly refresh the target.
      base(root);
      root.appendChild(window.CCC.el('p', 'muted', 'Target state is unknown until you refresh.'));
    }
  }
  async function load() {
    if (busy) return;
    busy = true;
    const root = document.getElementById('viewCodesys');
    const {el, getJSON} = window.CCC;
    base(root);
    const pending = el('p', 'muted', 'Checking targets… previous state is not current.');
    root.appendChild(pending);
    try {
      const data = await getJSON('/api/board/targets');
      busy = false;
      base(root);
      root.appendChild(el('p', 'muted', `Checked ${data.checked_at}. Refresh is manual; no automatic SSH retries.`));
      root.appendChild(el('p', '', data.gateway_help));
      const setup = el('details', '');
      setup.appendChild(el('summary', '', 'Target setup and password recovery'));
      setup.appendChild(el('p', '', data.setup));
      setup.appendChild(el('p', '', 'Inventory must pin the SSH machine_id, project and active application, gateway_guid and device_address, and an operator-verified GUI gateway path to the same box. Runtime credentials belong in the MCP process environment, never in this panel. Reconnect the server after changing credentials.'));
      setup.appendChild(el('p', '', 'Install/update uses an operator-staged codesyscontrol .deb with a configured version and SHA-256. Dependencies must already be installed or available to apt. The package, architecture and installed version are checked on the box. A private backup under /var/backups/agentmux-codesys precedes changes. sudo must work non-interactively; otherwise use a real terminal.'));
      setup.appendChild(el('p', '', 'For forgotten runtime passwords on administered lab boxes, follow the codesys-runtime-reset skill: back up user management and run /usr/local/sbin/codesys-usermgmt-reset in an interactive SSH terminal. Package reinstall is not password recovery.'));
      root.appendChild(setup);
      if (!data.targets.length) root.appendChild(el('p', '', 'No targets configured. Add the operator-owned codesys.json inventory to AGENTMUX_HOME.'));
      for (const target of data.targets) {
        const card = el('article', '');
        card.appendChild(el('h3', '', `${target.name} (${target.id})`));
        card.appendChild(el('p', 'muted', target.address));
        card.appendChild(el('strong', target.reachable ? '' : 'warn', target.reachable ? 'Reachable over SSH' : 'UNREACHABLE'));
        // Defensive: even a malformed/stale API row cannot display live state
        // or enable control buttons for an unreachable target.
        card.appendChild(el('p', '', target.reachable
          ? `Runtime: ${target.runtime_version || 'unknown'} · Application: ${target.application || 'unknown'} · State: ${target.state || 'unknown'}`
          : 'Runtime: unknown · Application: unknown · State: unknown'));
        card.appendChild(el('p', 'muted', `Last seen: ${target.last_seen || 'never'} · Checked: ${target.checked_at}`));
        for (const error of target.errors || []) card.appendChild(el('p', 'error', error));
        const reset = el('select', '');
        reset.setAttribute('aria-label', `Reset type for ${target.name}`);
        for (const [value, text] of [['Warm', 'Warm — non-retain variables'], ['Cold', 'Cold — includes retains'], ['Origin', 'Origin — removes application']]) {
          const option = el('option', '', text); option.value = value; reset.appendChild(option);
        }
        reset.value = 'Warm'; card.appendChild(reset);
        for (const [action, label] of Object.entries(labels)) {
          const button = el('button', 'btn', label + (['install', 'update'].includes(action) && target.package_version ? ` (${target.package_version})` : ''));
          button.disabled = !target.reachable || !(target.actions || []).includes(action);
          button.addEventListener('click', () => act(target, action, reset.value));
          card.appendChild(button);
        }
        root.appendChild(card);
      }
    } catch (err) {
      busy = false;
      base(root);
      root.appendChild(el('p', 'error', `Target status unavailable: ${err.message}. All current states are unknown; refresh manually.`));
    } finally {
      busy = false;
    }
  }
  // A CODESYS runtime is field equipment like everything else on the IIOT view, so
  // it is a card there rather than a top-level entry of its own.
  //
  // AND IT IS LAZY, which is the whole reason it ships collapsed. Every refresh here
  // is an SSH connection to a controller; opening the IIOT view to look at Modbus
  // must not quietly reach out to five PLCs. So the card loads when it is OPENED,
  // and opening it is the operator asking - the same contract the panel has always
  // had with its Refresh button.
  window.addEventListener('ccc:ready', () => {
    const card = document.querySelector('details[data-collapse-key="iiot:codesys"]');
    if (!card) return;
    let loaded = false;
    const maybe = () => {
      if (!card.open || loaded) return;
      loaded = true;
      load();
    };
    card.addEventListener('toggle', maybe);
    window.CCC.registerCard('iiot', maybe, 0);
  }, {once: true});
})();
