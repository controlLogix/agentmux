/* Decisions are staged per member; the board commits the whole proposal once. */
(() => {
  'use strict';
  let ui;
  let loading = false;
  const SETTINGS = [
    ['teamMaxAgents', 'Maximum live agents (1–32)', 1, 32],
    ['teamMaxWorkers', 'Maximum workers per team (0–8)', 0, 8],
    ['teamRequireApproval', 'Require roster approval (true/false)'],
    ['dashboardMayHire', 'Allow dashboard hiring (true/false)']
  ];

  function setup() {
    if (ui) return ui;
    const { el } = window.CCC;
    const header = el('div', 'teams-header');
    header.appendChild(el('h2', '', 'Teams'));
    const refresh = el('button', 'btn', 'Refresh');
    refresh.type = 'button';
    refresh.addEventListener('click', loadTeams);
    const stamp = el('span', 'stamp');
    stamp.setAttribute('aria-live', 'polite');
    header.appendChild(refresh);
    header.appendChild(stamp);
    const content = el('div', 'teams-content');
    document.getElementById('viewTeams').replaceChildren(header, content);
    ui = { refresh, stamp, content };
    return ui;
  }

  function rosterCard(task, roster, config, leads) {
    const { el, post, say } = window.CCC;
    const card = el('article', 'teams-card');
    card.appendChild(el('h3', '', `${task.key} · ${task.title}`));
    for (const gap of roster.gaps || []) {
      card.appendChild(el('p', 'teams-gap', `Roster gap: ${gap}`));
    }
    const stamp = el('p', 'stamp');
    stamp.setAttribute('aria-live', 'polite');
    const closed = ['done', 'deleted'].includes(task.status);
    const proposed = roster.members.filter(m => m.status === 'proposed');
    const decisions = new Map();
    const controls = [];
    const decided = roster.members.some(m => ['approved', 'rejected', 'finished'].includes(m.status));
    const save = el('button', 'btn', 'Save roster decision');
    save.type = 'button';
    save.disabled = true;
    for (const member of roster.members) {
      const row = el('div', 'teams-member');
      row.appendChild(window.CCC.markAgent(el('strong', '', member.agent_name),
                                           member.agent_name));
      row.appendChild(el('span', '', `${member.role} · ${member.status}`));
      const revision = window.AgentmuxUI.molecules.RevisionNotice.create({el, state: member.definitionState});
      if (revision) row.appendChild(revision);
      if (member.approved_by) row.appendChild(el('span', '', `Approved by ${member.approved_by}`));
      if (member.status === 'approved' && !closed && config.dashboardMayHire === true) {
        const hire = el('button', 'btn teams-hire', 'Hire');
        hire.type = 'button';
        hire.setAttribute('aria-label', `Hire ${member.agent_name}`);
        hire.addEventListener('click', () => submit('hire', { name: member.agent_name }));
        controls.push(hire);
        row.appendChild(hire);
      }
      if (member.status === 'proposed' && !closed && !decided) {
        const choices = [];
        for (const [label, approved] of [['Approve', true], ['Reject', false]]) {
          const button = el('button', 'btn', label);
          button.type = 'button';
          button.setAttribute('aria-label', `${label} ${member.agent_name}`);
          button.setAttribute('aria-pressed', 'false');
          button.addEventListener('click', () => {
            decisions.set(member.agent_name, approved);
            for (const choice of choices) choice.setAttribute('aria-pressed', String(choice === button));
            save.disabled = decisions.size !== proposed.length;
          });
          choices.push(button);
          controls.push(button);
          row.appendChild(button);
        }
      }
      card.appendChild(row);
    }
    if (!roster.members.length) card.appendChild(el('p', 'empty', 'No roster proposed yet.'));
    async function submit(op, extra) {
      const hiring = op === 'hire';
      if (loading) return;
      if (hiring && config.dashboardMayHire !== true) return;
      loading = true;
      ui.refresh.disabled = true;
      const disabled = controls.map(control => control.disabled);
      controls.forEach(control => { control.disabled = true; });
      if (hiring) say(stamp, `Hiring ${extra.name}…`);
      let written = false;
      try {
        // Hire accepts only identity: the server uses the approved saved definition.
        await post(`api/board/${op}`, hiring
          ? { id: task.key, name: extra.name }
          : { id: task.key, ...extra });
        written = true;
        // Never render the POST response or treat a local choice as board status.
        await refreshTeams();
      } catch (err) {
        // Preserve the API's distinct bound reasons (including approval, config,
        // slots, definition and listener); HTTP status alone loses that detail.
        const outcome = written
          ? (hiring ? 'Hired, but refresh failed' : 'Saved, but refresh failed')
          : (hiring ? 'Hire failed' : 'Not saved');
        say(stamp, `${outcome}: ${err.message}. Refresh to retry.`);
        if (!written) controls.forEach((control, index) => { control.disabled = disabled[index]; });
      } finally {
        loading = false;
        ui.refresh.disabled = false;
      }
    }
    if (!closed) {
      const selector = window.AgentmuxUI.molecules.LeadSelector.create({
        el, candidates: leads, label: `Lead definition for ${task.key}`
      });
      const leadChoice = selector.control;
      card.appendChild(selector.element);
      controls.push(leadChoice);
      const recruit = el('button', 'btn', roster.members.length ? 'Re-propose roster' : 'Propose roster');
      recruit.type = 'button';
      recruit.addEventListener('click', () => submit('recruit', leadChoice.value ? { lead: leadChoice.value } : {}));
      controls.push(recruit);
      card.appendChild(recruit);
    }
    if (proposed.length && !closed && !decided) {
      card.appendChild(el('p', 'hint', 'Choose Approve or Reject for every proposed member, then save the whole decision.'));
      save.addEventListener('click', () => {
        if (save.disabled || decisions.size !== proposed.length) return;
        return submit('approve', { members: roster.members.filter(m =>
          m.status === 'hired' || decisions.get(m.agent_name) === true).map(m => m.agent_name) });
      });
      controls.push(save);
      card.appendChild(save);
    }
    card.appendChild(stamp);
    return card;
  }

  async function refreshTeams() {
    const { el, getJSON, post, say, settingEditor } = window.CCC;
    const data = await getJSON('api/board/board');
    if (!data || !Array.isArray(data.tasks) || !data.config) throw new Error('Invalid board response');
    const tasks = data.tasks.filter(task => task.status !== 'deleted');
    const definitions = await getJSON('api/board/agents');
    if (!definitions || !Array.isArray(definitions.agents)) throw new Error('Invalid definition response');
    const leads = definitions.agents.filter(agent => agent.role === 'lead');
    const rosters = await Promise.all(tasks.map(task => getJSON(`api/board/roster?id=${encodeURIComponent(task.key)}`)));
    if (rosters.some(roster => !roster || !Array.isArray(roster.members))) throw new Error('Invalid roster response');
    const settings = el('section', 'teams-settings');
    settings.appendChild(el('h3', '', 'Team settings'));
    for (const [key, label, min, max] of SETTINGS) {
      settings.appendChild(settingEditor('board', { key, label, value: data.config[key] }, loadTeams, {
        stamp: ui.stamp,
        save: async raw => {
          let value;
          if (min === undefined) {
            if (!['true', 'false'].includes(raw)) throw new Error('Enter true or false');
            value = raw === 'true';
          } else {
            value = Number(raw);
            if (!/^\d+$/.test(raw) || !Number.isInteger(value) || value < min || value > max) {
              throw new Error(`Enter a whole number from ${min} to ${max}`);
            }
          }
          await post('api/board/config', { name: key, value });
        }
      }));
    }
    const list = el('section', 'teams-list');
    if (!tasks.length) list.appendChild(el('p', 'empty', 'No task cards found.'));
    tasks.forEach((task, index) => list.appendChild(rosterCard(task, rosters[index], data.config, leads)));
    ui.content.replaceChildren(settings, list);
    window.CCC.refreshLiveMarks(ui.content);
    say(ui.stamp, `${tasks.length} task rosters loaded`);
  }

  async function loadTeams() {
    setup();
    if (loading) return;
    loading = true;
    ui.refresh.disabled = true;
    try {
      await refreshTeams();
    } catch (err) {
      window.CCC.say(ui.stamp, `Teams unavailable: ${err.message}. Displayed results may be out of date; refresh to retry.`);
    } finally {
      loading = false;
      ui.refresh.disabled = false;
    }
  }

  window.AgentmuxFeatures = window.AgentmuxFeatures || {};
  window.AgentmuxFeatures.registerTeams = () => {
    window.CCC.registerPanel('organization', 'teams', loadTeams);
  };
})();
