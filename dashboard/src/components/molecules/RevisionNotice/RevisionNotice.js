/* Presentation only; callers supply data and actions. */
window.AgentmuxComponentImplementations.RevisionNotice = ({el, state}) => {
  const messages = {
    changed: 'Definition changed; this roster keeps its saved revision.',
    unavailable: 'Definition unavailable; this roster keeps its saved revision.',
    approval_required: 'Saved definition missing. Propose and approve this roster again before hiring.'
  };
  return messages[state] ? el('span', 'teams-revision', messages[state]) : null;
};
