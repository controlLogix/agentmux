/* Compatible entrypoint; feature code owns requests and state. */
window.addEventListener('ccc:ready', () => {
  window.AgentmuxFeatures.registerTeams();
}, {once: true});
