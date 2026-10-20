/* Compatible entrypoint; feature code owns requests and state. */
window.addEventListener('ccc:ready', () => {
  window.AgentmuxFeatures.registerAgentDefinitions();
}, {once: true});
