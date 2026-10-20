/* Presentation only; callers supply data and actions. */
window.AgentmuxComponentImplementations.DefinitionEditor = ({el, say, value, isEditing, onSubmit}) => {
  const form = el('form', 'agents-form');
  const inputs = {};
  const choices = {
    scope: ['repo', 'global'], posture: ['workspace-write', 'read-only', 'unrestricted'],
    role: ['worker', 'lead', 'reviewer', 'researcher'], worktree: ['per-member', 'integration', 'none']
  };
  for (const [key, label] of [
    ['name', 'Name'], ['scope', 'Scope'], ['description', 'Description'], ['cli', 'CLI'],
    ['model', 'Model (optional)'], ['auth', 'Auth method ID (optional)'], ['posture', 'Posture'],
    ['role', 'Role'], ['worktree', 'Worktree'], ['max_instances', 'Maximum instances (1–8)'],
    ['tools', 'Tools (comma separated)'], ['tools_deny', 'Denied tools (comma separated)'],
    ['capabilities', 'Capabilities (comma separated)'], ['persona', 'Persona']
  ]) {
    const input = el(key === 'persona' ? 'textarea' : choices[key] ? 'select' : 'input', 'rin');
    input.name = key;
    if (choices[key]) for (const choice of choices[key]) {
      const option = el('option', '', choice);
      option.value = choice;
      input.appendChild(option);
    }
    const fallback = choices[key] ? choices[key][0] : key === 'max_instances' ? 1 : '';
    input.value = Array.isArray(value[key]) ? value[key].join(', ') : value[key] ?? fallback;
    if (isEditing && ['name', 'scope'].includes(key)) input.disabled = true;
    if (['name', 'description'].includes(key)) input.required = true;
    if (key === 'name') { input.pattern = '[a-z][a-z0-9-]{0,63}'; input.maxLength = 64; }
    if (key === 'description') input.maxLength = 2048;
    if (key === 'persona') { input.maxLength = 4096; input.rows = 8; }
    if (key === 'max_instances') { input.type = 'number'; input.min = 1; input.max = 8; input.required = true; }
    inputs[key] = input;
    form.appendChild(window.AgentmuxUI.molecules.LabeledField.create({el, label, control: input, className: 'agents-label'}));
  }
  const save = el('button', 'btn', isEditing ? 'Save definition' : 'Create definition');
  save.type = 'submit';
  const stamp = el('p', 'stamp');
  stamp.setAttribute('aria-live', 'polite');
  form.appendChild(save);
  form.appendChild(stamp);
  let saving = false;
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (saving) return;
    const body = {};
    for (const [key, input] of Object.entries(inputs)) {
      const raw = input.value;
      body[key] = ['tools', 'tools_deny', 'capabilities'].includes(key)
        ? (raw.trim() ? raw.split(',').map(item => item.trim()) : [])
        : key === 'max_instances' ? Number(raw) : raw;
    }
    if (!body.cli) delete body.cli;
    saving = true;
    save.disabled = true;
    try {
      await onSubmit(body);
      say(stamp, 'Definition saved.');
    } catch (err) { say(stamp, err.message); }
    finally { saving = false; save.disabled = false; }
  });

  return form;
};
