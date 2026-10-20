/* Presentation only; callers supply data and actions. */
window.AgentmuxComponentImplementations.LeadSelector = ({el, candidates, label, value = '', onChange = () => {}}) => {
  const select = el('select', 'teams-lead');
  select.setAttribute('aria-label', label);
  const empty = el('option', '', 'Keep approved lead or compatibility default');
  empty.value = '';
  select.appendChild(empty);
  for (const candidate of candidates) {
    const option = el('option', '', candidate.name);
    option.value = candidate.name;
    select.appendChild(option);
  }
  select.value = value;
  select.addEventListener('change', () => onChange(select.value));
  return {element: window.AgentmuxUI.molecules.LabeledField.create({el, label: 'Lead definition ', control: select}), control: select};
};
