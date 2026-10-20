/* Presentation only; callers supply data and actions. */
window.AgentmuxComponentImplementations.LabeledField = ({el, label, control, className = ''}) => {
  const field = el('label', className, label);
  field.appendChild(control);
  return field;
};
