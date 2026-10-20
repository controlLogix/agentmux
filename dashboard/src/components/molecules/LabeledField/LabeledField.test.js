module.exports = ({components, el, assert}) => {
  const control = el('input');
  const field = components.molecules.LabeledField.create({el, label: 'Name', control});
  assert.equal(field.tag, 'label');
  assert.equal(field.textContent, 'Name');
  assert.equal(field.children[0], control);
};
