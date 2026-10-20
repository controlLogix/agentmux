module.exports = ({components, el, assert}) => {
  let selected;
  const selector = components.molecules.LeadSelector.create({el, candidates: [{name: 'a-first'}, {name: 'z-chosen'}], label: 'Project lead', onChange: value => { selected = value; }});
  assert.equal(selector.control['aria-label'], 'Project lead');
  assert.equal(selector.control.value, '');
  assert.equal(selector.control.children.length, 3);
  selector.control.value = 'z-chosen';
  selector.control.events.change();
  assert.equal(selected, 'z-chosen');
};
