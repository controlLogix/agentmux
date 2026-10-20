module.exports = ({components, el, assert}) => {
  const create = components.molecules.RevisionNotice.create;
  assert.equal(create({el, state: 'current'}), null);
  assert.match(create({el, state: 'changed'}).textContent, /keeps its saved revision/);
  assert.match(create({el, state: 'unavailable'}).textContent, /Definition unavailable/);
  assert.match(create({el, state: 'approval_required'}).textContent, /approve this roster again/);
};
