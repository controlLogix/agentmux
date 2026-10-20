module.exports = async ({components, el, say, flatten, assert}) => {
  let received;
  const form = components.organisms.DefinitionEditor.create({el, say, value: {name: 'reviewer', scope: 'repo', persona: 'Private persona', tools: ['Read'], max_instances: 2}, isEditing: true, onSubmit: async body => { received = body; throw Error('Conflict: reload'); }});
  const nodes = flatten(form);
  const field = name => nodes.find(node => node.name === name);
  assert.equal(field('name').disabled, true);
  assert.equal(field('scope').disabled, true);
  assert.equal(field('persona').value, 'Private persona');
  await form.events.submit({preventDefault() {}});
  assert.deepEqual([...received.tools], ['Read']);
  assert.equal(received.max_instances, 2);
  assert.equal(field('persona').value, 'Private persona');
  assert.equal(nodes.find(node => node.tag === 'button').disabled, false);
  assert.equal(nodes.find(node => node.cls === 'stamp').textContent, 'Conflict: reload');
  const success = components.organisms.DefinitionEditor.create({el, say, value: {}, isEditing: false, onSubmit: async () => {}});
  await success.events.submit({preventDefault() {}});
  assert.equal(flatten(success).find(node => node.cls === 'stamp').textContent, 'Definition saved.');
};
