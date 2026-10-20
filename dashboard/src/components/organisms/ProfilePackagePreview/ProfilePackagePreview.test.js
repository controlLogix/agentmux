module.exports = ({components, el, assert}) => {
  const node = components.organisms.ProfilePackagePreview.create({el,
    value: {projectRoot: '/project', profiles: [{name: '<script>untrusted</script>',
      packageId: 'example.survey', role: 'worker', scope: 'project opt-in only', appliesTo: '/project',
      supportedHosts: ['macos-arm64'], client: 'codex', permissions: {posture: 'unrestricted'},
      machinePathReviewRequired: true, machineReferences: ['C:/old/path'],
      sourceChecksum: 'sha256:source', incompatibleCapabilities: ['Write']}], problems: []}});
  const all = node => [node, ...node.children.flatMap(all)];
  const nodes = all(node);
  const text = nodes.map(row => row.textContent).join('\n');
  assert.match(text, /<script>untrusted<\/script>/);
  assert.match(text, /reference only; no live work is imported/);
  assert.match(text, /C:\/old\/path/);
  assert.match(text, /Unsupported named tool restrictions: Write/);
  assert.match(text, /Team approval and hiring remain separate/);
  assert.equal(nodes.some(row => ['form', 'button', 'script'].includes(row.tag)), false);
  const empty = components.organisms.ProfilePackagePreview.create({el,
    value: {projectRoot: '/project', profiles: [], problems: []}});
  assert.match(all(empty).map(row => row.textContent).join('\n'), /No bundled profile examples are available/);
};
