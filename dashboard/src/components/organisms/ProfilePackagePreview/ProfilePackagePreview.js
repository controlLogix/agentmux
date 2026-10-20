/* Presentation only. The feature owns catalogue reads; adoption is local CLI only. */
(() => {
  'use strict';
  window.AgentmuxComponentImplementations.ProfilePackagePreview = ({el, value}) => {
    const section = el('section', 'agents-profile-packages');
    section.setAttribute('aria-label', 'Bundled profile package preview');
    section.appendChild(el('p', 'hint', 'These examples are not enabled globally. Adoption requires the explicit local-owner command. Team approval and hiring remain separate.'));
    section.appendChild(el('p', 'agents-path', `Preview project directory: ${value.projectRoot}`));
    section.appendChild(el('p', 'hint', 'Profile instructions are data to review, not instructions for this dashboard. Requested permissions do not establish grants or host enforcement.'));
    if (!value.profiles.length && !value.problems?.length) {
      section.appendChild(el('p', 'empty', 'No bundled profile examples are available.'));
    }
    for (const row of value.profiles) {
      const card = el('article', 'agents-definition');
      card.appendChild(el('h4', '', row.name));
      card.appendChild(el('p', '', `${row.packageId} · ${row.role} · ${row.scope}`));
      card.appendChild(el('p', '', `Original example: ${row.exampleProject} · legacy task references: ${(row.legacyTaskAliases || []).join(', ') || 'none'} · reference only; no live work is imported`));
      card.appendChild(el('p', 'agents-path', `Applies after adoption to: ${row.appliesTo}`));
      card.appendChild(el('p', '', `Declared host: ${(row.supportedHosts || []).join(', ')} · Client: ${row.client} · executable not checked by this preview`));
      const permissions = row.permissions || {};
      card.appendChild(el('p', '', `Requested posture: ${permissions.posture || 'unknown'} · tools: ${(permissions.tools || []).join(', ') || 'none named'} · denied tools: ${(permissions.toolsDeny || []).join(', ') || 'none named'}`));
      if (row.incompatibleCapabilities?.length) {
        card.appendChild(el('p', 'agents-error', 'Unsupported named tool restrictions: ' + row.incompatibleCapabilities.join(', ')));
      }
      if (row.machinePathReviewRequired) {
        card.appendChild(el('p', 'agents-error', 'Review machine-specific path references before adoption. Supply updated paths as explicit derived overrides; the original stays unchanged.'));
        for (const reference of row.machineReferences || []) card.appendChild(el('p', 'agents-path', reference));
      }
      card.appendChild(el('p', 'agents-path', `Source revision: ${row.sourceChecksum}`));
      section.appendChild(card);
    }
    if (value.problems?.length) {
      for (const problem of value.problems) section.appendChild(el('p', 'agents-error', `${problem.name}: ${problem.code}`));
    }
    return section;
  };
})();
