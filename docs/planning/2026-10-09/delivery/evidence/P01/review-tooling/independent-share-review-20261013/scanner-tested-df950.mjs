// Read-only discovery. Workspace selection and server startup belong to the agent.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const safePath = value => typeof value === 'string' && value.length > 0 && !value.startsWith('/') &&
  !/[\\:\0\r\n]/.test(value) && value.split('/').every(part => part && part !== '.' && part !== '..');
const under = (path, directory) => path === directory || path.startsWith(directory + '/');

export function scanInbox({ repoRoot = '.', days = 30, reviewsDir = 'docs/reviews', now = new Date() } = {}) {
  if (!Number.isInteger(days) || days < 1 || days > 3650 || !safePath(reviewsDir)) throw new Error('Use 1–3650 days and a repository-relative reviews directory.');
  const git = args => execFileSync('git', ['--no-optional-locks', '--literal-pathspecs', '-C', resolve(repoRoot), ...args], {
    encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']
  }).trimEnd();
  const root = git(['rev-parse', '--show-toplevel']);
  const warnings = [];
  const read = (ref, path) => { try { return git(['show', ref + ':' + path]); } catch { return null; } };
  const json = (ref, path) => { const raw = read(ref, path); try { return raw === null ? null : JSON.parse(raw); } catch { return null; } };
  const setting = key => { try { return git(['config', '--get', key]); } catch { return ''; } };
  const email = setting('user.email');
  const since = new Date(now.getTime() - days * 86400000).toISOString();
  const refs = git(['for-each-ref', '--format=%(refname)%00%(objectname)%00%(symref)', 'refs/heads', 'refs/remotes'])
    .split('\n').filter(Boolean).map(line => {
      const [ref, head, symbolic] = line.split('\0'); return { ref, head, symbolic };
    }).filter(value => !value.symbolic);
  const heads = new Map();
  for (const { ref, head } of refs) {
    if (!heads.has(head)) heads.set(head, []);
    heads.get(head).push(ref);
  }
  if (heads.size > 100) warnings.push('Only the first 100 distinct branch heads were inspected. Narrow the repository or inspect remaining refs directly.');
  const items = new Map(), draftRoots = new Set();
  const latest = (head, path) => {
    const fields = git(['log', '-1', '--since=' + since, '--format=%H%x00%aI%x00%an%x00%ae%x00%s', head, '--', path]).split('\0');
    return fields.length === 5 ? { commit: fields[0], submittedAt: fields[1], author: fields[2], authorEmail: fields[3], subject: fields[4] } : null;
  };
  function reply(head, manifestPath, config, commit) {
    const path = manifestPath.replace(/review\.json$/, 'responses/' + commit + '.json');
    const receipt = json(head, path);
    if (!receipt) return 'unknown';
    if (receipt.schemaVersion !== 1 || receipt.documentId !== config.id || receipt.submissionCommit !== commit) return 'unknown';
    if (receipt.status === 'pending') return 'pending';
    if (receipt.status !== 'answered' || !Number.isFinite(Date.parse(receipt.answeredAt)) ||
      typeof receipt.responderEmail !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(receipt.responderEmail) || !safePath(receipt.responsePath)) return 'unknown';
    try { git(['cat-file', '-e', head + ':' + receipt.responsePath]); return 'answered'; }
    catch { return 'unknown'; }
  }
  for (const [head, branches] of [...heads].slice(0, 100)) {
    let files;
    try { files = git(['ls-tree', '-r', '--name-only', '-z', head, '--', reviewsDir]).split('\0').filter(Boolean); }
    catch { warnings.push('A branch head could not be inspected.'); continue; }
    const manifests = files.filter(path => path.startsWith(reviewsDir + '/') && path.endsWith('/review.json'));
    if (manifests.length > 100) warnings.push('Only the first 100 review manifests were inspected on ' + branches[0] + '.');
    for (const manifestPath of manifests.slice(0, 100)) {
      const config = json(head, manifestPath);
      if (!config || !ID.test(config.id) || typeof config.title !== 'string' || !safePath(config.notesPath) || !safePath(config.artifactPath)) {
        warnings.push('Invalid review manifest: ' + manifestPath + ' on ' + branches[0] + '.'); continue;
      }
      draftRoots.add(config.notesPath);
      const workPaths = Array.isArray(config.workPaths) ? config.workPaths : [];
      if (workPaths.some(path => !safePath(path))) { warnings.push('Invalid work paths in ' + manifestPath + '.'); continue; }
      const version = json(head, manifestPath.replace(/review\.json$/, 'document-version.json'))?.version || null;
      let noteFiles;
      try { noteFiles = git(['ls-tree', '-r', '--name-only', '-z', head, '--', config.notesPath]).split('\0').filter(Boolean); }
      catch { warnings.push('The notes directory could not be inspected for ' + manifestPath + '.'); continue; }
      for (const path of noteFiles.filter(path => under(path, config.notesPath) && path.endsWith('.md'))) {
        const text = read(head, path);
        const metadata = text?.match(/^```review-metadata\r?\n([\s\S]*?)\r?\n```(?:\r?\n|$)/m);
        let record; try { record = metadata && JSON.parse(metadata[1]); } catch { record = null; }
        const noteBlocks = text ? [...text.matchAll(/^(`{3,})review-note [a-z0-9-]+\r?\n([\s\S]*?)\r?\n\1(?=\r?\n|$)/gm)] : [];
        if (!record || record.format !== 'agentmux-review-notes' || record.schemaVersion !== 1 || record.documentId !== config.id || !noteBlocks.some(block => block[2].trim())) continue;
        add('notes', path, record.documentVersion, record.reviewer);
      }
      for (const path of workPaths) add('work', path, null, null);
      function add(kind, path, submittedVersion, reviewer) {
        const change = latest(head, path); if (!change) return;
        const key = [config.id, kind, path, change.commit].join('\0');
        const status = reply(head, manifestPath, config, change.commit);
        const statusByRef = Object.fromEntries(branches.map(ref => [ref, status]));
        if (items.has(key)) {
          const item = items.get(key); item.refs.push(...branches); Object.assign(item.replyByRef, statusByRef);
          item.replyStatus = new Set(Object.values(item.replyByRef)).size === 1 ? status : 'mixed';
          return;
        }
        items.set(key, { documentId: config.id, title: config.title, kind, path, ...change, reviewer,
          fromCurrentIdentity: Boolean(email && change.authorEmail.toLowerCase() === email.toLowerCase()),
          refs: [...branches], manifestPath, artifactPath: config.artifactPath,
          configuredBranch: config.shareBranch || null, configuredRemote: config.shareRemote || 'origin',
          documentVersion: submittedVersion, currentVersion: version,
          versionMatches: submittedVersion && version ? submittedVersion === version : null,
          replyStatus: status, replyByRef: statusByRef });
      }
    }
  }
  const drafts = git(['status', '--porcelain=v1', '-z', '--no-renames', '--untracked-files=all'])
    .split('\0').filter(Boolean).map(value => ({ status: value.slice(0, 2), path: value.slice(3) }))
    .filter(value => [...draftRoots].some(directory => under(value.path, directory)));
  return { repository: root, since, fetched: false, identity: { name: setting('user.name'), email },
    submissions: [...items.values()].sort((a, b) => b.submittedAt.localeCompare(a.submittedAt)),
    localDrafts: drafts, warnings, limits: { branchHeads: 100, manifestsPerHead: 100 },
    replyStatusMeaning: 'Unknown means no valid recorded reply was found; inspect the questions before deciding what needs answering.' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2); const options = {};
    for (let index = 0; index < args.length; index += 2) {
      const value = args[index + 1];
      if (!value || !['--repo', '--days', '--reviews-dir'].includes(args[index])) throw new Error('Use --repo <path>, --days <number> or --reviews-dir <relative-path>.');
      options[{ '--repo': 'repoRoot', '--days': 'days', '--reviews-dir': 'reviewsDir' }[args[index]]] = args[index] === '--days' ? Number(value) : value;
    }
    console.log(JSON.stringify(scanInbox(options), null, 2));
  } catch { console.error('Could not inspect the review inbox. Check the repository path, Git access and command arguments.'); process.exitCode = 1; }
}
