// Open, reuse or close the repository's single managed review server.
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createLocalReview } from './src/features/local-review.mjs';
import { manageReview, reviewEnvironment } from './src/features/review-server.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const gitEnv = reviewEnvironment();
const args = process.argv.slice(2);
const flag = args[0]?.startsWith('--') ? args.shift() : null;
const action = flag ? ({ '--status': 'status', '--stop': 'stop', '--restart': 'restart' }[flag]) : 'open';
const id = args[0] || 'agentmux-visual-review';
const port = args[1] === undefined ? undefined : Number(args[1]);
let running;
try {
  if (!action || args.length > 2) throw new Error('Usage: node docs/reviews/open.mjs [--status|--stop|--restart] [document-id] [port]');
  running = await manageReview({ repoRoot, reviewId: id, port, action, createReview: management => {
    const reviewRoot = resolve(repoRoot, 'docs/reviews', id);
    const config = JSON.parse(readFileSync(resolve(reviewRoot, 'review.json')));
    function source(path) {
      if (typeof path !== 'string' || isAbsolute(path)) throw new Error('Use repository-relative review paths.');
      const resolved = realpathSync.native(resolve(repoRoot, path));
      const rel = relative(realpathSync.native(repoRoot), resolved);
      if (rel.startsWith('..') || isAbsolute(rel)) throw new Error('Review source must stay inside the repository.');
      return resolved;
    }
    if (config.buildScript) execFileSync(process.execPath, [source(config.buildScript)], { cwd: repoRoot, env: gitEnv, stdio: 'inherit', windowsHide: true });
    const document = JSON.parse(readFileSync(resolve(reviewRoot, 'document-version.json')));
    return { ...createLocalReview({ repoRoot, config, document, html: readFileSync(source(config.artifactPath), 'utf8'), gitEnv, management }), documentVersion: document.version };
  } });
  if (action === 'status' || action === 'stop') console.log(JSON.stringify(running, null, 2));
  else {
    console.log('\n' + (running.reused ? 'Reusing your review: ' : 'Open your live review: ') + running.url);
    console.log('One server is shared by this repository’s worktrees. Ctrl+C in its owning terminal or open.mjs --stop closes it.');
    if (running.reused) {
      const current = JSON.parse(readFileSync(resolve(repoRoot, 'docs/reviews', id, 'document-version.json')));
      if (current.version !== running.version) console.log('The running page is an older built version. Wait for notes to save, then use open.mjs --restart and reload.');
    }
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
if (running?.stop) {
  const shutdown = () => { running.stop().catch(() => { console.error('Review shutdown failed. Do not start another server until it is resolved.'); process.exitCode = 1; }); };
  process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);
}
