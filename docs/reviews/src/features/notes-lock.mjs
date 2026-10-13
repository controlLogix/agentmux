// The operating system releases this local write lock if its process exits.
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { resolve, dirname, basename, join } from 'node:path';
import { realpathSync, existsSync } from 'node:fs';

export async function acquireNotesLock(path) {
  const full = resolve(path);
  const canonical = existsSync(full) ? realpathSync.native(full) : join(realpathSync.native(dirname(full)), basename(full));
  const normalized = process.platform === 'win32' ? canonical.toLowerCase() : canonical;
  const key = createHash('sha256').update(normalized).digest('hex');
  // Windows named pipes avoid excluded TCP port ranges. Other hosts use one
  // deterministic port; a busy lock must never be bypassed with a fallback.
  const port = 20000 + parseInt(key.slice(0, 8), 16) % 30000;
  const address = process.platform === 'win32' ? { path: '\\\\.\\pipe\\agentmux-review-' + key } : { port, host: '127.0.0.1' };
  const lock = createServer(client => { client.on('error', () => {}); client.end(); });
  try {
    await new Promise((done, reject) => { lock.once('error', reject); lock.listen(address, done); });
    return () => new Promise(done => lock.close(done));
  } catch (error) {
    if (error.code === 'EADDRINUSE' || (process.platform === 'win32' && error.code === 'EACCES')) throw Object.assign(new Error('Local write lock is busy. Another review or local app may be using it. Retry shortly.'), { status: 423 });
    throw error;
  }
}
