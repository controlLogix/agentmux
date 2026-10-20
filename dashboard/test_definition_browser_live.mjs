// AMUX-41: real browser requests against the enrolled disposable owner.
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
import readline from 'node:readline/promises';
const [url, driver, executablePath] = process.argv.slice(2);
const {chromium} = createRequire(import.meta.url)(driver);
const input = readline.createInterface({input: process.stdin});
const browser = await chromium.launch({executablePath, headless: true});
let closing;
const close = () => closing ||= browser.close();
process.on('SIGTERM', () => close().finally(() => process.exit(1)));
try {
  const page = await browser.newPage();
  await page.goto(url);
  const result = await page.evaluate(async () => {
    const response = await fetch('/api/local-auth/pair', {method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({challenge: '2345-6789-ABCD-EFGH-JKMP'})});
    if (response.status !== 200) throw new Error('pairing failed');
    window.testCsrf = (await response.json()).csrfToken;
    return document.cookie;
  });
  assert.ok(!result.includes('agentmux_local_session'));
  const post = (target, body) => page.evaluate(async ({target, body}) => {
    const response = await fetch('/api/board/' + target, {method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Agentmux-CSRF': window.testCsrf},
      body: JSON.stringify(body)});
    return {status: response.status, body: await response.json()};
  }, {target, body});
  let body = {name: 'writer', scope: 'repo', description: 'Browser original'};
  const created = await post('agentdef', body);
  assert.equal(created.status, 200, 'create status');
  assert.equal(created.body.description, body.description);
  const first = created.body.checksum;
  const edited = await post('agentdef', {...body, checksum: first, description: 'Browser edited'});
  assert.equal(edited.status, 200, 'edit status');
  assert.notEqual(edited.body.checksum, first);
  assert.equal((await post('agentdef', {...body, checksum: first})).status, 409);
  assert.equal((await post('agentdef', {...body, actor: 'forged'})).status, 401);
  const dropped = await post('agentdrop', {name: body.name, scope: body.scope,
    checksum: edited.body.checksum});
  assert.equal(dropped.status, 200, 'delete status');
  const recreated = await post('agentdef', body);
  assert.equal(recreated.status, 200, 'recreate status');
  process.stdout.write('READY_FOR_REVOCATION\n');
  await input.question('');
  assert.equal((await post('agentdef', {...body, checksum: recreated.body.checksum,
    description: 'Must not be saved'})).status, 401);
  process.stdout.write('PASS: enrolled browser definition edits and revocation\n');
} finally {
  input.close();
  await close();
}
