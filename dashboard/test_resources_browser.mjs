// Run only through test_resources_browser.py in the coordinator's live slot.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const [url, driverPath, executablePath] = process.argv.slice(2);
assert.ok(url && driverPath && executablePath, 'Expected isolated server, driver and browser paths');
const {chromium} = createRequire(import.meta.url)(driverPath);
const browser = await chromium.launch({headless: true, executablePath, timeout: 15000});
process.once('SIGTERM', async () => {
  await browser.close();
  process.exitCode = 2;
});
try {
  const context = await browser.newContext({viewport: {width: 1400, height: 1100}});
  const page = await context.newPage();
  let refreshes = 0;
  let nextResourceResponse = null;
  await page.route('**/api/**', async route => {
    const request = new URL(route.request().url());
    if (request.pathname === '/api/resources') {
      if (request.searchParams.get('refresh') === '1') refreshes++;
      if (nextResourceResponse) {
        const payload = nextResourceResponse;
        nextResourceResponse = null;
        await route.fulfill({json: payload});
      } else await route.continue();
    } else {
      // This test owns only Resources; other features cannot reach clients or services.
      await route.fulfill({json: {agents: [], teams: [], resources: [], providers: [],
        tasks: [], epics: [], runs: [], entries: [], messages: [], sessions: []}});
    }
  });
  await page.goto(url, {waitUntil: 'load'});
  await page.waitForFunction(() => !!window.CCC);
  await page.click('.nav-item[data-view="settings"]');
  await page.locator('#resList .res').first().waitFor({state: 'visible'});
  const cards = page.locator('#resList .res');
  assert.equal(await cards.count(), 8);
  const text = await page.locator('#resList').innerText();
  assert.ok(text.includes('Client tool is not installed.'));
  const statuses = await page.locator('#resList .res-state').allTextContents();
  assert.ok(statuses.includes('unknown'));
  assert.ok(statuses.includes('unavailable'));
  assert.ok(text.includes('your terminal'));
  assert.ok(text.includes('Plugins & skills'));
  assert.ok(!text.includes('fixture-secret-must-stay-private'));
  assert.ok(await page.locator('#resList .act-cmd').count() > 0);
  await page.click('#resRefresh');
  await page.waitForFunction(() => !document.getElementById('resRefresh').disabled);
  assert.equal(refreshes, 1);
  assert.equal(await cards.count(), 8);
  assert.ok(await page.locator('#resRefresh').isVisible());
  assert.ok(await page.getByText('Historical Windows/WSL hint only; not supported by the native macOS ARM64 beta.', {exact: true}).isVisible());
  nextResourceResponse = {error: 'Fixture refresh unavailable', resources: []};
  await page.click('#resRefresh');
  await page.waitForFunction(() => document.getElementById('resStamp').textContent.includes('Fixture refresh unavailable'));
  assert.equal(await cards.count(), 8);
  nextResourceResponse = {refreshing: true, resources: []};
  await page.click('#resRefresh');
  await page.waitForFunction(() => document.getElementById('resStamp').textContent.includes('checks are running'));
  assert.equal(await cards.count(), 8);
  await page.click('#resRefresh');
  await page.waitForFunction(() => document.getElementById('resStamp').textContent.startsWith('probed'));
  assert.equal(await cards.count(), 8);
  console.log('PASS: native browser Resources, optional-client absence, visible setup notes, refresh failure and recovery');
  await context.close();
} finally {
  await browser.close();
}
