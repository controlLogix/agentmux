/* End-to-end: the real dashboard, in a real browser, driven by Playwright.
 *
 * WHY THIS EXISTS AND WHAT IT IS FOR. Every other frontend suite here runs the
 * production functions against a DOM stub. That catches logic, and it caught a
 * lot - but it cannot catch the class of bug where the code is correct and the
 * PAGE is wrong: a script that loads after the event it listens for, a panel that
 * renders into an element that is not on screen, a card whose contents overflow
 * its box. Those are exactly the failures a stub cannot see, because a stub has no
 * load order, no layout and no box.
 *
 * The specific bug that prompted it: iiot.js, mqtt.js and netscan.js sat BELOW
 * app.js in index.html. app.js dispatches `ccc:ready` synchronously on its last
 * line, so all three subscribed to an event that had already fired, and four of
 * the five IIOT panels rendered nothing at all. Every unit test passed.
 *
 * Usage (test_e2e.sh handles all of this):
 *     node dashboard/test_e2e.mjs <base-url> <playwright-dir> [broker-port]
 */

import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const [baseURL, playwrightDir, brokerPort] = process.argv.slice(2);
if (!baseURL || !playwrightDir) {
  console.error('usage: test_e2e.mjs <base-url> <playwright-dir> [broker-port]');
  process.exit(2);
}
const drivers = createRequire(import.meta.url)(playwrightDir);
const browserName = process.env.AGENTMUX_E2E_BROWSER || 'firefox';
assert.ok(['firefox', 'chromium'].includes(browserName), 'unsupported test browser');
const testFilter = process.env.AGENTMUX_E2E_FILTER;


let passed = 0, failed = 0;
const failures = [];
// '  FAIL  <what>' - the same shape testlib.sh prints, and deliberately so. The gate
// pulls a failing suite's detail out with `grep -E '^[[:space:]]+FAIL'`; at column
// zero that matched nothing, so a real assertion failure here reached the gate as a
// suite that broke with no statement of what broke.
async function test(name, fn) {
  if (testFilter && !name.includes(testFilter)) return;
  try { await fn(); passed++; console.log('PASS ' + name); }
  catch (err) {
    failed++;
    failures.push(name);
    console.error('  FAIL  ' + name + '\n        ' + (err && err.message || err).split('\n')[0]);
  }
}

const browser = await drivers[browserName].launch({ headless: true,
  ...(process.env.AGENTMUX_E2E_BROWSER_EXECUTABLE
    ? {executablePath: process.env.AGENTMUX_E2E_BROWSER_EXECUTABLE} : {}) });
try {
const context = await browser.newContext({ viewport: { width: 1400, height: 950 } });
const page = await context.newPage();

// Anything the page logs as an error is a failure of its own. A dashboard that
// works only because nobody opened the console is not working.
const consoleErrors = [];
page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text()); });
page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message));

await page.goto(baseURL, { waitUntil: 'load' });
await page.waitForFunction(() => !!window.CCC, null, { timeout: 15000 });

const show = async (view) => {
  await page.click(`.nav-item[data-view="${view}"]`);
  await page.waitForSelector(`#view${view[0].toUpperCase() + view.slice(1)}:not([hidden])`);
};
const tab = async (view, panel) => {
  await page.click(`[data-tabs="${view}"] .subtab[data-panel="${panel}"]`);
  await page.waitForSelector(`#view${panel[0].toUpperCase() + panel.slice(1)}:not([hidden])`);
};
const text = (sel) => page.textContent(sel);

// ── the rail ────────────────────────────────────────────────────────────────

await test('the rail has exactly the ten views, in order', async () => {
  // Runs sits directly after Board because a run is what a board card becomes once
  // someone starts working on it, and the order is asserted rather than sorted so a
  // new entry has to be placed deliberately instead of landing wherever.
  const labels = await page.$$eval('.nav-item .nav-label', (ns) => ns.map(n => n.textContent));
  assert.deepEqual(labels, ['Terminals', 'Status', 'Board', 'Runs', 'Hub', 'Federation', 'Organization',
                            'IIOT', 'GitHub', 'Settings']);
});

await test('every rail button reveals its view and hides the others', async () => {
  for (const view of ['status', 'board', 'runs', 'hub', 'organization', 'iiot', 'github',
                      'settings', 'terminals']) {
    await show(view);
    const visible = await page.$$eval('.views > .view',
      (ns) => ns.filter(n => !n.hidden).map(n => n.id));
    assert.deepEqual(visible, ['view' + view[0].toUpperCase() + view.slice(1)],
                     `showing ${view} left ${visible.join(', ')} on screen`);
  }
});

// ── IIOT: the regression this file was written for ─────────────────────────

await test('all five IIOT cards render content, not just CODESYS', async () => {
  await show('iiot');
  const cards = await page.$$eval('#viewIiot details.card', (ns) => ns.map(n => ({
    key: n.dataset.collapseKey,
    title: n.querySelector('summary h3')?.textContent,
    open: n.open,
  })));
  assert.deepEqual(cards.map(c => c.key),
    ['iiot:modbus', 'iiot:dcp', 'iiot:mqtt', 'iiot:scan', 'iiot:codesys']);
  assert.deepEqual(cards.map(c => c.title),
    ['Modbus', 'PROFINET DCP', 'MQTT', 'Ethernet scanner', 'CODESYS targets']);

  // The bug: the body element existed but nothing ever filled it.
  for (const id of ['modbusHint', 'profinetPanel', 'mqttPanel', 'scanPanel']) {
    await page.waitForFunction(
      (elementId) => {
        const node = document.getElementById(elementId);
        return node && node.childElementCount > 0;
      }, id, { timeout: 15000 });
    const count = await page.$eval('#' + id, (n) => n.childElementCount);
    assert.ok(count > 0, `#${id} rendered nothing`);
  }
});

await test('every card title is bold, and they all match', async () => {
  const weights = await page.$$eval('#viewIiot details.card > summary h3',
    (ns) => ns.map(n => getComputedStyle(n).fontWeight));
  assert.equal(new Set(weights).size, 1, 'card titles disagree: ' + weights.join(', '));
  assert.ok(Number(weights[0]) >= 600, 'card titles are not bold: ' + weights[0]);
});

await test('no card overflows its box', async () => {
  // The two-line `sudo python3 taskmgmt/pn_dcp.py ... set --mac ...` used to run
  // straight out of the PROFINET card. Anything wider than its own box fails here.
  const overflow = await page.$$eval('#viewIiot details.card', (ns) => ns
    .filter(n => n.scrollWidth > n.clientWidth + 1)
    .map(n => `${n.dataset.collapseKey} (${n.scrollWidth} > ${n.clientWidth})`));
  assert.deepEqual(overflow, []);
  const wide = await page.$eval('#viewIiot',
    (n) => n.scrollWidth > n.clientWidth + 1);
  assert.equal(wide, false, 'the IIOT view scrolls sideways');
});

await test('the cards pack into columns with no dead space between them', async () => {
  await show('iiot');
  await page.evaluate(() => document.querySelectorAll('#viewIiot details.card')
    .forEach(c => { c.open = true; }));
  await page.waitForTimeout(1200);
  const layout = await page.evaluate(() => {
    const grid = document.querySelector('.iiot-grid');
    const box = grid.getBoundingClientRect();
    const cards = [...grid.querySelectorAll('.card')].map(c => {
      const r = c.getBoundingClientRect();
      return { key: c.dataset.collapseKey, x: Math.round(r.left - box.left),
               top: Math.round(r.top - box.top), bottom: Math.round(r.bottom - box.top) };
    });
    return { height: Math.round(box.height), cards };
  });
  assert.equal(layout.cards.length, 5);

  // THE ACTUAL COMPLAINT, stated as a measurement. Group the cards into columns by
  // their left edge; inside a column, the space between one card's bottom and the
  // next card's top must be the gutter and nothing more. Under the old grid this
  // was 255px in one column - a card-sized hole in the middle of the page - because
  // a grid row cannot be shorter than its tallest cell.
  const columns = new Map();
  for (const card of layout.cards) {
    if (!columns.has(card.x)) columns.set(card.x, []);
    columns.get(card.x).push(card);
  }
  const gaps = [];
  for (const [x, cards] of columns) {
    cards.sort((a, b) => a.top - b.top);
    for (let i = 1; i < cards.length; i++) {
      gaps.push({ x, after: cards[i - 1].key, gap: cards[i].top - cards[i - 1].bottom });
    }
  }
  const worst = gaps.reduce((m, g) => (g.gap > m.gap ? g : m), { gap: 0, after: 'none' });
  assert.ok(worst.gap <= 24,
    `${worst.gap}px of dead space after ${worst.after} — cards are not packing`);
  assert.ok(columns.size >= 2, 'expected more than one column at this viewport width');
});

await test('expand all and collapse all drive every card', async () => {
  await page.click('#iiotCollapse');
  assert.deepEqual(await page.$$eval('#viewIiot details.card', ns => ns.map(n => n.open)),
                   [false, false, false, false, false]);
  await page.click('#iiotExpand');
  assert.deepEqual(await page.$$eval('#viewIiot details.card', ns => ns.map(n => n.open)),
                   [true, true, true, true, true]);
  // The choice has to survive a reload, which is the whole point of the key.
  await page.reload({ waitUntil: 'load' });
  await page.waitForFunction(() => !!window.CCC);
  await show('iiot');
  assert.deepEqual(await page.$$eval('#viewIiot details.card', ns => ns.map(n => n.open)),
                   [true, true, true, true, true]);
  await page.click('#iiotCollapse');
  await page.click('#iiotExpand');
});

// ── MQTT: a live broker, a real topic tree ─────────────────────────────────

if (brokerPort) {
  await test('the MQTT panel browses a real broker', async () => {
    await show('iiot');
    await page.fill('#mqttPanel input[aria-label="Broker host"]', '127.0.0.1');
    await page.fill('#mqttPanel input[aria-label="Broker port"]', String(brokerPort));
    await page.fill('#mqttPanel input[aria-label="Topic filters"]', 'plant/#');
    await page.click('#mqttPanel button:has-text("Monitor")');

    await page.waitForFunction(
      () => /CONNECTED/.test(document.querySelector('#mqttPanel .field-state')?.textContent || ''),
      null, { timeout: 20000 });
    // The tree folds on '/', so `plant` is a branch and the leaves sit under it.
    await page.waitForSelector('#mqttPanel .mq-branch', { timeout: 20000 });
    const segments = await page.$$eval('#mqttPanel .mq-segment', ns => ns.map(n => n.textContent));
    assert.ok(segments.includes('plant'), 'no plant branch: ' + segments.join(', '));
    await page.waitForFunction(
      () => document.querySelectorAll('#mqttPanel .mq-leaf').length >= 3,
      null, { timeout: 20000 });
    const topics = await page.$$eval('#mqttPanel .mq-leaf .mq-topic',
      ns => ns.map(n => n.title));
    for (const wanted of ['plant/line1/temp', 'plant/line1/state', 'plant/line2/press']) {
      assert.ok(topics.includes(wanted), `missing ${wanted}: ${topics.join(', ')}`);
    }
  });

  await test('a retained value is marked retained and a live one is not', async () => {
    const meta = await page.$$eval('#mqttPanel .mq-leaf', ns => ns.map(n => ({
      topic: n.querySelector('.mq-topic')?.title,
      meta: n.querySelector('.mq-meta')?.textContent,
    })));
    const state = meta.find(m => m.topic === 'plant/line1/state');
    const temp = meta.find(m => m.topic === 'plant/line1/temp');
    assert.match(state.meta, /retained/);
    assert.doesNotMatch(temp.meta, /retained/);
    assert.match(temp.meta, /ago|just now/, 'a value with no age is a value you cannot trust');
  });

  await test('the tree opens deep enough to show a value without clicking', async () => {
    // A browser that shows you `plant` and nothing else has not browsed anything.
    const visible = await page.$$eval('#mqttPanel .mq-leaf .mq-topic',
      ns => ns.filter(n => n.offsetParent !== null).map(n => n.title));
    assert.ok(visible.includes('plant/line1/temp'),
              'no leaf is visible without expanding: ' + visible.join(', '));
  });

  await test('clicking a topic inspects it, with its payload pretty-printed', async () => {
    await page.click('#mqttPanel .mq-leaf .mq-topic[title="plant/line2/press"]');
    await page.waitForSelector('#mqttPanel .mq-inspect-topic');
    assert.equal(await text('#mqttPanel .mq-inspect-topic'), 'plant/line2/press');
    const payload = await text('#mqttPanel .mq-payload');
    assert.match(payload, /\{\n\s+"bar"/, 'JSON payload was not pretty-printed: ' + payload);
  });

  await test('the log tab shows arrival order and the buffer can be cleared', async () => {
    await page.click('#mqttPanel .mq-tabs .subtab:has-text("Log")');
    await page.waitForSelector('#mqttPanel .mq-log-row');
    const rows = await page.$$eval('#mqttPanel .mq-log-row', ns => ns.length);
    assert.ok(rows > 0, 'the log is empty');
    await page.click('#mqttPanel button:has-text("Clear buffer")');
    await page.waitForFunction(
      () => /0 topics|no topics/i.test(
        document.querySelector('#mqttPanel .field-state')?.textContent || '')
        || document.querySelectorAll('#mqttPanel .mq-log-row').length === 0,
      null, { timeout: 10000 });
  });

  await test('the panel names its client and whether this broker has credentials', async () => {
    // Both matter the moment a broker refuses you: "Not authorized" reads very
    // differently once you know the server had no username to offer it.
    const hint = await text('#mqttPanel .hint');
    assert.match(hint, /paho-mqtt \d+\.\d+/, 'the client is not named: ' + hint);
    assert.match(hint, /no credentials on file for this broker/);
    assert.match(hint, /never entered here/, 'it must say credentials are not typed in here');
  });

  await test('a publish goes out on the session the monitor already holds', async () => {
    // Not a second anonymous connection: that one would be refused by any broker
    // the monitor needed a credential to reach.
    const posted = [];
    await page.route('**/api/mqtt/monitor/publish', async (route) => {
      posted.push(JSON.parse(route.request().postData() || '{}'));
      await route.fulfill({ status: 200, contentType: 'application/json',
                            body: '{"ok":true,"detail":"Acknowledged by the broker at QoS 1."}' });
    });
    // Opened directly rather than by clicking the summary: this test is about the
    // publish contract, not about the disclosure widget.
    await page.evaluate(() => {
      document.querySelector('#mqttPanel details.subcard').open = true;
    });
    await page.fill('#mqttPanel input[aria-label="Publish topic"]', 'plant/line1/setpoint');
    await page.fill('#mqttPanel input[aria-label="Publish payload"]', '42');
    await page.selectOption('#mqttPanel select[aria-label="Publish QoS"]', '1');
    await page.check('#mqttPanel input[aria-label="Retain this message"]');
    let prompt = '';
    const onDialog = (d) => { prompt = d.message(); d.accept(); };
    page.once('dialog', onDialog);
    try {
      await page.click('#mqttPanel button[aria-label="Publish message"]');
      await page.waitForFunction(
        () => /Acknowledged/.test(document.querySelector('#mqttPanel')?.textContent || ''),
        null, { timeout: 15000 });
    } finally {
      // A `once` handler that never fired stays armed and silently eats the NEXT
      // test's confirm - which is how one failure here took the scanner down with
      // it and then crashed the run on a double-accept.
      page.off('dialog', onDialog);
    }
    assert.deepEqual(posted, [{ topic: 'plant/line1/setpoint', payload: '42',
                                qos: 1, retain: true }]);
    assert.match(prompt, /RETAINED/, 'a retained publish must say it outlives the session');
    assert.match(prompt, /QoS 1/);
    await page.unroute('**/api/mqtt/monitor/publish');
    await page.uncheck('#mqttPanel input[aria-label="Retain this message"]');
  });

  await test('stopping the monitor is reported, and it stays stopped', async () => {
    await page.click('#mqttPanel button:has-text("Stop")');
    await page.waitForFunction(
      () => /STOPPED/.test(document.querySelector('#mqttPanel .field-state')?.textContent || ''),
      null, { timeout: 10000 });
  });
}

// ── the scanner ─────────────────────────────────────────────────────────────

await test('the scanner finds a host on a port it was told to probe', async () => {
  await show('iiot');
  // This server's own port, which is ephemeral and so is not one of the named
  // industrial ports - which is precisely what the "Also probe" field is for, and
  // it makes the expected result knowable rather than "whatever else is listening
  // on this machine".
  const port = new URL(baseURL).port;
  await page.fill('#scanPanel input[aria-label="Range to scan"]', '127.0.0.1/32');
  await page.fill('#scanPanel input[aria-label="Operator name"]', 'e2e');
  await page.evaluate(() => {
    const card = document.querySelector('#scanPanel details.subcard');
    card.open = true;
    // Untick the standard set: the point is to assert on one known-open port.
    for (const box of card.querySelectorAll('input[type=checkbox]')) {
      box.checked = false;
      box.dispatchEvent(new Event('change'));
    }
  });
  await page.fill('#scanPanel input[aria-label="Additional ports"]', port);
  page.once('dialog', d => d.accept());
  await page.click('#scanPanel button:has-text("Scan")');
  await page.waitForFunction(
    () => /DONE|ERROR/.test(
      document.querySelector('#scanPanel .field-state')?.textContent || ''),
    null, { timeout: 90000 });
  const state = await text('#scanPanel .field-state');
  assert.match(state, /DONE/, 'scan did not finish: ' + state);
  const rows = await page.$$eval('#scanPanel .scan-table tbody tr',
    ns => ns.map(n => [...n.querySelectorAll('td')].map(t => t.textContent)));
  assert.equal(rows.length, 1, 'expected exactly one host: ' + JSON.stringify(rows));
  assert.equal(rows[0][0], '127.0.0.1');
  assert.match(rows[0][4], new RegExp(`\\b${port}\\b`), 'the open port is not listed');
  assert.match(state, /MACs? resolved/, 'the scan must say how many MACs it resolved');
  // An address and a MAC have no sensible break point; wrapping them across lines
  // makes the one column you scan down unreadable.
  const wrapped = await page.$$eval('#scanPanel .scan-table td.mono',
    ns => ns.filter(n => n.getClientRects().length > 1).map(n => n.textContent));
  assert.deepEqual(wrapped, [], 'an address or MAC is wrapped across lines');
});

await test('a malformed extra port is named, not silently dropped', async () => {
  await page.fill('#scanPanel input[aria-label="Additional ports"]', 'not-a-port');
  await page.click('#scanPanel button:has-text("Scan")');
  await page.waitForFunction(
    () => /is not a port or a port range/.test(
      document.querySelector('#scanPanel')?.textContent || ''),
    null, { timeout: 15000 });
});

await test('the scanner refuses a public range, in the page', async () => {
  const port = new URL(baseURL).port;
  await page.fill('#scanPanel input[aria-label="Additional ports"]', port);
  await page.fill('#scanPanel input[aria-label="Range to scan"]', '8.8.8.0/24');
  page.once('dialog', d => d.accept());
  await page.click('#scanPanel button:has-text("Scan")');
  await page.waitForFunction(
    () => /only private ranges/.test(document.querySelector('#scanPanel')?.textContent || ''),
    null, { timeout: 15000 });
});

// ── PROFINET ────────────────────────────────────────────────────────────────

await test('PROFINET reconciles an imported snapshot against the shared schema', async () => {
  await show('iiot');
  const schemaBox = '#profinetPanel textarea[aria-label="PROFINET station schema JSON"]';
  await page.click('#profinetPanel details.subcard:has-text("Expected stations") > summary');
  await page.fill(schemaBox, JSON.stringify({
    segment: 'cell-3',
    stations: [
      { mac: '00:1b:1b:00:00:01', name: 'drive-a', ip: '192.168.1.11', role: 'drive' },
      { mac: '00:0f:8f:00:00:02', name: 'io-b', ip: '192.168.1.12' },
    ],
  }, null, 2));
  await page.click('#profinetPanel button:has-text("Save shared schema")');
  await page.waitForFunction(
    () => /Shared schema saved/.test(document.querySelector('#profinetPanel')?.textContent || ''),
    null, { timeout: 15000 });

  await page.click('#profinetPanel details.subcard:has-text("Import a DCP") > summary');
  await page.fill('#profinetPanel textarea[aria-label="DCP JSON lines"]', [
    JSON.stringify({ kind: 'dcp-identify', mac: '00:1b:1b:00:00:01', name: 'drive-a',
                     ip: '192.168.1.99' }),
    JSON.stringify({ kind: 'dcp-identify', mac: 'aa:bb:cc:dd:ee:ff', name: 'stranger' }),
  ].join('\n'));
  await page.fill('#profinetPanel input[aria-label="Import actor"]', 'e2e');
  await page.click('#profinetPanel button:has-text("Import snapshot")');
  // Wait for the IMPORT, not just for any row. Saving the schema alone already
  // produces two MISSING rows, so `.dcp-row` is on screen before the import has
  // been sent - waiting on that selector raced the re-render and read the
  // pre-import table.
  await page.waitForFunction(
    () => /Imported 2 station record/.test(
      document.querySelector('#profinetPanel')?.textContent || ''),
    null, { timeout: 20000 });

  const rows = await page.$$eval('#profinetPanel .dcp-row', ns => ns.map(n => ({
    cls: n.className, chip: n.querySelector('.status-chip')?.textContent,
  })));
  assert.deepEqual(rows.map(r => r.chip), ['MISMATCH', 'MISSING', 'UNEXPECTED'],
                   'what needs attention must sort first, got ' + JSON.stringify(rows));
  const summary = await text('#profinetPanel .field-state');
  assert.match(summary, /1 mismatched/);
  assert.match(summary, /1 missing/);
  assert.match(summary, /1 unexpected/);
  const diff = await text('#profinetPanel .dcp-row.mismatch td.diff');
  assert.match(diff, /192\.168\.1\.99/);
  assert.match(diff, /expected 192\.168\.1\.11/);
});

// ── Status ──────────────────────────────────────────────────────────────────

await test('Status carries four tabs and shows exactly one at a time', async () => {
  await show('status');
  const labels = await page.$$eval('[data-tabs="status"] .subtab',
    ns => ns.map(n => n.textContent));
  assert.deepEqual(labels, ['Feed', 'Queue', 'Journal', 'Chatter']);
  for (const panel of ['feed', 'queue', 'journal', 'chatter']) {
    await tab('status', panel);
    const visible = await page.$$eval('#viewStatus .panels > .panel',
      ns => ns.filter(n => !n.hidden).map(n => n.id));
    assert.deepEqual(visible, ['view' + panel[0].toUpperCase() + panel.slice(1)]);
    const selected = await page.getAttribute(
      `[data-tabs="status"] .subtab[data-panel="${panel}"]`, 'aria-selected');
    assert.equal(selected, 'true');
  }
});

await test('the chosen Status tab survives a reload', async () => {
  await tab('status', 'journal');
  await page.reload({ waitUntil: 'load' });
  await page.waitForFunction(() => !!window.CCC);
  await show('status');
  await page.waitForSelector('#viewJournal:not([hidden])');
  assert.equal(await page.getAttribute(
    '[data-tabs="status"] .subtab[data-panel="journal"]', 'aria-selected'), 'true');
});

await test('the journal appends, filters and exports what is on screen', async () => {
  await show('status');
  await tab('status', 'journal');
  for (const subject of ['e2e alpha entry', 'e2e beta entry']) {
    await page.fill('#journalSubject', subject);
    await page.click('#journalAdd');
    await page.waitForFunction(
      (s) => document.querySelector('#journalList')?.textContent.includes(s),
      subject, { timeout: 15000 });
  }
  const before = await page.$$eval('#journalList .jentry', ns => ns.length);
  assert.ok(before >= 2);

  await page.fill('#journalSearch', 'alpha');
  await page.waitForFunction(
    () => document.querySelectorAll('#journalList .jentry').length === 1,
    null, { timeout: 15000 });
  assert.match(await text('#journalStamp'), /^1 of \d+ entr/);

  // Export writes what the filter left, not the whole journal.
  const download = page.waitForEvent('download', { timeout: 20000 });
  await page.click('#statusExport');
  const file = await download;
  const stream = await file.createReadStream();
  let body = '';
  for await (const chunk of stream) body += chunk;
  const exported = JSON.parse(body);
  assert.equal(exported.tab, 'journal');
  assert.equal(exported.rows.length, 1, 'export must follow the filter');
  assert.match(exported.rows[0].subject, /alpha/);
  await page.fill('#journalSearch', '');
});

await test('the export button names the active tab, not the last one to load', async () => {
  await tab('status', 'feed');
  const feedLabel = await text('#statusExport');
  await tab('status', 'journal');
  const journalLabel = await text('#statusExport');
  assert.match(feedLabel, /^export/);
  assert.match(journalLabel, /^export/);
  const journalRows = await page.$$eval('#journalList .jentry', ns => ns.length);
  assert.equal(journalLabel.trim(), `export ${journalRows}`);
});

// ── Board ───────────────────────────────────────────────────────────────────

await test('Board carries Tasks, Atlassian and Kanban, with all six drop columns',
  async () => {
    await show('board');
    assert.deepEqual(
      await page.$$eval('[data-tabs="board"] .subtab', ns => ns.map(n => n.textContent)),
      ['Tasks', 'Atlassian', 'Kanban']);
    await tab('board', 'kanban');
    await page.waitForSelector('#viewKanban .kanban-column');
    assert.deepEqual(await page.$$eval('#viewKanban .kanban-column', ns => ns.map(n => n.dataset.status)),
      ['backlog', 'open', 'in_progress', 'blocked', 'parked', 'done']);
    // Chrome is zoomed by --ui-scale; compare layout and viewport sizes in their own units.
    const columnHeights = await page.$$eval('#viewKanban .kanban-column', ns => ns.map(n => ({
      height: n.getBoundingClientRect().height, layoutHeight: n.offsetHeight,
      minHeight: getComputedStyle(n).minHeight,
      scale: Number(getComputedStyle(document.documentElement).getPropertyValue('--ui-scale')),
    })));
    for (const column of columnHeights) {
      assert.equal(column.minHeight, '220px');
      assert.ok(column.layoutHeight >= 220);
      assert.ok(column.scale > 0);
      assert.ok(column.height >= 220 * column.scale - 1, JSON.stringify(column));
    }
    assert.equal(await page.locator('#viewBoardtasks').isVisible(), false);
    assert.equal(await page.locator('#viewTickets').isVisible(), false);
    await tab('board', 'tickets');
    // WAIT for the panel rather than reading it the instant the tab is clicked. The
    // loader is a fetch, so asserting immediately was a race this test happened to
    // win - until anything else on the page competed for a connection, at which
    // point it failed while the panel was working perfectly.
    await page.waitForFunction(
      () => /not configured|issue/i.test(document.querySelector('#viewTickets')?.textContent || ''),
      null, { timeout: 15000 });
    const body = await text('#viewTickets');
    assert.match(body, /not configured|issue/i);
    await tab('board', 'boardtasks');
  });

await test('epics are collapsible cards and the choice survives a reload', async () => {
  await show('board');
  await tab('board', 'boardtasks');
  for (const title of ['E2E alpha epic', 'E2E beta epic']) {
    await page.fill('#epicTitle', title);
    await page.click('#epicAdd');
    await page.waitForFunction(
      (t) => document.querySelector('#boardList')?.textContent.includes(t),
      title, { timeout: 15000 });
  }
  const cards = await page.$$eval('#boardList details.epic', ns => ns.map(n => n.tagName));
  assert.ok(cards.length >= 2);
  assert.ok(cards.every(t => t === 'DETAILS'));
  assert.deepEqual(await page.$$eval('#boardList details.epic', ns => ns.map(n => n.open)),
                   cards.map(() => true), 'a board that opens collapsed hides the work');

  await page.click('#boardCollapse');
  assert.deepEqual(await page.$$eval('#boardList details.epic', ns => ns.map(n => n.open)),
                   cards.map(() => false));
  await page.reload({ waitUntil: 'load' });
  await page.waitForFunction(() => !!window.CCC);
  await show('board');
  await page.waitForSelector('#boardList details.epic');
  assert.deepEqual(await page.$$eval('#boardList details.epic', ns => ns.map(n => n.open)),
                   cards.map(() => false), 'collapse all was not remembered');
  await page.click('#boardExpand');
});

// The board renders ASYNCHRONOUSLY, and nothing about that is visible from outside:
// entering the view kicks off a loadBoard() whose replaceChildren() throws away every
// card. Typing into a card before that fetch lands types into an element which is
// about to be discarded - and the discard is SILENT, because the click that follows
// re-resolves its own selector, finds a fresh "add task" button whose input is empty,
// and submit() returns early without posting anything. The test then waits its full
// timeout for a row nobody ever created.
//
// That is the failure this suite showed in three consecutive gate runs and never
// standalone: the window between fill and click is microseconds on an idle machine
// and wide open when fifty other suites, a dashboard, a stub broker and two agents
// are sharing the box. Waiting for a longer timeout would not have helped - there
// was nothing on the way. Wait for the board to stop being rebuilt instead.
//
// Polled from NODE rather than through page.waitForFunction, because a predicate
// handed to that runs in the page and an async one there returns a promise - which
// is truthy the instant it is created, so the wait can be satisfied by a check that
// has not finished. Sampling from here keeps the sleep on this side of the bridge,
// where it is an ordinary await.
const boardSettled = async () => {
  // Identity, not count: a re-render puts equal-looking cards in place of the old
  // ones, so tag the card seen this time round and look for that same tag next time.
  const sample = () => page.evaluate(() => {
    const first = document.querySelector('#boardList details.epic');
    if (!first) return null;
    if (!first.dataset.settle) first.dataset.settle = String(Math.random());
    return first.dataset.settle;
  });
  const deadline = Date.now() + 30000;
  let last = null;
  while (Date.now() < deadline) {
    const seen = await sample();
    if (seen && seen === last) return;
    last = seen;
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('#boardList never stopped being rebuilt');
};

await test('dragging a task onto another epic refiles it for real', async () => {
  await show('board');
  await boardSettled();
  const epics = await page.$$eval('#boardList details.epic', ns => ns.map(n => n.dataset.epic));
  const [from, to] = epics.filter(Boolean);
  assert.ok(from && to, 'need two epics with keys');
  // Both open before touching them. A collapsed epic renders no .task-row and has no
  // bounding box to drop onto, so this waited 30s for something that could not appear.
  // Which epics are open is remembered in localStorage and driven by the collapse-all
  // test above - a sibling's UI state, which no test should depend on.
  await page.$$eval('#boardList details.epic', ns => ns.forEach(n => { n.open = true; }));
  const newTask = `#boardList details.epic[data-epic="${from}"] input[placeholder="new task"]`;
  await page.fill(newTask, 'E2E draggable task');
  // A tripwire for the race above: if the board does rebuild between the fill and the
  // click, say so here rather than letting it become an unexplained wait below.
  assert.equal(await page.$eval(newTask, (n) => n.value), 'E2E draggable task',
               'the new-task input was re-rendered away between typing and clicking');
  await page.click(`#boardList details.epic[data-epic="${from}"] button:has-text("add task")`);
  // 45s, not the 30s default: generous enough that if this still fires, "the box was
  // busy" is off the table and the message below is the diagnosis.
  await page.waitForSelector(`#boardList details.epic[data-epic="${from}"] .task-row`,
                             { timeout: 45000 })
    .catch(async () => {
      // Say what was ON SCREEN. A bare selector timeout reports the timeout and not
      // one thing about the page it gave up on, which is how this cost three runs.
      const stamp = await text('#boardStamp').catch(() => '(unreadable)');
      const open = await page
        .$eval(`#boardList details.epic[data-epic="${from}"]`, (n) => n.open)
        .catch(() => '(gone)');
      throw new Error(`no task row appeared in ${from}: open=${open}, board says "${stamp}"`);
    });

  const row = await page.$(`#boardList details.epic[data-epic="${from}"] .task-row`);
  const key = await row.evaluate(n => n.dataset.task);
  const target = await page.$(`#boardList details.epic[data-epic="${to}"]`);

  // Firefox needs the drag to be a real sequence of moves, not a single jump.
  const a = await row.boundingBox();
  const b = await target.boundingBox();
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
  await page.mouse.down();
  await page.mouse.move(b.x + b.width / 2, b.y + 20, { steps: 24 });
  await page.mouse.move(b.x + b.width / 2, b.y + 24, { steps: 6 });
  await page.mouse.up();

  await page.waitForFunction(
    (args) => {
      const moved = document.querySelector(
        `#boardList details.epic[data-epic="${args.to}"] .task-row[data-task="${args.key}"]`);
      return !!moved;
    }, { to, key }, { timeout: 30000 }).catch(() => {});

  // The drop is only real if the STORE moved it, so ask the API, not the DOM.
  const server = await page.evaluate(async () => {
    const r = await fetch('api/board/board', { cache: 'no-store' });
    return r.json();
  });
  const task = server.tasks.find(t => t.key === key);
  assert.ok(task, `task ${key} vanished`);
  assert.equal(task.epic, to, `${key} is still filed under ${task.epic}`);
  assert.match(await text('#boardStamp'), new RegExp(`${key} moved to ${to}`));
});

// ── Organization, GitHub, Settings ─────────────────────────────────────────

await test('Organization carries Agents and Teams, and both render', async () => {
  await show('organization');
  assert.deepEqual(
    await page.$$eval('[data-tabs="organization"] .subtab', ns => ns.map(n => n.textContent)),
    ['Agents', 'Teams']);
  await tab('organization', 'agents');
  await page.waitForFunction(
    () => document.getElementById('viewAgents').childElementCount > 0, null, { timeout: 15000 });
  await tab('organization', 'teams');
  await page.waitForFunction(
    () => document.getElementById('viewTeams').childElementCount > 0, null, { timeout: 15000 });
});

if (process.env.AGENTMUX_E2E_PROFILES === '1') {
await test('Profiles explicit owner adoption stays separate from the browser preview', async () => {
  const project = fs.realpathSync(process.env.AGENTMUX_E2E_PROJECT_ROOT);
  const python = process.env.AGENTMUX_E2E_PYTHON;
  assert.ok(python && python.startsWith('/'), 'prepared Python path is required');
  const sourceDirectory = new URL('../.agentmux/agents/', import.meta.url);
  const names = fs.readdirSync(sourceDirectory).filter(name => name.endsWith('.md')).sort();
  assert.equal(names.length, 14);
  const sourceDigests = () => names.map(name => createHash('sha256').update(fs.readFileSync(new URL(name, sourceDirectory))).digest('hex'));
  const before = sourceDigests();
  await show('organization');
  await tab('organization', 'agents');
  const panel = page.locator('#viewAgents');
  const preview = panel.locator('.agents-profile-preview');
  await preview.locator('summary').click();
  const catalogue = preview.locator('[aria-label="Bundled profile package preview"]');
  await catalogue.waitFor();
  assert.equal(await catalogue.locator('.agents-definition').count(), 14);
  assert.match(await catalogue.textContent(), /explicit local-owner command/);
  assert.match(await catalogue.textContent(), /Requested permissions do not establish grants/);
  assert.match(await catalogue.textContent(), /machine-specific path references/);
  assert.equal(await catalogue.locator('form,button,input').count(), 0);
  const metadata = await page.evaluate(async () => (await fetch('api/board/profiles')).json());
  assert.equal(metadata.projectRoot, project);
  const refused = await page.evaluate(async () => (await fetch('api/board/profiles', {method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify({actor: 'dashboard', approved: true})})).status);
  assert.equal(refused, 405);
  const initial = await page.evaluate(async () => (await fetch('api/board/agents')).json());
  assert.equal(initial.agents.some(row => ['scan-dev', 'agora-lead'].includes(row.name)), false);
  const privateDirectory = project + '/profile-command-private';
  fs.mkdirSync(privateDirectory, {mode: 0o700});
  const client = privateDirectory + '/selected-client';
  const request = privateDirectory + '/request.json';
  fs.writeFileSync(client, 'metadata-only executable fixture; never executed\n', {mode: 0o700});
  const selected = metadata.profiles.find(row => row.name === 'scan-dev');
  fs.writeFileSync(request, JSON.stringify({schemaVersion: '1.0.0', clients: {codex: client}, selections: [{
    packageId: selected.packageId, name: selected.name, sourceChecksum: selected.sourceChecksum,
    relationship: 'independent', parentPackage: null,
    overrides: {paths: {}, execution: {posture: 'read-only', worktree: 'none', maxInstances: 1}}
  }]}), {mode: 0o600});
  const command = (verb, extra = []) => {
    const result = spawnSync(python, [new URL('../taskmgmt/profilecli.py', import.meta.url).pathname,
      verb, '--project', project, '--request', request, ...extra], {encoding: 'utf8', timeout: 8000});
    // spawnSync retains and waits for this original command, including its output.
    assert.equal(result.error, undefined, 'local-owner command could not be joined');
    assert.equal(result.status, 0, 'local-owner command failed; private output withheld');
    return JSON.parse(result.stdout);
  };
  const observed = command('preview');
  assert.equal(fs.existsSync(project + '/.agentmux/profile-adoptions/record.json'), false);
  const saved = command('adopt', ['--approval-checksum', observed.approvalChecksum,
    '--record-checksum', observed.recordChecksum]);
  assert.equal(saved.profileCount, 1);
  const record = project + '/.agentmux/profile-adoptions/record.json';
  assert.equal(fs.statSync(record).mode & 0o777, 0o600);
  await panel.locator('.agents-header button').click();
  const adopted = panel.locator('.agents-list > .agents-definition').filter({has: page.locator('h4', {hasText: /^scan-dev$/})});
  await adopted.waitFor();
  assert.match(await adopted.textContent(), /Adopted profile package: example.survey/);
  assert.match(await adopted.textContent(), /Local owner adoption does not grant team approval/);
  assert.equal(await adopted.locator('form,button,details').count(), 0);
  assert.deepEqual(sourceDigests(), before);
  assert.equal(consoleErrors.filter(line => line.startsWith('pageerror:')).length, 0,
    'profile preview raised a browser exception');
});
}

// Explicit private roots are required because this scenario writes real definitions.
if (process.env.AGENTMUX_E2E_DEFINITIONS === '1') {
await test('Agents scoped editor preserves edits, conflicts, cancellation and permissions', async () => {
  const project = fs.realpathSync(process.env.AGENTMUX_E2E_PROJECT_ROOT);
  const globalRoot = fs.realpathSync(process.env.AGENTMUX_E2E_GLOBAL_ROOT);
  await show('organization');
  await tab('organization', 'agents');
  const panel = page.locator('#viewAgents');
  const post = body => page.evaluate(async body => {
    const response = await fetch('api/board/agentdef', {method: 'POST',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    return {status: response.status, data: await response.json()};
  }, body);
  for (const scope of ['repo', 'global']) {
    const name = 'browser-' + scope;
    const create = panel.locator(':scope > details.agents-editor');
    await create.locator('summary').click();
    await create.locator('[name=name]').fill(name);
    await create.locator('[name=scope]').selectOption(scope);
    await create.locator('[name=description]').fill('Browser definition');
    await create.locator('[name=persona]').fill('Private persona\nSecond line');
    await create.locator('[name=tools]').fill('Read, Grep');
    await create.locator('[name=tools_deny]').fill('Write');
    await create.locator('button[type=submit]').click();
    const card = panel.locator('.agents-definition').filter({has: page.locator('h4', {hasText: name})});
    await card.waitFor();
    const detail = await page.evaluate(async name =>
      (await fetch('api/board/agents?name=' + name)).json(), name);
    const expected = scope === 'repo' ? project + '/.agentmux/agents/' + name + '.md'
      : globalRoot + '/agents/' + name + '.md';
    assert.equal(detail.path, expected);
    assert.equal(fs.statSync(expected).mode & 0o777, 0o600);
    assert.match(await card.textContent(), /Requested tools are advisory/);
    await card.locator('summary').click();
    await card.locator('[name=persona]').fill('Saved browser edit');
    await Promise.all([page.waitForResponse(r => r.url().endsWith('/api/board/agents')),
      card.locator('button[type=submit]').click()]);
    await page.waitForFunction(() => !document.querySelector('.agents-header button').disabled);
    await card.locator('summary').click();
    await card.locator('[name=persona]').waitFor();
    assert.equal(await card.locator('[name=persona]').inputValue(), 'Saved browser edit');
    const current = await page.evaluate(async name =>
      (await fetch('api/board/agents?name=' + name)).json(), name);
    const updated = await post({...current, persona: 'Concurrent edit', actor: 'legacy-test'});
    assert.equal(updated.status, 200);
    await card.locator('[name=persona]').fill('Stale edit');
    await card.locator('button[type=submit]').click();
    await card.locator('.agents-editor .stamp').filter({hasText: 'reload before saving'}).waitFor();
    assert.match(fs.readFileSync(expected, 'utf8'), /Concurrent edit/);
    assert.doesNotMatch(fs.readFileSync(expected, 'utf8'), /Stale edit/);
    await Promise.all([page.waitForResponse(r => r.url().endsWith('/api/board/agents')),
      panel.locator('.agents-header button').click()]);
    await page.waitForFunction(() => !document.querySelector('.agents-header button').disabled);
    const remove = card.locator('button.del');
    page.once('dialog', dialog => dialog.dismiss());
    await remove.click();
    assert.ok(fs.existsSync(expected));
    page.once('dialog', dialog => dialog.accept());
    await remove.click();
    await card.waitFor({state: 'detached'});
    assert.equal(fs.existsSync(expected), false);
  }
});
}

if (process.env.AGENTMUX_E2E_DEFINITIONS === '1') {
await test('Teams scoped proposal uses a deliberate lead and preserves approved revisions', async () => {
  const post = (op, body) => page.evaluate(async ([op, body]) => {
    const response = await fetch('api/board/' + op, {method: 'POST',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    return {status: response.status, data: await response.json()};
  }, [op, body]);
  for (const name of ['a-first-lead', 'z-chosen-lead']) {
    const result = await post('agentdef', {name, scope: 'repo', role: 'lead',
      description: 'Browser lead', cli: 'codex', persona: 'Approved private persona'});
    assert.equal(result.status, 200, 'lead definition create status ' + result.status);
  }
  const epic = await post('create', {kind: 'epic', title: 'Browser team epic', actor: 'legacy-browser'});
  assert.equal(epic.status, 200, 'epic create status ' + epic.status);
  const task = await post('create', {kind: 'task', title: 'Browser scoped team', epic: epic.data.id,
    body: 'Exercise a deliberately selected lead and saved approval revision.',
    acceptance: ['The approved definition remains fixed after editing its source.'],
    actor: 'legacy-browser'});
  assert.equal(task.status, 200, 'task create status ' + task.status);
  const key = task.data.id;
  await show('organization');
  await tab('organization', 'teams');
  const panel = page.locator('#viewTeams');
  const card = panel.locator('.teams-card').filter({has: page.locator('h3', {hasText: key})});
  await card.waitFor();
  await panel.locator('.teams-actor input').fill('legacy-browser');
  const lead = card.locator('select.teams-lead');
  assert.equal(await lead.inputValue(), '');
  await lead.selectOption('z-chosen-lead');
  await Promise.all([page.waitForResponse(r => r.url().includes('/api/board/roster?id=' + key)),
    card.getByRole('button', {name: 'Propose roster', exact: true}).click()]);
  await page.waitForFunction(() => !document.querySelector('.teams-header button').disabled);
  const readRoster = () => page.evaluate(async key =>
    (await fetch('api/board/roster?id=' + key)).json(), key);
  let roster = await readRoster();
  assert.equal(roster.members.find(member => member.role === 'lead').agent_name, 'z-chosen-lead');
  for (const member of roster.members) {
    await card.getByRole('button', {name: 'Approve ' + member.agent_name, exact: true}).click();
  }
  await Promise.all([page.waitForResponse(r => r.url().includes('/api/board/roster?id=' + key)),
    card.getByRole('button', {name: 'Save roster decision', exact: true}).click()]);
  await page.waitForFunction(() => !document.querySelector('.teams-header button').disabled);
  const approved = await readRoster();
  assert.ok(approved.members.every(member => member.status === 'approved'));
  const definition = await page.evaluate(async () =>
    (await fetch('api/board/agents?name=z-chosen-lead')).json());
  const edited = await post('agentdef', {...definition, persona: 'New unapproved persona'});
  assert.equal(edited.status, 200);
  await Promise.all([page.waitForResponse(r => r.url().includes('/api/board/roster?id=' + key)),
    panel.locator('.teams-header button').click()]);
  await card.locator('.teams-revision').filter({hasText: 'Definition changed'}).waitFor();
  roster = await readRoster();
  const before = approved.members.find(member => member.role === 'lead');
  const after = roster.members.find(member => member.role === 'lead');
  assert.equal(after.definitionState, 'changed');
  for (const field of ['id', 'approved_by', 'approved_at', 'definitionRevision']) {
    assert.deepEqual(after[field], before[field]);
  }
  assert.equal(after.status, 'approved');
  assert.doesNotMatch(JSON.stringify(roster), /private persona|unapproved persona/);
});
}

await test('the GitHub panel shows an account card and never renders a token', async () => {
  await show('github');
  await page.waitForSelector('#viewGithub .gh-account', { timeout: 20000 });
  const body = await text('#viewGithub');
  assert.match(body, /Signed in as|Not signed in|gh is not installed/);
  assert.doesNotMatch(body, /gh[pousr]_[A-Za-z0-9]{10}/, 'a token-shaped string is on screen');
  assert.doesNotMatch(body, /github_pat_/);
  // The write forms are present, and both are disclosures rather than loose buttons.
  const summaries = await page.$$eval('#viewGithub .gh-writes > details > summary',
    ns => ns.map(n => n.textContent));
  assert.deepEqual(summaries, ['Create a repository', 'Open an issue']);
});

await test('Settings carries the Atlassian card and the theme importer', async () => {
  await show('settings');
  const keys = await page.$$eval('#viewSettings details.card',
    ns => ns.map(n => n.dataset.collapseKey));
  // Orchestration is INSERTED between auth and resources, never reordered - the order
  // is asserted here precisely so a card cannot quietly move. It sits beside Auth
  // because both answer "what is this machine permitted to do".
  assert.deepEqual(keys, ['settings:feed', 'settings:appearance', 'settings:atlassian',
                          'settings:auth', 'settings:orchestration',
                          'settings:resources']);
  await page.waitForFunction(
    () => document.getElementById('atlState')?.childElementCount > 0, null, { timeout: 20000 });
  assert.ok(await page.$('#jiraBase'), 'the Jira site field moved here from the ribbon');
});

await test('nothing that was removed is reachable any more', async () => {
  const body = await page.content();
  for (const gone of ['data-view="tickets"', 'data-view="queue"', 'data-view="feed"',
                      'data-view="journal"', 'data-view="agents"', 'data-view="teams"',
                      'data-view="chatter"', 'data-view="codesys"', 'bootpNotice',
                      'devList', 'mqLog']) {
    assert.ok(!body.includes(gone), `${gone} is still in the page`);
  }
});

// ── a panel whose script never arrives says so ──────────────────────────────

await test('with everything loaded, no banner is shown', async () => {
  assert.equal(await page.$eval('#banner', n => n.hidden), true,
               'a banner is showing when nothing is wrong: ' + await text('#banner'));
});

await test('a view script that fails to load is named, and the notice sticks', async () => {
  // Exactly what an operator hits when the dashboard's Python process is older
  // than the files on disk: server.py serves static files from an allowlist, so a
  // file it does not know about comes back as a JSON 404 and the browser refuses
  // to execute it under nosniff. The panel is then blank with no explanation.
  const broken = await context.newPage();
  const seen = [];
  broken.on('console', (m) => { if (m.type() === 'error') seen.push(m.text()); });
  for (const name of ['mqtt.js', 'netscan.js']) {
    await broken.route('**/' + name, (route) => route.fulfill({
      status: 404, contentType: 'application/json', body: '{"error": "not found"}' }));
  }
  await broken.goto(baseURL, { waitUntil: 'load' });
  await broken.waitForFunction(() => !!window.CCC, null, { timeout: 15000 });
  await broken.waitForFunction(
    () => { const b = document.getElementById('banner'); return b && !b.hidden; },
    null, { timeout: 15000 });

  const message = await broken.textContent('#banner');
  assert.match(message, /mqtt\.js/);
  assert.match(message, /netscan\.js/);
  assert.match(message, /restart/i, 'the notice must say what to do, not just what broke');

  // And it must SURVIVE the backend poll, which owns the other banner and clears
  // it on every success - that is what made this notice vanish half a second
  // after load, leaving a page that looked fine and was not.
  await broken.waitForTimeout(6000);
  assert.equal(await broken.$eval('#banner', n => n.hidden), false,
               'the notice was wiped by a successful backend poll');
  assert.match(await broken.textContent('#banner'), /mqtt\.js/);

  // The two panels really are the empty ones, and the other three still work.
  await broken.click('.nav-item[data-view="iiot"]');
  await broken.waitForTimeout(2500);
  const bodies = await broken.$$eval('#viewIiot .cardbody',
    (ns) => ns.map(n => [n.id, n.childElementCount]));
  const byId = Object.fromEntries(bodies);
  assert.equal(byId.mqttPanel, 0, 'mqtt panel should be the empty one here');
  assert.equal(byId.scanPanel, 0, 'scanner panel should be the empty one here');
  assert.ok(byId.modbusHint > 0, 'modbus should still render');
  assert.ok(byId.profinetPanel > 0, 'profinet should still render');
  assert.ok(seen.some(line => /failed to load/i.test(line)),
            'nothing was written to the console either');
  await broken.close();
});

// ── what is running, and getting to its pane ────────────────────────────────
//
// Every view names agents; none of them used to say which of those names is a
// process that exists right now. These check the marking is driven by the LIVE
// roster rather than by the text, because the board is full of historical
// assignees - `claude`, `tm-041` - that must stay inert.

// The roster is STUBBED rather than spawned. This suite runs on a throwaway home
// with no tmux, and what is under test is the frontend's marking logic, not the
// harness's ability to start a process. Stubbing also buys the one case a real
// spawn cannot easily produce: a live agent and a dead one side by side, which is
// the whole point - if everything were marked the mark would mean nothing.
const LIVE = 'e2e-live-agent';
const DEAD = 'e2e-dead-agent';

async function withRoster(target, names) {
  await target.route('**/api/agents', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.agents = names.map((name) => ({
      name, cli: 'shell', state: 'detached', task: 'TM-E2E',
      cwd: '/tmp', perms: 'UNRESTRICTED', started: new Date().toISOString(),
    }));
    body.tmux_server = true;
    // Fulfilled EXPLICITLY, not as `{response, json}`. Passing both was accepted by
    // Playwright 1.62 and silently stopped overriding the body in 1.63, so these four
    // tests passed against the Windows package in the npx cache and timed out against
    // the Linux one - a version difference masquerading as a product bug. The body is
    // being replaced wholesale anyway; the fetched response is only here so the stub
    // keeps the real payload's shape if it gains fields.
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    });
  });
}

await test('a running agent is marked and a finished one is not', async () => {
  // Two tasks on the board, one assigned to each name.
  await show('board');
  await tab('board', 'boardtasks');
  const epic = await page.$eval('#boardList details.epic[data-epic]', (n) => n.dataset.epic);
  // OPEN IT FIRST, and wait inside ITS OWN subtree below.
  //
  // A collapsed epic renders no task rows, so the old whole-board textContent check
  // could never see the name and timed out at 15s with nothing to say. Whether it was
  // open depended on what an earlier test had left in localStorage - the collapse-all
  // test drives exactly that, three tests earlier - which made this pass on one
  // machine and hang on another. A test that reads a sibling's UI state is not
  // testing what it claims to.
  await page.$eval(`#boardList details.epic[data-epic="${epic}"]`, (n) => { n.open = true; });
  for (const who of [LIVE, DEAD]) {
    await page.fill(`#boardList details.epic[data-epic="${epic}"] input[placeholder="new task"]`,
                    `task for ${who}`);
    await page.fill(`#boardList details.epic[data-epic="${epic}"] input[placeholder="agent"]`, who);
    await page.click(`#boardList details.epic[data-epic="${epic}"] button:has-text("add task")`);
    await page.waitForFunction(
      ([key, n]) => {
        const card = document.querySelector(`#boardList details.epic[data-epic="${key}"]`);
        if (card && !card.open) card.open = true;   // a redraw can re-collapse it
        return card?.textContent.includes(n);
      }, [epic, who], { timeout: 25000 });
  }
  await withRoster(page, [LIVE]);
  // Force the poll that owns the roster, then let the board redraw.
  await page.reload({ waitUntil: 'load' });
  await page.waitForFunction(() => !!window.CCC);
  await show('board');
  await page.waitForFunction((n) => {
    const node = [...document.querySelectorAll('[data-agent]')].find(e => e.dataset.agent === n);
    return node && node.classList.contains('is-live');
  }, LIVE, { timeout: 20000 });

  const marked = await page.$$eval('#viewBoard [data-agent]', (ns) => ns.map(n => ({
    name: n.dataset.agent, live: n.classList.contains('is-live') })));
  const live = marked.filter(m => m.live).map(m => m.name);
  const inert = marked.filter(m => !m.live).map(m => m.name);
  assert.ok(live.includes(LIVE), `${LIVE} is running and was not marked`);
  assert.ok(inert.includes(DEAD), `${DEAD} is not running and was marked`);
  assert.deepEqual([...new Set(live)], [LIVE],
    'something other than the running agent was marked live');
});

await test('a live name is a button; a finished one is inert text', async () => {
  const live = await page.$(`#viewBoard [data-agent="${LIVE}"]`);
  assert.equal(await live.getAttribute('role'), 'button');
  assert.equal(await live.getAttribute('tabindex'), '0');
  assert.match(await live.getAttribute('title'), /is running.*click to open its pane/);
  const dead = await page.$(`#viewBoard [data-agent="${DEAD}"]`);
  assert.equal(await dead.getAttribute('role'), null, 'a dead agent must not be a button');
  assert.equal(await dead.getAttribute('title'), null,
               'a dead agent must not claim it can be opened');
});

await test('clicking a live item opens the pane serving it', async () => {
  await page.click(`#viewBoard [data-agent="${LIVE}"]`);
  await page.waitForSelector('#viewTerminals:not([hidden])', { timeout: 15000 });
  await page.waitForFunction(() => document.querySelectorAll('.cell.focused').length === 1,
                             null, { timeout: 15000 });
  const focused = await page.$eval('.cell.focused', (n) => n.textContent.slice(0, 80));
  assert.ok(focused.includes(LIVE), `focused the wrong pane: ${focused}`);
  assert.equal(await page.$eval('#grid', (n) => n.classList.contains('focusing')), true);
});

await test('clicking a finished agent does nothing at all', async () => {
  await show('board');
  await page.waitForTimeout(800);
  await page.click(`#viewBoard [data-agent="${DEAD}"]`);
  await page.waitForTimeout(700);
  const visible = await page.$$eval('.views > .view',
    (ns) => ns.filter(n => !n.hidden).map(n => n.id));
  assert.deepEqual(visible, ['viewBoard'],
    'clicking a dead agent navigated somewhere; it must be inert');
});

await test('an agent name never wraps mid-word', async () => {
  // "demo-beta" broken across two lines is unreadable and ambiguous next to
  // "demo-alpha". The task TITLE is the truncatable thing in that row.
  await show('board');
  await page.waitForTimeout(1200);
  const wrapped = await page.$$eval('[data-agent]',
    (ns) => ns.filter(n => n.getClientRects().length > 1).map(n => n.dataset.agent));
  assert.deepEqual(wrapped, []);
});

await test('every renderer that names an agent tags it', async () => {
  // Source-level, deliberately. Whether a given view has a row on screen depends on
  // what happens to be in the store; whether its RENDERER tags agent names is a
  // property of the code, and a renderer that forgets should fail here rather than
  // be noticed by an operator wondering why chatter never lights up.
  const sources = {
    'app.js (board, queue, journal, feed)': ['t-agent', 'msg-who', 'f-who', 'epic-agent'],
    'chatter.js': ['chat-who'],
    'agents.js': ['agent.name'],
    'teams.js': ['member.agent_name'],
  };
  for (const [file, needles] of Object.entries(sources)) {
    const name = file.split(' ')[0];
    const src = fs.readFileSync('dashboard/' + name, 'utf8');
    assert.match(src, /markAgent\(/, `${name} names agents but never calls markAgent`);
    for (const needle of needles) {
      const at = src.indexOf(needle);
      assert.ok(at > 0, `${name}: expected to find ${needle}`);
    }
  }
});

// ── Runs, and the gate that waits for a person ─────────────────────────────
//
// The harness seeded two runs: e2e001 with every job verified and nothing left but an
// operator's decision, and e2e002 still in flight with a worker that never existed.
// Between them they cover both shapes this view has to draw.

await test('Runs lists what is in flight and says what is blocking each one', async () => {
  await show('runs');
  await page.waitForFunction(
    () => document.querySelectorAll('#viewRuns details.run').length >= 2,
    null, { timeout: 15000 });
  const ids = await page.$$eval('#viewRuns .run-id', ns => ns.map(n => n.textContent));
  assert.ok(ids.includes('e2e001') && ids.includes('e2e002'), `saw ${ids.join(', ')}`);
  // The blocking line is the product here: a job table answers eventually, one
  // sentence answers at a glance.
  const blocking = await page.$$eval('#viewRuns .run-blocking', ns => ns.map(n => n.textContent));
  assert.ok(blocking.some(t => /e2e002\/1 submitted, waiting on e2e-reviewer/.test(t)),
            `no blocking line named the reviewer: ${blocking.join(' | ')}`);
  assert.ok(blocking.every(t => !/e2e001/.test(t)),
            'a fully verified run must not claim to be blocked');
});

await test('an attempt count is always shown against its ceiling', async () => {
  // "tries=2" means nothing without the maximum, and the maximum is MAX_ATTEMPTS in
  // run.py - served in the payload so raising it there cannot leave this reading 2/3.
  await page.waitForFunction(
    () => document.querySelector('#viewRuns table.run-jobs .j-tries'),
    null, { timeout: 15000 });
  const tries = await page.$$eval('#viewRuns .j-tries', ns => ns.map(n => n.textContent));
  assert.ok(tries.length, 'no job rows rendered');
  for (const value of tries) assert.match(value, /^\d+\/\d+$/);
});

await test('worker and reviewer cells are tagged for the live-agent marking', async () => {
  // Open every run card and wait for its job table. A card's open state is remembered
  // in localStorage, so which ones are expanded depends on what ran before - the same
  // cross-test dependency that made the live-agent tests above pass on one machine and
  // hang on another. Assert against all of them, not whichever happened to be open.
  await page.$$eval('#viewRuns details.run', ns => ns.forEach(n => { n.open = true; }));
  await page.waitForFunction(
    () => document.querySelectorAll('#viewRuns table.run-jobs tr.job').length >= 3,
    null, { timeout: 25000 });
  const tagged = await page.$$eval('#viewRuns [data-agent]', ns => ns.map(n => n.dataset.agent));
  assert.ok(tagged.includes('e2e-worker') && tagged.includes('e2e-reviewer'),
            `runs tagged ${tagged.join(', ')}`);
  // None of these agents exist, so none may be marked live or made clickable.
  const live = await page.$$eval('#viewRuns [data-agent].is-live', ns => ns.length);
  assert.equal(live, 0, 'a torn-down agent must not be presented as running');
});

await test('a verified run asks the operator to decide, and shows the diff', async () => {
  await page.waitForSelector('#viewRuns .run-review.pending', { timeout: 15000 });
  const ask = await page.$eval('.run-review.pending .run-review-head', n => n.textContent);
  assert.match(ask, /will not complete this run until you do/);
  await page.waitForFunction(
    () => !document.querySelector('.run-diff')?.textContent.startsWith('Loading'),
    null, { timeout: 15000 });
  // This run was seeded with a base commit that does not exist, so the view has to say
  // what it is comparing against rather than quietly showing a different diff.
  const note = await page.$$eval('.run-review.pending .run-diff-rejected',
                                 ns => ns.map(n => n.textContent).join(' '));
  assert.match(note, /predates|against HEAD/i);
  const files = await page.$eval('.run-diff-files', n => n.textContent);
  assert.match(files, /dashboard\/runs\.js/);
});

await test('the rail badge says a run is waiting on you', async () => {
  await page.waitForFunction(() => !document.getElementById('badgeRuns').hidden,
                             null, { timeout: 20000 });
  const badge = await page.$eval('#badgeRuns',
    n => ({ text: n.textContent, title: n.title }));
  assert.equal(badge.text, '1');
  assert.match(badge.title, /e2e001: review/);
});

await test('a rejection with no reason is refused before it is sent', async () => {
  // A "request changes" carrying no reason gives the orchestrator nothing to act on,
  // so it never leaves the page.
  let posts = 0;
  await page.route('**/api/runs/*/review', async (route) => { posts += 1; await route.continue(); });
  try {
    await page.click('.run-review.pending .run-acts button:not(.primary)');
    await page.waitForSelector('.runs-notice', { timeout: 10000 });
    assert.equal(posts, 0, 'an empty rejection was sent to the server');
    assert.match(await page.$eval('.runs-notice', n => n.textContent), /Say what needs changing/);
  } finally {
    await page.unroute('**/api/runs/*/review');
  }
});

await test('a half-typed note survives the poll that redraws the view', async () => {
  // THE BUG THIS EXISTS FOR. This view polls every five seconds and draws itself with
  // replaceChildren; rebuilding regardless detached the button you were reaching for
  // and emptied the box you were typing in. You cannot use a review form that
  // reconstructs itself under your hands twice a minute.
  const note = await page.$('.run-review.pending .run-note');
  await note.fill('halfway through a thought');
  await page.waitForTimeout(7000);            // longer than the 5s poll
  assert.equal(await page.$eval('.run-review.pending .run-note', n => n.value),
               'halfway through a thought');
});

await test('approving records the decision and the run stops asking', async () => {
  page.once('dialog', (d) => d.accept());
  await page.click('.run-review.pending .run-acts button.primary');
  await page.waitForSelector('#viewRuns .run-review.approved', { timeout: 15000 });
  const head = await page.$eval('.run-review.approved .run-review-head', n => n.textContent);
  assert.match(head, /Approved by .* the orchestrator may complete this run/);
  // And the badge clears, because nothing is waiting on the operator any more.
  await page.waitForFunction(() => document.getElementById('badgeRuns').hidden,
                             null, { timeout: 20000 });
});

await test('the server refuses to approve a run whose jobs are unverified', async () => {
  // The gate is the server's, not the button's - the page merely declines to offer a
  // control. Prove the refusal survives someone calling the endpoint directly.
  const out = await page.evaluate(async () => {
    const r = await fetch('api/runs/e2e002/review', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision: 'approved' }),
    });
    return { status: r.status, body: await r.text() };
  });
  assert.equal(out.status, 409);
  assert.match(out.body, /not verified yet/);
});

await test('runs are read-only over HTTP apart from that one decision', async () => {
  for (const [path, method] of [['api/runs', 'POST'], ['api/runs/e2e001', 'POST'],
                                ['api/runs/e2e001/diff', 'POST']]) {
    const status = await page.evaluate(async ([p, m]) => {
      const r = await fetch(p, { method: m, headers: { 'Content-Type': 'application/json' },
                                 body: '{}' });
      return r.status;
    }, [path, method]);
    assert.equal(status, 405, `${method} ${path} should be 405, got ${status}`);
  }
});

// ── and the console stayed quiet ───────────────────────────────────────────

await test('the page logged no errors while all of that happened', () => {
  // Failed fetches from panels pointed at absent equipment are the page working,
  // not the page breaking; a thrown exception is not.
  // "can't establish a connection to the server" is how FIREFOX reports a failed
  // EventSource - the terminal stream with no agents behind it. Chromium says
  // "Failed to load resource", which was already exempt. Same event, same
  // non-failure, different browser wording; the filter only knew one of them.
  const real = consoleErrors.filter(line =>
    !/Failed to load resource|NetworkError|ERR_CONNECTION|favicon/i.test(line)
    && !/can.t establish a connection to the server/i.test(line));
  // Printed as well as asserted: deepEqual against [] truncates the actual array in
  // the harness output, so a failure here used to say only that something was logged
  // and never what - which is the least useful shape a console-error test can take.
  if (real.length) {
    console.log('      console errors the page logged:');
    for (const line of real.slice(0, 8)) console.log('        ' + line.slice(0, 160));
  }
  assert.deepEqual(real, []);
});

if (testFilter && passed + failed === 0) throw new Error('test filter matched no checks');
console.log(`\npassed ${passed}, failed ${failed}`);
if (failures.length) console.log('failed: ' + failures.join('; '));
process.exitCode = failed ? 1 : 0;
} finally {
  await browser.close();
}
