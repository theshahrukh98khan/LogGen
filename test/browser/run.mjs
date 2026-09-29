/**
 * Browser tests for the LogGen console.
 *
 * These cover what unit tests cannot: that the console actually renders the
 * catalogue, that filtering and search reach the right records, that the
 * destination state is reported honestly, and that sending a record puts it on
 * screen. They drive a real browser against a real server.
 *
 *   node run.mjs                         # against http://127.0.0.1:8088
 *   BASE=http://host:9000 node run.mjs   # somewhere else
 *
 * The server must already be running, with a reachable destination configured.
 * See the README in this directory.
 */
import { chromium } from 'playwright';

const BASE = process.env.BASE || 'http://127.0.0.1:8088';

const pass = [], fail = [];
const ck = (name, ok, detail = '') => {
  (ok ? pass : fail).push(name);
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `  -> ${detail}` : ''}`);
};
const section = (t) => console.log(`\n=== ${t} ===`);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1500, height: 950 } });

const errors = [], failedRequests = [];
page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
page.on('requestfailed', (r) => failedRequests.push(`${r.method()} ${r.url()}`));

await page.goto(BASE, { waitUntil: 'networkidle' });
await page.waitForSelector('.card', { timeout: 15000 });
await page.waitForTimeout(1500);

// ---------------------------------------------------------------------------
section('Catalogue renders');

const apiCount = await page.evaluate(async () =>
  (await (await fetch('/api/controls')).json()).length);
ck('every control has a card', (await page.locator('.card').count()) === apiCount, apiCount);
ck('sources are listed', (await page.locator('#sourceTabs .tab').count()) >= 2);
ck('groups are listed', (await page.locator('#groupTabs .tab').count()) >= 2);
ck('cards lead with an identifier',
  (await page.locator('.card .card-id').first().textContent()).trim().length > 0);

// ---------------------------------------------------------------------------
section('Layout fills the screen');

ck('the page itself does not scroll',
  await page.evaluate(() => document.documentElement.scrollHeight <= window.innerHeight + 1));
ck('columns fill the viewport', await page.evaluate(() => {
  const m = document.querySelector('main').getBoundingClientRect();
  const a = document.querySelector('.activity').getBoundingClientRect();
  return Math.abs(m.height - a.height) < 2;
}));
ck('the grid scrolls inside its column', await page.evaluate(() => {
  const g = document.querySelector('.grid');
  return g.scrollHeight > g.clientHeight;
}));
ck('a favicon is declared',
  await page.evaluate(() => !!document.querySelector('link[rel=icon]')));
ck('the favicon is served', (await (await page.request.get(BASE + '/favicon.svg')).status()) === 200);
// Every scroller should look the same, which means none of them falls back to
// the browser default.
ck('scrollbars are styled consistently', await page.evaluate(() => {
  const s = getComputedStyle(document.documentElement);
  return s.scrollbarWidth === 'thin' || s.scrollbarColor !== 'auto';
}));

// ---------------------------------------------------------------------------
section('Navigation');

ck('two sections', (await page.locator('#mainNav .nav-item').count()) === 2);
await page.click('[data-view=admin]');
await page.waitForTimeout(350);
ck('Administration opens on the hub', await page.locator('#adminHub').isVisible());
ck('no panel is open on arrival',
  !(await page.locator('#adminProfiles').isVisible()) &&
  !(await page.locator('#adminCustoms').isVisible()) &&
  !(await page.locator('#adminEstate').isVisible()));
ck('back is hidden on the hub', !(await page.locator('#adminBack').isVisible()));

// Every tile has a section heading above it and a panel behind it. A tile that
// leads nowhere is the failure this catches.
const groups = await page.locator('.hub-group').count();
ck('the hub is grouped into sections', groups >= 4, `${groups} sections`);
const tiles = await page.locator('#adminHub .tile').all();
ck('every tile carries an icon and a label',
  (await Promise.all(tiles.map(async (t) =>
    (await t.locator('svg').count()) === 1 &&
    (await t.locator('span').textContent()).trim().length > 0))).every(Boolean));

for (const [tile, panel, word] of [
  ['profiles', '#adminProfiles', 'target'],
  ['customs', '#adminCustoms', 'control'],
  ['tokens', '#adminTokens', 'placeholder'],
  ['estate', '#adminEstate', 'estate'],
  ['about', '#adminAbout', 'about'],
]) {
  await page.click(`[data-admin=${tile}]`);
  await page.waitForTimeout(250);
  ck(`the ${tile} tile opens its panel`, await page.locator(panel).isVisible());
  ck(`the heading names ${tile}`,
    (await page.locator('#adminTitle').textContent()).toLowerCase().includes(word),
    await page.locator('#adminTitle').textContent());
  ck(`the hub is put away for ${tile}`, !(await page.locator('#adminHub').isVisible()));
  await page.click('#adminBack');
  await page.waitForTimeout(250);
  ck(`back returns to the hub from ${tile}`, await page.locator('#adminHub').isVisible());
}

// Administration has no global Done. Every card that can be edited saves
// itself, so there is nothing left for one button at the top to mean.
ck('there is no Done button', (await page.locator('#btnCloseAdmin').count()) === 0);

for (const [tile, form, label] of [
  ['profiles', '#profileForm', 'destination'],
  ['customs', '#customForm', 'control'],
  ['estate', '#envForm', 'estate'],
]) {
  await page.click(`[data-admin=${tile}]`);
  await page.waitForTimeout(250);
  const save = page.locator(`${form} button[type=submit]`);
  ck(`the ${tile} card has its own save`, (await save.count()) === 1);
  ck(`the ${tile} save is visible and named`,
    (await save.isVisible()) &&
    (await save.textContent()).toLowerCase().includes(label),
    await save.textContent());
  await page.click('#adminBack');
  await page.waitForTimeout(250);
}

// Escape steps back one level rather than leaving administration entirely.
await page.click('[data-admin=estate]');
await page.waitForTimeout(250);
await page.keyboard.press('Escape');
await page.waitForTimeout(250);
ck('Escape steps back to the hub',
  (await page.locator('#adminHub').isVisible()) && (await page.locator('#adminView').isVisible()));

// The About page reads its facts from the API rather than hard-coding them.
await page.click('[data-admin=about]');
await page.waitForTimeout(250);
const facts = await page.locator('#aboutFacts dt').allTextContents();
ck('About reports the build and the data location',
  facts.some((f) => /version/i.test(f)) && facts.some((f) => /configuration/i.test(f)),
  facts.join(', '));
const controlsFact = await page.locator('#aboutFacts dd').nth(1).textContent();
ck('About counts the catalogue', Number(controlsFact) > 100, controlsFact);
await page.click('#adminBack');
await page.waitForTimeout(250);

// The standalone placeholder reference lists the same tokens as the form.
await page.click('[data-admin=tokens]');
await page.waitForTimeout(250);
const refTokens = await page.locator('#placeholderRef code[data-token]').count();
ck('the placeholder reference is populated', refTokens > 10, `${refTokens} tokens`);
await page.click('#adminBack');
await page.waitForTimeout(250);

// The destination bar switches and tests a destination; editing one is a job
// for Administration, so the bar must not offer a second way in.
await page.click('[data-view=send]');
await page.waitForTimeout(300);
ck('the destination bar has no edit button',
  (await page.locator('#btnEditTarget').count()) === 0);

await page.click('[data-view=send]');
await page.waitForTimeout(350);
ck('Send returns to the workspace', await page.locator('#simView').isVisible());

// ---------------------------------------------------------------------------
section('Home link and unsaved changes');

// The mark is the way back to the workspace from anywhere.
await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('#brandHome');
await page.waitForTimeout(350);
ck('the logo returns to Send', await page.locator('#simView').isVisible());
ck('the logo does not leave a hash behind', !page.url().endsWith('#'),
  page.url());

// An untouched form navigates away without a word.
await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('[data-admin=estate]');
await page.waitForTimeout(300);
await page.click('#adminBack');
await page.waitForTimeout(300);
ck('a clean form leaves without asking',
  (await page.locator('#adminHub').isVisible()) &&
  !(await page.locator('#dialog').isVisible()));

// A touched one does not.
await page.click('[data-admin=estate]');
await page.waitForTimeout(300);
const realDomain = await page.inputValue('#ev_domain');
await page.fill('#ev_domain', 'unsaved-edit.example');
await page.click('#brandHome');
await page.waitForTimeout(300);
ck('leaving a dirty form asks first', await page.locator('#dialog').isVisible());
ck('it is still on the form behind the prompt', await page.locator('#adminEstate').isVisible());

// Keep editing stays put and keeps the edit.
await page.click('#dlg_cancel');
await page.waitForTimeout(300);
ck('keep editing stays on the form',
  (await page.locator('#adminEstate').isVisible()) &&
  !(await page.locator('#dialog').isVisible()));
ck('keep editing does not undo the edit',
  (await page.inputValue('#ev_domain')) === 'unsaved-edit.example');

// Discard drops the edit and leaves.
await page.click('#brandHome');
await page.waitForTimeout(300);
await page.click('#dlg_discard');
await page.waitForTimeout(400);
ck('discard leaves the panel', await page.locator('#simView').isVisible());
await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('[data-admin=estate]');
await page.waitForTimeout(400);
ck('discard did not save the edit',
  (await page.inputValue('#ev_domain')) === realDomain,
  await page.inputValue('#ev_domain'));

// Save writes it, then leaves. Put the real value back afterwards so the rest
// of the suite sees the estate it expects.
await page.fill('#ev_domain', 'guard-test.example');
await page.click('#adminBack');
await page.waitForTimeout(300);
await page.click('#dlg_save');
await page.waitForTimeout(700);
ck('save leaves the panel once it has written',
  (await page.locator('#adminHub').isVisible()) &&
  !(await page.locator('#dialog').isVisible()));
const saved = await (await fetch(`${BASE}/api/state`)).json();
ck('save actually persisted the edit', saved.env.domain === 'guard-test.example',
  saved.env.domain);

await page.click('[data-admin=estate]');
await page.waitForTimeout(300);
await page.fill('#ev_domain', realDomain);
await page.click('#envForm button[type=submit]');
await page.waitForTimeout(500);
ck('the estate is back as it was',
  (await (await fetch(`${BASE}/api/state`)).json()).env.domain === realDomain);
await page.click('#adminBack');
await page.waitForTimeout(300);
await page.click('[data-view=send]');
await page.waitForTimeout(300);

// ---------------------------------------------------------------------------
section('Filtering');

const sources = await page.locator('#sourceTabs .tab span:first-child').allTextContents();
for (const src of sources.slice(1, 4)) {
  const tab = page.locator('#sourceTabs .tab')
    .filter({ has: page.locator(`span:text-is("${src}")`) });
  const expected = parseInt(await tab.locator('.n').textContent(), 10);
  await tab.click();
  await page.waitForTimeout(200);
  ck(`${src} filters the grid`, (await page.locator('.card').count()) === expected, expected);
}
await page.locator('#sourceTabs .tab').first().click();
await page.waitForTimeout(200);
ck('all sources restores the list', (await page.locator('.card').count()) === apiCount);

// ---------------------------------------------------------------------------
section('Search');

// Shorthand an analyst actually types has to work, not just the catalogue's
// own wording.
for (const q of ['4625', 'sqli', 'kerberoast']) {
  await page.fill('#search', q);
  await page.waitForTimeout(300);
  ck(`"${q}" finds something`, (await page.locator('.card').count()) > 0);
}
await page.fill('#search', 'zzzznomatch');
await page.waitForTimeout(300);
ck('no match shows an empty state', await page.locator('#emptyHint').isVisible());
ck('the empty state offers a way out', (await page.locator('#clearFilters').count()) === 1);
await page.click('#clearFilters');
await page.waitForTimeout(300);
ck('clearing filters restores the list', (await page.locator('.card').count()) === apiCount);

// ---------------------------------------------------------------------------
section('Destination state');

const barClass = await page.evaluate(() => document.getElementById('targetBar').className);
ck('a state is reported', /good|unverified|bad|warn/.test(barClass), barClass);
// UDP cannot confirm delivery, and the bar must say so rather than imply it is
// fine.
if (barClass.includes('unverified')) {
  ck('UDP is described honestly',
    (await page.locator('#tbNote').textContent()).toLowerCase().includes('not confirmed'));
}

// ---------------------------------------------------------------------------
section('Sending');

await page.fill('#search', '4625');
await page.waitForTimeout(300);

// The card body is inert: clicking it must neither send nor open anything.
// This is the guard against a stray click reaching a production collector.
const beforeBodyClick = await page.evaluate(async () =>
  (await (await fetch('/api/activity')).json()).length);
await page.locator('.card').first().locator('.card-id').click();
await page.waitForTimeout(1000);
ck('clicking a card does not send it',
  (await page.evaluate(async () =>
    (await (await fetch('/api/activity')).json()).length)) === beforeBodyClick);
ck('clicking a card does not open a panel', !(await page.locator('#drawer').isVisible()));

// Sending takes its own button, revealed on hover.
await page.locator('.card').first().hover();
await page.waitForTimeout(250);
await page.locator('.card').first().locator('.card-send').click();
await page.waitForTimeout(1300);

ck('the readout shows the record',
  (await page.locator('#readoutWire').textContent()).startsWith('<'));
ck('the priority is decoded', /PRI \d+/.test(await page.locator('#readoutMeta').textContent()));
ck('a sent row appears', (await page.locator('.act').count()) > 0);
ck('sent rows do not repeat the bytes', (await page.locator('.act-wire').count()) === 0);
// The activity feed is the only record of what was sent. A second list of the
// same sends used to sit above the grid, which said nothing the feed did not.
ck('there is no duplicate recents strip',
  (await page.locator('#recentWrap').count()) === 0);

// Clicking a row must put that exact record back in the readout. Send a second,
// different record first so there is always something to replay; the check is
// worthless if it can quietly skip itself.
await page.evaluate(async () => {
  await fetch('/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ controlId: 'linux-sudo-success' }),
  });
});
await page.waitForTimeout(3000);

const replay = await page.evaluate(async () => {
  const feed = await (await fetch('/api/activity')).json();
  const shown = document.getElementById('readoutWire').textContent;
  const other = feed.find((e) => e.wire && e.wire !== shown);
  if (!other) return { ok: false, why: 'the feed holds only one distinct record' };
  const row = document.querySelector(`.act[data-seq="${other.seq}"]`);
  if (!row) return { ok: false, why: `row ${other.seq} is not rendered` };
  row.click();
  return { ok: true, want: other.wire };
});
if (!replay.ok) {
  ck('clicking a sent row replays that record', false, replay.why);
} else {
  await page.waitForTimeout(400);
  ck('clicking a sent row replays that record',
    (await page.locator('#readoutWire').textContent()) === replay.want);
}

// ---------------------------------------------------------------------------
section('Keyboard');

await page.keyboard.press('Escape');
await page.click('body');
await page.waitForTimeout(150);
await page.keyboard.press('/');
await page.waitForTimeout(250);
ck('"/" focuses search', await page.evaluate(() => document.activeElement.id === 'search'));
await page.keyboard.type('sudo');
await page.waitForTimeout(400);
await page.keyboard.press('ArrowDown');
await page.waitForTimeout(200);
ck('ArrowDown steps into the grid',
  await page.evaluate(() => document.activeElement.classList.contains('card')));
const beforeKey = await page.locator('.act').count();
await page.keyboard.press('Enter');
await page.waitForTimeout(1300);
ck('Enter sends the focused card', (await page.locator('.act').count()) > beforeKey);
await page.keyboard.press('/');
await page.waitForTimeout(200);
await page.keyboard.press('Escape');
await page.waitForTimeout(250);
ck('Escape clears the search', (await page.inputValue('#search')) === '');

// ---------------------------------------------------------------------------
section('Details drawer');

await page.fill('#search', 'kerberoast');
await page.waitForTimeout(350);
// The actions are revealed on hover, so a resting grid stays quiet and
// neither button can be hit by accident.
ck('card actions are hidden at rest', await page.evaluate(() =>
  parseFloat(getComputedStyle(document.querySelector('.card-actions')).opacity) === 0));
await page.locator('.card').first().hover();
await page.waitForTimeout(300);
ck('card actions appear on hover', await page.evaluate(() =>
  parseFloat(getComputedStyle(document.querySelector('.card-actions')).opacity) === 1));
ck('keyboard focus reveals them too', await page.evaluate(() => {
  document.querySelector('.card').focus();
  return parseFloat(getComputedStyle(document.querySelector('.card-actions')).opacity) === 1;
}));
await page.locator('.card').first().hover();
await page.waitForTimeout(250);
await page.locator('.card').first().locator('.card-open').click();
await page.waitForTimeout(350);
ck('the drawer opens', await page.locator('#drawer').isVisible());
ck('parameters are listed', (await page.locator('#drawerParams input[data-param]').count()) > 0);
await page.click('#drawerPreview');
await page.waitForTimeout(700);
ck('preview renders without sending',
  !(await page.locator('#drawerWire').evaluate((e) => e.classList.contains('hidden'))));
await page.keyboard.press('Escape');
await page.waitForTimeout(250);
ck('Escape closes the drawer', !(await page.locator('#drawer').isVisible()));
await page.fill('#search', '');
await page.waitForTimeout(250);

// ---------------------------------------------------------------------------
section('Library: a control on a new source');

await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('[data-admin=customs]');
await page.waitForTimeout(400);

const stamp = Date.now();
await page.fill('#cc_source', 'browsertest');
await page.fill('#cc_group', 'Firewall');
await page.fill('#cc_name', `Browser test ${stamp}`);
await page.fill('#cc_desc', 'Created by the browser test suite.');
await page.fill('#cc_tag', 'btest');
await page.click('#cc_addParam');
await page.waitForTimeout(150);
await page.fill('.param-row [data-f=key]', 'srcip');
await page.fill('.param-row [data-f=label]', 'Source IP');
await page.fill('.param-row [data-f=default]', '{{external_ip}}');
await page.fill('#cc_template', 'src={{srcip}} dst={{internal_ip}} action=deny id={{int:1-99}}');

await page.click('#cc_preview');
await page.waitForTimeout(800);
const previewWire = await page.locator('#cc_wire').textContent();
ck('preview renders before saving', previewWire.includes('btest'), previewWire.slice(0, 80));
ck('preview expands every token', !previewWire.includes('{{'), previewWire.slice(0, 80));

await page.click('#customForm button[type=submit]');
await page.waitForTimeout(900);
ck('the control is listed',
  (await page.locator('#customList .profile-row').count()) > 0);

await page.click('[data-view=send]');
await page.waitForTimeout(500);
const newSources = await page.locator('#sourceTabs .tab span:first-child').allTextContents();
ck('the new source appears in Send',
  newSources.some((s) => s.toLowerCase() === 'browsertest'), newSources.join(' | '));

// A declared parameter left blank must resolve, not leak braces.
await page.fill('#search', `Browser test ${stamp}`);
await page.waitForTimeout(400);
ck('the custom control is marked', (await page.locator('.card .tag.custom').count()) > 0);
await page.locator('.card').first().hover();
await page.waitForTimeout(250);
await page.locator('.card').first().locator('.card-open').click();
await page.waitForTimeout(300);
await page.click('#drawerPreview');
await page.waitForTimeout(700);
const customWire = await page.locator('#drawerWire').textContent();
ck('a blank parameter resolves via its default',
  /src=\d+\.\d+\.\d+\.\d+/.test(customWire), customWire.slice(0, 110));
await page.keyboard.press('Escape');

// Clean up after ourselves.
await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('[data-admin=customs]');
await page.waitForTimeout(400);
// Deleting asks in the console's own dialog, not the browser's. A native one
// would never open, so a stray page.on('dialog') here would hide a regression
// rather than catch it.
let nativeDialogs = 0;
page.on('dialog', async (d) => { nativeDialogs++; await d.dismiss(); });

await page.locator('#customList .profile-row', { hasText: `Browser test ${stamp}` })
  .locator('[data-act=delete]').click();
await page.waitForTimeout(300);
ck('deleting asks in the console, not the browser',
  (await page.locator('#dialog').isVisible()) && nativeDialogs === 0);
ck('the delete dialog names what goes',
  (await page.locator('#dialogBody').textContent()).includes(`Browser test ${stamp}`));
ck('cancel is focused, so a stray Enter cannot delete',
  await page.locator('#dlg_cancel').evaluate((e) => e === document.activeElement));

// Cancel leaves it alone.
await page.click('#dlg_cancel');
await page.waitForTimeout(600);
ck('cancelling keeps the control', await page.evaluate(async (s) => {
  const list = await (await fetch('/api/customs')).json();
  return list.some((c) => c.name === `Browser test ${s}`);
}, stamp));

await page.locator('#customList .profile-row', { hasText: `Browser test ${stamp}` })
  .locator('[data-act=delete]').click();
await page.waitForTimeout(300);
await page.click('#dlg_delete');
await page.waitForTimeout(900);
ck('the control can be deleted', await page.evaluate(async (s) => {
  const list = await (await fetch('/api/customs')).json();
  return !list.some((c) => c.name === `Browser test ${s}`);
}, stamp));
await page.click('[data-view=send]');
await page.waitForTimeout(300);
await page.fill('#search', '');

// ---------------------------------------------------------------------------
section('Form alignment');

await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('[data-admin=profiles]');
await page.waitForTimeout(400);

// Host carries a hint under its caption and Port does not. They sit next to
// each other, so if a hint moves its own control the two stop lining up.
const box = (sel) => page.locator(sel).evaluate((e) => {
  const r = e.getBoundingClientRect();
  return { top: Math.round(r.top), bottom: Math.round(r.bottom), h: Math.round(r.height) };
});
const host = await box('#pf_host');
const port = await box('#pf_port');
ck('a hint does not push its own control out of line',
  Math.abs(host.bottom - port.bottom) <= 1,
  `host bottom ${host.bottom}, port bottom ${port.bottom}`);
ck('controls in a row are the same height',
  Math.abs(host.h - port.h) <= 1, `${host.h} vs ${port.h}`);

// Captions stay at the top of their cell, so the hint grows downward into the
// gap rather than shifting the row.
const capTops = await page.locator('#profileForm .form-grid > label:not(.check)')
  .evaluateAll((els) => els.slice(0, 5).map((e) => Math.round(e.getBoundingClientRect().top)));
ck('captions in a row start level',
  new Set(capTops).size === 1, capTops.join(', '));

// An input and a select must match, or every row with both looks staggered.
const sel = await box('#pf_protocol');
ck('inputs and selects are the same height',
  Math.abs(sel.h - port.h) <= 1, `select ${sel.h}, input ${port.h}`);
ck('inputs and selects sit on the same line',
  Math.abs(sel.bottom - port.bottom) <= 1);

// The same rule has to hold on the control form, which has more hinted fields.
await page.click('#adminBack');
await page.waitForTimeout(250);
await page.click('[data-admin=customs]');
await page.waitForTimeout(400);
const ev = await box('#cc_eventid');
const ch = await box('#cc_channel');
const mi = await box('#cc_mitre');
ck('hinted fields line up with each other',
  Math.abs(ev.bottom - ch.bottom) <= 1 && Math.abs(ev.bottom - mi.bottom) <= 1,
  `${ev.bottom}, ${ch.bottom}, ${mi.bottom}`);

await page.click('#adminBack');
await page.waitForTimeout(250);
await page.click('[data-view=send]');
await page.waitForTimeout(300);

// ---------------------------------------------------------------------------
section('Accessibility');

ck('cards are keyboard reachable',
  await page.evaluate(() => document.querySelector('.card').tabIndex >= 0));
// :focus-visible only matches once the browser believes it is being driven by
// a keyboard, so this presses a key first. Without it the check passes or fails
// on whatever the previous section happened to do last, which is not a property
// of the stylesheet at all.
await page.keyboard.press('Tab');
await page.waitForTimeout(100);
ck('focus is visible', await page.evaluate(() => {
  const c = document.querySelector('.card');
  c.focus();
  const s = getComputedStyle(c);
  return s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0;
}));
ck('the destination select is labelled',
  await page.evaluate(() => !!document.getElementById('profileSelect').getAttribute('aria-label')));
ck('external links carry noopener', await page.evaluate(() =>
  [...document.querySelectorAll('a[target=_blank]')].every((a) => /noopener/.test(a.rel))));

// ---------------------------------------------------------------------------
section('Responsive');

for (const [w, h, name] of [[390, 844, 'phone'], [820, 1180, 'tablet'], [1100, 800, 'laptop']]) {
  await page.setViewportSize({ width: w, height: h });
  await page.waitForTimeout(450);
  ck(`no horizontal overflow on ${name}`, await page.evaluate(() =>
    document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1));
  ck(`cards render on ${name}`, (await page.locator('.card').count()) > 0);
}
await page.setViewportSize({ width: 1500, height: 950 });
await page.waitForTimeout(300);

// ---------------------------------------------------------------------------
section('Safety');

// A record field carrying markup must never become live DOM.
await page.evaluate(async () => {
  await fetch('/api/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      controlId: 'linux-sshd-failed-password',
      params: { user: '<img src=x onerror=window.__xss=1>' },
    }),
  });
});
await page.waitForTimeout(2800);
ck('injected markup does not execute', await page.evaluate(() => window.__xss !== 1));
ck('injected markup is not parsed',
  (await page.locator('.activity img, #readout img').count()) === 0);

// ---------------------------------------------------------------------------
section('Runtime');

ck('no page or console errors', errors.length === 0, errors.slice(0, 3).join(' | '));
ck('no failed requests', failedRequests.length === 0, failedRequests.slice(0, 3).join(' | '));

await browser.close();

console.log(`\n${'='.repeat(58)}`);
console.log(`PASS ${pass.length}   FAIL ${fail.length}`);
if (fail.length) {
  console.log('\nFAILURES:');
  fail.forEach((f) => console.log(`  - ${f}`));
}
console.log('='.repeat(58));
process.exit(fail.length ? 1 : 0);
