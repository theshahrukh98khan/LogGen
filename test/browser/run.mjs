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
page.on('console', (m) => {
  if (m.type() !== 'error') return;
  // "Failed to load resource" is the browser noting a non-2xx response. This
  // suite drives a great many on purpose, checking that the API refuses an
  // unauthenticated caller, a wrong password, a short one, a forged reset
  // link. Each is asserted directly where it happens, so counting them here
  // as well only makes this check fail for doing its job. These events also
  // arrive well after the call that caused them, which defeats any attempt to
  // filter them by when they happened. Real breakage still lands: a thrown
  // exception arrives as pageerror, a request that never completes as
  // requestfailed, and anything else the console logs is still counted.
  if (/Failed to load resource/.test(m.text())) return;
  errors.push(`console: ${m.text()}`);
});
page.on('requestfailed', (r) => failedRequests.push(`${r.method()} ${r.url()}`));

// The console requires a session now, so the suite signs in before anything
// else.
//
// A fresh install is admin/admin, but the shipped password is five characters
// and the policy floor is eight, so it cannot be restored once changed. Rather
// than fight that, the suite moves a fresh install onto a known test password
// on its first run and uses that from then on, which leaves it re-runnable
// against the same data directory.
const USER = process.env.LOGGEN_USER || 'admin';
const PASSWORD = process.env.LOGGEN_PASSWORD || 'loggen-browser-tests';

await page.goto(BASE, { waitUntil: 'networkidle' });
await page.waitForTimeout(600);

// ---------------------------------------------------------------------------
section('Authentication');

ck('the console is behind a sign-in', await page.locator('#authView').isVisible());
ck('the workspace is not rendered to a stranger',
  !(await page.locator('#simView').isVisible()));

// Nothing that names the SIEM or puts records on the wire may answer without
// a session. This is the check that matters most in this whole file.
const unguarded = await page.evaluate(async () => {
  const probes = [
    ['GET', '/api/state'], ['GET', '/api/profiles'], ['GET', '/api/controls'],
    ['GET', '/api/customs'], ['GET', '/api/activity'], ['GET', '/api/placeholders'],
    ['PUT', '/api/env'], ['POST', '/api/send'], ['POST', '/api/preview'],
    ['POST', '/api/profiles'], ['POST', '/api/auth/change'],
  ];
  const open = [];
  for (const [method, path] of probes) {
    const r = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: method === 'GET' ? undefined : '{}',
    });
    if (r.status !== 401) open.push(`${method} ${path} -> ${r.status}`);
  }
  return open;
});
ck('every API refuses an unauthenticated caller', unguarded.length === 0, unguarded.join(', '));

// A wrong password must not say which half was wrong, or the endpoint becomes
// a way to discover the username.
const wrongUser = await page.evaluate(async () => {
  const r = await fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'nobody-by-that-name', password: 'whatever' }),
  });
  return (await r.json()).error;
});
const wrongPass = await page.evaluate(async (u) => {
  const r = await fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: u, password: 'definitely-not-it' }),
  });
  return (await r.json()).error;
}, USER);
ck('a bad username and a bad password read the same', wrongUser === wrongPass,
  `${wrongUser} vs ${wrongPass}`);

// Move a fresh install off the shipped credentials, so the rest of the suite
// has a password that satisfies the policy.
const wasFresh = await page.evaluate(async (pw) => {
  const login = (p) => fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'admin', password: p }),
  });
  // Probing leaves a session behind either way, so it is always cleared: the
  // suite signs in through the form next, and it cannot do that if it is
  // already signed in.
  let fresh = false;
  if (!(await login(pw)).ok) {
    if (!(await login('admin')).ok) throw new Error('neither the default nor the test password works');
    const r = await fetch('/api/auth/change', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current: 'admin', password: pw }),
    });
    if (!r.ok) throw new Error('could not move off the default password');
    fresh = true;
  }
  await fetch('/api/auth/logout', { method: 'POST' });
  return fresh;
}, PASSWORD);
if (wasFresh) console.log('  ..    moved this install off admin/admin');
await page.reload({ waitUntil: 'networkidle' });
await page.waitForTimeout(600);

// Sign in through the form, the way a person does.
await page.fill('#au_user', USER);
await page.fill('#au_pass', PASSWORD);
await page.click('#au_submit');
await page.waitForSelector('.card', { timeout: 15000 });
await page.waitForTimeout(1200);

ck('signing in reveals the console', await page.locator('#simView').isVisible());
ck('the sign-in page is gone', !(await page.locator('#authView').isVisible()));
ck('the signed-in account is named',
  (await page.locator('#whoAmI').textContent()).trim().length > 0);

// The session cookie must not be readable from script, or an injected string
// anywhere in the console would be enough to steal it.
ck('the session cookie is not visible to script',
  !(await page.evaluate(() => document.cookie.includes('loggen_session'))),
  await page.evaluate(() => document.cookie));

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

// Save writes it, then leaves. The value is stamped, because a fixed one that
// a previous run left behind would make this fill a no-op, the form clean, and
// the whole check pass by never asking anything.
const guardDomain = `guard-${Date.now()}.example`;
await page.fill('#ev_domain', guardDomain);
await page.click('#adminBack');
await page.waitForTimeout(300);
await page.click('#dlg_save');
await page.waitForTimeout(700);
ck('save leaves the panel once it has written',
  (await page.locator('#adminHub').isVisible()) &&
  !(await page.locator('#dialog').isVisible()));
const saved = await page.evaluate(async () => (await (await fetch('/api/state')).json()));
ck('save actually persisted the edit', saved.env.domain === guardDomain, saved.env.domain);

await page.click('[data-admin=estate]');
await page.waitForTimeout(300);
await page.fill('#ev_domain', realDomain);
await page.click('#envForm button[type=submit]');
await page.waitForTimeout(500);
ck('the estate is back as it was', await page.evaluate(async (want) =>
  (await (await fetch('/api/state')).json()).env.domain === want, realDomain));
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
section('Stale build notice');

ck('no notice while the build is unchanged',
  await page.locator('#stale').evaluate((e) => e.classList.contains('hidden')));
ck('the build is stamped on API responses', await page.evaluate(async () => {
  const r = await fetch('/api/activity');
  return !!r.headers.get('X-LogGen-Version');
}));

// Drive the client half directly. Restarting the server mid-suite is not
// something this runner can do, and the part worth pinning is that a changed
// build raises the notice while a repeat of the same one does not.
ck('the same build again raises nothing', await page.evaluate(() => {
  noteBuild(state.build);
  return document.getElementById('stale').classList.contains('hidden');
}));
ck('a different build raises the notice', await page.evaluate(() => {
  noteBuild('v0.0.0-not-the-running-build');
  return !document.getElementById('stale').classList.contains('hidden');
}));
ck('the notice offers a reload',
  (await page.locator('#staleReload').count()) === 1);
ck('the notice does not cover the app', await page.evaluate(() => {
  const s = document.getElementById('stale').getBoundingClientRect();
  const t = document.querySelector('.targetbar').getBoundingClientRect();
  return s.bottom <= t.top + 1;
}));

// Put it back so the sections after this see an ordinary page.
await page.evaluate(() => document.getElementById('stale').classList.add('hidden'));

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
section('Account settings');

await page.click('[data-view=admin]');
await page.waitForTimeout(300);
ck('Administration offers a sign-in tile', (await page.locator('[data-admin=signin]').count()) === 1);
ck('Administration offers a recovery tile', (await page.locator('[data-admin=recovery]').count()) === 1);

await page.click('[data-admin=signin]');
await page.waitForTimeout(350);
ck('the sign-in panel opens', await page.locator('#adminSignin').isVisible());
ck('it shows the current account',
  (await page.inputValue('#si_user')) === USER, await page.inputValue('#si_user'));

const canLogin = (pw) => page.evaluate(async (p) => {
  const r = await fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'admin', password: p }),
  });
  return r.ok;
}, pw);

// The current password is what stands between an unlocked screen and a
// permanent takeover, so a wrong one must be refused.
await page.fill('#si_current', 'not the current password');
await page.fill('#si_pass', 'a-much-longer-one');
await page.fill('#si_pass2', 'a-much-longer-one');
await page.click('#signinForm button[type=submit]');
await page.waitForTimeout(700);
ck('a wrong current password is refused', await canLogin(PASSWORD),
  'the password changed despite a wrong current one');

// Mismatched new passwords never reach the server.
await page.fill('#si_current', PASSWORD);
await page.fill('#si_pass', 'first-attempt-here');
await page.fill('#si_pass2', 'second-attempt-here');
await page.click('#signinForm button[type=submit]');
await page.waitForTimeout(600);
ck('mismatched passwords are caught',
  /not the same/i.test(await page.locator('#toast').textContent()),
  await page.locator('#toast').textContent());

// Too short is refused by the server, whatever the form allows.
ck('a short password is refused', await page.evaluate(async (cur) => {
  const r = await fetch('/api/auth/change', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current: cur, password: 'short' }),
  });
  return !r.ok;
}, PASSWORD));

// A real change, then straight back, so the suite can be run twice.
const tempPassword = 'temp-' + Date.now();
await page.fill('#si_current', PASSWORD);
await page.fill('#si_pass', tempPassword);
await page.fill('#si_pass2', tempPassword);
await page.click('#signinForm button[type=submit]');
await page.waitForTimeout(900);
ck('the password can be changed', await canLogin(tempPassword));
ck('the old password stops working', !(await canLogin(PASSWORD)));
ck('the default credentials warning stays down once changed',
  await page.locator('#defaultCreds').evaluate((e) => e.classList.contains('hidden')));

// Changing the password signs out other sessions, but not the one that did it.
await page.reload({ waitUntil: 'networkidle' });
await page.waitForTimeout(1000);
ck('the session that made the change survives it',
  await page.locator('#simView').isVisible());

// Put it back.
await page.click('[data-view=admin]');
await page.waitForTimeout(300);
await page.click('[data-admin=signin]');
await page.waitForTimeout(350);
await page.fill('#si_current', tempPassword);
await page.fill('#si_pass', PASSWORD);
await page.fill('#si_pass2', PASSWORD);
await page.click('#signinForm button[type=submit]');
await page.waitForTimeout(900);
ck('the password can be set back', await canLogin(PASSWORD));

// Recovery. The stored mail password is never sent back to the browser.
await page.click('#adminBack');
await page.waitForTimeout(250);
await page.click('[data-admin=recovery]');
await page.waitForTimeout(350);
ck('the recovery panel opens', await page.locator('#adminRecovery').isVisible());
await page.fill('#rc_email', 'soc@example.com');
await page.fill('#rc_host', 'smtp.example.com');
await page.fill('#rc_port', '587');
await page.fill('#rc_from', 'loggen@example.com');
await page.fill('#rc_pass', 'a-mail-password');
await page.click('#recoveryForm button[type=submit]');
await page.waitForTimeout(800);
ck('recovery settings save',
  (await page.evaluate(async () => (await (await fetch('/api/auth/state')).json()).recoveryEmail))
    === 'soc@example.com');
ck('the mail password never comes back to the browser',
  await page.evaluate(async () => {
    const s = await (await fetch('/api/auth/state')).json();
    return s.smtp.hasPassword === true && s.smtp.password === undefined;
  }));
ck('the form says a password is stored rather than looking empty',
  /saved/i.test(await page.locator('#rc_pwnote').textContent()));

// With recovery configured, the sign-in page offers the reset link.
await page.evaluate(() => fetch('/api/auth/logout', { method: 'POST' }));
await page.reload({ waitUntil: 'networkidle' });
await page.waitForTimeout(800);
ck('signing out returns to the sign-in page', await page.locator('#authView').isVisible());
ck('the forgotten password link appears once recovery is set',
  await page.locator('#au_forgot').isVisible());

// The reset request says the same thing whatever name is given, so it cannot
// be used to find out what the account is called.
await page.click('#au_forgot');
await page.waitForTimeout(300);
await page.fill('#fg_user', 'somebody-else-entirely');
await page.click('#forgotForm button[type=submit]');
await page.waitForTimeout(1200);
const noteA = (await page.locator('#fg_note').textContent()).trim();
await page.fill('#fg_user', USER);
await page.click('#forgotForm button[type=submit]');
await page.waitForTimeout(1200);
ck('a reset request does not reveal the username',
  noteA === (await page.locator('#fg_note').textContent()).trim(), noteA);

// A forged reset link is refused.
ck('a made-up reset link is refused', await page.evaluate(async () => {
  const r = await fetch('/api/auth/reset', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'not.a.real.token', password: 'long-enough-here' }),
  });
  return !r.ok;
}));

// Back in for the rest of the suite.
await page.click('#fg_back');
await page.waitForTimeout(250);
await page.fill('#au_user', USER);
await page.fill('#au_pass', PASSWORD);
await page.click('#au_submit');
await page.waitForSelector('.card', { timeout: 15000 });
await page.waitForTimeout(800);
ck('signed back in', await page.locator('#simView').isVisible());


// Clear the recovery settings so a re-run starts where this one did.
await page.evaluate(() => fetch('/api/auth/recovery', {
  method: 'PUT', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: '', smtp: { host: '', port: 0, from: '', user: '', password: '' } }),
}));
await page.waitForTimeout(400);

// ---------------------------------------------------------------------------
section('Sign-in throttle');

// This runs last, because it deliberately locks the account for ten minutes
// and nothing after it could sign in.
await page.evaluate(() => fetch('/api/auth/logout', { method: 'POST' }));
await page.reload({ waitUntil: 'networkidle' });
await page.waitForTimeout(700);

const attempt = async (pw) => {
  await page.fill('#au_user', USER);
  await page.fill('#au_pass', pw);
  await page.click('#au_submit');
  await page.waitForTimeout(450);
};

// Four wrong ones warn without locking.
for (let i = 0; i < 3; i++) await attempt('wrong-password-here');
ck('a wrong password is reported', await page.locator('#au_error').isVisible());
await attempt('wrong-password-here');
ck('it warns before the lock rather than after',
  /attempt/i.test(await page.locator('#au_hint').textContent()),
  await page.locator('#au_hint').textContent());

// The fifth locks it.
await attempt('wrong-password-here');
ck('five failures inside a minute lock the account',
  /too many attempts/i.test(await page.locator('#au_error').textContent()),
  await page.locator('#au_error').textContent());
ck('the lock names ten minutes',
  /10 minutes/.test(await page.locator('#au_error').textContent()),
  await page.locator('#au_error').textContent());

// The button counts the wait down rather than just failing.
const label = await page.locator('#au_submit').textContent();
ck('the button shows how long is left', /locked for \d+:\d\d/i.test(label), label);
ck('the button is disabled while locked',
  await page.locator('#au_submit').isDisabled());

// The correct password must not get in during the lock, or it protects nothing.
ck('the right password is refused while locked', await page.evaluate(async (pw) => {
  const r = await fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: 'admin', password: pw }),
  });
  return !r.ok;
}, PASSWORD));

// A reload must not clear it either, or the lock is one keypress from useless.
await page.reload({ waitUntil: 'networkidle' });
await page.waitForTimeout(700);
ck('reloading does not clear the lock',
  await page.locator('#au_submit').isDisabled(),
  await page.locator('#au_submit').textContent());

// ---------------------------------------------------------------------------
section('Runtime');

ck('no page or console errors', errors.length === 0, JSON.stringify(errors.slice(0, 6), null, 1));
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
