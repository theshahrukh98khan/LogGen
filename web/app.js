'use strict';

const state = {
  env: {},
  profiles: [],
  controls: [],
  source: 'all',
  group: 'all',
  query: '',
  active: null,   // control currently open in the drawer
  lastSeq: 0,     // newest activity sequence number already rendered
  view: 'send',   // send | targets | library
  recent: [],     // ids of controls sent lately, newest first
  customs: [],    // operator-defined controls
  sources: [],    // every source that has at least one control
  placeholders: [],
};

// Matches activityCap in the server; the feed keeps at most this many rows.
const ACTIVITY_CAP = 400;

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error((data && data.error) || `${res.status} ${res.statusText}`);
  return data;
}

// ---------------------------------------------------------------------------
// Toast
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg, kind = '') {
  const el = $('toast');
  el.textContent = msg;
  el.className = `toast ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 4500);
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

async function boot() {
  try {
    const s = await api('GET', '/api/state');
    state.env = s.env;
    state.profiles = s.profiles;
    state.controls = s.controls;
    state.customs = s.customs || [];
    state.sources = s.sources || [];
    state.placeholders = await api('GET', '/api/placeholders');
  } catch (err) {
    toast(`Could not load state: ${err.message}`, 'bad');
    return;
  }
  loadRecent();
  renderProfileSelect();
  renderTabs();
  renderGrid();
  renderRecent();
  checkTarget();
  buildFacilitySelects();
  renderPlaceholders();
  renderSourceOptions();
  refreshActivity();
  setInterval(refreshActivity, 2500);
}

// ---------------------------------------------------------------------------
// Target selector
// ---------------------------------------------------------------------------

function currentProfile() {
  const id = $('profileSelect').value;
  return state.profiles.find((p) => p.id === id) || state.profiles[0];
}

function renderProfileSelect() {
  const sel = $('profileSelect');
  const previous = sel.value;
  sel.innerHTML = '';
  state.profiles.forEach((p) => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.name + (p.isDefault ? '  (default)' : '');
    sel.appendChild(opt);
  });
  const stillThere = state.profiles.some((p) => p.id === previous);
  const fallback = (state.profiles.find((p) => p.isDefault) || state.profiles[0] || {}).id;
  sel.value = stillThere ? previous : fallback;
  renderTargetAddr();
}

function renderTargetAddr() {
  const p = currentProfile();
  $('targetAddr').textContent = p ? `${p.protocol}://${p.host}:${p.port} · ${p.format}` : '';
}

// ---------------------------------------------------------------------------
// Destination status
// ---------------------------------------------------------------------------

// checkTarget probes the destination and says plainly what is known.
//
// UDP is the trap here: the socket always opens, so a send to a host that is
// not listening looks identical to one that works. The bar says so rather than
// showing a green light that means nothing.
async function checkTarget() {
  const p = currentProfile();
  const bar = $('targetBar');
  const text = $('tbStateText');
  const note = $('tbNote');

  if (!p) {
    bar.className = 'targetbar warn';
    text.textContent = 'No destination';
    note.textContent = 'Add one before sending.';
    return;
  }

  bar.className = 'targetbar checking';
  text.textContent = 'Checking';
  note.textContent = '';

  let res;
  try {
    res = await api('POST', `/api/profiles/${p.id}/test`, {});
  } catch {
    bar.className = 'targetbar bad';
    text.textContent = 'Unreachable';
    note.textContent = 'Could not probe the destination.';
    return;
  }

  if (!res.ok) {
    bar.className = 'targetbar bad';
    // A name that does not resolve and a port nothing answers on need
    // different fixes, so they get different advice.
    if (res.stage === 'resolve') {
      text.textContent = 'Name not found';
      note.textContent = res.error || 'The destination name does not resolve.';
    } else {
      text.textContent = 'Unreachable';
      note.textContent = 'Nothing is listening. Check the host, port and firewall.';
    }
    return;
  }

  // With a named destination, show what it resolved to: a stale DNS record is
  // invisible otherwise.
  const r = res.resolved;
  const resolvedTo = (r && !r.isIp && r.addrs && r.addrs.length)
    ? ` ${r.host} resolves to ${r.addrs.join(', ')}.`
    : '';

  if (p.protocol === 'udp') {
    bar.className = 'targetbar unverified';
    text.textContent = 'Ready';
    note.textContent =
      'UDP delivery is not confirmed by sending. Verify a record arrived at the collector.' + resolvedTo;
  } else {
    bar.className = 'targetbar good';
    text.textContent = 'Connected';
    note.textContent = resolvedTo.trim();
  }
}

// ---------------------------------------------------------------------------
// Recently sent
// ---------------------------------------------------------------------------

// The same few records get fired over and over while a rule is being written,
// so the last handful stay one click away.
function loadRecent() {
  try {
    state.recent = JSON.parse(localStorage.getItem('loggen.recent') || '[]');
  } catch { state.recent = []; }
}

function rememberRecent(id) {
  state.recent = [id, ...state.recent.filter((x) => x !== id)].slice(0, 6);
  try { localStorage.setItem('loggen.recent', JSON.stringify(state.recent)); } catch {}
  renderRecent();
}

function renderRecent() {
  const wrap = $('recentWrap');
  const row = $('recentRow');
  if (!wrap || !row) return;

  const items = state.recent
    .map((id) => state.controls.find((c) => c.id === id))
    .filter(Boolean);

  wrap.classList.toggle('hidden', items.length === 0);
  row.innerHTML = '';
  items.forEach((c) => {
    const b = document.createElement('button');
    b.className = 'chip-btn';
    b.type = 'button';
    const a = anchorFor(c);
    b.innerHTML = '<span class="chip-id">' + esc(a.text) + '</span>' +
                  '<span class="chip-name">' + esc(c.name) + '</span>';
    b.onclick = () => send(c, {});
    row.appendChild(b);
  });
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

const VIEW_COPY = {
  library: ['Library', 'Your own log sources and records'],
  targets: ['Destinations', 'Where LogGen sends records'],
};

function showView(view) {
  state.view = view;
  document.querySelectorAll('#mainNav .nav-item').forEach((b) =>
    b.classList.toggle('active', b.dataset.view === view));

  const admin = view !== 'send';
  $('adminView').classList.toggle('hidden', !admin);
  $('simView').classList.toggle('hidden', admin);

  if (!admin) return;

  const copy = VIEW_COPY[view] || VIEW_COPY.library;
  $('adminTitle').textContent = copy[0];
  $('adminSub').textContent = copy[1];
  showAdminTab(view === 'targets' ? 'profiles' : 'customs');
  renderProfileList();
  renderCustomList();
  renderSourceOptions();
  fillEnvForm();
}

// ---------------------------------------------------------------------------
// Controls
// ---------------------------------------------------------------------------

const SOURCE_LABELS = {
  all: 'All sources',
  windows: 'Windows',
  linux: 'Linux',
  nginx: 'Nginx',
  apache: 'Apache',
  oracle: 'Oracle',
  paloalto: 'Palo Alto',
  fortigate: 'FortiGate',
  sophos: 'Sophos',
  'cisco-asa': 'Cisco ASA',
  'cisco-ftd': 'Cisco FTD',
  trendmicro: 'Trend Micro',
  diagnostics: 'Diagnostics',
};

function sourceLabel(src) {
  return SOURCE_LABELS[src] || src.charAt(0).toUpperCase() + src.slice(1);
}

// railRow builds one filter row: a name on the left, a count on the right.
function railRow(label, count, active, onClick) {
  const b = document.createElement('button');
  b.className = 'tab' + (active ? ' active' : '');
  b.type = 'button';
  b.innerHTML = '<span>' + esc(label) + '</span><span class="n">' + count + '</span>';
  b.onclick = onClick;
  return b;
}

// renderTabs fills the source rail. Groups are scoped to the chosen source,
// because "Authentication" means something different under Windows than it
// does under Oracle.
function renderTabs() {
  const rail = $('sourceTabs');
  rail.innerHTML = '';

  const sources = [...new Set(state.controls.map((c) => c.source))].sort();
  rail.appendChild(railRow('All sources', state.controls.length,
    state.source === 'all', () => { state.source = 'all'; state.group = 'all'; renderAll(); }));

  sources.forEach((src) => {
    const n = state.controls.filter((c) => c.source === src).length;
    rail.appendChild(railRow(sourceLabel(src), n, state.source === src,
      () => { state.source = src; state.group = 'all'; renderAll(); }));
  });

  renderGroupRail();
}

function renderGroupRail() {
  const rail = $('groupTabs');
  if (!rail) return;
  rail.innerHTML = '';

  const inSource = state.controls.filter(
    (c) => state.source === 'all' || c.source === state.source);
  const groups = [...new Set(inSource.map((c) => c.group))].sort();

  rail.appendChild(railRow('All groups', inSource.length,
    state.group === 'all', () => { state.group = 'all'; renderAll(); }));

  groups.forEach((g) => {
    const n = inSource.filter((c) => c.group === g).length;
    rail.appendChild(railRow(g, n, state.group === g,
      () => { state.group = g; renderAll(); }));
  });
}

// renderAll repaints both rails and the grid after a filter change.
function renderAll() {
  renderTabs();
  renderGrid();
}

function matches(c) {
  if (state.source !== 'all' && c.source !== state.source) return false;
  if (state.group !== 'all' && c.group !== state.group) return false;
  if (!state.query) return true;
  // The ID and source are searched too, so shorthand people actually type
  // finds things: "sqli" matches nginx-sqli even though the catalog calls it
  // "SQL injection attempt".
  const hay = [c.name, c.desc, c.eventId, c.group, c.channel, c.id, c.source,
    ...(c.mitre || []), ...(c.wazuh || [])].join(' ').toLowerCase();
  return hay.includes(state.query);
}

function renderGrid() {
  const grid = $('controlGrid');
  const list = state.controls.filter(matches);
  grid.innerHTML = '';

  const count = $('controlCount');
  if (count) count.textContent = list.length + ' control' + (list.length === 1 ? '' : 's');

  const hint = $('emptyHint');
  if (!list.length) {
    hint.innerHTML = '<p>Nothing matches that.</p>' +
      '<p class="muted">Try a different search, or clear the filters.</p>' +
      '<button class="btn" id="clearFilters">Clear filters</button>';
    hint.classList.remove('hidden');
    const btn = document.getElementById('clearFilters');
    if (btn) btn.onclick = () => {
      state.source = 'all'; state.group = 'all'; state.query = '';
      $('search').value = '';
      renderAll();
    };
    return;
  }
  hint.classList.add('hidden');

  list.forEach((c) => grid.appendChild(card(c)));
}

// anchorFor picks what a card leads with. Analysts recognise these records by
// their identifier, so that is the headline: an event ID where one exists, the
// channel where it does not, and the source as a last resort.
function anchorFor(c) {
  if (c.eventId) return { text: c.eventId, numeric: /^[0-9]/.test(c.eventId) };
  if (c.channel) return { text: c.channel, numeric: false };
  return { text: c.source, numeric: false };
}

function card(c) {
  const el = document.createElement('div');
  el.className = 'card sev-' + c.severity;
  el.tabIndex = 0;
  el.title = 'Click to send. Use Details to set fields first.';

  const anchor = anchorFor(c);
  const tags = [];
  if (c.custom) tags.push('<span class="tag custom">custom</span>');
  (c.mitre || []).forEach((m) => tags.push('<span class="tag mitre">' + esc(m) + '</span>'));
  (c.wazuh || []).forEach((w) => tags.push('<span class="tag wazuh">' + esc(w) + '</span>'));

  el.innerHTML =
    '<span class="sev-chip sev-' + esc(c.severity) + '">' + esc(c.severity) + '</span>' +
    '<div class="card-id' + (anchor.numeric ? '' : ' text') + '">' + esc(anchor.text) + '</div>' +
    '<div class="card-title">' + esc(c.name) + '</div>' +
    '<div class="card-desc">' + esc(c.desc || '') + '</div>' +
    '<div class="tags">' + tags.join('') + '</div>' +
    '<button class="card-open" type="button">Details</button>';

  el.querySelector('.card-open').onclick = (e) => { e.stopPropagation(); openDrawer(c); };
  el.onclick = () => send(c, {});
  el.onkeydown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); send(c, {}); }
  };
  return el;
}

// ---------------------------------------------------------------------------
// Send / preview
// ---------------------------------------------------------------------------

function burstSettings() {
  return {
    count: Math.max(1, parseInt($('burstCount').value, 10) || 1),
    delayMs: Math.max(0, parseInt($('burstDelay').value, 10) || 0),
  };
}

async function send(control, params) {
  const p = currentProfile();
  if (!p) { toast('No target profile configured.', 'bad'); return; }
  const { count, delayMs } = burstSettings();

  try {
    const res = await api('POST', '/api/send', {
      controlId: control.id, profileId: p.id, params, count, delayMs,
    });
    rememberRecent(control.id);
    if (res.queued) {
      toast(`Queued ${res.queued} × ${control.name} → ${res.target}`, 'ok');
    } else {
      toast(`Sent ${control.name} → ${res.target} (${res.bytes} bytes)`, 'ok');
    }
  } catch (err) {
    toast(`Send failed: ${err.message}`, 'bad');
  }
  refreshActivity();
}

async function preview(control, params) {
  const p = currentProfile();
  try {
    const res = await api('POST', '/api/preview', {
      controlId: control.id, profileId: p ? p.id : '', params,
    });
    const pre = $('drawerWire');
    pre.textContent = res.wire;
    pre.classList.remove('hidden');
  } catch (err) {
    toast(`Preview failed: ${err.message}`, 'bad');
  }
}

// ---------------------------------------------------------------------------
// Drawer
// ---------------------------------------------------------------------------

function openDrawer(c) {
  state.active = c;
  $('drawerTitle').textContent = c.name;
  $('drawerDesc').textContent = c.desc || '';

  const meta = [];
  if (c.eventId) meta.push(`<span class="tag evt">EID ${esc(c.eventId)}</span>`);
  if (c.channel) meta.push(`<span class="tag">${esc(c.channel)}</span>`);
  meta.push(`<span class="tag">${esc(c.group)}</span>`);
  if (c.custom) meta.push('<span class="tag custom">custom</span>');
  (c.mitre || []).forEach((m) => meta.push(`<span class="tag mitre">${esc(m)}</span>`));
  (c.wazuh || []).forEach((w) => meta.push(`<span class="tag wazuh">rule ${esc(w)}</span>`));
  $('drawerMeta').innerHTML = meta.join('');

  const box = $('drawerParams');
  box.innerHTML = '';
  (c.params || []).forEach((p) => {
    const lab = document.createElement('label');
    lab.innerHTML = `${esc(p.label)}<input data-param="${esc(p.key)}" placeholder="${esc(p.placeholder || 'auto')}">`;
    box.appendChild(lab);
  });
  if (!(c.params || []).length) {
    box.innerHTML = '<p class="hint">This control takes no parameters.</p>';
  }

  $('drawerWire').classList.add('hidden');
  $('drawer').classList.remove('hidden');
}

function drawerParams() {
  const out = {};
  $('drawerParams').querySelectorAll('input[data-param]').forEach((i) => {
    if (i.value.trim()) out[i.dataset.param] = i.value.trim();
  });
  return out;
}

// ---------------------------------------------------------------------------
// Wire readout
// ---------------------------------------------------------------------------

const FACILITY_NAMES = ['kern','user','mail','daemon','auth','syslog','lpr','news',
  'uucp','cron','authpriv','ftp','ntp','audit','alert','clock',
  'local0','local1','local2','local3','local4','local5','local6','local7'];
const SEVERITY_NAMES = ['emerg','alert','crit','err','warning','notice','info','debug'];

// decodePri turns the leading <134> into "local0 . info", which is the one
// piece of a syslog line people routinely have to work out by hand.
function decodePri(wire) {
  const m = /^<(\d{1,3})>/.exec(wire || '');
  if (!m) return null;
  const pri = parseInt(m[1], 10);
  const f = pri >> 3, s = pri & 7;
  if (f > 23 || s > 7) return null;
  return { pri, facility: FACILITY_NAMES[f] || ('facility' + f), severity: SEVERITY_NAMES[s] };
}

// showOnWire updates the readout and flashes the lamp for one send.
function showOnWire(act, isNew = true) {
  if (!act || !act.wire) return;
  const box = $('readout');
  const pre = $('readoutWire');
  pre.textContent = act.wire;
  pre.classList.remove('empty');

  // Each fact is its own element so the row's flex gap separates them.
  const bits = [];
  const d = decodePri(act.wire);
  if (d) {
    bits.push('<span><b>PRI ' + d.pri + '</b> ' + esc(d.facility) +
      ' \u00b7 ' + esc(d.severity) + '</span>');
  }
  if (act.target) bits.push('<span>' + esc(act.target) + '</span>');
  if (act.bytes) bits.push('<span><b>' + act.bytes + '</b> bytes</span>');
  if (act.control) bits.push('<span class="name">' + esc(act.control) + '</span>');
  $('readoutMeta').innerHTML = bits.join('');

  if (!isNew) return;
  box.classList.remove('live');
  void box.offsetWidth;           // restart the pulse
  box.classList.add('live');
  setTimeout(() => box.classList.remove('live'), 700);
}

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------

// activityEntry builds one row of the feed.
function activityEntry(a) {
  const el = document.createElement('button');
  el.type = 'button';
  el.className = 'act' + (a.ok ? '' : ' fail');
  el.dataset.seq = a.seq;
  el.title = 'Show this record above';

  const t = new Date(a.time).toLocaleTimeString();
  el.innerHTML =
    '<div class="act-head">' +
      '<span class="act-name">' + esc(a.control) + '</span>' +
      '<span class="act-time">' + esc(t) + '</span>' +
    '</div>' +
    '<div class="act-meta">' +
      (a.ok ? a.bytes + ' bytes' : 'failed') + ' · ' + esc(a.target) +
    '</div>' +
    (a.error ? '<div class="act-err">' + esc(a.error) + '</div>' : '');

  // The full bytes live in the readout, so a row is a way back to one rather
  // than a second copy of it.
  el.onclick = () => showOnWire(a, false);
  return el;
}

// refreshActivity prepends whatever is new rather than rebuilding the feed.
//
// The feed is polled on a timer, and a full rebuild on every tick would discard
// any text the operator had selected — which matters here, because copying a
// record out of the feed to paste into a decoder is the main thing this panel is
// for. Entries carry a monotonic sequence number so we can tell what is new.
function renderActivity(list) {
  const box = $('activityList');

  if (!list || !list.length) {
    if (state.lastSeq !== 0 || !box.querySelector('.hint')) {
      box.innerHTML = '<p class="hint">Records you send appear here.</p>';
      state.lastSeq = 0;
    }
    return;
  }

  // The API returns newest first.
  const fresh = list.filter((a) => a.seq > state.lastSeq);
  if (!fresh.length) return;

  // A cleared view, or a server restart that reset the counter, needs a rebuild.
  const rebuild = state.lastSeq === 0 || list[list.length - 1].seq > state.lastSeq + 1;
  if (rebuild) {
    box.innerHTML = '';
    list.forEach((a) => box.appendChild(activityEntry(a)));
  } else {
    // Oldest of the new batch first, so each prepend leaves them newest-first.
    for (let i = fresh.length - 1; i >= 0; i--) {
      box.insertBefore(activityEntry(fresh[i]), box.firstChild);
    }
    while (box.children.length > ACTIVITY_CAP) {
      box.removeChild(box.lastChild);
    }
  }

  showOnWire(list[0]);
  state.lastSeq = list[0].seq;
}

async function refreshActivity() {
  let list;
  try {
    list = await api('GET', '/api/activity');
  } catch {
    return;
  }
  renderActivity(list);
}

// ---------------------------------------------------------------------------
// Profiles modal
// ---------------------------------------------------------------------------

function renderProfileList() {
  const box = $('profileList');
  box.innerHTML = '';
  state.profiles.forEach((p) => {
    const row = document.createElement('div');
    row.className = 'profile-row';
    row.innerHTML = `
      <div>
        <div class="pr-name">${esc(p.name)} ${p.isDefault ? '<span class="badge">default</span>' : ''}</div>
        <div class="pr-meta">${esc(p.protocol)}://${esc(p.host)}:${p.port} · ${esc(p.format)} · win:${esc(p.winFormat)}</div>
      </div>
      <div class="pr-actions">
        <button class="btn ghost small" data-act="edit">Edit</button>
        <button class="btn ghost small" data-act="default">Default</button>
        <button class="btn ghost small danger" data-act="delete">Delete</button>
      </div>`;

    row.querySelector('[data-act=edit]').onclick = () => fillProfileForm(p);
    row.querySelector('[data-act=default]').onclick = async () => {
      try {
        state.profiles = await api('POST', `/api/profiles/${p.id}/default`);
        renderProfileSelect(); renderProfileList();
        toast(`${p.name} is now the default target.`, 'ok');
      } catch (err) { toast(err.message, 'bad'); }
    };
    row.querySelector('[data-act=delete]').onclick = async () => {
      if (!confirm(`Delete profile "${p.name}"?`)) return;
      try {
        await api('DELETE', `/api/profiles/${p.id}`);
        state.profiles = await api('GET', '/api/profiles');
        renderProfileSelect(); renderProfileList();
        toast('Profile deleted.', 'ok');
      } catch (err) { toast(err.message, 'bad'); }
    };
    box.appendChild(row);
  });
}

function fillProfileForm(p) {
  $('pf_id').value = p ? p.id : '';
  $('pf_name').value = p ? p.name : '';
  $('pf_host').value = p ? p.host : '';
  $('pf_port').value = p ? p.port : 514;
  $('pf_protocol').value = p ? p.protocol : 'udp';
  $('pf_format').value = p ? p.format : 'rfc3164';
  $('pf_framing').value = p ? p.tcpFraming : 'lf';
  $('pf_winformat').value = p ? p.winFormat : 'snare';
  $('pf_webraw').checked = p ? !!p.webRaw : false;
  $('pf_default').checked = p ? !!p.isDefault : false;
}

function readProfileForm() {
  return {
    name: $('pf_name').value,
    host: $('pf_host').value,
    port: parseInt($('pf_port').value, 10) || 514,
    protocol: $('pf_protocol').value,
    format: $('pf_format').value,
    tcpFraming: $('pf_framing').value,
    winFormat: $('pf_winformat').value,
    webRaw: $('pf_webraw').checked,
    isDefault: $('pf_default').checked,
  };
}

// ---------------------------------------------------------------------------
// Estate modal
// ---------------------------------------------------------------------------

function fillEnvForm() {
  $('ev_domain').value = state.env.domain || '';
  $('ev_netbios').value = state.env.netbios || '';
  $('ev_winhost').value = state.env.winHost || '';
  $('ev_linuxhost').value = state.env.linuxHost || '';
  $('ev_webhost').value = state.env.webHost || '';
  $('ev_dbhost').value = state.env.dbHost || '';
  $('ev_dbname').value = state.env.dbName || '';
  $('ev_subnet').value = state.env.subnet || '';
  $('ev_fwhost').value = state.env.fwHost || '';
  $('ev_fwserial').value = state.env.fwSerial || '';
  $('ev_intiface').value = state.env.intIface || '';
  $('ev_extiface').value = state.env.extIface || '';
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

$('profileSelect').onchange = () => { renderTargetAddr(); checkTarget(); };

$('search').oninput = (e) => { state.query = e.target.value.trim().toLowerCase(); renderGrid(); };

$('btnTest').onclick = async () => {
  const p = currentProfile();
  if (!p) return;
  await checkTarget();
  try {
    const res = await api('POST', `/api/profiles/${p.id}/test`, {});
    toast(res.ok ? `${res.target} — ${res.note}` : `${res.target} — ${res.error}`,
      res.ok ? 'ok' : 'bad');
  } catch (err) { toast(err.message, 'bad'); }
};

// Profiles and the estate now live in the Administration view; admin.js wires
// the button that opens it.

$('pf_reset').onclick = () => fillProfileForm(null);

$('profileForm').onsubmit = async (e) => {
  e.preventDefault();
  const id = $('pf_id').value;
  const body = readProfileForm();
  try {
    if (id) await api('PUT', `/api/profiles/${id}`, body);
    else await api('POST', '/api/profiles', body);
    state.profiles = await api('GET', '/api/profiles');
    renderProfileSelect(); renderProfileList();
    toast('Profile saved.', 'ok');
  } catch (err) { toast(err.message, 'bad'); }
};

$('envForm').onsubmit = async (e) => {
  e.preventDefault();
  try {
    state.env = await api('PUT', '/api/env', {
      domain: $('ev_domain').value,
      netbios: $('ev_netbios').value,
      winHost: $('ev_winhost').value,
      linuxHost: $('ev_linuxhost').value,
      webHost: $('ev_webhost').value,
      dbHost: $('ev_dbhost').value,
      dbName: $('ev_dbname').value,
      subnet: $('ev_subnet').value,
      fwHost: $('ev_fwhost').value,
      fwSerial: $('ev_fwserial').value,
      intIface: $('ev_intiface').value,
      extIface: $('ev_extiface').value,
    });
    fillEnvForm();
    toast('Estate saved.', 'ok');
  } catch (err) { toast(err.message, 'bad'); }
};

$('drawerClose').onclick = () => $('drawer').classList.add('hidden');
$('drawerPreview').onclick = () => state.active && preview(state.active, drawerParams());
$('drawerSend').onclick = () => state.active && send(state.active, drawerParams());

$('btnClearActivity').onclick = () => {
  $('activityList').innerHTML = '<p class="hint">View cleared. New sends will appear here.</p>';
  // Forget what was rendered so the next poll repopulates from scratch.
  state.lastSeq = 0;
};

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

// boot() is called at the end of admin.js, once every function it needs exists.
