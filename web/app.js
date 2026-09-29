'use strict';

const state = {
  env: {},
  profiles: [],
  controls: [],
  source: 'all',
  query: '',
  active: null, // control currently open in the drawer
};

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
  } catch (err) {
    toast(`Could not load state: ${err.message}`, 'bad');
    return;
  }
  renderProfileSelect();
  renderTabs();
  renderGrid();
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
// Controls
// ---------------------------------------------------------------------------

const SOURCE_LABELS = {
  all: 'All',
  windows: 'Windows',
  linux: 'Linux',
  nginx: 'Nginx',
  apache: 'Apache',
  oracle: 'Oracle',
  diagnostics: 'Diagnostics',
};

function renderTabs() {
  const sources = ['all', ...new Set(state.controls.map((c) => c.source))];
  const tabs = $('sourceTabs');
  tabs.innerHTML = '';
  sources.forEach((src) => {
    const count = src === 'all'
      ? state.controls.length
      : state.controls.filter((c) => c.source === src).length;
    const b = document.createElement('button');
    b.className = 'tab' + (state.source === src ? ' active' : '');
    b.textContent = `${SOURCE_LABELS[src] || src} (${count})`;
    b.onclick = () => { state.source = src; renderTabs(); renderGrid(); };
    tabs.appendChild(b);
  });
}

function matches(c) {
  if (state.source !== 'all' && c.source !== state.source) return false;
  if (!state.query) return true;
  const hay = [c.name, c.desc, c.eventId, c.group, c.channel,
    ...(c.mitre || []), ...(c.wazuh || [])].join(' ').toLowerCase();
  return hay.includes(state.query);
}

function renderGrid() {
  const grid = $('controlGrid');
  const list = state.controls.filter(matches);
  grid.innerHTML = '';

  const hint = $('emptyHint');
  if (!list.length) {
    hint.textContent = state.controls.length
      ? 'No controls match this filter.'
      : 'No controls registered yet.';
    hint.classList.remove('hidden');
    return;
  }
  hint.classList.add('hidden');

  list.forEach((c) => grid.appendChild(card(c)));
}

function card(c) {
  const el = document.createElement('div');
  el.className = `card sev-${c.severity}`;
  el.title = 'Click to send · use the Details button to edit fields first';

  const tags = [];
  if (c.eventId) tags.push(`<span class="tag evt">EID ${esc(c.eventId)}</span>`);
  if (c.channel) tags.push(`<span class="tag">${esc(c.channel)}</span>`);
  (c.mitre || []).forEach((m) => tags.push(`<span class="tag mitre">${esc(m)}</span>`));
  (c.wazuh || []).forEach((w) => tags.push(`<span class="tag wazuh">${esc(w)}</span>`));

  el.innerHTML = `
    <button class="card-open" type="button">Details</button>
    <div class="card-title">${esc(c.name)}</div>
    <div class="card-desc">${esc(c.desc || '')}</div>
    <div class="tags">${tags.join('')}</div>`;

  el.querySelector('.card-open').onclick = (e) => { e.stopPropagation(); openDrawer(c); };
  el.onclick = () => send(c, {});
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
// Activity
// ---------------------------------------------------------------------------

async function refreshActivity() {
  let list;
  try {
    list = await api('GET', '/api/activity');
  } catch {
    return;
  }
  const box = $('activityList');
  if (!list || !list.length) {
    box.innerHTML = '<p class="hint">Nothing sent yet. Click a control to emit a record.</p>';
    return;
  }
  box.innerHTML = '';
  list.forEach((a) => {
    const el = document.createElement('div');
    el.className = 'act' + (a.ok ? '' : ' fail');
    const t = new Date(a.time).toLocaleTimeString();
    el.innerHTML = `
      <div class="act-head">
        <span class="act-name">${esc(a.control)}</span>
        <span class="act-time">${esc(t)}</span>
      </div>
      <div class="act-meta">${esc(a.target)} · ${a.ok ? `${a.bytes} bytes` : 'FAILED'}</div>
      ${a.error ? `<div class="act-err">${esc(a.error)}</div>` : ''}
      ${a.wire ? `<pre class="act-wire">${esc(a.wire)}</pre>` : ''}`;
    box.appendChild(el);
  });
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
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

$('profileSelect').onchange = renderTargetAddr;

$('search').oninput = (e) => { state.query = e.target.value.trim().toLowerCase(); renderGrid(); };

$('btnTest').onclick = async () => {
  const p = currentProfile();
  if (!p) return;
  try {
    const res = await api('POST', `/api/profiles/${p.id}/test`, {});
    toast(res.ok ? `${res.target} — ${res.note}` : `${res.target} — ${res.error}`, res.ok ? 'ok' : 'bad');
  } catch (err) { toast(err.message, 'bad'); }
};

$('btnProfiles').onclick = () => {
  renderProfileList();
  fillProfileForm(currentProfile());
  $('profilesModal').classList.remove('hidden');
};

$('btnEnv').onclick = () => { fillEnvForm(); $('envModal').classList.remove('hidden'); };

document.querySelectorAll('[data-close]').forEach((b) => {
  b.onclick = () => $(b.dataset.close).classList.add('hidden');
});

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
};

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  $('drawer').classList.add('hidden');
  document.querySelectorAll('.modal').forEach((m) => m.classList.add('hidden'));
});

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

boot();
