'use strict';

// Administration view: SIEM targets, the simulated estate, and the operator's
// own log sources and controls.
//
// Loaded after app.js, which defines the shared state and helpers. boot() is
// called at the bottom of this file so everything is defined first.

// ---------------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------------

const ADMIN_COPY = {
  hub: ['Administration', 'Everything LogGen lets you configure'],
  profiles: ['SIEM targets', 'Where LogGen sends records'],
  customs: ['Custom controls', 'Records you define yourself'],
  tokens: ['Placeholders', 'Tokens a custom control can expand'],
  estate: ['Simulated estate', 'The organisation every record refers to'],
  about: ['About', 'This build and where it keeps its configuration'],
};

const ADMIN_PANELS = {
  profiles: 'adminProfiles',
  customs: 'adminCustoms',
  tokens: 'adminTokens',
  estate: 'adminEstate',
  about: 'adminAbout',
};

// showAdminTab drives both levels of the administration view: "hub" shows the
// landing grid, any other name opens that one panel with a way back.
function showAdminTab(name) {
  if (!ADMIN_PANELS[name]) name = 'hub';
  state.adminTab = name;

  const onHub = name === 'hub';
  $('adminHub').classList.toggle('hidden', !onHub);
  $('adminBack').classList.toggle('hidden', onHub);
  Object.entries(ADMIN_PANELS).forEach(([n, id]) =>
    $(id).classList.toggle('hidden', n !== name));

  const copy = ADMIN_COPY[name];
  $('adminTitle').textContent = copy[0];
  $('adminSub').textContent = copy[1];

  if (name === 'tokens') renderPlaceholders($('placeholderRef'));
  if (name === 'about') renderAbout();

  // Focus the heading so a keyboard user is told where they landed instead of
  // being left on a tile that has just been hidden.
  $('adminTitle').setAttribute('tabindex', '-1');
  $('adminTitle').focus({ preventScroll: true });
}

// renderAbout fills the About page from whatever /api/state reported.
function renderAbout() {
  const sources = (state.sources || []).length;
  const facts = [
    ['Version', state.version || 'dev'],
    ['Controls', String((state.controls || []).length)],
    ['Log sources', String(sources)],
    ['Your controls', String((state.customs || []).length)],
    ['Destinations', String((state.profiles || []).length)],
    ['Configuration', state.dataDir || 'data/profiles.json'],
    ['Console', location.origin],
  ];
  $('aboutFacts').innerHTML = facts
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
    .join('');
}

// ---------------------------------------------------------------------------
// Syslog facility and severity pickers
// ---------------------------------------------------------------------------

const FACILITIES = [
  [0, 'kern'], [1, 'user'], [2, 'mail'], [3, 'daemon'], [4, 'auth'],
  [5, 'syslog'], [6, 'lpr'], [7, 'news'], [8, 'uucp'], [9, 'cron'],
  [10, 'authpriv'], [11, 'ftp'], [16, 'local0'], [17, 'local1'],
  [18, 'local2'], [19, 'local3'], [20, 'local4'], [21, 'local5'],
  [22, 'local6'], [23, 'local7'],
];

const SEVERITIES = [
  [0, 'emerg'], [1, 'alert'], [2, 'crit'], [3, 'err'],
  [4, 'warning'], [5, 'notice'], [6, 'info'], [7, 'debug'],
];

function buildFacilitySelects() {
  const fac = $('cc_facility');
  fac.innerHTML = FACILITIES.map((f) =>
    '<option value="' + f[0] + '">' + f[0] + ' · ' + f[1] + '</option>').join('');
  fac.value = '16';

  const sev = $('cc_syslogsev');
  sev.innerHTML = SEVERITIES.map((s) =>
    '<option value="' + s[0] + '">' + s[0] + ' · ' + s[1] + '</option>').join('');
  sev.value = '6';
}

// ---------------------------------------------------------------------------
// Placeholder reference
// ---------------------------------------------------------------------------

function renderPlaceholders(mount) {
  const box = mount || $('placeholderList');
  if (!box) return;

  const groups = {};
  (state.placeholders || []).forEach((p) => {
    (groups[p.group] = groups[p.group] || []).push(p);
  });

  box.innerHTML = Object.keys(groups).map((g) => {
    const rows = groups[g].map((p) =>
      '<div class="token-row"><code data-token="' + esc(p.token) + '">' +
      esc(p.token) + '</code><span>' + esc(p.meaning) + '</span></div>').join('');
    return '<div class="token-group"><h5>' + esc(g) + '</h5>' + rows + '</div>';
  }).join('');

  // Clicking a token inserts it at the cursor, which beats retyping braces.
  box.querySelectorAll('code[data-token]').forEach((el) => {
    el.onclick = () => insertToken(el.dataset.token);
  });
}

function insertToken(tok) {
  const ta = $('cc_template');
  const start = ta.selectionStart == null ? ta.value.length : ta.selectionStart;
  const end = ta.selectionEnd == null ? ta.value.length : ta.selectionEnd;
  ta.value = ta.value.slice(0, start) + tok + ta.value.slice(end);
  ta.focus();
  ta.selectionStart = ta.selectionEnd = start + tok.length;
}

function renderSourceOptions() {
  const dl = $('sourceOptions');
  if (!dl) return;
  dl.innerHTML = (state.sources || [])
    .map((s) => '<option value="' + esc(s) + '">').join('');
}

// ---------------------------------------------------------------------------
// Custom controls
// ---------------------------------------------------------------------------

function renderCustomList() {
  const box = $('customList');
  if (!box) return;

  if (!state.customs.length) {
    box.innerHTML = '<p class="hint">No custom controls yet. Fill in the form to add one.</p>';
    return;
  }

  box.innerHTML = '';
  state.customs.forEach((c) => {
    const row = document.createElement('div');
    row.className = 'profile-row';
    row.innerHTML =
      '<div>' +
        '<div class="pr-name">' + esc(c.name) + '</div>' +
        '<div class="pr-meta">' + esc(c.source) + ' · ' + esc(c.group) +
          ' · ' + esc(c.severity) + (c.tag ? ' · tag:' + esc(c.tag) : '') + '</div>' +
      '</div>' +
      '<div class="pr-actions">' +
        '<button class="btn ghost small" data-act="edit">Edit</button>' +
        '<button class="btn ghost small danger" data-act="delete">Delete</button>' +
      '</div>';

    row.querySelector('[data-act=edit]').onclick = () => guard(() => {
      fillCustomForm(c);
      $('cc_source').scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
    row.querySelector('[data-act=delete]').onclick = async () => {
      if (!await confirmDelete('control', c.name)) return;
      try {
        await api('DELETE', '/api/customs/' + c.id);
        await reloadCatalog();
        fillCustomForm(null);
        toast('Custom control deleted.', 'ok');
      } catch (err) { toast(err.message, 'bad'); }
    };
    box.appendChild(row);
  });
}

// paramRow renders one editable parameter definition.
function paramRow(p) {
  p = p || {};
  const row = document.createElement('div');
  row.className = 'param-row';
  row.innerHTML =
    '<input placeholder="key" data-f="key" value="' + esc(p.key || '') + '">' +
    '<input placeholder="Label" data-f="label" value="' + esc(p.label || '') + '">' +
    '<input placeholder="Default, e.g. {{external_ip}}" data-f="default" value="' +
      esc(p.default || '') + '">' +
    '<button type="button" class="btn ghost small danger" data-act="rm">Remove</button>';
  row.querySelector('[data-act=rm]').onclick = () => row.remove();
  return row;
}

function readParams() {
  const out = [];
  $('cc_params').querySelectorAll('.param-row').forEach((row) => {
    const get = (f) => row.querySelector('[data-f=' + f + ']').value.trim();
    const key = get('key');
    if (!key) return;
    out.push({
      key: key,
      label: get('label') || key,
      placeholder: 'auto',
      default: get('default'),
    });
  });
  return out;
}

function fillCustomForm(c) {
  $('customFormTitle').textContent = c ? 'Editing: ' + c.name : 'New control';
  $('cc_id').value = c ? c.id : '';
  $('cc_source').value = c ? c.source : '';
  $('cc_group').value = c ? c.group : '';
  $('cc_name').value = c ? c.name : '';
  $('cc_desc').value = c ? (c.desc || '') : '';
  $('cc_severity').value = c ? c.severity : 'info';
  $('cc_eventid').value = c ? (c.eventId || '') : '';
  $('cc_channel').value = c ? (c.channel || '') : '';
  $('cc_mitre').value = c && c.mitre ? c.mitre.join(', ') : '';
  $('cc_wazuh').value = c && c.wazuh ? c.wazuh.join(', ') : '';
  $('cc_tag').value = c ? (c.tag || '') : '';
  $('cc_host').value = c ? (c.host || '') : '';
  $('cc_facility').value = c && c.facility != null ? String(c.facility) : '16';
  $('cc_syslogsev').value = c && c.syslogSeverity != null ? String(c.syslogSeverity) : '6';
  $('cc_pid').checked = c ? !!c.includePid : false;
  $('cc_template').value = c ? c.template : '';

  const box = $('cc_params');
  box.innerHTML = '';
  ((c && c.params) || []).forEach((p) => box.appendChild(paramRow(p)));

  $('cc_wire').classList.add('hidden');
  markClean('customForm');
}

function readCustomForm() {
  const list = (id) => $(id).value.split(',').map((x) => x.trim()).filter(Boolean);
  return {
    source: $('cc_source').value.trim().toLowerCase(),
    group: $('cc_group').value.trim(),
    name: $('cc_name').value.trim(),
    desc: $('cc_desc').value.trim(),
    severity: $('cc_severity').value,
    eventId: $('cc_eventid').value.trim(),
    channel: $('cc_channel').value.trim(),
    mitre: list('cc_mitre'),
    wazuh: list('cc_wazuh'),
    tag: $('cc_tag').value.trim(),
    host: $('cc_host').value.trim(),
    facility: parseInt($('cc_facility').value, 10),
    syslogSeverity: parseInt($('cc_syslogsev').value, 10),
    includePid: $('cc_pid').checked,
    params: readParams(),
    template: $('cc_template').value,
  };
}

// reloadCatalog refreshes everything a custom control change can affect.
async function reloadCatalog() {
  const s = await api('GET', '/api/state');
  state.controls = s.controls;
  state.customs = s.customs || [];
  state.sources = s.sources || [];
  renderAll();
  renderCustomList();
  renderSourceOptions();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// Everything that leaves an editable panel goes through guard(), which asks
// before unsaved edits are thrown away.
document.querySelectorAll('#mainNav .nav-item').forEach((b) => {
  b.onclick = () => guard(() => showView(b.dataset.view));
});

$('staleReload').onclick = () => guard(() => location.reload());

$('brandHome').onclick = (e) => {
  e.preventDefault();
  guard(() => showView('send'));
};

document.querySelectorAll('#adminHub .tile').forEach((b) => {
  b.onclick = () => showAdminTab(b.dataset.admin);
});

$('adminBack').onclick = () => guard(() => showAdminTab('hub'));

// ---------------------------------------------------------------------------
// Keyboard
//
// This tool gets driven repeatedly while a rule is being written on another
// screen, so the common path stays on the keyboard.
// ---------------------------------------------------------------------------

document.addEventListener('keydown', (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);

  // "/" jumps to search from anywhere.
  if (e.key === '/' && !typing) {
    e.preventDefault();
    guard(() => {
      showView('send');
      $('search').focus();
      $('search').select();
    });
    return;
  }

  if (e.key === 'Escape') {
    if (!$('drawer').classList.contains('hidden')) {
      $('drawer').classList.add('hidden');
      return;
    }
    // Inside an administration panel, Escape steps back to the hub rather than
    // out of administration altogether, so one key does not lose two levels.
    if (state.view === 'admin' && state.adminTab !== 'hub') {
      // Escape out of a panel is navigation like any other, so it asks too.
      // The guard dialog handles its own Escape before this ever runs.
      guard(() => showAdminTab('hub'));
      return;
    }
    if (document.activeElement === $('search')) {
      $('search').value = '';
      state.query = '';
      renderGrid();
      $('search').blur();
    }
    return;
  }

  // From the search box, Enter sends the first match and Down steps into the
  // grid, so a search can be completed without reaching for the mouse.
  if (document.activeElement === $('search')) {
    const first = document.querySelector('#controlGrid .card');
    if (e.key === 'Enter' && first) { e.preventDefault(); first.click(); }
    if (e.key === 'ArrowDown' && first) { e.preventDefault(); first.focus(); }
    return;
  }

  // Arrow keys move between cards once one has focus.
  if (document.activeElement.classList.contains('card')) {
    const cards = [...document.querySelectorAll('#controlGrid .card')];
    const i = cards.indexOf(document.activeElement);
    const cols = Math.max(1, Math.round(
      document.getElementById('controlGrid').clientWidth /
      (document.activeElement.offsetWidth + 9)));
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, ArrowDown: i + cols, ArrowUp: i - cols }[e.key];
    if (next !== undefined && cards[next]) { e.preventDefault(); cards[next].focus(); }
  }
});

$('cc_addParam').onclick = () => $('cc_params').appendChild(paramRow());
$('cc_reset').onclick = () => guard(() => fillCustomForm(null));

$('cc_preview').onclick = async () => {
  const body = readCustomForm();
  if (!body.template.trim()) { toast('A record template is required.', 'bad'); return; }

  // Preview an unsaved control by saving nothing: render it server-side through
  // a throwaway request so the operator sees the real wire format before
  // committing it.
  try {
    const res = await api('POST', '/api/preview-custom', {
      control: body,
      profileId: currentProfile() ? currentProfile().id : '',
    });
    const pre = $('cc_wire');
    pre.textContent = res.wire;
    pre.classList.remove('hidden');
  } catch (err) { toast('Preview failed: ' + err.message, 'bad'); }
};

$('customForm').onsubmit = async (e) => {
  e.preventDefault();
  const id = $('cc_id').value;
  const body = readCustomForm();
  try {
    if (id) await api('PUT', '/api/customs/' + id, body);
    else await api('POST', '/api/customs', body);
    await reloadCatalog();
    fillCustomForm(null);
    toast(id ? 'Custom control updated.' : 'Custom control added.', 'ok');
  } catch (err) { toast(err.message, 'bad'); }
};

// Everything is defined now, so the app can start.
boot();
