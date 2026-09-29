'use strict';

// Administration view: SIEM targets, the simulated estate, and the operator's
// own log sources and controls.
//
// Loaded after app.js, which defines the shared state and helpers. boot() is
// called at the bottom of this file so everything is defined first.

// ---------------------------------------------------------------------------
// View switching
// ---------------------------------------------------------------------------

function showAdmin(show) {
  $('adminView').classList.toggle('hidden', !show);
  $('simView').classList.toggle('hidden', show);
  if (show) {
    renderProfileList();
    renderCustomList();
    renderSourceOptions();
    fillEnvForm();
  }
}

function showAdminTab(name) {
  document.querySelectorAll('.admin-tabs .tab').forEach((b) =>
    b.classList.toggle('active', b.dataset.admin === name));
  const panels = { customs: 'adminCustoms', profiles: 'adminProfiles', estate: 'adminEstate' };
  Object.entries(panels).forEach(([n, id]) =>
    $(id).classList.toggle('hidden', n !== name));
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

function renderPlaceholders() {
  const box = $('placeholderList');
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

    row.querySelector('[data-act=edit]').onclick = () => {
      fillCustomForm(c);
      $('cc_source').scrollIntoView({ behavior: 'smooth', block: 'center' });
    };
    row.querySelector('[data-act=delete]').onclick = async () => {
      if (!confirm('Delete custom control "' + c.name + '"?')) return;
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
  renderTabs();
  renderGrid();
  renderCustomList();
  renderSourceOptions();
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

$('btnAdmin').onclick = () => showAdmin(true);
$('btnCloseAdmin').onclick = () => showAdmin(false);

document.querySelectorAll('.admin-tabs .tab').forEach((b) => {
  b.onclick = () => showAdminTab(b.dataset.admin);
});

$('cc_addParam').onclick = () => $('cc_params').appendChild(paramRow());
$('cc_reset').onclick = () => fillCustomForm(null);

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
