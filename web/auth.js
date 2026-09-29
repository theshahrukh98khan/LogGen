'use strict';

// Sign-in, password recovery, and the account settings in Administration.
//
// Loaded before app.js. app.js calls gateBoot() instead of booting straight
// into the console, so the workspace is never briefly visible to somebody who
// has no session.

// ---------------------------------------------------------------------------
// Which of the three auth forms is on screen
// ---------------------------------------------------------------------------

function showAuthForm(which) {
  ['loginForm', 'forgotForm', 'resetForm'].forEach((id) =>
    $(id).classList.toggle('hidden', id !== which));
  const focus = { loginForm: 'au_pass', forgotForm: 'fg_user', resetForm: 'rs_pass' }[which];
  const el = $(focus);
  if (el) setTimeout(() => el.focus(), 40);
}

function showSignIn(state) {
  document.body.classList.add('signed-out');
  $('authView').classList.remove('hidden');

  // The first run has to say what the credentials are, or there is no way in.
  // It only ever admits that the documented default is still in place, which
  // is the first thing anybody would try regardless.
  $('au_hint').classList.toggle('hidden', !state.pristine);
  if (state.pristine) {
    $('au_hint').innerHTML =
      'First run. Sign in with <b>admin</b> / <b>admin</b>, then change it in Administration.';
  }
  $('au_forgot').classList.toggle('hidden', !state.canReset);

  if (state.lockedFor > 0) lockOut(state.lockedFor);
  showAuthForm('loginForm');
}

function hideSignIn() {
  document.body.classList.remove('signed-out');
  $('authView').classList.add('hidden');
}

function authError(id, msg) {
  const el = $(id);
  if (!msg) { el.classList.add('hidden'); return; }
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Lockout
// ---------------------------------------------------------------------------

let lockTimer = null;

// lockOut disables the form and counts down, so the wait is visible rather
// than looking like the console has broken.
function lockOut(seconds) {
  clearInterval(lockTimer);
  const btn = $('au_submit');
  const tick = () => {
    if (seconds <= 0) {
      clearInterval(lockTimer);
      btn.disabled = false;
      btn.textContent = 'Sign in';
      authError('au_error', '');
      return;
    }
    const m = Math.floor(seconds / 60);
    const s = String(seconds % 60).padStart(2, '0');
    btn.disabled = true;
    btn.textContent = `Locked for ${m}:${s}`;
    seconds--;
  };
  tick();
  lockTimer = setInterval(tick, 1000);
}

// ---------------------------------------------------------------------------
// Sign in
// ---------------------------------------------------------------------------

async function doLogin(e) {
  e.preventDefault();
  authError('au_error', '');

  let res;
  try {
    res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user: $('au_user').value, password: $('au_pass').value }),
    });
  } catch {
    authError('au_error', 'Could not reach the console.');
    return;
  }

  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    authError('au_error', body.error || 'That did not work.');
    if (body.lockedFor) lockOut(body.lockedFor);
    else if (body.remaining !== undefined) {
      $('au_hint').classList.remove('hidden');
      $('au_hint').textContent = body.remaining === 1
        ? 'One more wrong attempt locks this account for 10 minutes.'
        : `${body.remaining} attempts left before this account locks for 10 minutes.`;
    }
    $('au_pass').select();
    return;
  }

  $('au_pass').value = '';
  await loadAuthState();
  hideSignIn();
  await startConsole();
}

async function doSignOut() {
  await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
  location.reload();
}

// ---------------------------------------------------------------------------
// Forgotten password
// ---------------------------------------------------------------------------

async function doForgot(e) {
  e.preventDefault();
  const res = await fetch('/api/auth/forgot', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user: $('fg_user').value }),
  }).catch(() => null);

  // The reply is the same whether or not the name matched, so this cannot be
  // used to find out what the account is called.
  const body = res ? await res.json().catch(() => ({})) : {};
  $('fg_note').textContent = body.note ||
    'If that account has a recovery address, a reset link is on its way.';
  $('fg_note').classList.remove('hidden');
}

async function doReset(e) {
  e.preventDefault();
  authError('rs_error', '');

  if ($('rs_pass').value !== $('rs_pass2').value) {
    authError('rs_error', 'Those two passwords are not the same.');
    return;
  }

  const res = await fetch('/api/auth/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: state.resetToken, password: $('rs_pass').value }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    authError('rs_error', body.error || 'That did not work.');
    return;
  }

  // Drop the token out of the address bar, so the link is not sitting in
  // history or in whatever the next screenshot catches.
  history.replaceState(null, '', location.pathname);
  state.resetToken = null;
  showAuthForm('loginForm');
  toast('Password changed. Sign in with it.', 'ok');
}

// ---------------------------------------------------------------------------
// Administration: sign-in and recovery
// ---------------------------------------------------------------------------

function fillSigninForm() {
  $('si_current').value = '';
  $('si_user').value = state.auth.user || '';
  $('si_pass').value = '';
  $('si_pass2').value = '';
  markClean('signinForm');
}

function fillRecoveryForm() {
  const s = (state.auth && state.auth.smtp) || {};
  $('rc_email').value = (state.auth && state.auth.recoveryEmail) || '';
  $('rc_host').value = s.host || '';
  $('rc_port').value = s.port || '';
  $('rc_from').value = s.from || '';
  $('rc_user').value = s.user || '';
  $('rc_pass').value = '';
  // A stored password is never sent back to the browser, so the field says
  // what leaving it blank will do rather than looking empty by mistake.
  $('rc_pwnote').textContent = s.hasPassword ? 'saved, blank leaves it alone' : 'optional';
  markClean('recoveryForm');
}

async function saveSignin(e) {
  e.preventDefault();
  if ($('si_pass').value !== $('si_pass2').value) {
    toast('Those two passwords are not the same.', 'bad');
    return;
  }
  try {
    const out = await api('POST', '/api/auth/change', {
      current: $('si_current').value,
      user: $('si_user').value,
      password: $('si_pass').value,
    });
    state.auth.user = out.user;
    state.auth.pristine = false;
    renderWhoAmI();
    fillSigninForm();
    toast('Sign-in updated. Other sessions have been signed out.', 'ok');
  } catch (err) { toast(err.message, 'bad'); }
}

async function saveRecovery(e) {
  e.preventDefault();
  try {
    const out = await api('PUT', '/api/auth/recovery', {
      email: $('rc_email').value,
      smtp: {
        host: $('rc_host').value,
        port: parseInt($('rc_port').value, 10) || 0,
        user: $('rc_user').value,
        password: $('rc_pass').value,
        from: $('rc_from').value,
      },
    });
    await loadAuthState();
    fillRecoveryForm();
    toast(out.canReset
      ? 'Recovery saved. A forgotten password can now be reset from the sign-in page.'
      : 'Recovery saved. Add an address and a mail server to enable resets.', 'ok');
  } catch (err) { toast(err.message, 'bad'); }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

async function loadAuthState() {
  const res = await fetch('/api/auth/state');
  state.auth = await res.json();
  return state.auth;
}

function renderWhoAmI() {
  $('whoAmI').textContent = state.auth.user || '';
  $('defaultCreds').classList.toggle('hidden', !state.auth.pristine);
}

// gateBoot decides between the console and the sign-in page. app.js calls it
// rather than booting the console directly.
async function gateBoot() {
  let st;
  try {
    st = await loadAuthState();
  } catch {
    document.body.classList.remove('signed-out');
    toast('Could not reach the console.', 'bad');
    return;
  }


  // A reset link is followed before anything else, since somebody arriving on
  // one cannot sign in by definition.
  const token = new URLSearchParams(location.search).get('reset');
  if (token) {
    state.resetToken = token;
    document.body.classList.add('signed-out');
    $('authView').classList.remove('hidden');
    showAuthForm('resetForm');
    return;
  }

  if (!st.authenticated) { showSignIn(st); return; }
  hideSignIn();
  await startConsole();
}
