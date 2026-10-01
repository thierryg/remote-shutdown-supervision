/* =============================================================================
 * Remote Shutdown - LAN parental control and machine management (master/agent)
 * -----------------------------------------------------------------------------
 * File    : master/rsd_master/static/app.js
 * Purpose : Web console logic (i18n, session, machines, enrollment, settings, audit, chat)
 * Author  : Thierry Gayet <thierry.gayet@labworks.fr>
 * Project : remote-shutdown (version: VERSION)
 * Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
 * =============================================================================
 * Framework-free single-page application.
 *  - CSP: the page is served with `default-src 'self'` (no inline script or style), so this
 *    file is loaded once at the end of <body>, never uses eval, and builds every dynamic
 *    element with createElement/textContent (no innerHTML with data: no XSS from agent names).
 *  - i18n: texts come from i18n/<locale>.json; en-US is the reference and the fallback.
 *    Locale precedence: localStorage "rsd.lang" > navigator.language > en-US.
 *  - Security: every state-changing request carries the X-RSD anti-CSRF header; background
 *    polling carries X-RSD-Background so that it does not extend the idle session.
 */
'use strict';

/** Supported locales and their native names (en-US is the reference). */
const LOCALES = {
  'en-US': 'English', fr: 'Français', es: 'Español', nl: 'Nederlands', de: 'Deutsch', it: 'Italiano',
  ru: 'Русский', zh: '中文', id: 'Bahasa Indonesia', ko: '한국어', ja: '日本語', th: 'ไทย',
};

let dict = {};
let fallback = {};
let locale = 'en-US';
let info = null;
let agentsCache = [];
let pollTimer = null;
let chatTimer = null;
let chatState = null;

/* --- helpers ------------------------------------------------------------- */

/** Return the element with the given id. */
const $ = (id) => document.getElementById(id);

/**
 * Translate a key, with {name} placeholders.
 * @param {string} key i18n key.
 * @param {Object} [vars] placeholder values.
 * @returns {string}
 */
function t(key, vars) {
  let text = dict[key] ?? fallback[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) text = text.replaceAll(`{${k}}`, String(v));
  }
  return text;
}

/**
 * Create an element.
 * @param {string} tag tag name.
 * @param {Object} [attrs] attributes; "class", "text", "on<event>" and "data-*" are handled.
 * @param {...(Node|string)} children child nodes or texts.
 * @returns {HTMLElement}
 */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children) if (c !== null && c !== undefined) el.append(c);
  return el;
}

/** Show or hide an element. */
function show(el, visible) { el.classList.toggle('hidden', !visible); }

/**
 * Show a short notification.
 * @param {string} text message.
 * @param {boolean} [error] error style.
 */
function toast(text, error = false) {
  const el = $('toast');
  el.textContent = text;
  el.classList.toggle('error', error);
  show(el, true);
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => show(el, false), 4000);
}

/**
 * Format a duration in seconds as "2 d 3 h 04 min".
 * @param {number|null} seconds duration.
 */
function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), mm = Math.floor((s % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d} ${t('unit.d')}`);
  if (d || hh) parts.push(`${hh} ${t('unit.h')}`);
  parts.push(`${String(mm).padStart(d || hh ? 2 : 1, '0')} ${t('unit.min')}`);
  return parts.join(' ');
}

/** Format a Unix time with the current locale. */
function fmtDate(ts) {
  return ts ? new Date(ts * 1000).toLocaleString(locale === 'en-US' ? 'en-US' : locale) : '—';
}

/** Split minutes into {d, h, m}. */
function splitMinutes(total) {
  return { d: Math.floor(total / 1440), h: Math.floor((total % 1440) / 60), m: total % 60 };
}

/** Read the d/h/m inputs of a form as minutes. */
function readMinutes(form) {
  const n = (name) => Math.max(0, parseInt(form.elements[name].value || '0', 10) || 0);
  return n('d') * 1440 + n('h') * 60 + n('m');
}

/** Fill the d/h/m inputs of a form. */
function writeMinutes(form, total) {
  const p = splitMinutes(total);
  form.elements.d.value = p.d;
  form.elements.h.value = p.h;
  form.elements.m.value = p.m;
}

/* --- API ----------------------------------------------------------------- */

/** API error carrying the i18n key returned by the server. */
class ApiError extends Error {
  constructor(status, key) { super(key); this.status = status; this.key = key; }
}

/**
 * Call the JSON API.
 * @param {string} method HTTP method.
 * @param {string} path API path.
 * @param {Object} [body] JSON body.
 * @param {boolean} [background] polling request (does not extend the session).
 */
async function api(method, path, body, background = false) {
  const headers = { Accept: 'application/json' };
  if (method !== 'GET') headers['X-RSD'] = '1';
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (background) headers['X-RSD-Background'] = '1';
  const res = await fetch(path, {
    method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) {
    const key = (data && data.detail) || 'error.unexpected';
    if (res.status === 401 && path !== '/api/login') showLogin();
    else if (key === 'error.password_change_required') showPassword(true);
    throw new ApiError(res.status, key);
  }
  return data;
}

/** Report an API failure to the user. */
function fail(err) {
  if (err instanceof ApiError) {
    if (err.status !== 401) toast(t(err.key), true);
  } else {
    toast(t('error.network'), true);
  }
}

/* --- i18n ---------------------------------------------------------------- */

/** Load a locale (en-US always loaded as fallback) and translate the static markup. */
async function loadLocale(code) {
  if (!Object.keys(fallback).length) {
    fallback = await (await fetch('/static/i18n/en-US.json')).json();
  }
  locale = LOCALES[code] ? code : 'en-US';
  dict = locale === 'en-US' ? fallback : await (await fetch(`/static/i18n/${locale}.json`)).json();
  document.documentElement.lang = locale;
  document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  try { localStorage.setItem('rsd.lang', locale); } catch (e) { /* private mode */ }
}

/** Choose the initial locale. */
function initialLocale() {
  let saved = null;
  try { saved = localStorage.getItem('rsd.lang'); } catch (e) { saved = null; }
  if (saved && LOCALES[saved]) return saved;
  const nav = (navigator.language || 'en-US');
  if (LOCALES[nav]) return nav;
  const short = nav.split('-')[0];
  return LOCALES[short] ? short : 'en-US';
}

/* --- navigation ---------------------------------------------------------- */

/** Show one page and hide the others. */
function showPage(name) {
  document.querySelectorAll('.page').forEach((p) => show(p, p.id === `page-${name}`));
  document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b.dataset.page === name));
  clearInterval(pollTimer);
  pollTimer = null;
  if (name === 'machines') {
    refreshMachines();
    pollTimer = setInterval(() => refreshMachines(true), 5000);
  } else if (name === 'enroll') {
    refreshEnroll();
  } else if (name === 'settings') {
    refreshSettings();
  } else if (name === 'audit') {
    refreshAudit();
  }
}

/** Show the login page. */
function showLogin() {
  show($('nav'), false);
  show($('logout'), false);
  $('whoami').textContent = '';
  showPage('login');
}

/** Show the password page (forced: no navigation until it is changed). */
function showPassword(forced) {
  show($('nav'), !forced);
  show($('password-forced'), forced);
  showPage('password');
}

/** Enter the application after authentication. */
async function enterApp(me) {
  $('whoami').textContent = me.username;
  $('version').textContent = `v${me.version}`;
  show($('logout'), true);
  if (me.must_change) {
    showPassword(true);
    return;
  }
  show($('nav'), true);
  try { info = await api('GET', '/api/info'); } catch (e) { info = null; }
  showPage('machines');
}

/* --- machines ------------------------------------------------------------ */

/** Return the effective limit label of an agent. */
function limitLabel(a) {
  if (a.limit_mode === 'unlimited') return t('limit.unlimited_short');
  if (!a.effective_limit_minutes) return t('limit.none');
  const label = fmtDuration(a.effective_limit_minutes * 60);
  return a.limit_mode === 'inherit' ? `${label} (${t('limit.default_short')})` : label;
}

/** Return the IP/MAC cell content of an agent. */
function networkCell(a) {
  const cell = h('div', { class: 'net' });
  cell.append(h('div', { text: a.ip || '—' }));
  const ifs = (a.interfaces || []).filter((i) => i.mac || (i.ipv4 || []).length);
  if (ifs.length) {
    const details = h('details', {}, h('summary', { text: t('machines.interfaces', { n: ifs.length }) }));
    for (const i of ifs) {
      details.append(h('div', { class: 'iface' },
        h('strong', { text: i.name }), ' ', [...(i.ipv4 || []), ...(i.ipv6 || [])].join(', '),
        i.mac ? h('span', { class: 'muted', text: ` ${i.mac}` }) : null));
    }
    cell.append(details);
  }
  return cell;
}

/** Render the machines table. */
function renderMachines(agents, serverTime) {
  const body = $('machines-body');
  body.replaceChildren();
  const skew = serverTime ? Date.now() / 1000 - serverTime : 0;
  let up = 0;
  for (const a of agents) {
    const isUp = a.status === 'UP';
    if (isUp) up += 1;
    const status = h('span', { class: `badge ${isUp ? 'up' : 'down'}`, text: isUp ? t('status.up') : t('status.down') });
    const statusCell = h('td', {}, status);
    if (a.shutdown_at) {
      const left = Math.max(0, a.shutdown_at - Date.now() / 1000 + skew);
      statusCell.append(h('div', { class: 'warn', text: t('machines.shutdown_in', { time: fmtDuration(left + 59) }) }));
    } else if (!isUp && a.last_seen) {
      statusCell.append(h('div', { class: 'muted small', text: t('machines.last_seen', { date: fmtDate(a.last_seen) }) }));
    }
    const unread = a.last_chat_in > (readChat()[a.id] || 0);
    const actions = h('td', { class: 'actions' },
      h('button', { type: 'button', class: 'danger small', disabled: !isUp, text: t('action.shutdown'), onclick: () => openShutdown(a) }),
      a.shutdown_at ? h('button', { type: 'button', class: 'small', text: t('action.cancel'), onclick: () => cancelShutdown(a) }) : null,
      h('button', { type: 'button', class: 'small', disabled: !isUp, text: t('action.message'), onclick: () => openMessage(a) }),
      h('button', { type: 'button', class: `small${unread ? ' unread' : ''}`, text: t('action.chat'), onclick: () => openChat(a) }),
      h('button', { type: 'button', class: 'small ghost', text: t('action.edit'), onclick: () => openEdit(a) }));
    body.append(h('tr', { class: isUp ? '' : 'is-down' },
      h('td', {}, h('div', { class: 'name', text: a.display_name || a.hostname }),
        a.display_name && a.display_name !== a.hostname ? h('div', { class: 'muted small', text: a.hostname }) : null),
      statusCell,
      h('td', { text: isUp ? fmtDuration(a.uptime) : '—' }),
      h('td', { text: limitLabel(a) }),
      h('td', {}, networkCell(a)),
      h('td', {}, h('div', { text: a.os || '—' }), h('div', { class: 'muted small', text: `${a.arch || ''} · agent ${a.agent_version || '?'}` })),
      actions));
  }
  show($('machines-empty'), agents.length === 0);
  $('machines-summary').textContent = t('machines.summary', { up, total: agents.length });
}

/** Reload the machines. */
async function refreshMachines(background = false) {
  try {
    const data = await api('GET', '/api/agents', undefined, background);
    agentsCache = data.agents;
    renderMachines(data.agents, data.server_time);
  } catch (e) {
    if (!background) fail(e);
  }
}

/** Open the shutdown dialog for one agent (or all when agent is null). */
function openShutdown(agent) {
  const dlg = $('dlg-shutdown');
  const form = $('shutdown-form');
  $('shutdown-title').textContent = agent
    ? t('shutdown.title', { name: agent.display_name || agent.hostname }) : t('shutdown.title_all');
  form.reset();
  api('GET', '/api/settings').then((s) => { form.elements.delay.value = s.shutdown_delay_seconds; }).catch(() => {
    form.elements.delay.value = 60;
  });
  dlg.onclose = async () => {
    if (dlg.returnValue !== 'ok') return;
    const body = { delay: parseInt(form.elements.delay.value, 10) || 0, message: form.elements.message.value,
      force: form.elements.force.checked };
    try {
      if (agent) {
        await api('POST', `/api/agents/${agent.id}/shutdown`, body);
        toast(t('shutdown.sent'));
      } else {
        const r = await api('POST', '/api/shutdown-all', body);
        toast(t('shutdown.sent_all', { n: r.agents.length }));
      }
      refreshMachines();
    } catch (e) { fail(e); }
  };
  dlg.showModal();
}

/** Cancel the pending shutdown of an agent. */
async function cancelShutdown(agent) {
  try {
    await api('POST', `/api/agents/${agent.id}/cancel`);
    toast(t('shutdown.cancelled'));
    refreshMachines();
  } catch (e) { fail(e); }
}

/** Open the popup message dialog. */
function openMessage(agent) {
  const dlg = $('dlg-message');
  const form = $('message-form');
  form.reset();
  dlg.onclose = async () => {
    if (dlg.returnValue !== 'ok') return;
    try {
      await api('POST', `/api/agents/${agent.id}/message`, { text: form.elements.text.value });
      toast(t('message.sent'));
    } catch (e) { fail(e); }
  };
  dlg.showModal();
}

/** Return the last read chat message id per agent (localStorage). */
function readChat() {
  try { return JSON.parse(localStorage.getItem('rsd.chat') || '{}'); } catch (e) { return {}; }
}

/** Remember the last read chat message of an agent. */
function markChatRead(agentId, id) {
  const state = readChat();
  state[agentId] = Math.max(state[agentId] || 0, id);
  try { localStorage.setItem('rsd.chat', JSON.stringify(state)); } catch (e) { /* private mode */ }
}

/** Append chat messages to the open chat dialog. */
function appendChat(messages) {
  const log = $('chat-log');
  for (const m of messages) {
    log.append(h('div', { class: `bubble ${m.direction}` },
      h('div', { class: 'meta', text: `${m.author} · ${fmtDate(m.ts)}` }), h('div', { text: m.text })));
    chatState.after = Math.max(chatState.after, m.id);
  }
  if (messages.length) {
    log.scrollTop = log.scrollHeight;
    markChatRead(chatState.agent.id, chatState.after);
  }
}

/** Fetch the new chat messages. */
async function pollChat(background = true) {
  if (!chatState) return;
  try {
    const data = await api('GET', `/api/agents/${chatState.agent.id}/chat?after=${chatState.after}`, undefined, background);
    appendChat(data.messages);
  } catch (e) { if (!background) fail(e); }
}

/** Open the chat dialog of an agent. */
function openChat(agent) {
  const dlg = $('dlg-chat');
  const form = $('chat-form');
  chatState = { agent, after: 0 };
  $('chat-title').textContent = t('chat.title', { name: agent.display_name || agent.hostname });
  show($('chat-windows-note'), /windows/i.test(agent.os || ''));
  $('chat-log').replaceChildren();
  form.reset();
  pollChat(false);
  chatTimer = setInterval(() => pollChat(true), 3000);
  dlg.onclose = () => { clearInterval(chatTimer); chatState = null; refreshMachines(true); };
  dlg.showModal();
}

/** Send the chat input (the dialog stays open). */
async function sendChat(event) {
  const form = $('chat-form');
  if (event.submitter && event.submitter.value !== 'send') return;
  event.preventDefault();
  const text = form.elements.text.value.trim();
  if (!text || !chatState) return;
  try {
    await api('POST', `/api/agents/${chatState.agent.id}/chat`, { text });
    form.elements.text.value = '';
    await pollChat(false);
  } catch (e) { fail(e); }
}

/** Open the machine settings dialog. */
function openEdit(agent) {
  const dlg = $('dlg-edit');
  const form = $('edit-form');
  form.elements.display_name.value = agent.display_name || agent.hostname;
  form.elements.limit_mode.value = agent.limit_mode;
  writeMinutes(form, agent.limit_minutes || 0);
  const sync = () => show($('edit-dhm'), form.elements.limit_mode.value === 'custom');
  form.elements.limit_mode.onchange = sync;
  sync();
  dlg.onclose = async () => {
    if (dlg.returnValue === 'delete') {
      confirmAction(t('edit.confirm_delete', { name: agent.display_name || agent.hostname }), async () => {
        try {
          await api('DELETE', `/api/agents/${agent.id}`);
          toast(t('edit.deleted'));
          refreshMachines();
        } catch (e) { fail(e); }
      });
      return;
    }
    if (dlg.returnValue !== 'ok') return;
    const body = { display_name: form.elements.display_name.value, limit_mode: form.elements.limit_mode.value,
      limit_minutes: readMinutes(form) };
    try {
      await api('PATCH', `/api/agents/${agent.id}`, body);
      toast(t('common.saved'));
      refreshMachines();
    } catch (e) { fail(e); }
  };
  dlg.showModal();
}

/** Ask for a confirmation, then run the action. */
function confirmAction(text, action) {
  const dlg = $('dlg-confirm');
  $('confirm-text').textContent = text;
  dlg.onclose = () => { if (dlg.returnValue === 'ok') action(); };
  dlg.showModal();
}

/* --- enrollment ---------------------------------------------------------- */

/**
 * Return the master address agents should use: the one this browser reached the console at,
 * unless it is a loopback name (console opened on the master itself).
 */
function masterAddress() {
  const host = location.hostname;
  if (!['localhost', '127.0.0.1', '[::1]', '::1'].includes(host)) return host;
  if (info && info.addresses && info.addresses.length) return info.addresses[0];
  return host;
}

/** Fill the installation commands for a new token. */
function showCommands(token) {
  const fp = info ? info.ca_fingerprint : '<FINGERPRINT>';
  const v = info ? info.version : '<VERSION>';
  const host = masterAddress();
  const port = info && info.web_port !== 8443 ? `:${info.web_port}` : '';
  $('token-value').textContent = token;
  $('cmd-linux').textContent = `sudo apt install ./rsd-agent_${v}_amd64.deb\n`
    + `sudo rsd-agent enroll --token ${token} --fingerprint ${fp} --master ${host}${port}`;
  $('cmd-linux-rpm').textContent = `sudo dnf install ./rsd-agent-${v}-1.x86_64.rpm   # zypper install on openSUSE\n`
    + `sudo rsd-agent enroll --token ${token} --fingerprint ${fp} --master ${host}${port}`;
  $('cmd-macos').textContent = `sudo installer -pkg rsd-agent-${v}.pkg -target /\n`
    + `sudo /usr/local/bin/rsd-agent enroll --token ${token} --fingerprint ${fp} --master ${host}${port}`;
  $('cmd-windows').textContent = `msiexec /i rsd-agent-${v}-x64.msi /qn MASTER=${host}${port} `
    + `ENROLL_TOKEN=${token} CA_FINGERPRINT=${fp}`;
  show($('token-result'), true);
}

/** Reload the enrollment page. */
async function refreshEnroll() {
  try {
    info = await api('GET', '/api/info');
    $('ca-fingerprint').textContent = info.ca_fingerprint.match(/.{2}/g).join(':');
    $('master-addresses').textContent = [...info.addresses, ...info.names].join(', ');
    const data = await api('GET', '/api/tokens');
    const body = $('tokens-body');
    body.replaceChildren();
    for (const tok of data.tokens) {
      body.append(h('tr', {},
        h('td', { text: tok.label || '—' }), h('td', { text: fmtDate(tok.expires) }), h('td', { text: tok.uses_left }),
        h('td', {}, h('button', { type: 'button', class: 'small ghost', text: t('enroll.revoke'), onclick: async () => {
          try { await api('DELETE', `/api/tokens/${tok.id}`); refreshEnroll(); } catch (e) { fail(e); }
        } }))));
    }
    if (!data.tokens.length) body.append(h('tr', {}, h('td', { colspan: '4', class: 'muted', text: t('enroll.none') })));
  } catch (e) { fail(e); }
}

/* --- settings ------------------------------------------------------------ */

/** Reload the settings form. */
async function refreshSettings() {
  try {
    const s = await api('GET', '/api/settings');
    const form = $('settings-form');
    writeMinutes(form, s.default_limit_minutes);
    form.elements.warning_minutes.value = s.warning_minutes;
    form.elements.shutdown_delay_seconds.value = s.shutdown_delay_seconds;
  } catch (e) { fail(e); }
}

/* --- audit --------------------------------------------------------------- */

/** Reload the audit log. */
async function refreshAudit() {
  try {
    const data = await api('GET', '/api/audit');
    const chain = $('audit-chain');
    chain.textContent = data.chain_ok ? t('audit.chain_ok') : t('audit.chain_broken');
    chain.className = `badge ${data.chain_ok ? 'up' : 'down'}`;
    const names = Object.fromEntries(agentsCache.map((a) => [a.id, a.display_name || a.hostname]));
    const body = $('audit-body');
    body.replaceChildren();
    for (const e of data.entries) {
      const details = Object.keys(e.details || {}).length ? JSON.stringify(e.details) : '';
      body.append(h('tr', {},
        h('td', { text: fmtDate(e.ts) }), h('td', { text: e.actor }), h('td', { text: e.action }),
        h('td', { text: names[e.target] || e.target }), h('td', { class: 'mono small', text: details })));
    }
  } catch (e) { fail(e); }
}

/* --- wiring -------------------------------------------------------------- */

/** Attach the event handlers and start the application. */
async function boot() {
  const select = $('lang');
  for (const [code, name] of Object.entries(LOCALES)) select.append(h('option', { value: code, text: name }));
  await loadLocale(initialLocale());
  select.value = locale;
  select.addEventListener('change', async () => {
    await loadLocale(select.value);
    const active = document.querySelector('.page:not(.hidden)');
    if (active && active.id === 'page-machines') renderMachines(agentsCache);
  });

  document.querySelectorAll('.tab').forEach((b) => b.addEventListener('click', () => showPage(b.dataset.page)));

  $('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try {
      await api('POST', '/api/login', { username: f.elements.username.value, password: f.elements.password.value });
      f.reset();
      enterApp(await api('GET', '/api/me'));
    } catch (e) { fail(e); }
  });

  $('password-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    if (f.elements.new.value !== f.elements.repeat.value) {
      toast(t('error.password_mismatch'), true);
      return;
    }
    try {
      await api('POST', '/api/password', { current: f.elements.current.value, new: f.elements.new.value });
      f.reset();
      toast(t('password.changed'));
      enterApp(await api('GET', '/api/me'));
    } catch (e) { fail(e); }
  });

  $('logout').addEventListener('click', async () => {
    try { await api('POST', '/api/logout'); } catch (e) { /* already logged out */ }
    showLogin();
  });

  $('open-password').addEventListener('click', () => showPassword(false));
  $('shutdown-all').addEventListener('click', () => openShutdown(null));
  $('chat-form').addEventListener('submit', sendChat);

  $('token-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try {
      const tok = await api('POST', '/api/tokens', {
        label: f.elements.label.value, ttl_minutes: parseInt(f.elements.ttl_minutes.value, 10),
        uses: parseInt(f.elements.uses.value, 10),
      });
      showCommands(tok.token);
      refreshEnroll();
    } catch (e) { fail(e); }
  });

  $('settings-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    try {
      await api('PUT', '/api/settings', {
        default_limit_minutes: readMinutes(f),
        warning_minutes: parseInt(f.elements.warning_minutes.value, 10) || 0,
        shutdown_delay_seconds: parseInt(f.elements.shutdown_delay_seconds.value, 10) || 0,
      });
      toast(t('common.saved'));
    } catch (e) { fail(e); }
  });

  try {
    enterApp(await api('GET', '/api/me'));
  } catch (e) {
    if (!(e instanceof ApiError)) fail(e);
    else if (e.status === 401) showLogin();
  }
}

boot();
