'use strict';
// 云电脑保活面板：轮询 /api/state 渲染，POST /api/<action> 执行操作。
// 受 CSP 限制不使用内联脚本/样式；浏览器端不保存任何凭据。

const $ = id => document.getElementById(id);
const TZ = { timeZone: 'Asia/Shanghai', hour12: false };
const HOUR = 3600 * 1000;

let state = null;
let csrf = '';
let tab = 'password';
let polling = false;
let lastEventId = null;
let timelineKey = '';
let selectedKey = null;

const ACTION_LABELS = {
  connect: '正在连接云电脑',
  'power-connect': '正在开机并进入系统',
  devices: '正在刷新设备状态',
  password: '正在验证账号密码',
  'sms-send': '正在发送验证码',
  'sms-login': '正在验证登录',
  challenge: '正在完成设备验证',
};

// 一次连接的关键阶段（按协议顺序），字段来自后端过滤后的结果
const STAGES = [
  { name: '网关认证', ok: r => r.gatewayAuthenticated },
  { name: '桌面通道', ok: r => r.desktopChannelAuthenticated || r.desktopProtocolConnected },
  { name: '桌面画面', ok: r => r.desktopFrameReceived },
  { name: 'Windows 登录', ok: r => r.guestSessionEntered && r.guestLogonState === 1 },
  { name: '在线上报', ok: r => r.connectedReportAccepted },
  { name: '断开清理', ok: r => r.disconnectedReportAccepted },
];

/* ---------- 工具函数 ---------- */
const when = r => r.finishedAt || r.startedAt;
function fmt(value, opts) {
  return value ? new Date(value).toLocaleString('zh-CN', { ...TZ, ...opts }) : '—';
}
const fmtFull = v => fmt(v, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const fmtDay = v => fmt(v, { month: '2-digit', day: '2-digit' });
const fmtTime = v => fmt(v, { hour: '2-digit', minute: '2-digit' });

function elapsed(ms) {
  const min = Math.floor(ms / 60000);
  if (min < 1) return { value: '刚刚', unit: '' };
  if (min < 60) return { value: String(min), unit: '分钟' };
  const h = Math.floor(min / 60);
  if (h < 48) return { value: String(h), unit: '小时' };
  return { value: String(Math.floor(h / 24)), unit: '天' };
}
function clockDiff(ms) {
  if (!(ms > 0)) return '即将开始';
  const s = Math.ceil(ms / 1000);
  const pad = n => String(n).padStart(2, '0');
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor(s % 3600 / 60))}:${pad(s % 60)}`;
}
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function text(id, value) { $(id).textContent = value; }
function verdictOf(r) {
  if (r.success) return { label: '成功', tone: 'good' };
  if (r.legacyMainOnly) return { label: '仅认证', tone: 'warn' };
  if (r.legacyDisplayOnly) return { label: '仅画面', tone: 'warn' };
  return { label: '未完成', tone: 'bad' };
}
function errorText(r) {
  return r.errorHint || (r.errorCode ? '业务码 ' + r.errorCode : '请检查会话或连接状态');
}

function toast(message, error = false) {
  const node = $('toast');
  node.textContent = message;
  node.className = 'toast' + (error ? ' error' : '');
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, 4500);
}

/* ---------- 后端交互 ---------- */
async function action(name, data = {}) {
  try {
    const response = await fetch('/api/' + name, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(data),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || '操作失败');
    await poll();
    return true;
  } catch (error) {
    toast(error.message || '操作失败', true);
    return false;
  }
}

// 任何操作前先保存设置；成功后清空敏感输入并解除"已修改"标记
async function save(notify = false) {
  const ok = await action('settings', {
    intervalHours: Number($('interval').value),
    holdSeconds: Number($('hold').value),
    targetId: $('target').value,
    mobile: $('mobile').value.trim(),
    username: $('username').value.trim(),
    password: $('password').value,
    selected_username: $('selected_username').value.trim(),
  });
  if (ok) {
    for (const id of ['mobile', 'username', 'password', 'selected_username']) $(id).value = '';
    for (const id of ['interval', 'hold', 'target']) delete $(id).dataset.dirty;
    if (notify) toast('设置已保存到本机');
  }
  return ok;
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const response = await fetch('/api/state', { cache: 'no-store' });
    if (!response.ok) throw new Error();
    render(await response.json());
  } catch {
    $('service').className = 'service offline';
    text('service-text', '本地服务未连接');
  } finally {
    polling = false;
  }
}

/* ---------- 渲染 ---------- */
function lastSuccess(data) {
  return data.history.find(r => r.success) || (data.lastResult?.success ? data.lastResult : null);
}

function renderHero(data) {
  const machine = data.machines.find(m => m.machineId === data.targetId);
  const status = machine?.machineStatus;
  const badge = $('machine-badge');
  badge.textContent = status === 'available' ? '可用' : status === 'shutdown' ? '已关机' : (status || '本地缓存');
  badge.className = 'badge' + (status === 'available' ? ' good' : status === 'shutdown' ? ' warn' : '');
  text('machine-name', machine?.machineName || '尚未选择云电脑');
  const spec = (machine?.resourceType || '').match(/(\d+)C(\d+)G/);
  text('machine-spec', machine ? [machine.originCompanyCode, spec && `${spec[1]} 核 ${spec[2]} GB`, '…' + machine.machineId.slice(-6)].filter(Boolean).join(' · ') : '');

  const r = data.lastResult;
  let headline, subline, tone;
  if (data.busy) {
    headline = (ACTION_LABELS[data.action] || '正在执行') + '…';
    subline = data.action === 'connect' || data.action === 'power-connect'
      ? `将保持 ${data.holdSeconds} 秒，完成断开清理后返回结果。`
      : '完成后状态会自动更新。';
    tone = 'busy';
  } else if (data.authenticationRequired) {
    headline = '登录已失效'; subline = '自动续登未成功，请在设置中重新登录。'; tone = 'bad';
  } else if (!data.sessionAvailable) {
    headline = '尚未登录'; subline = '在设置中填写账号并登录后即可连接。'; tone = 'bad';
  } else if (!r) {
    headline = '还没有连接记录'; subline = '点击「立即连接」走一遍完整的进入系统流程。'; tone = 'idle';
  } else if (r.success) {
    headline = '最近一次成功进入系统'; subline = '已确认 Windows 登录与桌面画面，并完成断开清理 · ' + fmtFull(when(r)); tone = 'good';
  } else {
    headline = '最近一次连接未完成'; subline = errorText(r); tone = 'warn';
  }
  text('headline', headline);
  text('subline', subline);
  $('orb').dataset.tone = tone;

  // 主操作
  const locked = data.busy || data.loopEnabled;
  const connecting = data.busy && data.action === 'connect';
  $('connect').disabled = locked || !data.sessionAvailable;
  $('connect').classList.toggle('loading', connecting);
  text('connect-text', connecting ? '连接中' : '立即连接');
  $('power-connect').disabled = locked || !data.sessionAvailable;
  text('power-connect', data.busy && data.action === 'power-connect' ? '正在开机…' : '开机并进入系统');
  $('refresh').disabled = locked || !data.sessionAvailable;

  // 周期保活开关
  const sw = $('loop-switch');
  sw.setAttribute('aria-checked', String(data.loopEnabled));
  sw.disabled = !data.loopEnabled && (data.busy || !data.sessionAvailable);
  text('keepalive-detail', `${data.loopEnabled ? '运行中' : '已关闭'} · 每 ${data.intervalHours} 小时连接一次，保持 ${data.holdSeconds} 秒`);
}

// 每秒刷新：距上次成功、倒计时与外环进度
function renderLive() {
  if (!state) return;
  const ok = lastSuccess(state);
  if (ok) {
    const e = elapsed(Date.now() - new Date(when(ok)).getTime());
    const big = $('since-success');
    big.replaceChildren(document.createTextNode(e.value));
    if (e.unit) big.append(el('small', '', e.unit));
    text('since-success-at', fmtDay(when(ok)) + ' ' + fmtTime(when(ok)));
  } else {
    text('since-success', '—');
    text('since-success-at', '暂无成功记录');
  }

  let progress = 0, caption, next = '—';
  if (state.busy) {
    caption = '连接进行中';
    next = state.loopEnabled ? '本轮进行中' : '—';
  } else if (state.loopEnabled && state.nextRunAt) {
    const nextAt = new Date(state.nextRunAt).getTime();
    const span = state.intervalHours * HOUR;
    progress = Math.min(1, Math.max(0, 1 - (nextAt - Date.now()) / span));
    caption = '外环：本轮间隔已过 ' + Math.round(progress * 100) + '%';
    next = clockDiff(nextAt - Date.now());
  } else {
    caption = '周期保活未开启';
  }
  $('ring-progress').setAttribute('stroke-dashoffset', String(Math.round(1000 * (1 - progress))));
  $('ring-progress').classList.toggle('empty', progress <= 0);
  text('ring-caption', caption);
  text('next-countdown', next);
  $('next-countdown').title = state.loopEnabled && state.nextRunAt ? fmtFull(state.nextRunAt) : '';
}

function renderAttention(data) {
  let title = '', detail = '', label = '去登录';
  if (data.pending) {
    title = '等待设备验证'; detail = '验证短信已发送，请在 10 分钟内填写最新验证码。'; label = '填写验证码';
  } else if (data.authenticationRequired) {
    title = '登录已失效'; detail = '票据续登失败，需要手动登录；周期保活已无法继续。';
  } else if (!data.sessionAvailable) {
    title = '尚未登录'; detail = '登录后才能连接和开启周期保活。';
  }
  $('attention').hidden = !title;
  text('attention-title', title);
  text('attention-detail', detail);
  text('attention-action', label);
}

function renderTimeline(data) {
  const history = [...data.history].reverse(); // 旧 → 新
  const key = JSON.stringify([history.map(when), data.loopEnabled, data.nextRunAt, data.busy && data.action]);
  if (!history.some(r => when(r) === selectedKey)) selectedKey = history.length ? when(history.at(-1)) : null;
  $('timeline-empty').hidden = history.length > 0 || data.busy;
  if (key !== timelineKey) {
    timelineKey = key;
    const list = $('timeline');
    list.replaceChildren();
    for (const r of history) {
      const v = verdictOf(r);
      const item = el('li', 'node ' + v.tone);
      const button = el('button', 'node-button');
      button.type = 'button';
      button.dataset.key = when(r);
      button.setAttribute('aria-label', fmtFull(when(r)) + ' ' + v.label);
      button.append(el('span', 'node-dot'), el('span', 'node-day', fmtDay(when(r))), el('span', 'node-time', fmtTime(when(r))), el('span', 'node-tag', v.label));
      button.onclick = () => { selectedKey = when(r); renderSelection(); };
      item.append(button);
      list.append(item);
    }
    if (data.busy && (data.action === 'connect' || data.action === 'power-connect')) {
      const item = el('li', 'node live');
      const box = el('div', 'node-button');
      box.append(el('span', 'node-dot'), el('span', 'node-day', '现在'), el('span', 'node-time', fmtTime(new Date())), el('span', 'node-tag', '进行中'));
      item.append(box);
      list.append(item);
    }
    if (data.loopEnabled && data.nextRunAt && !data.busy) {
      const item = el('li', 'node future');
      const box = el('div', 'node-button');
      box.append(el('span', 'node-dot'), el('span', 'node-day', fmtDay(data.nextRunAt)), el('span', 'node-time', fmtTime(data.nextRunAt)), el('span', 'node-tag', '下一次'));
      item.append(box);
      list.append(item);
    }
  }
  renderSelection();
}

function renderSelection() {
  const r = state?.history.find(h => when(h) === selectedKey);
  for (const b of document.querySelectorAll('.node-button[data-key]')) {
    b.classList.toggle('selected', b.dataset.key === selectedKey);
    b.setAttribute('aria-pressed', String(b.dataset.key === selectedKey));
  }
  $('detail').hidden = !r;
  if (!r) return;

  const v = verdictOf(r);
  const verdict = $('detail-verdict');
  verdict.textContent = v.label;
  verdict.className = 'verdict ' + v.tone;
  text('detail-time', fmtFull(when(r)));
  text('detail-hold', r.controlHoldSeconds ? r.controlHoldSeconds + ' 秒' : '—');
  text('detail-attempt', r.maxAttempts > 1 ? `${r.attempt}/${r.maxAttempts}` : (r.attempt ? String(r.attempt) : '—'));
  text('detail-power', r.powerOnAccepted ? (r.powerOnCompleted ? '已完成' : '已受理') : '—');

  const list = $('detail-stages');
  list.replaceChildren();
  let blocked = false;
  STAGES.forEach((stage, i) => {
    let status;
    if (r.success || stage.ok(r)) status = blocked ? 'late' : 'done';
    else if (!blocked) { status = 'fail'; blocked = true; }
    else status = 'skip';
    const li = el('li', 'stage ' + status);
    li.append(el('span', 'stage-mark', status === 'fail' ? '✕' : (status === 'skip' ? String(i + 1) : '✓')), el('span', 'stage-name', stage.name));
    li.title = { done: '完成', late: '完成（发生在中断之后）', fail: '在此阶段中断', skip: '未到达' }[status];
    list.append(li);
  });

  $('detail-error').hidden = r.success;
  if (!r.success) {
    text('detail-error-text', errorText(r) + (r.errorType && !r.errorHint?.includes(r.errorType) ? '（' + r.errorType + '）' : ''));
    const meta = [r.failedStage && 'stage=' + r.failedStage, r.errorType, r.errorCode && 'code=' + r.errorCode, r.diagnosticCode && 'diag=' + r.diagnosticCode].filter(Boolean).join('  ');
    text('detail-error-meta', meta);
    $('detail-error-meta').hidden = !meta;
  }
}

function renderLogs(data) {
  const busyText = data.busy ? (ACTION_LABELS[data.action] || '执行中') : '空闲';
  text('console-state', busyText);
  $('console-state').classList.toggle('live', data.busy);
  const last = data.events.at(-1);
  text('console-last', last ? last.message : '');
  $('console-last').className = 'console-last ' + (last?.level || '');

  const lastId = last?.id ?? 0;
  if (lastId === lastEventId) return;
  const first = lastEventId === null;
  lastEventId = lastId;
  const box = $('logs');
  const stick = first || box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.replaceChildren();
  for (const e of data.events) {
    const row = el('div', 'log ' + e.level);
    row.append(el('time', '', new Date(e.at).toLocaleTimeString('zh-CN', TZ)), el('span', '', e.message));
    box.append(row);
  }
  if (stick) box.scrollTop = box.scrollHeight;
}

function renderSettings(data) {
  const select = $('target');
  if (!select.dataset.dirty) {
    select.replaceChildren();
    for (const m of data.machines) {
      const supported = m.originCompanyCode === 'ZTE';
      const option = el('option', '', m.machineName + (supported ? '' : '（暂不支持）'));
      option.value = m.machineId;
      option.disabled = !supported;
      select.append(option);
    }
    if (!select.options.length) {
      const option = el('option', '', '暂无设备，请登录后刷新');
      option.value = '';
      select.append(option);
    }
    select.value = data.targetId || '';
  }
  if (!$('interval').dataset.dirty) $('interval').value = data.intervalHours;
  if (!$('hold').dataset.dirty) $('hold').value = data.holdSeconds;

  $('mobile').placeholder = data.auth.mobileHint || '填写完整绑定手机号';
  $('username').placeholder = data.auth.usernameConfigured ? '已配置 · 留空保留' : '填写账号';
  $('password').placeholder = data.auth.passwordConfigured ? '已保存 · 留空保留' : '填写密码';
  text('account-hint', data.auth.mobileHint || '本机保存');
  const chip = $('session-chip');
  chip.textContent = data.authenticationRequired ? '已失效' : data.sessionAvailable ? '已登录' : '未登录';
  chip.className = 'chip ' + (data.sessionAvailable ? 'good' : 'bad');

  text('code-label', data.pending ? '设备验证短信验证码' : '登录短信验证码');
  text('challenge-hint', data.pending ? '设备验证短信已发送，请输入最新验证码。' : '');
  text('verify', data.pending ? '完成验证' : '验证');
  setTab(tab);

  const locked = data.busy || data.loopEnabled;
  for (const id of ['password-login', 'sms-send', 'verify', 'save', 'target', 'interval', 'hold',
    'mobile', 'username', 'password', 'selected_username']) $(id).disabled = locked;
  text('drawer-lock', data.loopEnabled ? '周期保活运行中，关闭后才能修改设置或登录。' : '有操作正在执行，完成后才能修改设置。');
  $('drawer-lock').hidden = !locked;
}

function render(data) {
  state = data;
  csrf = data.csrf;
  $('service').className = 'service online';
  text('service-text', '本地服务正常');
  document.body.classList.toggle('busy', data.busy);
  renderHero(data);
  renderLive();
  renderAttention(data);
  renderTimeline(data);
  renderSettings(data);
  renderLogs(data);
}

/* ---------- 设置抽屉 ---------- */
function setTab(value) {
  tab = value;
  for (const name of ['password', 'sms']) {
    const button = $('tab-' + name);
    button.classList.toggle('on', value === name);
    button.setAttribute('aria-selected', String(value === name));
    $(name + '-panel').hidden = value !== name;
  }
  $('verification').hidden = value === 'password' && !state?.pending;
}

let lastFocus = null;
function openDrawer(sectionId) {
  lastFocus = document.activeElement;
  const drawer = $('drawer');
  drawer.inert = false;
  drawer.setAttribute('aria-hidden', 'false');
  drawer.classList.add('open');
  $('scrim').hidden = false;
  $('open-settings').setAttribute('aria-expanded', 'true');
  document.body.classList.add('no-scroll');
  if (sectionId) {
    $(sectionId).scrollIntoView({ block: 'start' });
    const input = state?.pending ? $('code') : $(sectionId).querySelector('input,button,select');
    setTimeout(() => input?.focus(), 200);
  } else {
    setTimeout(() => $('close-settings').focus(), 200);
  }
}
function closeDrawer() {
  const drawer = $('drawer');
  drawer.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
  drawer.inert = true;
  $('scrim').hidden = true;
  $('open-settings').setAttribute('aria-expanded', 'false');
  document.body.classList.remove('no-scroll');
  lastFocus?.focus?.();
}

/* ---------- 事件 ---------- */
$('open-settings').onclick = () => openDrawer();
$('close-settings').onclick = closeDrawer;
$('scrim').onclick = closeDrawer;
document.addEventListener('keydown', e => { if (e.key === 'Escape' && $('drawer').classList.contains('open')) closeDrawer(); });
$('attention-action').onclick = () => openDrawer('login-group');

$('save').onclick = () => save(true);
$('refresh').onclick = () => action('devices');
$('connect').onclick = async () => { if (await save()) await action('connect'); };
$('power-connect').onclick = async () => {
  if (!confirm('将向当前云电脑发送开机请求，就绪后进入系统。是否继续？')) return;
  if (await save()) await action('power-connect');
};
$('loop-switch').onclick = async () => {
  if (state?.loopEnabled) await action('loop-stop');
  else if (await save()) await action('loop-start');
};
$('password-login').onclick = async () => { if (await save()) await action('password'); };
$('sms-send').onclick = async () => { if (await save()) await action('sms-send'); };
$('verify').onclick = async () => {
  const code = $('code').value.trim();
  if (!code) { toast('请输入验证码', true); $('code').focus(); return; }
  if (await action(state?.pending ? 'challenge' : 'sms-login', { code })) $('code').value = '';
};
$('code').addEventListener('keydown', e => { if (e.key === 'Enter' && !$('verify').disabled) $('verify').click(); });
$('tab-password').onclick = () => setTab('password');
$('tab-sms').onclick = () => setTab('sms');
for (const id of ['interval', 'hold', 'target']) {
  for (const type of ['input', 'change']) $(id).addEventListener(type, () => { $(id).dataset.dirty = '1'; });
}

function tick() {
  $('clock').textContent = new Date().toLocaleTimeString('zh-CN', TZ);
  renderLive();
}
tick();
setInterval(tick, 1000);
poll();
setInterval(poll, 1500);
