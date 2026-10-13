'use strict';
/* Argus SOC dashboard — vanilla JS, no dependencies.
   Served same-origin from the Argus FastAPI server; all REST calls are relative. */

/* ---------------- utils ---------------- */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const SEV_COLOR = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0284c7' };
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

/* REST rows carry mitre/compliance/entities/enrichment/triage as *_json strings;
   WebSocket alert frames carry them as native objects. Accept both. */
function J(v, fallback) {
  if (v == null || v === '') return fallback;
  if (typeof v === 'string') { try { return JSON.parse(v); } catch { return fallback; } }
  return v;
}
/* /api/v1/stats returns by_severity / by_rule as [{key, count}] lists. Normalize to {k: n}. */
function kvList(v) {
  if (Array.isArray(v)) {
    const o = {};
    for (const e of v) o[e.key] = e.count;
    return o;
  }
  return v || {};
}
function normAlert(a) {
  const n = Object.assign({}, a);
  n.mitre = J(a.mitre, J(a.mitre_json, [])) || [];
  n.compliance = J(a.compliance, J(a.compliance_json, {})) || {};
  n.entities = J(a.entities, J(a.entities_json, {})) || {};
  n.enrichment = J(a.enrichment, J(a.enrichment_json, {})) || {};
  n.triage = J(a.triage, J(a.triage_json, {})) || {};
  n.event_ids = J(a.event_ids, J(a.event_ids_json, [])) || [];
  return n;
}
function normIncident(i) {
  const n = Object.assign({}, i);
  n.agents = J(i.agents, J(i.agents_json, [])) || [];
  n.alert_ids = J(i.alert_ids, J(i.alert_ids_json, [])) || [];
  n.entities = J(i.entities, J(i.entities_json, {})) || {};
  n.mitre = J(i.mitre, J(i.mitre_json, [])) || [];
  return n;
}

function mitreUrl(t) {
  const p = String(t).split('.');
  return 'https://attack.mitre.org/techniques/' + p[0] + (p[1] ? '/' + p[1] : '') + '/';
}
function mitreChip(t) {
  return `<a class="chip" href="${mitreUrl(t)}" target="_blank" rel="noopener" title="Open in MITRE ATT&amp;CK">${esc(t)}</a>`;
}
function sevBadge(s) {
  const k = String(s || 'unknown').toLowerCase();
  return `<span class="sev sev-${esc(k)}">${esc(k)}</span>`;
}
function fmtTime(iso) {
  const d = new Date(iso);
  return isNaN(d) ? '—' : d.toLocaleString();
}
function shortClock(iso) {
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toLocaleTimeString([], { hour12: false });
}
function timeAgo(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return Math.floor(s) + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* ---------------- state ---------------- */
const S = {
  key: localStorage.getItem('argus_api_key') || '',
  view: 'overview',
  ws: null, wsOpen: false, retries: 0, pollTimer: null,
  alerts: [], incidents: [], agents: [], coverage: null,
  rules: [], rulesById: {},
  alertToIncident: {},
  ticker: [],
  incStatus: '',
  selectedInc: new Set(),
  activityDays: 14,
  notifs: [],
};

/* ---------------- API ---------------- */
async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {}, { 'X-API-Key': S.key });
  if (opts.body !== undefined && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  let r;
  try {
    r = await fetch(path, Object.assign({}, opts, { headers }));
  } catch (e) {
    throw new Error('network error: ' + e.message);
  }
  if (r.status === 401) {
    openSettings('The server rejected the API key (HTTP 401). Enter a valid key.');
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error('HTTP ' + r.status + ' on ' + path);
  return r.json();
}

/* ---------------- toasts ---------------- */
function toast(title, sub, kind = 'info', ms = 6500) {
  const box = $('toasts');
  const el = document.createElement('div');
  el.className = 'toast toast-' + kind;
  el.innerHTML = `<div class="t-title">${esc(title)}</div>` +
    (sub ? `<div class="t-sub">${esc(sub)}</div>` : '');
  const dismiss = () => { el.classList.add('out'); setTimeout(() => el.remove(), 320); };
  el.addEventListener('click', dismiss);
  box.appendChild(el);
  setTimeout(dismiss, ms);
  while (box.children.length > 5) box.firstChild.remove();
}

/* ---------------- settings (API key) ---------------- */
function openSettings(msg) {
  $('apiKeyInput').value = S.key || '';
  $('settingsOverlay').hidden = false;
  if (msg) toast('API key required', msg, 'error');
  setTimeout(() => $('apiKeyInput').focus(), 50);
}
function closeSettings() { $('settingsOverlay').hidden = true; }

/* ---------------- drawer ---------------- */
function showDrawer(html) {
  $('drawerBody').innerHTML = html;
  $('drawer').hidden = false;
  $('drawerOverlay').hidden = false;
  $('drawer').scrollTop = 0;
}
function closeDrawer() {
  $('drawer').hidden = true;
  $('drawerOverlay').hidden = true;
}

/* ---------------- shared render helpers ---------------- */
function renderEntities(e) {
  const out = Object.entries(e || {}).map(([k, v]) =>
    `<span class="chip">${esc(k)}: ${esc(Array.isArray(v) ? v.join(', ') : v)}</span>`);
  return out.length ? out.join('') : '<span class="muted">—</span>';
}
function renderCompliance(c) {
  const out = [];
  for (const [fw, reqs] of Object.entries(c || {})) {
    const name = fw.replace(/_/g, ' ').toUpperCase();
    (Array.isArray(reqs) ? reqs : [reqs]).forEach((r) => out.push(`<span class="chip">${esc(name)} ${esc(r)}</span>`));
  }
  return out.length ? out.join('') : '<span class="muted">—</span>';
}
function renderTriage(t) {
  if (!t || !Object.keys(t).length)
    return '<div class="muted">No suggestions for this alert yet.</div>';
  return `
    <div class="triage-box"><div class="t-head">Summary${t.confidence ? `<span class="conf">${esc(t.confidence)} confidence</span>` : ''}</div>
      <div>${esc(t.summary || '—')}</div></div>
    <div class="triage-box"><div class="t-head">Why it matters</div>
      <div>${esc(t.why_it_matters || '—')}</div></div>
    <div class="triage-box"><div class="t-head">Remediation</div>
      <ul>${(t.remediation || []).map((r) => `<li>${esc(r)}</li>`).join('') || '<li>—</li>'}</ul></div>`;
}
function renderEnrichment(enr) {
  const keys = Object.keys(enr || {});
  if (!keys.length) return '<div class="muted">No enrichment data.</div>';
  return keys.map((k) => {
    const e = enr[k] || {};
    const rep = String(e.reputation || 'unknown').toLowerCase();
    const cls = rep.includes('malicious') ? 'rep-malicious'
      : rep.includes('suspicious') ? 'rep-suspicious'
      : (rep.includes('clean') || rep.includes('harmless') || rep.includes('benign')) ? 'rep-clean'
      : 'rep-unknown';
    const details = Object.entries(e)
      .filter(([dk]) => dk !== 'reputation')
      .map(([dk, dv]) => `<div class="d-kv" style="margin-top:4px"><span class="k">${esc(dk)}</span>` +
        `<span class="v">${esc(typeof dv === 'object' ? JSON.stringify(dv) : dv)}</span></div>`).join('');
    return `<div class="triage-box"><div class="t-head">${esc(k)}` +
      `<span class="rep ${cls}" style="float:right">${esc(e.reputation || 'unknown')}</span></div>` +
      `<div class="d-kv"><span class="k">source</span><span class="v">${esc(e.source || (Array.isArray(e.sources) ? e.sources.join(', ') : '—'))}</span></div>${details}</div>`;
  }).join('');
}

/* ---------------- navigation ---------------- */
const LOADERS = {};
function showView(name) {
  S.view = name;
  document.querySelectorAll('.nav-btn').forEach((b) => {
    const on = b.dataset.view === name;
    b.classList.toggle('active', on);
    if (on) {
      const lbl = b.querySelector('.nav-label');
      const crumb = $('crumbCurrent');
      if (lbl && crumb) crumb.textContent = lbl.textContent.trim();
    }
  });
  document.querySelectorAll('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
  closeDrawer();
  paintSkeletons(name);
  if (LOADERS[name]) LOADERS[name]();
}
function refreshCurrent() { if (LOADERS[S.view]) LOADERS[S.view](); }

/* ---------------- ticker ---------------- */
function pushTicker(html) {
  S.ticker.unshift({ html, ts: new Date().toISOString() });
  S.ticker = S.ticker.slice(0, 20);
  renderTicker();
}
function renderTicker() {
  const track = $('tickerTrack');
  const items = S.ticker.length ? S.ticker : [{ html: '<span class="ticker-empty">Waiting for live updates…</span>', ts: null }];
  const half = items.map((i) =>
    `<span class="ticker-item">${i.ts ? `<span class="t-time">${esc(shortClock(i.ts))}</span>` : ''}${i.html}</span>`).join('');
  track.innerHTML = half + half; // duplicated for a seamless CSS loop
  track.style.animation = 'none';
  void track.offsetWidth;
  track.style.animation = '';
}

/* ---------------- nav badges ---------------- */
async function refreshNavBadges() {
  try {
    const stats = await api('/api/v1/stats');
    const bySev = kvList(stats.by_severity);
    const crit = (bySev.critical || 0) + (bySev.high || 0);
    const ab = $('navAlertCount');
    ab.textContent = crit > 999 ? '999+' : String(crit);
    ab.classList.toggle('show', crit > 0);
    const ib = $('navIncCount');
    const open = stats.incidents_open || 0;
    ib.textContent = open > 999 ? '999+' : String(open);
    ib.classList.toggle('show', open > 0);
  } catch { /* badges stay as-is */ }
}
const debouncedBadges = debounce(refreshNavBadges, 2000);

/* ---------------- rules cache ---------------- */
async function ensureRules() {
  if (S.rules.length) return;
  try {
    const d = await api('/api/v1/rules');
    S.rules = d.rules || [];
    S.rulesById = Object.fromEntries(S.rules.map((r) => [r.id, r]));
  } catch { /* leave empty */ }
}

/* ---------------- OVERVIEW ---------------- */
function renderDonut(bySev) {
  const total = SEV_ORDER.reduce((t, k) => t + (bySev[k] || 0), 0);
  // 42x42 viewBox: circle r=15.9155 has circumference exactly 100,
  // so dasharray percentages map 1:1 to arc fractions.
  let offset = 25, circles = '';
  for (const k of SEV_ORDER) {
    const frac = total ? ((bySev[k] || 0) / total) * 100 : 0;
    if (frac > 0.01) {
      circles += `<circle cx="21" cy="21" r="15.9155" fill="none" stroke="${SEV_COLOR[k]}" ` +
        `stroke-width="5" stroke-linecap="round" stroke-dasharray="${frac.toFixed(2)} 100" stroke-dashoffset="${offset.toFixed(2)}"/>`;
    }
    offset -= frac;
  }
  $('donutWrap').innerHTML =
    `<svg viewBox="0 0 42 42" width="190" height="190" role="img" aria-label="${total} alerts">${circles}` +
    `<text x="21" y="20.5" text-anchor="middle" class="donut-center" font-size="8.5">${total}</text>` +
    `<text x="21" y="26.5" text-anchor="middle" class="donut-sub" font-size="3">ALERTS</text></svg>`;
  $('donutLegend').innerHTML = SEV_ORDER.map((k) =>
    `<span class="legend-item"><span class="legend-swatch" style="background:${SEV_COLOR[k]};color:${SEV_COLOR[k]}"></span>` +
    `${k}<span class="legend-count">${bySev[k] || 0}</span></span>`).join('');
}

/* Animate stat numbers counting up from 0 on each overview load. */
function countUp(el, target) {
  const dur = 750, t0 = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(target * eased).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

async function loadOverview() {
  let stats;
  try { stats = await api('/api/v1/stats'); }
  catch (e) { if (!String(e.message).includes('unauthorized')) toast('Failed to load stats', e.message, 'error'); return; }
  S.stats = stats;
  await ensureRules();

  const cards = [
    { label: 'Events checked', value: stats.events, sub: 'total', color: '#0284c7', view: null },
    { label: 'Alerts', value: stats.alerts, sub: 'found so far', color: '#ea580c', view: 'alerts' },
    { label: 'Open cases', value: stats.incidents_open, sub: 'need a look', color: '#dc2626', view: 'incidents' },
    { label: 'Devices', value: stats.agents, sub: 'connected', color: '#059669', view: 'agents' },
  ];
  $('statGrid').innerHTML = cards.map((c) =>
    `<div class="stat-card" style="--sc:${c.color}${c.view ? ';cursor:pointer' : ''}"${c.view ? ` data-goto="${c.view}"` : ''}>` +
    `<div class="stat-label">${c.label}</div><div class="stat-value" data-count="${Number(c.value || 0)}">0</div>` +
    `<div class="stat-sub">${c.sub}</div></div>`).join('');
  document.querySelectorAll('#statGrid .stat-value[data-count]').forEach((el) =>
    countUp(el, Number(el.dataset.count) || 0));
  document.querySelectorAll('#statGrid .stat-card[data-goto]').forEach((el) =>
    el.addEventListener('click', () => showView(el.dataset.goto)));

  renderDonut(kvList(stats.by_severity));

  const ruleEntries = Object.entries(kvList(stats.by_rule)).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxR = (ruleEntries[0] && ruleEntries[0][1]) || 1;
  $('topRules').innerHTML = ruleEntries.length ? ruleEntries.map(([rid, n]) => {
    const r = S.rulesById[rid] || {};
    const color = SEV_COLOR[String(r.severity || '').toLowerCase()] || 'var(--accent)';
    return `<div class="bar-row"><span class="bar-label" title="${esc(r.name || rid)}">${esc(rid)}</span>` +
      `<span class="bar-count">${n}</span>` +
      `<div class="bar-track"><div class="bar-fill" style="width:${(n / maxR * 100).toFixed(1)}%;background:${color}"></div></div></div>`;
  }).join('') : '<div class="empty">No rule hits yet.</div>';

  const mitre = (stats.by_mitre || []).slice(0, 10);
  const maxM = (mitre[0] && mitre[0][1]) || 1;
  $('topMitre').innerHTML = mitre.length ? mitre.map(([t, n]) =>
    `<div class="bar-row"><span class="bar-label">${mitreChip(t)}</span>` +
    `<span class="bar-count">${n}</span>` +
    `<div class="bar-track"><div class="bar-fill" style="width:${(n / maxM * 100).toFixed(1)}%"></div></div></div>`).join('')
    : '<div class="empty">No MITRE techniques observed yet.</div>';

  try {
    const data = await api('/api/v1/alerts?limit=500');
    S.alerts = (data.alerts || []).map(normAlert);
    renderActivityChart(S.alerts, S.activityDays || 14);
    if (!S.notifsSeeded) {
      S.notifsSeeded = true;
      S.alerts.filter((a) => ['critical', 'high'].includes(String(a.severity || '').toLowerCase()))
        .slice(0, 8)
        .forEach((a) => addNotif('alert', a.title, `${a.severity} · ${a.rule_id || ''}`, a, false));
    }
  } catch { $('activityChart').innerHTML = '<div class="empty">Could not load activity data.</div>'; }
}
LOADERS.overview = loadOverview;

/* Stacked area chart: alert volume stacked by severity.
   days=1 -> hourly buckets (24h); otherwise daily buckets. Uses theme-aware
   .chart-* classes so the dark theme can recolor gridlines and ticks. */
function renderActivityChart(alerts, days) {
  days = days || 14;
  const hourly = days === 1;
  const N = hourly ? 24 : days;
  const now = new Date();
  const starts = [];
  if (hourly) {
    const h = new Date(now); h.setMinutes(0, 0, 0);
    for (let i = N - 1; i >= 0; i--) { const d = new Date(h); d.setHours(d.getHours() - i); starts.push(d); }
  } else {
    const d0 = new Date(now); d0.setHours(0, 0, 0, 0);
    for (let i = N - 1; i >= 0; i--) { const d = new Date(d0); d.setDate(d.getDate() - i); starts.push(d); }
  }
  const spanMs = hourly ? 3600000 : 86400000;
  const buckets = starts.map(() => ({ critical: 0, high: 0, medium: 0, low: 0 }));
  for (const a of (alerts || [])) {
    const t = new Date(a.ts);
    if (isNaN(t) || !(a.severity in buckets[0])) continue;
    const idx = Math.floor((t - starts[0]) / spanMs);
    if (idx >= 0 && idx < N) buckets[idx][a.severity]++;
  }
  const totals = buckets.map((b) => b.critical + b.high + b.medium + b.low);
  const grand = totals.reduce((s, v) => s + v, 0);
  const sevTotals = {};
  for (const s of SEV_ORDER) sevTotals[s] = buckets.reduce((t, b) => t + b[s], 0);
  $('activityLegend').innerHTML = SEV_ORDER.map((s) =>
    `<span class="legend-item"><span class="legend-swatch" style="background:${SEV_COLOR[s]}"></span>` +
    `${s}<span class="legend-count">${sevTotals[s]}</span></span>`).join('');
  if (!grand) { $('activityChart').innerHTML = `<div class="empty">No alerts in the last ${hourly ? '24 hours' : days + ' days'}.</div>`; return; }

  const W = 760, H = 290, L = 38, R = 14, T = 12, B = 30;
  const iw = W - L - R, ih = H - T - B;
  const maxV = Math.max(4, ...totals);
  const X = (i) => L + ((i + 0.5) / N) * iw;
  const Y = (v) => T + ih - (v / maxV) * ih;
  const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const label = (d) => hourly
    ? `${String(d.getHours()).padStart(2, '0')}:00`
    : `${d.getDate()} ${MON[d.getMonth()]}`;
  const every = hourly ? 4 : (N > 20 ? 5 : N > 10 ? 2 : 1);
  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Alert volume by severity">`;
  for (let i = 0; i <= 4; i++) {
    const v = Math.round(maxV * i / 4), yy = Y(v).toFixed(1);
    svg += `<line class="chart-gridline" x1="${L}" y1="${yy}" x2="${W - R}" y2="${yy}"/>` +
      `<text class="chart-tick" x="${L - 8}" y="${+yy + 4}" text-anchor="end">${v}</text>`;
  }
  starts.forEach((d, i) => {
    if (i % every === 0) svg += `<text class="chart-xlabel" x="${X(i).toFixed(1)}" y="${H - 8}" text-anchor="middle">${label(d)}</text>`;
  });
  let cum = new Array(N).fill(0);
  for (const sev of ['low', 'medium', 'high', 'critical']) {
    const nc = buckets.map((b, i) => cum[i] + b[sev]);
    const top = nc.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
    const bot = cum.map((v, i) => `${X(i).toFixed(1)},${Y(v).toFixed(1)}`).reverse().join(' ');
    svg += `<polygon points="${top} ${bot}" fill="${SEV_COLOR[sev]}" fill-opacity="0.78"><title>${sev}: ${sevTotals[sev]}</title></polygon>`;
    cum = nc;
  }
  svg += `<path class="chart-total-line" d="${cum.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ')}" fill="none"/>`;
  svg += '</svg>';
  $('activityChart').innerHTML = svg;
}

/* ---------------- ALERTS ---------------- */
async function loadAlerts() {
  let data;
  try { data = await api('/api/v1/alerts?limit=500'); }
  catch (e) { if (!String(e.message).includes('unauthorized')) toast('Failed to load alerts', e.message, 'error'); return; }
  S.alerts = (data.alerts || []).map(normAlert);
  renderAlerts();
}
function filteredAlerts() {
  const sevF = $('alertSevFilter').value;
  const q = $('alertSearch').value.trim().toLowerCase();
  return S.alerts.filter((a) => {
    if (sevF && String(a.severity).toLowerCase() !== sevF) return false;
    if (q) {
      const hay = [a.title, a.hostname, a.agent_id, a.rule_id, a.rule_name].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}
function exportAlertsCsv() {
  const rows = filteredAlerts();
  const head = ['id', 'time', 'severity', 'title', 'rule_id', 'rule_name', 'agent_id', 'hostname', 'mitre'];
  const q = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
  const lines = [head.join(',')].concat(rows.map((a) =>
    [a.id, a.ts, a.severity, a.title, a.rule_id, a.rule_name, a.agent_id, a.hostname,
     (a.mitre || []).join(';')].map(q).join(',')));
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'argus-alerts-' + new Date().toISOString().slice(0, 10) + '.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  toast('Exported', rows.length + ' alert' + (rows.length === 1 ? '' : 's') + ' saved as CSV', 'success');
}
function renderAlerts() {  const rows = filteredAlerts();
  $('alertsBody').innerHTML = rows.map((a) =>
    `<tr data-alert="${esc(a.id)}">` +
    `<td>${sevBadge(a.severity)}</td>` +
    `<td class="time" title="${esc(fmtTime(a.ts))}">${esc(timeAgo(a.ts))}</td>` +
    `<td title="${esc(a.title)}">${esc(a.title)}</td>` +
    `<td class="mono">${esc(a.rule_id)}</td>` +
    `<td class="mono">${esc(a.hostname || a.agent_id || '—')}</td>` +
    `<td>${renderEntities(a.entities)}</td></tr>`).join('');
  $('alertsEmpty').hidden = rows.length > 0;
  $('alertCount').textContent = `${rows.length} of ${S.alerts.length} alerts`;
  document.querySelectorAll('#alertsBody tr').forEach((tr) =>
    tr.addEventListener('click', () => {
      const a = S.alerts.find((x) => x.id === tr.dataset.alert);
      if (a) openAlertDrawer(a);
    }));
}
LOADERS.alerts = loadAlerts;

function openAlertDrawer(a) {
  a = normAlert(a);
  const tri = a.triage || {};
  const linked = S.alertToIncident[a.id];
  const html = `
    <div>${sevBadge(a.severity)} <span class="chip">${esc(a.rule_id)}</span></div>
    <h2>${esc(a.title)}</h2>
    <div class="desc">${esc(a.description || '')}</div>
    <div class="d-kv">
      <span class="k">Alert ID</span><span class="v">${esc(a.id)}</span>
      <span class="k">When</span><span class="v">${esc(fmtTime(a.ts))}</span>
      <span class="k">Device</span><span class="v">${esc(a.agent_id || '—')} (${esc(a.hostname || '—')})</span>
      <span class="k">Rule</span><span class="v">${esc(a.rule_name || a.rule_id)}</span>
      <span class="k">Events</span><span class="v">${esc(a.event_count ?? 1)} linked</span>
    </div>
    <div class="d-sec"><div class="d-sec-title">Attack methods</div>
      <div>${(a.mitre || []).map(mitreChip).join('') || '<span class="muted">—</span>'}</div></div>
    <div class="d-sec"><div class="d-sec-title">Standards</div>
      <div>${renderCompliance(a.compliance)}</div></div>
    <div class="d-sec"><div class="d-sec-title">Details found</div>
      <div>${renderEntities(a.entities)}</div></div>
    <div class="d-sec"><div class="d-sec-title">Threat information</div>
      ${renderEnrichment(a.enrichment)}</div>
    <div class="d-sec"><div class="d-sec-title">What to do</div>
      ${renderTriage(tri)}</div>
    <div class="d-sec"><div class="d-sec-title">What happened</div>
      ${renderAlertTimeline(a)}</div>
    <div class="d-sec"><div class="d-sec-title">Similar alerts</div>
      ${renderRelatedAlerts(a)}</div>
    ${linked ? `<div class="d-sec"><div class="d-sec-title">Linked case</div>
      <button class="linked-btn" id="linkedIncBtn">Open case ${esc(String(linked).slice(0, 8))} →</button></div>` : ''}`;
  showDrawer(html);
  if (linked) {
    $('linkedIncBtn').addEventListener('click', (ev) => { ev.stopPropagation(); openIncident(linked); });
  }
}

/* Vertical detection timeline for the alert drawer. */
function renderAlertTimeline(a) {
  const linked = S.alertToIncident[a.id];
  const sevC = SEV_COLOR[String(a.severity || '').toLowerCase()] || 'var(--primary)';
  const steps = [
    { t: 'Spotted', s: `${a.event_count ?? 1} event${(a.event_count ?? 1) === 1 ? '' : 's'} on ${esc(a.hostname || a.agent_id || 'unknown device')}`, ts: a.ts, done: true, c: 'var(--muted)' },
    { t: `Alert raised by ${esc(a.rule_id || 'Argus')}`, s: esc(a.rule_name || a.title || ''), ts: a.ts, done: true, c: sevC },
  ];
  if (linked) steps.push({ t: 'Grouped into a case', s: 'Case ' + String(linked).slice(0, 8), ts: null, done: true, c: 'var(--primary)' });
  else steps.push({ t: 'Case grouping', s: 'Not grouped yet', ts: null, done: false, c: 'var(--faint)' });
  return `<div class="d-timeline">` + steps.map((s) =>
    `<div class="d-step${s.done ? ' done' : ''}" style="--tc:${s.c}">` +
    `<div class="s-title">${s.t}</div><div class="s-sub">${s.s}${s.ts ? ' · ' + esc(fmtTime(s.ts)) : ''}</div></div>`).join('') + `</div>`;
}

/* Related alerts: same host or same rule, newest first, excluding self. */
function renderRelatedAlerts(a) {
  const rel = (S.alerts || [])
    .filter((x) => x.id !== a.id && (x.hostname === a.hostname || x.rule_id === a.rule_id))
    .sort((x, y) => String(y.ts).localeCompare(String(x.ts)))
    .slice(0, 5);
  if (!rel.length) return '<div class="muted small">No similar alerts right now.</div>';
  const html = `<div class="rel-list">` + rel.map((x) =>
    `<div class="rel-row" data-alert="${esc(x.id)}">${sevBadge(x.severity)}` +
    `<span class="t" title="${esc(x.title)}">${esc(x.title)}</span>` +
    `<span class="when">${esc(timeAgo(x.ts))}</span></div>`).join('') + `</div>`;
  setTimeout(() => document.querySelectorAll('#drawerBody .rel-row').forEach((el) =>
    el.addEventListener('click', () => {
      const found = (S.alerts || []).find((z) => z.id === el.dataset.alert);
      if (found) openAlertDrawer(found);
    })), 0);
  return html;
}

/* ---------------- INCIDENTS ---------------- */
async function loadIncidents() {
  const st = S.incStatus;
  let data;
  try { data = await api('/api/v1/incidents' + (st ? `?status=${encodeURIComponent(st)}` : '?limit=200')); }
  catch (e) { if (!String(e.message).includes('unauthorized')) toast('Failed to load cases', e.message, 'error'); return; }
  S.incidents = (data.incidents || []).map(normIncident);
  S.alertToIncident = {};
  for (const inc of S.incidents) {
    for (const aid of inc.alert_ids || []) if (!(aid in S.alertToIncident)) S.alertToIncident[aid] = inc.id;
  }
  renderIncidents();
}
function statusBadge(st) {
  const k = String(st || 'open').toLowerCase();
  const label = k === 'acknowledged' ? 'In progress' : k;
  return `<span class="status-badge status-${esc(k)}">${esc(label)}</span>`;
}
function flatEntities(e) {
  const vals = [];
  for (const v of Object.values(e || {})) {
    if (Array.isArray(v)) vals.push(...v.map(String));
    else if (v != null) vals.push(String(v));
  }
  return [...new Set(vals)].slice(0, 6);
}
function renderIncidents() {
  $('incCards').innerHTML = S.incidents.map((inc) => {
    const color = SEV_COLOR[String(inc.severity || '').toLowerCase()] || 'var(--accent)';
    const n = (inc.alert_ids || []).length;
    return `<div class="inc-card" style="--sc:${color}" data-inc="${esc(inc.id)}">
      <div class="inc-card-head"><div class="left"><input type="checkbox" class="inc-select" data-inc="${esc(inc.id)}" aria-label="Select case">${sevBadge(inc.severity)}</div>${statusBadge(inc.status)}</div>
      <div class="inc-title">${esc(inc.title)}</div>
      <div class="inc-meta">
        <div class="row"><span class="k">Alerts</span><span><strong>${n}</strong> linked</span></div>
        <div class="row"><span class="k">Devices</span><span>${(inc.agents || []).map((x) => `<span class="chip">${esc(x)}</span>`).join('') || '—'}</span></div>
        <div class="row"><span class="k">Details</span><span>${flatEntities(inc.entities).map((x) => `<span class="chip">${esc(x)}</span>`).join('') || '—'}</span></div>
        <div class="row"><span class="k">Attack</span><span>${(inc.mitre || []).slice(0, 5).map(mitreChip).join('') || '—'}</span></div>
        <div class="row"><span class="k">Updated</span><span class="mono">${esc(timeAgo(inc.updated || inc.created))}</span></div>
      </div>
      <div class="inc-actions">
        <button class="btn ack" data-act="ack" ${inc.status === 'acknowledged' || inc.status === 'closed' ? 'disabled' : ''}>Handle</button>
        <button class="btn close-btn" data-act="close" ${inc.status === 'closed' ? 'disabled' : ''}>Close</button>
      </div>
    </div>`;
  }).join('');
  $('incEmpty').hidden = S.incidents.length > 0;
  $('incCount').textContent = `${S.incidents.length} case${S.incidents.length === 1 ? '' : 's'}`;
  document.querySelectorAll('#incCards .inc-card').forEach((card) => {
    card.addEventListener('click', () => openIncident(card.dataset.inc));
    const sel = card.querySelector('.inc-select');
    if (sel) {
      sel.checked = S.selectedInc.has(card.dataset.inc);
      card.classList.toggle('selected', sel.checked);
      sel.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (sel.checked) S.selectedInc.add(card.dataset.inc);
        else S.selectedInc.delete(card.dataset.inc);
        card.classList.toggle('selected', sel.checked);
        updateBulkBar();
      });
    }
    card.querySelectorAll('button[data-act]').forEach((btn) =>
      btn.addEventListener('click', (ev) => { ev.stopPropagation(); incidentAction(card.dataset.inc, btn.dataset.act); }));
  });
  updateBulkBar();
}
LOADERS.incidents = loadIncidents;

/* Bulk selection bar for incidents. */
function updateBulkBar() {
  const n = S.selectedInc.size;
  $('bulkBar').hidden = n === 0;
  $('bulkCount').textContent = n ? `${n} selected` : '';
}
async function bulkIncidentAction(action) {
  const ids = [...S.selectedInc];
  if (!ids.length) return;
  let ok = 0, fail = 0;
  await Promise.all(ids.map(async (id) => {
    try {
      await api(`/api/v1/incidents/${encodeURIComponent(id)}/${action}`,
        { method: 'POST', body: JSON.stringify({ note: '' }) });
      ok++;
    } catch { fail++; }
  }));
  S.selectedInc.clear();
  toast(`Bulk ${action === 'ack' ? 'handle' : 'close'}`, `${ok} succeeded${fail ? `, ${fail} failed` : ''}`, fail ? 'error' : 'success');
  await loadIncidents();
  debouncedBadges();
}

async function incidentAction(id, action) {
  try {
    await api(`/api/v1/incidents/${encodeURIComponent(id)}/${action}`,
      { method: 'POST', body: JSON.stringify({ note: '' }) });
    toast('Case ' + (action === 'ack' ? 'picked up' : 'closed'), String(id).slice(0, 8), 'success');
    closeDrawer();
    await loadIncidents();
    debouncedBadges();
  } catch (e) {
    if (!String(e.message).includes('unauthorized')) toast('Action failed', e.message, 'error');
  }
}

async function openIncident(id) {
  let inc;
  try { inc = await api(`/api/v1/incidents/${encodeURIComponent(id)}`); }
  catch (e) { if (!String(e.message).includes('unauthorized')) toast('Failed to load case', e.message, 'error'); return; }
  inc = normIncident(inc);
  const alerts = (inc.alerts || []).map(normAlert)
    .sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
  const color = SEV_COLOR[String(inc.severity || '').toLowerCase()] || 'var(--accent)';
  const html = `
    <div style="display:flex;gap:8px;align-items:center">${sevBadge(inc.severity)}${statusBadge(inc.status)}</div>
    <h2>${esc(inc.title)}</h2>
    <div class="desc">${esc(inc.triage_summary || '')}</div>
    <div class="d-kv">
      <span class="k">Case ID</span><span class="v">${esc(inc.id)}</span>
      <span class="k">Created</span><span class="v">${esc(fmtTime(inc.created))}</span>
      <span class="k">Updated</span><span class="v">${esc(fmtTime(inc.updated))}</span>
      <span class="k">Devices</span><span class="v">${(inc.agents || []).map(esc).join(', ') || '—'}</span>
      ${inc.note ? `<span class="k">Note</span><span class="v">${esc(inc.note)}</span>` : ''}
    </div>
    <div class="d-sec"><div class="d-sec-title">Attack methods</div>
      <div>${(inc.mitre || []).map(mitreChip).join('') || '<span class="muted">—</span>'}</div></div>
    <div class="d-sec"><div class="d-sec-title">Details</div>
      <div>${flatEntities(inc.entities).map((x) => `<span class="chip">${esc(x)}</span>`).join('') || '<span class="muted">—</span>'}</div></div>
    <div class="d-sec"><div class="d-sec-title">Actions</div>
      <div style="display:flex;gap:8px">
        <button class="btn ack" id="dAck" ${inc.status === 'acknowledged' || inc.status === 'closed' ? 'disabled' : ''}>Handle</button>
        <button class="btn close-btn" id="dClose" ${inc.status === 'closed' ? 'disabled' : ''}>Close</button>
      </div></div>
    <div class="d-sec"><div class="d-sec-title">Alert timeline (${alerts.length})</div>
      <div class="timeline">
        ${alerts.length ? alerts.map((a) => `
          <div class="tl-item" style="--tc:${SEV_COLOR[String(a.severity || '').toLowerCase()] || 'var(--accent)'}" data-alert="${esc(a.id)}">
            <div class="tl-title">${esc(a.title)}</div>
            <div class="tl-meta">${esc(a.rule_id)} · ${esc(fmtTime(a.ts))}</div>
          </div>`).join('') : '<div class="muted">No alerts attached.</div>'}
      </div></div>`;
  showDrawer(html);
  $('dAck').addEventListener('click', () => incidentAction(inc.id, 'ack'));
  $('dClose').addEventListener('click', () => incidentAction(inc.id, 'close'));
  document.querySelectorAll('#drawerBody .tl-item').forEach((el) =>
    el.addEventListener('click', () => {
      const a = alerts.find((x) => x.id === el.dataset.alert);
      if (a) openAlertDrawer(a);
    }));
}

/* ---------------- AGENTS ---------------- */
function riskColor(score) {
  if (score >= 70) return '#dc2626';
  if (score >= 40) return '#ea580c';
  if (score >= 15) return '#d97706';
  return '#059669';
}
async function loadAgents() {
  let data;
  try { data = await api('/api/v1/agents'); }
  catch (e) { if (!String(e.message).includes('unauthorized')) toast('Failed to load agents', e.message, 'error'); return; }
  S.agents = data.agents || [];
  const online = S.agents.filter((a) => a.online).length;
  $('agentsBody').innerHTML = S.agents.map((a) => {
    const score = Math.round(Number(a.risk_score) || 0);
    return `<tr>
      <td><span class="online-dot ${a.online ? 'on' : 'off'}">${a.online ? 'Online' : 'Offline'}</span></td>
      <td><strong>${esc(a.hostname || a.id)}</strong></td>
      <td class="mono">${esc(a.id)}</td>
      <td class="mono">${esc(a.os || '—')}</td>
      <td class="mono">${esc(a.version || '—')}</td>
      <td><div class="risk-bar"><div class="risk-track"><div class="risk-fill" style="width:${score}%;background:${riskColor(score)}"></div></div><span class="risk-num">${score}</span></div></td>
      <td class="time" title="${esc(fmtTime(a.last_seen))}">${esc(timeAgo(a.last_seen))}</td>
    </tr>`;
  }).join('');
  $('agentsEmpty').hidden = S.agents.length > 0;
  $('agentCount').textContent = `${S.agents.length} device${S.agents.length === 1 ? '' : 's'} · ${online} online`;
}
LOADERS.agents = loadAgents;

/* ---------------- COVERAGE ---------------- */
async function loadCoverage() {
  let data;
  try { data = await api('/api/v1/coverage'); }
  catch (e) { if (!String(e.message).includes('unauthorized')) toast('Failed to load coverage', e.message, 'error'); return; }
  S.coverage = data;
  renderCoverage();
}
/* MITRE technique -> tactic mapping (for the coverage heatmap). */
const TACTIC_ORDER = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
const TECH_TACTIC = {
  'T1003': 'Credential Access', 'T1003.001': 'Credential Access', 'T1003.008': 'Credential Access',
  'T1021.004': 'Lateral Movement',
  'T1041': 'Exfiltration', 'T1048': 'Exfiltration',
  'T1053.003': 'Persistence',
  'T1059': 'Execution', 'T1059.004': 'Execution',
  'T1070': 'Defense Evasion', 'T1070.004': 'Defense Evasion',
  'T1071': 'Command and Control', 'T1071.004': 'Command and Control',
  'T1078': 'Persistence', 'T1098.004': 'Persistence',
  'T1110.001': 'Credential Access',
  'T1136': 'Persistence', 'T1136.001': 'Persistence',
  'T1204.002': 'Execution',
  'T1222.002': 'Defense Evasion',
  'T1486': 'Impact',
  'T1505.003': 'Persistence',
  'T1543.002': 'Persistence', 'T1547.006': 'Persistence',
  'T1548.003': 'Privilege Escalation',
  'T1562.001': 'Defense Evasion', 'T1562.004': 'Impact',
  'T1611': 'Privilege Escalation',
};

/* ATT&CK navigator-style heatmap: techniques grouped by tactic, colored by alert volume. */
function renderHeatmap() {
  const el = $('attackHeatmap');
  if (!el) return;
  const cov = (S.coverage && S.coverage.coverage) || {};
  const techs = Object.keys(cov);
  if (!techs.length) { el.innerHTML = '<div class="empty">No coverage data available.</div>'; return; }
  const counts = {};
  for (const [t, n] of (S.stats && S.stats.by_mitre) || []) counts[t] = n;
  const maxC = Math.max(1, ...Object.values(counts), 0);
  const byTactic = {};
  for (const t of techs) {
    const tac = TECH_TACTIC[t] || 'Other';
    (byTactic[tac] = byTactic[tac] || []).push(t);
  }
  const cols = TACTIC_ORDER.filter((t) => byTactic[t]);
  if (byTactic.Other) cols.push('Other');
  el.innerHTML = cols.map((tac) => {
    const tiles = byTactic[tac].sort().map((t) => {
      const c = counts[t] || 0;
      const heat = c / maxC;
      const bg = c ? `background:rgba(29,78,216,${(0.18 + 0.82 * heat).toFixed(2)})` : '';
      const hot = heat > 0.45 ? ' hot' : '';
      return `<button class="hm-tile${hot}" style="${bg}" data-tech="${esc(t)}" title="${esc(t)} — ${c} alert${c === 1 ? '' : 's'}. Click to filter.">${esc(t)}<span class="hm-count">${c} alert${c === 1 ? '' : 's'}</span></button>`;
    }).join('');
    return `<div class="hm-col"><div class="hm-col-head">${esc(tac)}</div>${tiles}</div>`;
  }).join('');
  el.querySelectorAll('.hm-tile').forEach((b) => b.addEventListener('click', () => {
    $('covSearch').value = b.dataset.tech;
    renderCoverage();
    $('covSearch').focus();
  }));
}

function renderCoverage() {
  const cov = (S.coverage && S.coverage.coverage) || {};
  const rules = (S.coverage && S.coverage.rules) || [];
  const nameById = Object.fromEntries(rules.map((r) => [r.id, r.name || r.id]));
  $('covTechCount').textContent = S.coverage ? S.coverage.techniques : 0;
  $('covRuleCount').textContent = rules.length;
  const q = $('covSearch').value.trim().toLowerCase();
  const rows = Object.entries(cov)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .filter(([t, ids]) => !q || t.toLowerCase().includes(q) ||
      ids.some((id) => String(id).toLowerCase().includes(q)));
  $('coverageBody').innerHTML = rows.map(([t, ids]) =>
    `<tr><td>${mitreChip(t)}</td>` +
    `<td>${ids.map((id) => `<span class="chip" title="${esc(nameById[id] || id)}">${esc(id)}</span>`).join('')}</td>` +
    `<td class="mono">${ids.length}</td></tr>`).join('');
  $('coverageEmpty').hidden = rows.length > 0;
  renderHeatmap();
}
LOADERS.coverage = loadCoverage;

/* ---------------- RULES ---------------- */
async function loadRules() {
  await ensureRules();
  renderRules();
}
function renderRules() {
  const q = $('ruleSearch').value.trim().toLowerCase();
  const rows = S.rules.filter((r) => !q ||
    [r.id, r.name, r.severity, r.source, (r.mitre || []).join(' ')].join(' ').toLowerCase().includes(q));
  $('rulesBody').innerHTML = rows.map((r) =>
    `<tr><td class="mono"><strong>${esc(r.id)}</strong></td>` +
    `<td>${esc(r.name || '')}<div class="muted tiny">${esc(r.description || '')}</div></td>` +
    `<td>${sevBadge(r.severity)}</td>` +
    `<td>${(r.mitre || []).map(mitreChip).join('') || '<span class="muted">—</span>'}</td>` +
    `<td class="mono">${esc(r.source || '—')}</td></tr>`).join('');
  $('rulesEmpty').hidden = rows.length > 0;
  $('ruleCount').textContent = `${rows.length} of ${S.rules.length} rules loaded`;
}
LOADERS.rules = loadRules;

/* ---------------- WebSocket live feed ---------------- */
function wsUrl() {
  return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/feed';
}
function setConn(state, label) {
  const pill = $('connPill');
  pill.className = 'pill ' + state;
  $('connText').textContent = label;
}
function connectWS() {
  if (S.wsOpen) return;
  let ws;
  try { ws = new WebSocket(wsUrl()); } catch { scheduleReconnect(); return; }
  S.ws = ws;
  ws.onopen = () => {
    S.wsOpen = true; S.retries = 0;
    stopPolling(); setConn('live', 'LIVE');
  };
  ws.onmessage = (ev) => { try { handleFrame(JSON.parse(ev.data)); } catch { /* ignore */ } };
  ws.onclose = () => {
    S.wsOpen = false;
    setConn('reconnecting', 'RECONNECTING');
    scheduleReconnect();
  };
  ws.onerror = () => { try { ws.close(); } catch { /* ignore */ } };
}
function scheduleReconnect() {
  S.retries += 1;
  if (S.retries >= 3 && !S.pollTimer) {
    setConn('polling', 'POLLING');
    startPolling();
    toast('WebSocket unavailable', 'Falling back to 15s REST polling.', 'info');
  }
  const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(S.retries, 5)));
  setTimeout(() => { if (!S.wsOpen) connectWS(); }, delay);
}
function startPolling() {
  stopPolling();
  refreshCurrent();
  S.pollTimer = setInterval(refreshCurrent, 15000);
}
function stopPolling() {
  if (S.pollTimer) { clearInterval(S.pollTimer); S.pollTimer = null; }
}

function handleFrame(f) {
  if (!f || typeof f !== 'object') return;
  switch (f.type) {
    case 'hello':
      break;
    case 'alert': {
      const a = normAlert(f.alert || {});
      S.alerts.unshift(a);
      S.alerts = S.alerts.slice(0, 500);
      pushTicker(`${sevBadge(a.severity)} <span>${esc(a.title)}</span>`);
      toast('New ' + String(a.severity || 'alert') + ' alert', a.title, String(a.severity || 'info').toLowerCase());
      if (['critical', 'high'].includes(String(a.severity || '').toLowerCase()))
        addNotif('alert', a.title, `${a.severity} · ${a.rule_id || ''}`, a, true);
      if (S.view === 'alerts') renderAlerts();
      if (S.view === 'overview') loadOverview();
      debouncedBadges();
      break;
    }
    case 'incident': {
      const inc = normIncident(f.incident || f);
      pushTicker(`<span class="chip">case</span> <span>${esc(inc.title || inc.id || '')}</span>`);
      toast('Case update', inc.title || String(inc.id || ''), 'info');
      addNotif('incident', inc.title || 'Case update', String(inc.status || ''), inc, true);
      if (S.view === 'incidents') loadIncidents();
      debouncedBadges();
      break;
    }
    case 'ingest': {
      const acc = f.accepted || 0, na = f.new_alerts || 0;
      pushTicker(`<span class="chip">ingest</span> <span>${acc} event${acc === 1 ? '' : 's'} accepted${na ? ` · ${na} new alert${na === 1 ? '' : 's'}` : ''}</span>`);
      if (S.view === 'overview') loadOverview();
      debouncedBadges();
      break;
    }
    case 'notification': {
      const msg = f.message || f.detail || f.text || '';
      pushTicker(`<span class="chip">notice</span> <span>${esc(f.title || msg)}</span>`);
      toast(f.title || 'Notification', msg, 'info');
      break;
    }
    case 'event':
    case 'agent':
      break; // frames exist for future use; nothing to render yet
    default:
      break;
  }
}

/* ---------------- init ---------------- */
function wire() {
  document.querySelectorAll('.nav-btn').forEach((b) =>
    b.addEventListener('click', () => showView(b.dataset.view)));

  $('settingsBtn').addEventListener('click', () => openSettings());
  $('saveKeyBtn').addEventListener('click', () => {
    const v = $('apiKeyInput').value.trim();
    S.key = v;
    localStorage.setItem('argus_api_key', S.key);
    closeSettings();
    toast('API key saved', 'Reconnecting…', 'success', 3000);
    if (S.ws) { try { S.ws.close(); } catch { /* ignore */ } }
    S.wsOpen = false; S.retries = 0;
    connectWS();
    refreshCurrent();
    refreshNavBadges();
  });
  $('apiKeyInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('saveKeyBtn').click();
  });

  $('alertSevFilter').addEventListener('change', renderAlerts);
  $('alertSearch').addEventListener('input', debounce(renderAlerts, 200));
  $('covSearch').addEventListener('input', debounce(renderCoverage, 200));
  $('ruleSearch').addEventListener('input', debounce(renderRules, 200));

  document.querySelectorAll('#incTabs .tab').forEach((t) =>
    t.addEventListener('click', () => {
      document.querySelectorAll('#incTabs .tab').forEach((x) => x.classList.remove('active'));
      t.classList.add('active');
      S.incStatus = t.dataset.status;
      loadIncidents();
    }));

  $('drawerClose').addEventListener('click', closeDrawer);
  $('drawerOverlay').addEventListener('click', closeDrawer);
  wireUpgrades();
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (!$('settingsOverlay').hidden) closeSettings();
      else if (!$('drawer').hidden) closeDrawer();
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  wire();
  renderTicker();
  if (!S.key) openSettings();
  showView('overview');
  refreshNavBadges();
  if (S.key) connectWS();
});

/* ============================================================
   UPGRADE PACK — theme, skeletons, command palette,
   notification center, chart ranges, bulk actions, CSV export
   ============================================================ */

/* ---------------- Theme ---------------- */
function initTheme() {
  let t = 'light';
  try { t = localStorage.getItem('argus_theme') || 'light'; } catch (e) { /* ignore */ }
  document.documentElement.dataset.theme = t === 'dark' ? 'dark' : 'light';
}
function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('argus_theme', next); } catch (e) { /* ignore */ }
}

/* ---------------- Skeleton loaders ---------------- */
function paintSkeletons(view) {
  const sk = (cls, n) => Array(n).fill(`<div class="skeleton ${cls}"></div>`).join('');
  const skRows = (n) => `<tr><td colspan="8" style="padding:12px 16px;border:none">${sk('sk-row', n)}</td></tr>`;
  try {
    if (view === 'overview') {
      $('statGrid').innerHTML = sk('sk-stat', 4);
      $('activityChart').innerHTML = '<div class="skeleton sk-panel"></div>';
      $('donutWrap').innerHTML = ''; $('donutLegend').innerHTML = '';
      $('topRules').innerHTML = sk('sk-row', 6); $('topMitre').innerHTML = sk('sk-row', 6);
    } else if (view === 'alerts') {
      $('alertsBody').innerHTML = skRows(8);
    } else if (view === 'incidents') {
      $('incCards').innerHTML = sk('sk-panel', 3);
    } else if (view === 'agents') {
      $('agentsBody').innerHTML = skRows(3);
    } else if (view === 'coverage') {
      $('attackHeatmap').innerHTML = '<div class="skeleton sk-panel"></div>';
      $('coverageBody').innerHTML = skRows(8);
    } else if (view === 'rules') {
      $('rulesBody').innerHTML = skRows(8);
    }
  } catch (e) { /* view not fully built yet; ignore */ }
}

/* ---------------- Notification center ---------------- */
function getReadNotifIds() {
  try { return new Set(JSON.parse(localStorage.getItem('argus_notif_read') || '[]')); }
  catch (e) { return new Set(); }
}
function saveReadNotifIds(set) {
  try { localStorage.setItem('argus_notif_read', JSON.stringify([...set].slice(-200))); } catch (e) { /* ignore */ }
}
function addNotif(kind, title, sub, ref, unread) {
  const rid = (ref && (ref.id || ref.alert_id)) ? String(ref.id || ref.alert_id) : Date.now().toString(36) + Math.random().toString(16).slice(2);
  const id = kind + ':' + rid;
  if (S.notifs.some((n) => n.id === id)) return;
  S.notifs.unshift({ id, kind, title: String(title || kind), sub: String(sub || ''), ts: new Date().toISOString(), ref: ref || null });
  S.notifs = S.notifs.slice(0, 30);
  if (!unread) { const r = getReadNotifIds(); r.add(id); saveReadNotifIds(r); }
  updateNotifBadge();
  if (!$('notifDropdown').hidden) renderNotifs();
}
function updateNotifBadge() {
  const read = getReadNotifIds();
  const n = S.notifs.filter((x) => !read.has(x.id)).length;
  const b = $('notifBadge');
  if (!b) return;
  b.hidden = n === 0;
  b.textContent = n > 9 ? '9+' : String(n);
}
function renderNotifs() {
  const read = getReadNotifIds();
  $('notifList').innerHTML = S.notifs.length ? S.notifs.map((n) =>
    `<div class="notif-item${read.has(n.id) ? '' : ' unread'}" data-nid="${esc(n.id)}" role="menuitem">` +
    `<div class="n-body"><div class="n-title">${esc(n.title)}</div>` +
    `<div class="n-when">${esc(timeAgo(n.ts))}${n.sub ? ' · ' + esc(n.sub) : ''}</div></div></div>`).join('')
    : '<div class="notif-empty">No notifications yet. New critical and high alerts will appear here.</div>';
  document.querySelectorAll('#notifList .notif-item').forEach((el) =>
    el.addEventListener('click', () => {
      const n = S.notifs.find((x) => x.id === el.dataset.nid);
      const r2 = getReadNotifIds(); r2.add(el.dataset.nid); saveReadNotifIds(r2);
      updateNotifBadge(); renderNotifs();
      $('notifDropdown').hidden = true;
      if (n && n.ref) {
        if (n.kind === 'alert') openAlertDrawer(n.ref);
        else if (n.kind === 'incident' && n.ref.id) openIncident(n.ref.id);
      }
    }));
}

/* ---------------- Command palette ---------------- */
let paletteIdx = 0, paletteItems = [];
function fuzzyMatch(hay, q) {
  hay = String(hay || '').toLowerCase();
  q = String(q || '').toLowerCase().trim();
  if (!q) return true;
  let hi = 0;
  for (const ch of q) { hi = hay.indexOf(ch, hi); if (hi === -1) return false; hi++; }
  return true;
}
function buildPaletteIndex() {
  const items = [];
  const views = [['overview', 'Overview'], ['alerts', 'Alerts'], ['incidents', 'Cases'], ['agents', 'Devices'], ['coverage', 'Coverage'], ['rules', 'Rules']];
  for (const [v, label] of views)
    items.push({ kind: 'view', label, sub: 'Go to view', hay: `${label} view ${v}`, run: () => showView(v) });
  for (const a of (S.alerts || []).slice(0, 200))
    items.push({ kind: 'alert', label: a.title || a.id, sub: `${a.severity || ''} · ${a.rule_id || ''}`, hay: `${a.title} ${a.rule_id} ${a.hostname} ${a.id}`, run: () => openAlertDrawer(a) });
  for (const i of (S.incidents || []).slice(0, 100))
    items.push({ kind: 'case', label: i.title || i.id, sub: String(i.status || ''), hay: `${i.title} ${i.status} ${i.id}`, run: () => openIncident(i.id) });
  for (const r of (S.rules || []).slice(0, 100))
    items.push({ kind: 'rule', label: `${r.id} — ${r.name || ''}`, sub: String(r.severity || ''), hay: `${r.id} ${r.name}`, run: () => { showView('rules'); $('ruleSearch').value = r.id; renderRules(); } });
  for (const g of (S.agents || []).slice(0, 100))
    items.push({ kind: 'device', label: g.hostname || g.agent_id || 'device', sub: String(g.os || ''), hay: `${g.hostname} ${g.agent_id}`, run: () => showView('agents') });
  return items;
}
function openPalette() {
  paletteIdx = 0;
  $('paletteOverlay').hidden = false;
  $('paletteInput').value = '';
  renderPalette('');
  setTimeout(() => $('paletteInput').focus(), 30);
}
function closePalette() { $('paletteOverlay').hidden = true; }
function renderPalette(q) {
  const hits = buildPaletteIndex().filter((it) => fuzzyMatch(it.hay, q)).slice(0, 40);
  const order = ['view', 'alert', 'case', 'rule', 'device'];
  paletteItems = [];
  for (const k of order) for (const it of hits.filter((h) => h.kind === k)) paletteItems.push(it);
  paletteIdx = Math.min(paletteIdx, Math.max(0, paletteItems.length - 1));
  let html = '', pi = 0;
  for (const k of order) {
    const g = hits.filter((h) => h.kind === k);
    if (!g.length) continue;
    html += `<div class="palette-group">${k}s</div>`;
    for (const it of g) {
      html += `<button class="palette-item${pi === paletteIdx ? ' selected' : ''}" data-pi="${pi}">` +
        `<span class="p-kind">${k}</span><span class="p-main" title="${esc(it.label)}">${esc(it.label)}</span>` +
        `<span class="p-sub">${esc(it.sub || '')}</span></button>`;
      pi++;
    }
  }
  $('paletteResults').innerHTML = html || '<div class="palette-empty">No matches.</div>';
  document.querySelectorAll('#paletteResults .palette-item').forEach((el) =>
    el.addEventListener('click', () => {
      const it = paletteItems[+el.dataset.pi];
      closePalette();
      if (it) it.run();
    }));
  const sel = document.querySelector('#paletteResults .palette-item.selected');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}

/* ---------------- Extra wiring ---------------- */
function wireUpgrades() {
  initTheme();
  $('themeBtn').addEventListener('click', toggleTheme);

  /* palette */
  $('paletteTrigger').addEventListener('click', openPalette);
  $('paletteOverlay').addEventListener('click', (e) => { if (e.target === $('paletteOverlay')) closePalette(); });
  $('paletteInput').addEventListener('input', () => { paletteIdx = 0; renderPalette($('paletteInput').value); });
  $('paletteInput').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); paletteIdx = Math.min(paletteItems.length - 1, paletteIdx + 1); renderPalette($('paletteInput').value); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); paletteIdx = Math.max(0, paletteIdx - 1); renderPalette($('paletteInput').value); }
    else if (e.key === 'Enter') { const it = paletteItems[paletteIdx]; closePalette(); if (it) it.run(); }
  });
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); }
    else if (e.key === 'Escape') {
      if (!$('paletteOverlay').hidden) closePalette();
      else if (!$('notifDropdown').hidden) $('notifDropdown').hidden = true;
    }
  });

  /* notifications */
  updateNotifBadge();
  $('notifBtn').addEventListener('click', (e) => {
    e.stopPropagation();
    const dd = $('notifDropdown');
    dd.hidden = !dd.hidden;
    if (!dd.hidden) renderNotifs();
  });
  $('notifClear').addEventListener('click', (e) => {
    e.stopPropagation();
    saveReadNotifIds(new Set(S.notifs.map((n) => n.id)));
    updateNotifBadge(); renderNotifs();
  });
  document.addEventListener('click', (e) => {
    if (!$('notifDropdown').hidden && !e.target.closest('.notif-wrap')) $('notifDropdown').hidden = true;
  });

  /* activity chart ranges */
  document.querySelectorAll('#activityRange button').forEach((b) =>
    b.addEventListener('click', () => {
      document.querySelectorAll('#activityRange button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      S.activityDays = parseInt(b.dataset.days, 10) || 14;
      if ((S.alerts || []).length) renderActivityChart(S.alerts, S.activityDays);
      else loadOverview();
    }));

  /* CSV export */
  $('exportCsvBtn').addEventListener('click', exportAlertsCsv);

  /* bulk incident actions */
  $('bulkAck').addEventListener('click', () => bulkIncidentAction('ack'));
  $('bulkClose').addEventListener('click', () => bulkIncidentAction('close'));
  $('bulkClear').addEventListener('click', () => { S.selectedInc.clear(); renderIncidents(); });
}
