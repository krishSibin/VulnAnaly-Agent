// ─────────────────────────────────────────────────────────────────────────────
//  Remediation Desk — app.js
// ─────────────────────────────────────────────────────────────────────────────
let vulns    = [];   // findings, highest priority first (server sorts them)
let history  = [];   // patch runs, newest first
let nodes    = [];
let filter   = 'all';
let openId   = null; // sys_id shown in the detail drawer
let editingNode = null;
let justPatched = null; // sys_id whose logs should animate in once
let sync = null;        // agent's background ServiceNow sync status
let automation = null;  // autopilot settings from the agent
let running = [];       // sys_ids being remediated right now
let feedAfter = 0;      // last activity id received
let feedFilter = 'all';
let feedItems = [];
const SOURCE_LABEL = { agent: 'Agent', ai: 'AI review', node: 'Node', servicenow: 'ServiceNow', team: 'Server team' };

const DEFAULT_NOTE = 'Requesting approval for automated patch execution';

// Results reported by a node after a check/install run
const RESULT_LABEL = {
  running:       'running…',
  already_fixed: 'already at a safe version',
  fixed:         'upgraded and verified',
  vulnerable:    'still vulnerable (check-only node)',
  failed:        'update attempted, not verified',
  not_installed: 'software not found on the node',
  manual:        'needs a manual patch',
  version_unavailable: 'approved version not available',
};

document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('[data-filter]').forEach(c => c.addEventListener('click', () => {
    filter = c.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach(x => x.classList.toggle('active', x === c));
    renderQueue();
  }));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDetail(); });
  document.querySelectorAll('[data-feed]').forEach(c => c.addEventListener('click', () => {
    feedFilter = c.dataset.feed;
    document.querySelectorAll('[data-feed]').forEach(x => x.classList.toggle('active', x === c));
    renderFeed(true);
  }));
  pollActivity();
  setInterval(pollActivity, 2000);

  loadConfig();
  refreshNodes();
  loadHistory();
  await refreshFromState();
  if (!vulns.length && !(sync && (sync.running || sync.last_at))) fetchVulnerabilities();

  setInterval(refreshNodes, 15000);
  setInterval(refreshFromState, 20000);
  setInterval(renderLede, 30000);
  // While a server team is deciding, check for their answer every 3 s
  setInterval(() => { if (vulns.some(v => v.approval_status === 'Awaiting Approval')) refreshFromState(); }, 3000);
});

// ─── Tabs ─────────────────────────────────────────────────────────────────────
function switchTab(tab) {
  ['activity', 'queue', 'servers', 'history', 'settings'].forEach(t => {
    document.getElementById(`tab-${t}`).hidden = t !== tab;
    document.getElementById(`nav-${t}`).classList.toggle('active', t === tab);
  });
  if (tab === 'history') loadHistory();
  if (tab === 'servers') refreshNodes();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function apiFetch(url, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 4000);
}

function when(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
               : d.toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

// Risk tier from ServiceNow's rating ("1 - Critical"…); unrated items fall back to the score
function tier(v) {
  const r = String(v.risk_rating || '').trim()[0];
  const s = Number(v.risk_score) || 0;
  const byScore = s >= 90 ? '1' : s >= 70 ? '2' : s >= 40 ? '3' : s > 0 ? '4' : '5';
  const key = ['1', '2', '3', '4'].includes(r) ? r : byScore;
  return {
    '1': { cls: 't-crit', label: 'Critical' },
    '2': { cls: 't-high', label: 'High' },
    '3': { cls: 't-mod',  label: 'Moderate' },
    '4': { cls: 't-low',  label: 'Low' },
    '5': { cls: 't-none', label: 'Not rated' },
  }[key];
}

function stage(v) {
  if ((v.state || '').includes('Closed')) return 'patched';
  return { 'Awaiting Approval': 'waiting', 'Approved': 'ready', 'Rejected': 'rejected' }[v.approval_status] || 'needs';
}

// ServiceNow titles unlinked items "... detected on <host>"
function titleOf(v) {
  const s = String(v.summary || v.short_description || '').trim();
  return !s || s.startsWith('...') ? null : s;
}

function isNew(v) {
  return v.new && v.added_at && Date.now() - new Date(v.added_at) < 60 * 60000;
}

function nodeFor(v) { return nodes.find(n => n.node_id === v.target_node_id); }
function runFor(v)  { return history.find(h => h.sys_id === v.sys_id); }

// Description minus the tagged lines the seeders add (Summary:, QID:, Marker: …)
function cleanPath(desc) {
  return String(desc || '').split('\n')
    .filter(l => l.trim() && !/^(Summary|QID|Marker|Risk Score|Batch|Task|Item|Server CI):/i.test(l.trim()))
    .join('\n');
}

// ─── Config / status ──────────────────────────────────────────────────────────
async function loadConfig() {
  try {
    const c = await apiFetch('/api/config');
    const snow = document.getElementById('sys-snow');
    snow.classList.toggle('on', c.servicenow_configured);
    snow.classList.toggle('warn', !c.servicenow_configured);
    snow.title = c.servicenow_configured ? `Connected to ${c.instance_url}` : 'ServiceNow is not configured';
    const ai = (c.gemini_configured || c.tcs_gateway_configured) && !c.llm_key_rejected;
    const llm = document.getElementById('sys-llm');
    llm.classList.toggle('on', ai);
    llm.classList.toggle('warn', !ai);
    document.getElementById('sys-llm-label').textContent = c.llm_key_rejected ? 'AI key rejected'
      : ai ? (c.tcs_gateway_configured ? 'TCS gateway' : 'Gemini') : 'Rules only';
    llm.title = c.llm_mode;
    if (c.instance_url) document.getElementById('cfg-url').value = c.instance_url;
    window.__llmMode = c.llm_mode;
    renderLede();
  } catch (e) { console.error(e); }
}

async function saveConfig(e) {
  e.preventDefault();
  const payload = {
    instance_url:    document.getElementById('cfg-url').value,
    username:        document.getElementById('cfg-user').value,
    password:        document.getElementById('cfg-pass').value,
    gemini_api_key:  document.getElementById('cfg-gemini').value,
    tcs_gateway_key: document.getElementById('cfg-tcs').value,
  };
  try {
    const res = await apiFetch('/api/config', 'POST', payload);
    toast(`Settings saved. Analysis: ${res.llm_mode}`, 'ok');
    document.getElementById('cfg-pass').value = '';
    document.getElementById('cfg-gemini').value = '';
    document.getElementById('cfg-tcs').value = '';
    await loadConfig();
    switchTab('queue');
    fetchVulnerabilities();
  } catch (err) { toast(`Couldn't save settings: ${err.message}`, 'err'); }
}

// ─── Findings ─────────────────────────────────────────────────────────────────
async function fetchVulnerabilities() {
  const btn = document.getElementById('btn-fetch');
  btn.disabled = true; btn.classList.add('spin');
  document.getElementById('queue-lede').textContent =
    vulns.length ? 'Syncing with ServiceNow… new findings are analysed as they arrive.'
                 : 'Fetching open findings from ServiceNow and analysing each one. With AI on, this can take a minute.';
  try {
    const json = await apiFetch('/api/fetch-vulnerabilities', 'POST');
    vulns = json.data || [];
    sync = json.sync || sync;
    render();
    loadConfig();
    const st = json.sync || {};
    toast(!vulns.length ? 'ServiceNow returned no open findings'
      : st.new && st.updated ? `Synced: ${st.new} new, ${st.updated} updated${st.closed ? `, ${st.closed} closed in ServiceNow` : ''}`
      : st.new ? `Loaded ${st.new} open findings from ServiceNow`
      : `Synced: no new findings${st.closed ? `, ${st.closed} closed in ServiceNow` : ''}`, st.new ? 'ok' : '');
  } catch (e) {
    toast(`Couldn't fetch from ServiceNow: ${e.message}`, 'err');
    renderLede();
  } finally {
    btn.disabled = false; btn.classList.remove('spin');
  }
}

// Re-read the agent's in-memory list (no ServiceNow or AI calls)
async function refreshFromState() {
  try {
    const before = new Map(vulns.map(v => [v.sys_id, v.approval_status]));
    const json = await apiFetch('/api/vulnerabilities');
    sync = json.sync || sync;
    automation = json.automation || automation;
    running = json.running || [];
    renderAutopilot();
    if (!(json.data || []).length && vulns.length) {
      agentLostList(new Error('Vulnerability not found'));
      return;
    }
    const fresh = (json.data || []).filter(v => before.size && !before.has(v.sys_id));
    if (fresh.length) {
      toast(`${fresh.length} new finding${fresh.length > 1 ? 's' : ''} from ServiceNow: ${fresh[0].remediation_task}${fresh.length > 1 ? ' and more' : ''}`, 'ok');
    }
    vulns = json.data || [];
    vulns.forEach(v => {
      if (before.get(v.sys_id) === 'Awaiting Approval' && v.approval_status !== 'Awaiting Approval') {
        const a = v.approval_info || {};
        const ok = v.approval_status === 'Approved';
        toast(`${a.node_label || 'Server team'} ${ok ? 'approved' : 'rejected'} ${v.remediation_task} (${a.approver || 'server owner'})`, ok ? 'ok' : 'err');
      }
    });
    render();
  } catch (e) { console.error(e); }
}

function render() {
  renderLede();
  renderTally();
  renderQueue();
  renderServers();
  if (openId) renderDetail();
}

function renderLede() {
  const el = document.getElementById('queue-lede');
  if (!vulns.length) { el.textContent = 'Fetch open findings from ServiceNow to start.'; return; }
  const open = vulns.filter(v => stage(v) !== 'patched').length;
  let synced = '';
  if (sync && sync.last_at) {
    const mins = Math.round((Date.now() - new Date(sync.last_at)) / 60000);
    synced = ` Synced from ServiceNow ${mins < 1 ? 'just now' : `${mins} min ago`}`;
    if (sync.next_at) {
      const next = Math.max(0, Math.round((new Date(sync.next_at) - Date.now()) / 60000));
      synced += `, next sync in ${next < 1 ? 'under a minute' : `${next} min`}`;
    }
    synced += sync.error ? `. Last sync failed: ${sync.error}` : '.';
  }
  el.textContent = `${open} open of ${vulns.length} findings, highest risk first. Analysed with ${window.__llmMode || 'the agent'}.${synced}`;
}

function renderTally() {
  const count = s => vulns.filter(v => stage(v) === s).length;
  const set = (id, n) => document.getElementById(id).textContent = vulns.length ? n : '–';
  set('t-open',     vulns.filter(v => stage(v) !== 'patched').length);
  set('t-critical', vulns.filter(v => stage(v) !== 'patched' && tier(v).cls === 't-crit').length);
  set('t-waiting',  count('waiting'));
  set('t-ready',    count('ready'));
  set('t-patched',  count('patched'));

  const n = { all: vulns.length, needs: count('needs') + count('rejected'), waiting: count('waiting'), ready: count('ready'), patched: count('patched') };
  document.querySelectorAll('[data-filter]').forEach(c => {
    const label = c.textContent.replace(/\s*\d+$/, '');
    c.innerHTML = `${esc(label)}${vulns.length ? `<span class="n">${n[c.dataset.filter]}</span>` : ''}`;
  });
}

function matches(v) {
  const s = stage(v);
  if (filter === 'needs'   && !(s === 'needs' || s === 'rejected')) return false;
  if (filter !== 'all' && filter !== 'needs' && s !== filter) return false;
  const q = document.getElementById('search').value.trim().toLowerCase();
  if (!q) return true;
  return [v.configuration_item, v.summary, v.remediation_task, v.qid, v.cve, v.target_node_label,
          (v.fix_strategy || {}).target_software].some(x => String(x || '').toLowerCase().includes(q));
}

function railHTML(v) {
  const s = stage(v);
  const a = v.approval_info || {};
  const stops = {
    needs:    ['done', '', '', ''],
    waiting:  ['done', 'now', '', ''],
    ready:    ['done', 'done', 'ok', ''],
    rejected: ['done', 'done', 'bad', ''],
    patched:  ['done', 'done', 'done', 'ok'],
  }[s];
  const run = runFor(v);
  const text = {
    needs:    v.target_node_id ? ['', 'Needs approval'] : ['bad', 'No server node owns this host'],
    waiting:  ['wait', `Waiting on ${a.node_label || 'server team'}`],
    ready:    running.includes(v.sys_id) || (run && run.result === 'running')
                ? ['wait', `Patching on ${run ? run.executed_on_node : 'its server'}…`]
                : run && !run.verified
                ? ['bad', `Last run: ${RESULT_LABEL[run.result] || run.result}`]
                : ['ok', `Approved by ${a.approver || 'server team'}. Ready to patch`],
    rejected: ['bad', `Rejected by ${a.approver || 'server team'}`],
    patched:  ['', run && run.verified ? `Patched on ${run.executed_on_node}` : 'Closed in ServiceNow'],
  }[s];
  const names = ['Found', 'Sent for approval', 'Approved', 'Patched'];
  return `<div class="rail">
    <div class="rail-track" aria-hidden="true">${stops.map((c, i) => `<span class="stop ${c}" title="${names[i]}"><i></i></span>`).join('')}</div>
    <div class="rail-text ${text[0]}">${esc(text[1])}</div>
  </div>`;
}

function actionHTML(v) {
  const id = esc(v.sys_id);
  switch (stage(v)) {
    case 'needs':
    case 'rejected':
      return v.target_node_id
        ? `<button class="btn btn-sm" onclick="event.stopPropagation(); openDetail('${id}', true)">${stage(v) === 'rejected' ? 'Ask again' : 'Request approval'}</button>`
        : '';
    case 'waiting': {
      return '';
    }
    case 'ready':
      if (running.includes(v.sys_id)) return '';
      return `<button class="btn btn-sm btn-go" onclick="event.stopPropagation(); applyFix('${id}', this)">Apply fix</button>`;
    default:
      return '';
  }
}

function renderQueue() {
  const list = document.getElementById('queue');
  if (!vulns.length) {
    list.innerHTML = `<li class="empty">No findings loaded. <button class="link" onclick="fetchVulnerabilities()">Fetch from ServiceNow</button></li>`;
    return;
  }
  const shown = vulns.filter(matches);
  if (!shown.length) {
    list.innerHTML = `<li class="empty">Nothing matches this filter.</li>`;
    return;
  }
  list.innerHTML = shown.map(v => {
    const t = tier(v);
    const fix = v.fix_strategy || {};
    const score = Number(v.risk_score) > 0 ? v.risk_score : '—';
    return `<li class="finding ${t.cls} ${stage(v) === 'patched' ? 'is-patched' : ''} ${v.sys_id === openId ? 'selected' : ''}"
                tabindex="0" onclick="openDetail('${esc(v.sys_id)}')"
                onkeydown="if(event.key==='Enter')openDetail('${esc(v.sys_id)}')">
      <div class="score"><span class="score-n">${esc(score)}</span><span class="score-l">${t.label}</span></div>
      <div class="f-main">
        <div class="f-title ${titleOf(v) ? '' : 'unlinked'}">${isNew(v) ? '<span class="new-tag">NEW</span>' : ''}${esc(titleOf(v) || 'No vulnerability linked in ServiceNow')}</div>
        <div class="f-meta">
          <b>${esc(v.configuration_item)}</b>
          <span>${esc(v.remediation_task)}</span>
          ${v.cve ? `<span>${esc(v.cve)}</span>` : ''}
          ${v.target_node_label ? `<span>${esc(v.target_node_label)}</span>` : ''}
          <span class="patch">${esc(fix.patch_type || '')}</span>
        </div>
      </div>
      ${railHTML(v)}
      <div class="f-act">${actionHTML(v)}</div>
    </li>`;
  }).join('');
}

// ─── Detail drawer ────────────────────────────────────────────────────────────
function openDetail(sysId, focusRequest = false) {
  openId = sysId;
  renderDetail();
  renderQueue();
  document.getElementById('detail').classList.add('open');
  document.getElementById('detail').setAttribute('aria-hidden', 'false');
  document.getElementById('scrim').classList.add('open');
  setTimeout(() => {
    const el = focusRequest ? document.getElementById('d-note') : document.querySelector('.d-close');
    if (el) el.focus();
  }, 60);
}

function closeDetail() {
  if (!openId) return;
  openId = null;
  document.getElementById('detail').classList.remove('open');
  document.getElementById('detail').setAttribute('aria-hidden', 'true');
  document.getElementById('scrim').classList.remove('open');
  renderQueue();
}

function renderDetail() {
  const v = vulns.find(x => x.sys_id === openId);
  const body = document.getElementById('detail-body');
  if (!v) { body.innerHTML = ''; return; }

  // Don't redraw under someone typing; keep a half-typed note across refreshes
  const typed = document.getElementById('d-note');
  if (typed && document.activeElement === typed && body.dataset.for === openId) return;
  body.dataset.for = openId;
  const note = typed ? typed.value : DEFAULT_NOTE;

  const t = tier(v);
  const fix = v.fix_strategy || {};
  const llm = v.llm_analysis || {};
  const a = v.approval_info || {};
  const s = stage(v);
  const run = runFor(v);
  const node = nodeFor(v);
  const nodeName = v.target_node_label || 'its server';
  const path = cleanPath(v.description);

  // Approval timeline
  const tl = [`<li><div class="tl-what">Found in ServiceNow</div><div class="tl-note">${esc(v.remediation_task)} · assigned to ${esc(v.assignment_group)}</div></li>`];
  if (a.requested_at) {
    tl.push(`<li class="${s === 'waiting' ? 'wait' : ''}"><div class="tl-what">Sent to ${esc(a.node_label)} for approval</div><div class="tl-when">${when(a.requested_at)}</div></li>`);
  }
  if (s === 'waiting') {
    tl.push(`<li class="wait"><div class="tl-what">Waiting for ${esc(a.node_label)}'s team</div><div class="tl-note">The server team decides on their side. This updates on its own when they answer.</div></li>`);
  }
  if (a.decided_at) {
    const ok = a.status === 'Approved' || s === 'patched';
    tl.push(`<li class="${ok ? 'ok' : 'bad'}"><div class="tl-what">${ok ? 'Approved' : 'Rejected'} by ${esc(a.approver)}</div><div class="tl-when">${when(a.decided_at)}</div>${a.comments ? `<div class="tl-note">“${esc(a.comments)}”</div>` : ''}</li>`);
  }
  if (run) {
    tl.push(`<li class="${run.verified ? 'ok' : 'bad'}"><div class="tl-what">${run.verified ? 'Verified fixed' : 'Not fixed'} on ${esc(run.executed_on_node)}</div><div class="tl-when">${when(run.executed_at)}</div><div class="tl-note">${esc(run.outcome || '')}</div></li>`);
  }

  // What to do next
  let next = '';
  if ((s === 'needs' || s === 'rejected') && v.target_node_id) {
    next = `<div class="d-request">
      <label for="d-note">Note to ${esc(nodeName)}'s team</label>
      <textarea id="d-note">${esc(note)}</textarea>
      <div class="d-actions">
        <button class="btn btn-primary" onclick="requestApproval('${esc(v.sys_id)}', this)">Send to ${esc(nodeName)} for approval</button>
        ${node && node.status !== 'online' ? `<span class="note">${esc(nodeName)} looks offline. Start node_worker.py first.</span>` : ''}
      </div>
    </div>`;
  } else if (s === 'needs') {
    next = `<p class="d-text" style="margin-top:12px">No server node lists <code>${esc(v.configuration_item)}</code>. Add it to a node's <code>ci_names</code> in <code>server_registry.json</code> to request approval.</p>`;
  }

  const plan = Array.isArray(llm.remediation_plan) ? llm.remediation_plan : [];
  const urgency = llm.patch_urgency ? `<span class="urgency ${esc(llm.patch_urgency)}">${esc(String(llm.patch_urgency).replace('_', ' '))}</span>` : '';

  const logs = (run && run.logs) || [];
  const reveal = justPatched === v.sys_id;
  justPatched = null;

  body.innerHTML = `
    <div class="d-head ${t.cls}">
      <button class="d-close" onclick="closeDetail()" aria-label="Close details">×</button>
      <div class="d-ids"><span>${esc(v.remediation_task)}</span><span>${esc(v.qid)}</span>${v.cve ? `<span>${esc(v.cve)}</span>` : ''}<span>${esc(v.state)}</span></div>
      <div class="d-top">
        <div class="score"><span class="score-n">${Number(v.risk_score) > 0 ? esc(v.risk_score) : '—'}</span><span class="score-l">${t.label}</span></div>
        <div>
          <h2 class="d-title" id="d-title">${esc(titleOf(v) || 'No vulnerability linked in ServiceNow')}</h2>
          <div class="d-server">${esc(v.configuration_item)} <span>· ${esc(v.target_node_label || 'no node')} · ${esc(v.operating_environment || '')}</span></div>
        </div>
      </div>
      ${railHTML(v)}
    </div>

    <section class="d-sec">
      <h3 class="d-label">What was found</h3>
      ${titleOf(v) ? '' : `<p class="d-text" style="margin-bottom:12px">This item has no vulnerability linked in ServiceNow, so it has no title or risk score. Open ${esc(v.remediation_task)} in ServiceNow and set its Vulnerability field.</p>`}
      ${v.vulnerability_summary ? `<p class="d-text" style="margin-bottom:12px">${esc(v.vulnerability_summary)}</p>` : ''}
      ${path ? `<pre class="d-path">${esc(path)}</pre>` : ''}
      <dl class="facts" style="margin-top:${path ? 12 : 0}px">
        <dt>Risk rating</dt><dd>${esc(v.risk_rating)}${Number(v.risk_score) > 0 ? ` · score ${esc(v.risk_score)}` : ' · ServiceNow has not scored this item'}</dd>
        ${v.cve ? `<dt>CVE</dt><dd class="mono">${esc(v.cve)}${v.cvss_v3 ? ` · CVSS ${esc(v.cvss_v3)} ${esc(v.cvss_severity || '')}` : ''}</dd>` : ''}
        ${v.scanner ? `<dt>Found by</dt><dd>${esc(v.scanner)}${v.first_found ? ` · first ${esc(when(v.first_found))}, last ${esc(when(v.last_found))}` : ''}</dd>` : ''}
        <dt>Business impact</dt><dd>${esc(v.business_impact)}</dd>
        <dt>Team</dt><dd>${esc(v.assignment_group)}</dd>
        <dt>Environment</dt><dd>${esc(v.operating_environment)}</dd>
      </dl>
    </section>

    <section class="d-sec">
      <h3 class="d-label">Why it matters ${urgency}</h3>
      <p class="d-text">${esc(llm.risk_assessment || 'No analysis available.')}</p>
    </section>

    <section class="d-sec">
      <h3 class="d-label">The fix</h3>
      <dl class="facts">
        ${v.vendor_solution ? `<dt>Vendor says</dt><dd>${esc(v.vendor_solution)}</dd>` : ''}
        <dt>Patch</dt><dd>${esc(fix.patch_type)}</dd>
        <dt>Software</dt><dd>${esc(fix.target_software)}</dd>
        <dt>Source</dt><dd>${esc(fix.dl_source)}</dd>
        <dt>Reboot</dt><dd>${fix.requires_reboot ? 'Required, in the next maintenance window' : 'Not needed'}</dd>
      </dl>
      <pre class="term" style="margin-top:12px"><div class="cmdline">$ ${esc(fix.fix_command)}</div></pre>
      ${plan.length ? `<h3 class="d-label" style="margin-top:18px">Plan</h3><ol class="plan">${plan.map(p => `<li><span>${esc(p)}</span></li>`).join('')}</ol>` : ''}
    </section>

    <section class="d-sec">
      <h3 class="d-label">Approval</h3>
      <ol class="timeline">${tl.join('')}</ol>
      ${llm.approval_request_message && (s === 'needs' || s === 'rejected') ? `<p class="d-quote">${esc(llm.approval_request_message)}</p>` : ''}
      ${next}
    </section>

    ${s === 'ready' && !running.includes(v.sys_id) ? `
    <section class="d-sec">
      <h3 class="d-label">Patch</h3>
      <div class="d-actions">
        <button class="btn btn-go" onclick="applyFix('${esc(v.sys_id)}', this)">Apply fix on ${esc(nodeName)}</button>
        <span class="note">${esc(nodeName)} checks the installed version${node && node.mode === 'install' ? ' and installs the update' : ' (check-only node, nothing is installed)'}. ${esc(v.remediation_task)} is closed in ServiceNow only if the fix is verified.</span>
      </div>
    </section>` : ''}

    ${run ? `
    <section class="d-sec">
      <h3 class="d-label">Patch run</h3>
      <dl class="facts" style="margin-bottom:12px">
        <dt>Result</dt><dd><span class="tag ${run.verified ? 'ok' : 'warn'}">${esc(RESULT_LABEL[run.result] || run.result)}</span></dd>
        ${run.before_version ? `<dt>Version</dt><dd class="mono">${esc(run.before_version)}${run.after_version && run.after_version !== run.before_version ? ` → ${esc(run.after_version)}` : ''}${run.fixed_version ? ` · fixed in ${esc(run.fixed_version)}` : ''}</dd>` : ''}
        <dt>Ran on</dt><dd>${esc(run.executed_on_node)} <span class="tag">${run.mode === 'install' ? 'install mode' : 'check only'}</span></dd>
        <dt>When</dt><dd>${when(run.executed_at)}</dd>
        <dt>ServiceNow</dt><dd>${run.servicenow_closed ? `<span class="tag ok">Closed</span>` : run.servicenow_synced ? `<span class="tag warn">Left open, work note added</span>` : `<span class="tag warn">Not updated</span>`}</dd>
      </dl>
      <pre class="term ${reveal ? 'reveal' : ''}">${logs.map((l, i) =>
        `<div class="${/RESULT: (VERIFIED|.*Not vulnerable)/.test(l) ? 'ok' : /RESULT:|not installed|No automated/i.test(l) ? 'warn' : /^\$ /.test(l) ? 'cmdline' : ''}" style="${reveal ? `animation-delay:${i * 90}ms` : ''}">${esc(l)}</div>`).join('')}</pre>
    </section>` : ''}
  `;
}

// ─── Actions ──────────────────────────────────────────────────────────────────
// The agent keeps findings in memory; after a restart it no longer knows the list on screen
function agentLostList(e) {
  if (!/Vulnerability not found/i.test(e.message)) return false;
  toast('The agent restarted and lost its list. Reloading from ServiceNow, then try again.', 'err');
  closeDetail();
  fetchVulnerabilities();
  return true;
}

async function requestApproval(sysId, btn, note) {
  const text = note ?? (document.getElementById('d-note') || {}).value ?? DEFAULT_NOTE;
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  try {
    const res = await apiFetch('/api/approval/request', 'POST', { sys_id: sysId, comments: text });
    toast(`Sent to ${res.node} for approval`, 'ok');
    await refreshFromState();
  } catch (e) {
    if (agentLostList(e)) return;
    toast(`Couldn't send for approval: ${e.message}`, 'err');
    if (btn) { btn.disabled = false; btn.textContent = 'Try again'; }
  }
}

async function requestTopPriority() {
  if (!vulns.length) { toast('Fetch findings from ServiceNow first'); return; }
  const top = vulns.find(v => stage(v) === 'needs' && v.target_node_id);
  if (!top) { toast('Every finding a server can handle is already sent, approved or patched'); return; }
  await requestApproval(top.sys_id, null, DEFAULT_NOTE);
  openDetail(top.sys_id);
}

async function applyFix(sysId, btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Patching…'; }
  try {
    const res = await apiFetch('/api/remediate', 'POST', { sys_id: sysId, simulate: false });
    toast(`Started on ${res.executed_on_node}. Follow it in the panel or the Activity tab.`);
    await loadHistory();
    openId = sysId;
    await refreshFromState();
    openDetail(sysId);
  } catch (e) {
    if (agentLostList(e)) return;
    toast(`Patch failed: ${e.message}`, 'err');
    if (btn) { btn.disabled = false; btn.textContent = 'Try again'; }
  }
}

// ─── Servers ──────────────────────────────────────────────────────────────────
async function refreshNodes() {
  try {
    const data = await apiFetch('/api/nodes');
    nodes = data.nodes || [];
    const online = nodes.filter(n => n.status === 'online').length;
    document.getElementById('nav-servers-count').textContent = `${online}/${nodes.length}`;
    document.getElementById('sys-nodes-label').textContent = `${online}/${nodes.length} servers`;
    const el = document.getElementById('sys-nodes');
    el.classList.toggle('on', online === nodes.length && online > 0);
    el.classList.toggle('warn', online < nodes.length);
    renderServers();
    if (openId) renderDetail();
  } catch (e) { console.error(e); }
}

function renderServers() {
  const grid = document.getElementById('servers');
  if (!nodes.length) { grid.innerHTML = `<div class="panel">No servers in server_registry.json.</div>`; return; }
  grid.innerHTML = nodes.map(n => {
    const mine = vulns.filter(v => v.target_node_id === n.node_id);
    const open = mine.filter(v => stage(v) !== 'patched').length;
    const waiting = mine.filter(v => stage(v) === 'waiting').length;
    const patched = mine.filter(v => stage(v) === 'patched').length;
    const on = n.status === 'online';
    return `<article class="server">
      <div class="server-top">
        <div>
          <div class="server-name">${esc(n.label)}</div>
          <div class="server-addr">${esc(n.ip)}:${esc(n.port)} · ${esc(n.os || 'Windows Server')}</div>
        </div>
        <span class="status ${on ? 'on' : ''}"><i class="dot"></i>${on ? (n.mode === 'install' ? 'Online · installs updates' : 'Online · check only') : 'Offline'}</span>
      </div>
      <div class="cis">${(n.ci_names || []).map(c => `<span class="ci">${esc(c)}</span>`).join('')}</div>
      <div class="server-stats">
        <div><b>${open}</b><span>open findings</span></div>
        <div class="wait"><b>${waiting}</b><span>waiting on team</span></div>
        <div><b>${patched}</b><span>patched</span></div>
      </div>
      ${editingNode === n.node_id ? `
      <div class="ip-form">
        <label>IP address<input id="ip-${esc(n.node_id)}" value="${esc(n.ip)}"></label>
        <label>Port<input id="port-${esc(n.node_id)}" type="number" value="${esc(n.port)}"></label>
        <button class="btn btn-sm btn-primary" onclick="saveNodeIP('${esc(n.node_id)}')">Save</button>
        <button class="btn btn-sm" onclick="editingNode=null; renderServers()">Cancel</button>
      </div>` : `
      <div class="server-actions">
        <button class="btn btn-sm" onclick="editingNode='${esc(n.node_id)}'; renderServers()">Change address</button>
      </div>`}
    </article>`;
  }).join('');
}

async function saveNodeIP(nodeId) {
  const payload = {
    node_id: nodeId,
    ip:      document.getElementById(`ip-${nodeId}`).value.trim(),
    port:    parseInt(document.getElementById(`port-${nodeId}`).value, 10),
  };
  try {
    await apiFetch('/api/nodes/update-ip', 'POST', payload);
    editingNode = null;
    toast(`Address saved: ${payload.ip}:${payload.port}`, 'ok');
    refreshNodes();
  } catch (e) { toast(`Couldn't save address: ${e.message}`, 'err'); }
}

// ─── History ──────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const data = await apiFetch('/api/history');
    history = data.history || [];
    const tbody = document.getElementById('history');
    if (!history.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty">No patches run yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = history.map(h => `<tr>
      <td class="mono">${esc(when(h.executed_at))}</td>
      <td class="mono">${esc(h.server)}</td>
      <td>${esc(h.summary)}</td>
      <td>${esc(h.patch_applied)}<div class="sub">${esc(RESULT_LABEL[h.result] || h.result || '')}</div></td>
      <td>${esc(h.executed_on_node)}<div class="sub">${h.mode === 'install' ? 'install mode' : 'check only'}</div></td>
      <td>${esc(h.approved_by || '—')}</td>
      <td>${h.servicenow_closed ? '<span class="tag ok">Closed</span>' : '<span class="tag warn">Left open</span>'}</td>
    </tr>`).join('');
  } catch (e) { console.error(e); }
}

// ─── Activity feed & autopilot ────────────────────────────────────────────────
async function pollActivity() {
  try {
    const data = await apiFetch(`/api/activity?after=${feedAfter}`);
    const fresh = data.activity || [];
    if (!fresh.length) return;
    feedAfter = fresh[fresh.length - 1].id;
    feedItems = feedItems.concat(fresh).slice(-1500);
    renderFeed(false, fresh);
    // Something happened: refresh the list, history and any open panel
    loadHistory();
    refreshFromState();
  } catch (e) { /* agent restarting */ }
}

function feedMatches(a) {
  if (feedFilter === 'steps')    return a.source !== 'node';
  if (feedFilter === 'node')     return a.source === 'node';
  if (feedFilter === 'problems') return a.level === 'warn' || a.level === 'error';
  return true;
}

function feedRow(a, prev) {
  const t = new Date(a.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  // Consecutive lines from the same source about the same item read as one block
  const cont = prev && prev.source === a.source && prev.sys_id === a.sys_id && a.source === 'node';
  const ref = a.number && !cont
    ? `<button class="ev-ref" onclick="openFromFeed('${esc(a.sys_id)}')">${esc(a.number)} · ${esc(a.server)}</button>` : '';
  return `<li class="ev src-${esc(a.source)} lv-${esc(a.level)} ${cont ? 'cont' : ''}">
    <time>${t}</time><span class="src">${esc(SOURCE_LABEL[a.source] || a.source)}</span>
    <div class="ev-body">${ref}<span class="ev-text">${esc(a.text)}</span></div></li>`;
}

function renderFeed(full, fresh = []) {
  const list = document.getElementById('feed');
  const follow = document.getElementById('feed-follow').checked;
  const shown = (full ? feedItems : fresh).filter(feedMatches);
  if (full || list.querySelector('.empty')) {
    const all = feedItems.filter(feedMatches);
    list.innerHTML = all.length
      ? all.map((a, i) => feedRow(a, all[i - 1])).join('')
      : `<li class="empty">${feedItems.length ? 'Nothing matches this filter yet.' : 'Waiting for the agent…'}</li>`;
  } else if (shown.length) {
    const all = feedItems.filter(feedMatches);
    const start = all.length - shown.length;
    list.insertAdjacentHTML('beforeend', shown.map((a, i) => feedRow(a, all[start + i - 1])).join(''));
    while (list.children.length > 1500) list.firstElementChild.remove();
  }
  if (follow) list.scrollTop = list.scrollHeight;
}

function openFromFeed(sysId) {
  switchTab('queue');
  openDetail(sysId);
}

function renderAutopilot() {
  if (!automation) return;
  const on = automation.enabled;
  const bar = document.getElementById('autopilot-bar');
  const every = sync && sync.interval_minutes ? `every ${sync.interval_minutes} min` : 'on a schedule';
  bar.className = `autopilot ${on ? '' : 'paused'}`;
  bar.innerHTML = on
    ? `<b>Autopilot on</b><p>Syncs with ServiceNow ${every}, asks the server team to approve every finding scored ${automation.min_score} or more, and patches as soon as they approve. ServiceNow is closed only when the fix is verified.${running.length ? ` <strong>${running.length} patch${running.length > 1 ? 'es' : ''} running now.</strong>` : ''}</p>`
    : `<b>Autopilot paused</b><p>Nothing is sent for approval or patched automatically. You can still do each step from the Queue.</p>`;
  document.getElementById('btn-autopilot').textContent = on ? 'Pause autopilot' : 'Resume autopilot';
  const chip = document.getElementById('sys-auto');
  chip.classList.toggle('on', on);
  chip.classList.toggle('warn', !on);
  document.getElementById('sys-auto-label').textContent = on ? 'Autopilot on' : 'Autopilot paused';
}

async function toggleAutopilot() {
  try {
    automation = await apiFetch('/api/automation', 'POST', { enabled: !(automation && automation.enabled) });
    renderAutopilot();
  } catch (e) { toast(`Couldn't change the autopilot: ${e.message}`, 'err'); }
}
