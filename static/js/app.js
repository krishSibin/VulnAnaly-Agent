// ─────────────────────────────────────────────────────────────────────────────
//  Vulnerability Agent Dashboard — app.js
// ─────────────────────────────────────────────────────────────────────────────
let currentVulnerabilities = [];
let activeItem = null;

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) lucide.createIcons();
  loadConfig();
  fetchVulnerabilities();
  refreshNodes();
  loadHistory();
  // Auto-refresh node status every 15 s
  setInterval(refreshNodesSilent, 15000);
});

// ─── Tab Navigation ───────────────────────────────────────────────────────────
function switchTab(tab) {
  const tabs = ['dashboard', 'nodes', 'history', 'settings'];
  tabs.forEach(t => {
    document.getElementById(`tab-${t}`).style.display   = (t === tab) ? '' : 'none';
    document.getElementById(`nav-${t}`).classList.toggle('active', t === tab);
  });
  if (tab === 'history') loadHistory();
  if (tab === 'nodes')   refreshNodes();
}

// ─── Config ───────────────────────────────────────────────────────────────────
async function loadConfig() {
  try {
    const data = await apiFetch('/api/config');
    // ServiceNow
    document.getElementById('snow-status').innerHTML =
      data.servicenow_configured
        ? '<span class="status-indicator"></span>Connected (Live)'
        : '<span class="status-indicator warn"></span>Not Configured';

    // LLM mode label
    const mode = data.llm_mode || 'Heuristic';
    document.getElementById('llm-mode-label').textContent  = mode;
    document.getElementById('banner-llm-mode').textContent = mode;

    if (data.instance_url) document.getElementById('cfg-url').value = data.instance_url;
  } catch (e) { console.error('Config load failed', e); }
}

async function saveConfig() {
  const payload = {
    instance_url:    document.getElementById('cfg-url').value,
    username:        document.getElementById('cfg-user').value,
    password:        document.getElementById('cfg-pass').value,
    gemini_api_key:  document.getElementById('cfg-gemini').value,
    tcs_gateway_key: document.getElementById('cfg-tcs').value,
  };
  try {
    const res = await apiFetch('/api/config', 'POST', payload);
    alert(`✅ Saved. LLM Mode: ${res.llm_mode}`);
    loadConfig();
    fetchVulnerabilities();
    switchTab('dashboard');
  } catch (e) { alert('Save failed: ' + e); }
}

// ─── Vulnerabilities ─────────────────────────────────────────────────────────
async function fetchVulnerabilities() {
  const tbody = document.getElementById('vuln-tbody');
  tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-dim);">
    <i data-lucide="loader"></i>&nbsp; Fetching from ServiceNow & prioritizing…</td></tr>`;
  if (window.lucide) lucide.createIcons();
  try {
    const json = await apiFetch('/api/fetch-vulnerabilities', 'POST');
    currentVulnerabilities = json.data || [];
    renderVulnerabilities(currentVulnerabilities);
    updateMetrics(currentVulnerabilities);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:#ef4444;padding:20px;">Fetch failed: ${e}</td></tr>`;
  }
}

function renderVulnerabilities(items) {
  const tbody = document.getElementById('vuln-tbody');
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:30px;">No vulnerabilities found.</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map((item, i) => {
    const isCritical  = item.risk_score >= 80 || (item.risk_rating || '').includes('1 - Critical');
    const riskClass   = isCritical ? 'badge-critical' : 'badge-high';
    const isRemediated = (item.state || '').includes('Closed');

    const approval = item.approval_status || 'Pending';
    const apClass  = approval === 'Approved'  ? 'badge-approved'
                   : approval === 'Rejected'  ? 'badge-critical'
                   : 'badge-pending';

    const fix      = item.fix_strategy || {};
    const nodeLabel = item.target_node_label || '—';

    return `<tr>
      <td>
        <span class="badge ${riskClass}">${item.risk_rating || 'High'}</span>
        <div style="font-size:.72rem;color:var(--text-dim);font-family:var(--font-mono);margin-top:4px;">
          Score ${item.risk_score} &nbsp;·&nbsp; #${i + 1}
        </div>
      </td>
      <td>
        <span class="badge badge-server">${item.configuration_item}</span>
        <div style="font-size:.72rem;color:var(--text-dim);margin-top:4px;">${item.remediation_task}</div>
      </td>
      <td>
        <div style="font-weight:600;color:#fff;">${item.summary || 'Vulnerability'}</div>
        <div style="font-size:.72rem;color:var(--text-muted);font-family:var(--font-mono);margin-top:2px;">${(item.description || '').substring(0,60)}</div>
        <div style="font-size:.7rem;color:var(--accent-cyan);margin-top:2px;">${item.qid || ''}</div>
      </td>
      <td style="font-size:.82rem;">${item.assignment_group || 'WINTEL'}</td>
      <td>
        <div style="color:#38bdf8;font-size:.8rem;font-weight:500;">${fix.patch_type || '—'}</div>
        <div style="font-size:.72rem;color:var(--text-dim);">${fix.target_software || ''}</div>
      </td>
      <td>
        <span class="badge badge-server" style="font-size:.72rem;">${nodeLabel}</span>
      </td>
      <td><span class="badge ${apClass}">${approval}</span></td>
      <td>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          ${!isRemediated && approval === 'Pending' ? `
            <button class="btn btn-secondary btn-sm" onclick="openApprovalModal('${item.sys_id}')">
              Review & Approve
            </button>` : ''}
          ${!isRemediated && approval === 'Approved' ? `
            <button class="btn btn-primary btn-sm" onclick="applyRemediation('${item.sys_id}')">
              <i data-lucide="play" style="width:13px;height:13px;"></i>&nbsp;Apply Fix
            </button>` : ''}
          ${isRemediated ? `
            <span class="badge badge-approved">✓ Patched</span>` : ''}
        </div>
      </td>
    </tr>`;
  }).join('');
  if (window.lucide) lucide.createIcons();
}

function updateMetrics(items) {
  let critical = 0, pending = 0, remediated = 0;
  const servers = new Set();
  items.forEach(v => {
    if (v.risk_score >= 80 || (v.risk_rating || '').includes('1 - Critical')) critical++;
    if (v.approval_status === 'Pending') pending++;
    if ((v.state || '').includes('Closed')) remediated++;
    if (v.configuration_item) servers.add(v.configuration_item);
  });
  document.getElementById('count-critical').textContent  = critical;
  document.getElementById('count-pending').textContent   = pending;
  document.getElementById('count-remediated').textContent = remediated;
}

// ─── Approval Modal ───────────────────────────────────────────────────────────
function openApprovalModal(sysId) {
  activeItem = currentVulnerabilities.find(v => v.sys_id === sysId);
  if (!activeItem) return;
  const fix = activeItem.fix_strategy || {};
  const llm = activeItem.llm_analysis  || {};

  document.getElementById('modal-server').textContent   = `Target Host: ${activeItem.configuration_item}`;
  document.getElementById('modal-summary').textContent  = activeItem.summary || '';
  document.getElementById('modal-assigned').textContent =
    `Team: ${activeItem.assignment_group}  |  Task: ${activeItem.remediation_task}`;
  document.getElementById('modal-node-target').innerHTML =
    `<span class="badge badge-server" style="font-size:.75rem;">Node: ${activeItem.target_node_label || 'Local'}</span>`;

  document.getElementById('modal-ai-msg').innerHTML =
    `<strong>Risk:</strong> ${llm.risk_assessment || '—'}<br><br>
     <strong>Change Request Message:</strong><br>
     <em>${llm.approval_request_message || '—'}</em>`;

  document.getElementById('modal-command').textContent =
    `Source : ${fix.dl_source || '—'}\nCommand: ${fix.fix_command || '—'}`;

  document.getElementById('approval-modal').style.display = 'flex';
}

function closeModal() {
  document.getElementById('approval-modal').style.display = 'none';
  activeItem = null;
}

async function submitDecision(approved) {
  if (!activeItem) return;
  try {
    await apiFetch('/api/approval', 'POST', {
      sys_id:   activeItem.sys_id,
      approved,
      comments: document.getElementById('modal-comments').value,
    });
    closeModal();
    fetchVulnerabilities();
  } catch (e) { alert('Approval failed: ' + e); }
}

// ─── Remediation ──────────────────────────────────────────────────────────────
async function applyRemediation(sysId) {
  try {
    const res = await apiFetch('/api/remediate', 'POST', { sys_id: sysId, simulate: true });
    if (res.status === 'success') {
      const logs    = res.execution?.logs || [];
      const node    = res.executed_on_node || 'Local';
      const fallback = res.fallback_mode;
      showExecutionLogs(logs, node, fallback);
      fetchVulnerabilities();
      loadHistory();
    } else {
      alert('Remediation failed: ' + JSON.stringify(res));
    }
  } catch (e) { alert('Apply fix error: ' + e); }
}

async function autoProcessTopPriority() {
  // Find top unprocessed pending item and approve + fix it
  const topPending = currentVulnerabilities.find(
    v => v.approval_status === 'Pending' && !(v.state || '').includes('Closed')
  );
  if (topPending) {
    await apiFetch('/api/approval', 'POST', {
      sys_id:   topPending.sys_id,
      approved: true,
      comments: 'Emergency auto-approval by Security Committee',
    });
  }
  const topApproved = currentVulnerabilities.find(
    v => v.approval_status === 'Approved' && !(v.state || '').includes('Closed')
  ) || (topPending ? { sys_id: topPending.sys_id } : null);

  if (topApproved) {
    await applyRemediation(topApproved.sys_id);
  } else {
    alert('No high-priority items pending — all items may already be remediated!');
  }
}

function showExecutionLogs(logs, nodeName, fallback) {
  document.getElementById('exec-node-badge').textContent = nodeName;
  const container = document.getElementById('exec-logs');
  container.innerHTML = logs.map(l => {
    const color = l.includes('SUCCESS') || l.includes('✅') ? '#34d399'
                : l.includes('FALLBACK') ? '#fbbf24'
                : '#38bdf8';
    return `<div style="color:${color};">${l}</div>`;
  }).join('');
  if (fallback) {
    container.innerHTML += `<div style="color:#fbbf24;margin-top:12px;">⚠ Node unreachable — local simulation used. Demo still works!</div>`;
  }
  document.getElementById('execution-modal').style.display = 'flex';
}

function closeExecutionModal() {
  document.getElementById('execution-modal').style.display = 'none';
}

// ─── Nodes ────────────────────────────────────────────────────────────────────
async function refreshNodes() {
  try {
    const data = await apiFetch('/api/nodes');
    renderNodes(data.nodes || []);
  } catch (e) { console.error('Node refresh failed', e); }
}

async function refreshNodesSilent() {
  try {
    const data = await apiFetch('/api/nodes');
    updateNodeBadges(data.nodes || []);
    renderNodes(data.nodes || []);
  } catch (_) {}
}

function renderNodes(nodes) {
  const grid   = document.getElementById('nodes-grid');
  let onlineCount = 0;

  grid.innerHTML = nodes.map(n => {
    const online = n.status === 'online';
    if (online) onlineCount++;
    const dotClass  = online ? 'online' : 'offline';
    const cardClass = online ? 'online' : 'offline';
    const ciChips   = (n.ci_names || []).map(c => `<span class="ci-chip">${c}</span>`).join('');
    const lastSeen  = n.last_seen ? `Last seen: ${n.last_seen}` : 'Not yet connected';

    return `
      <div class="node-card ${cardClass}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
          <div class="node-label">
            <span class="node-status-dot ${dotClass}"></span>${n.label}
          </div>
          <span class="badge ${online ? 'badge-approved' : 'badge-pending'}">${n.status}</span>
        </div>
        <div class="node-meta">${n.ip}:${n.port} &nbsp;·&nbsp; ${n.os || 'Windows'}</div>
        <div class="node-ci-chips">${ciChips}</div>
        <div style="font-size:.72rem;color:var(--text-dim);margin-bottom:12px;">${lastSeen}</div>
        <button class="btn btn-secondary btn-sm" onclick="openIPEdit('${n.node_id}', '${n.label}', '${n.ip}', ${n.port})">
          <i data-lucide="pencil" style="width:13px;height:13px;"></i>&nbsp;Update IP
        </button>
      </div>`;
  }).join('');

  if (window.lucide) lucide.createIcons();
  updateNodeBadges(nodes);
}

function updateNodeBadges(nodes) {
  const online = nodes.filter(n => n.status === 'online').length;
  const total  = nodes.length;
  document.getElementById('count-nodes').textContent    = `${online} / ${total}`;
  document.getElementById('sidebar-nodes').textContent  = `${online} / ${total}`;
  const badge = document.getElementById('online-badge');
  badge.textContent = online > 0 ? online : '';
  badge.style.display = online > 0 ? 'inline-block' : 'none';
}

function openIPEdit(nodeId, label, ip, port) {
  document.getElementById('edit-node-id').value    = nodeId;
  document.getElementById('edit-node-label').textContent = label;
  document.getElementById('edit-node-ip').value    = ip;
  document.getElementById('edit-node-port').value  = port;
  document.getElementById('ip-edit-panel').style.display = '';
  document.getElementById('ip-edit-panel').scrollIntoView({ behavior: 'smooth' });
}

async function saveNodeIP() {
  const payload = {
    node_id: document.getElementById('edit-node-id').value,
    ip:      document.getElementById('edit-node-ip').value,
    port:    parseInt(document.getElementById('edit-node-port').value),
  };
  try {
    await apiFetch('/api/nodes/update-ip', 'POST', payload);
    document.getElementById('ip-edit-panel').style.display = 'none';
    refreshNodes();
  } catch (e) { alert('IP update failed: ' + e); }
}

// ─── History ─────────────────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const data = await apiFetch('/api/history');
    const history = data.history || [];
    const tbody   = document.getElementById('history-tbody');
    if (!history.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-dim);">No patches executed yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = history.map(h => `
      <tr>
        <td><span class="badge badge-server">${h.server}</span></td>
        <td style="color:#38bdf8;font-weight:500;">${h.patch_applied}</td>
        <td>${h.target_software}</td>
        <td><span class="badge badge-server" style="font-size:.72rem;">${h.executed_on_node || 'Local'}</span></td>
        <td><span class="badge ${h.fallback_mode ? 'badge-medium' : 'badge-approved'}">
          ${h.fallback_mode ? 'Simulated' : 'Live Dispatch'}</span></td>
        <td><span class="badge ${h.servicenow_synced ? 'badge-approved' : 'badge-pending'}">
          ${h.servicenow_synced ? 'Updated' : 'Local'}</span></td>
      </tr>`).join('');
  } catch (e) { console.error('History load failed', e); }
}

// ─── Utility ─────────────────────────────────────────────────────────────────
async function apiFetch(url, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}
