/**
 * SentinelOps — Main App Controller
 * Manages global state, WebSocket events, SAIA counter, and agent detail modals
 */

// ============ GLOBAL STATE ============
const AppState = {
    incidentId: null,
    incidentActive: false,
    timerStart: null,
    timerInterval: null,
    lastState: null,
    agentData: {
        orchestrator: { findings: [], logs: [], splQueries: [], saiaCalls: 0 },
        threat_hunter: { findings: [], logs: [], splQueries: [], saiaCalls: 0 },
        rca_agent: { findings: [], logs: [], splQueries: [], saiaCalls: 0 },
        blast_radius: { findings: [], logs: [], splQueries: [], saiaCalls: 0 },
        remediation: { findings: [], logs: [], splQueries: [], saiaCalls: 0 },
    },
};

// ============ INITIALIZATION ============
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
});

// ============ DEMO TRIGGER ============
async function triggerDemo() {
    const btn = document.getElementById('btn-trigger-demo');
    btn.disabled = true;
    btn.textContent = '⏳ Launching...';
    btn.style.opacity = '0.6';

    try {
        const resp = await fetch('/api/incident/trigger-demo', { method: 'POST' });
        const data = await resp.json();

        if (data.status === 'accepted') {
            AppState.incidentId = data.incident_id;
            AppState.incidentActive = true;
            startIncident(data.incident_id);
        } else {
            btn.textContent = '❌ Failed — Retry';
            btn.disabled = false;
            btn.style.opacity = '1';
        }
    } catch (err) {
        console.error('Demo trigger failed:', err);
        btn.textContent = '❌ Error — Retry';
        btn.disabled = false;
        btn.style.opacity = '1';
    }
}

function startIncident(incidentId) {
    // Hide welcome, show war room
    document.getElementById('welcome-container').classList.add('hidden');
    document.getElementById('war-room').classList.remove('hidden');
    document.getElementById('saia-counter').classList.remove('hidden');

    // Update header
    document.getElementById('incident-id').textContent = incidentId;

    // Start timer
    AppState.timerStart = Date.now();
    AppState.timerInterval = setInterval(updateTimer, 1000);
    updateTimer();

    // Start polling status
    pollIncidentStatus();
}

function updateTimer() {
    if (!AppState.timerStart) return;
    const elapsed = Math.floor((Date.now() - AppState.timerStart) / 1000);
    const min = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const sec = String(elapsed % 60).padStart(2, '0');
    document.getElementById('incident-timer').textContent = `${min}:${sec}`;
}

// ============ STATUS POLLING ============
async function pollIncidentStatus() {
    if (!AppState.incidentId) return;

    try {
        const resp = await fetch(`/api/incident/${AppState.incidentId}/status`);
        const data = await resp.json();

        if (data.state) {
            AppState.lastState = data.state;
            updateDashboard(data.state, data.meta);
        }

        // Continue polling unless complete
        const status = data.meta?.status || 'running';
        if (status !== 'complete' && status !== 'error') {
            setTimeout(pollIncidentStatus, 1500);
        } else {
            // Final update
            setTimeout(() => pollIncidentStatus(), 2000);
        }
    } catch (err) {
        console.error('Polling error:', err);
        setTimeout(pollIncidentStatus, 3000);
    }
}

// ============ DASHBOARD UPDATE ============
function updateDashboard(state, meta) {
    // Update severity badge
    const severity = state.severity_assessment || '';
    if (severity) {
        const badge = document.getElementById('severity-badge');
        badge.textContent = severity;
        badge.className = `severity-badge ${severity.toLowerCase()}`;
        badge.classList.remove('hidden');
    }

    // Update SAIA counters
    updateSaiaCounters(state);

    // Update agent statuses
    const agentStatus = state.agent_status || {};
    updateAllAgentStatuses(agentStatus);

    // Count active agents
    const activeCount = Object.values(agentStatus).filter(s => s === 'running').length;
    const completeCount = Object.values(agentStatus).filter(s => s === 'complete').length;
    document.getElementById('agents-active-count').textContent =
        activeCount > 0 ? `${activeCount} running` : `${completeCount}/5 done`;

    // Update evidence board
    updateEvidenceBoard(state);

    // Update timeline
    updateTimeline(state);

    // Update remediation actions
    updateActions(state);

    // Update execution log
    updateExecutionLog(state.execution_log || []);

    // Store agent-specific data
    storeAgentData(state);

    // Show approval buttons when waiting
    const orchestratorStatus = agentStatus.orchestrator || '';
    if (orchestratorStatus === 'waiting_approval' || orchestratorStatus === 'complete') {
        document.getElementById('approval-buttons').classList.remove('hidden');
    }

    // Show post-mortem button if document exists
    if (state.postmortem_document) {
        showPostmortemButton();
    }
}

// ============ SAIA COUNTER ============
function updateSaiaCounters(state) {
    const saia = state.total_saia_calls || 0;
    const spl = state.total_spl_queries || 0;
    const saved = state.total_saved_searches || 0;

    animateCounter('saia-call-count', saia);
    animateCounter('spl-query-count', spl);
    animateCounter('saved-search-count', saved);
}

function animateCounter(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current === targetValue) return;

    // Animate counting up
    const step = Math.max(1, Math.ceil((targetValue - current) / 5));
    let val = current;
    const interval = setInterval(() => {
        val += step;
        if (val >= targetValue) {
            val = targetValue;
            clearInterval(interval);
        }
        el.textContent = val;
    }, 60);
}

// ============ AGENT DATA STORAGE ============
function storeAgentData(state) {
    // Threat findings
    if (state.threat_findings?.length > 0) {
        AppState.agentData.threat_hunter.findings = state.threat_findings;
    }
    // RCA findings
    if (state.rca_findings?.length > 0) {
        AppState.agentData.rca_agent.findings = state.rca_findings;
    }
    // Blast radius
    if (state.blast_radius?.length > 0) {
        AppState.agentData.blast_radius.findings = state.blast_radius;
    }
    // Remediation
    if (state.remediation_actions?.length > 0) {
        AppState.agentData.remediation.findings = state.remediation_actions;
    }
    // Orchestrator narrative
    if (state.incident_narrative) {
        AppState.agentData.orchestrator.findings = [{
            type: 'narrative',
            content: state.incident_narrative,
            severity: state.severity_assessment,
            mitre: state.mitre_techniques,
        }];
    }

    // Distribute log entries to agents
    for (const entry of (state.execution_log || [])) {
        const agent = entry.agent;
        if (agent && AppState.agentData[agent]) {
            const existing = AppState.agentData[agent].logs;
            if (!existing.find(e => e.timestamp === entry.timestamp && e.detail === entry.detail)) {
                existing.push(entry);
            }
        }
    }
}

// ============ AGENT DETAIL MODAL ============
function openAgentDetail(agentName) {
    const modal = document.getElementById('agent-detail-modal');
    const title = document.getElementById('modal-agent-title');
    const body = document.getElementById('modal-agent-body');

    const agentLabels = {
        orchestrator: '🎯 Orchestrator — Incident Commander',
        threat_hunter: '🔍 Threat Hunter — IOC & MITRE Analysis',
        rca_agent: '🔬 RCA Agent — Root Cause Analysis',
        blast_radius: '💥 Blast Radius — Impact Mapping',
        remediation: '🛠️ Remediation — Action Planning',
    };

    title.textContent = agentLabels[agentName] || agentName;
    body.innerHTML = buildAgentDetailContent(agentName);
    modal.classList.remove('hidden');
}

function closeAgentDetail() {
    document.getElementById('agent-detail-modal').classList.add('hidden');
}

function buildAgentDetailContent(agentName) {
    const data = AppState.agentData[agentName];
    const state = AppState.lastState || {};
    let html = '';

    // Status section
    const status = (state.agent_status || {})[agentName] || 'idle';
    html += `<div class="agent-detail-section">
        <h3>Status</h3>
        <p><span class="agent-status-badge ${status}" style="display:inline-block">${status.toUpperCase()}</span></p>
    </div>`;

    // Agent-specific content
    switch (agentName) {
        case 'threat_hunter':
            html += buildThreatHunterDetail(data);
            break;
        case 'rca_agent':
            html += buildRCADetail(data);
            break;
        case 'blast_radius':
            html += buildBlastRadiusDetail(data);
            break;
        case 'remediation':
            html += buildRemediationDetail(data);
            break;
        case 'orchestrator':
            html += buildOrchestratorDetail(data);
            break;
    }

    // Log entries section
    if (data.logs.length > 0) {
        html += `<div class="agent-detail-section">
            <h3>📋 Activity Log (${data.logs.length} entries)</h3>
            <div style="max-height: 200px; overflow-y: auto;">`;
        for (const log of data.logs.slice(-20)) {
            const detail = log.detail || '';
            const highlighted = detail
                .replace(/\[SAIA:[^\]]+\]/g, '<span class="log-saia-tag">$&</span>')
                .replace(/\[MCP:[^\]]+\]/g, '<span class="log-mcp-tag">$&</span>');
            html += `<div class="log-entry">${highlighted}</div>`;
        }
        html += `</div></div>`;
    }

    if (data.findings.length === 0 && data.logs.length === 0) {
        html += '<div class="agent-detail-section"><p style="color: var(--text-muted); text-align: center; padding: 20px;">No data yet — agent has not run.</p></div>';
    }

    return html;
}

function buildThreatHunterDetail(data) {
    if (data.findings.length === 0) return '';
    let html = `<div class="agent-detail-section">
        <h3>🎯 Threat Findings (${data.findings.length})</h3>
        <table class="agent-detail-table">
            <tr><th>ID</th><th>Finding</th><th>Severity</th><th>MITRE</th><th>Confidence</th></tr>`;

    for (const f of data.findings) {
        html += `<tr>
            <td><code>${f.finding_id || ''}</code></td>
            <td>${f.title || ''}</td>
            <td><span class="finding-severity ${f.severity || ''}">${(f.severity || '').toUpperCase()}</span></td>
            <td><code>${f.mitre_technique || ''}</code></td>
            <td>${f.confidence ? Math.round(f.confidence * 100) + '%' : 'N/A'}</td>
        </tr>`;
    }
    html += '</table></div>';

    // IOCs section
    const allIOCs = data.findings.flatMap(f => f.iocs || []);
    if (allIOCs.length > 0) {
        html += `<div class="agent-detail-section">
            <h3>🌐 Indicators of Compromise (${allIOCs.length})</h3>
            <table class="agent-detail-table">
                <tr><th>Type</th><th>Value</th><th>Context</th></tr>`;
        for (const ioc of allIOCs.slice(0, 15)) {
            html += `<tr>
                <td>${(ioc.type || '').toUpperCase()}</td>
                <td><span class="ioc-badge">${ioc.value || ''}</span></td>
                <td>${ioc.context || ''}</td>
            </tr>`;
        }
        html += '</table></div>';
    }

    // Show SPL queries
    const splQueries = data.findings.filter(f => f.evidence_spl);
    if (splQueries.length > 0) {
        html += `<div class="agent-detail-section"><h3>📊 SPL Queries Executed</h3>`;
        for (const f of splQueries) {
            html += `<div class="agent-detail-spl" style="margin-bottom: 6px;">${f.evidence_spl}</div>`;
        }
        html += '</div>';
    }

    return html;
}

function buildRCADetail(data) {
    if (data.findings.length === 0) return '';
    const f = data.findings[0];
    let html = `<div class="agent-detail-section">
        <h3>🔬 Root Cause</h3>
        <p style="color: var(--text-primary); line-height: 1.6;">${f.root_cause || 'Under investigation'}</p>
        <p style="margin-top: 8px;"><strong>Confidence:</strong> ${f.confidence ? Math.round(f.confidence * 100) + '%' : 'N/A'}</p>
    </div>`;

    if (f.contributing_factors?.length > 0) {
        html += `<div class="agent-detail-section"><h3>⚠️ Contributing Factors</h3><ul style="padding-left: 20px;">`;
        for (const factor of f.contributing_factors) {
            html += `<li style="margin-bottom: 4px; color: var(--text-secondary);">${factor}</li>`;
        }
        html += '</ul></div>';
    }

    if (f.causal_chain?.length > 0) {
        html += `<div class="agent-detail-section"><h3>🔗 Causal Chain (${f.causal_chain.length} events)</h3>
        <table class="agent-detail-table"><tr><th>#</th><th>Time</th><th>Event</th><th>Host</th><th>MITRE</th></tr>`;
        f.causal_chain.forEach((e, i) => {
            const time = e.time ? e.time.substring(11, 19) : '';
            html += `<tr><td>${i+1}</td><td><code>${time}</code></td><td>${e.event || ''}</td><td><code>${e.host || ''}</code></td><td>${e.mitre || ''}</td></tr>`;
        });
        html += '</table></div>';
    }

    return html;
}

function buildBlastRadiusDetail(data) {
    if (data.findings.length === 0) return '';
    const entities = data.findings;
    const types = ['host', 'user', 'service', 'data_store'];
    const labels = { host: '🖥️ Hosts', user: '👤 Users', service: '⚙️ Services', data_store: '💾 Data Stores' };
    let html = '';

    for (const type of types) {
        const items = entities.filter(e => e.entity_type === type);
        if (items.length === 0) continue;

        html += `<div class="agent-detail-section"><h3>${labels[type]} (${items.length})</h3>
        <table class="agent-detail-table"><tr><th>Name</th><th>Risk</th><th>Score</th><th>Details</th></tr>`;
        for (const e of items) {
            const emoji = e.risk_level === 'compromised' ? '🔴' : '🟡';
            html += `<tr><td>${emoji} <code>${e.name || ''}</code></td><td>${e.risk_level || ''}</td>
                <td>${e.risk_score ? Math.round(e.risk_score * 100) + '%' : ''}</td>
                <td style="font-size:0.72rem;">${e.details || ''}</td></tr>`;
        }
        html += '</table></div>';
    }
    return html;
}

function buildRemediationDetail(data) {
    if (data.findings.length === 0) return '';
    let html = `<div class="agent-detail-section">
        <h3>🛠️ Remediation Actions (${data.findings.length})</h3>
        <table class="agent-detail-table">
            <tr><th>Priority</th><th>Action</th><th>Target</th><th>Type</th><th>Approval</th></tr>`;

    const sorted = [...data.findings].sort((a, b) => (a.priority || 99) - (b.priority || 99));
    for (const a of sorted) {
        const approvalBadge = a.requires_approval ? '🔒 Required' : '✅ Auto';
        html += `<tr>
            <td><span class="action-priority p${a.priority || 5}" style="display:inline-flex; width:24px; height:24px; font-size:0.65rem;">P${a.priority || '?'}</span></td>
            <td><strong>${a.title || ''}</strong></td>
            <td><code style="font-size:0.65rem;">${(a.target || '').substring(0, 30)}</code></td>
            <td>${a.action_type || ''}</td>
            <td>${approvalBadge}</td>
        </tr>`;
    }
    html += '</table></div>';

    // Show detailed descriptions
    html += `<div class="agent-detail-section"><h3>📝 Action Details</h3>`;
    for (const a of sorted) {
        html += `<div style="margin-bottom: 10px; padding: 8px 10px; background: rgba(20,30,55,0.3); border-radius: 6px;">
            <strong style="color: var(--accent-cyan);">${a.title || ''}</strong>
            <p style="color: var(--text-secondary); margin-top: 4px; font-size: 0.75rem;">${a.description || ''}</p>
            ${a.risk_assessment ? `<p style="color: var(--accent-orange); font-size: 0.7rem; margin-top: 2px;">Risk: ${a.risk_assessment}</p>` : ''}
        </div>`;
    }
    html += '</div>';
    return html;
}

function buildOrchestratorDetail(data) {
    if (data.findings.length === 0) return '';
    const state = AppState.lastState || {};
    let html = '';

    // Narrative
    if (state.incident_narrative) {
        html += `<div class="agent-detail-section">
            <h3>📝 Incident Narrative</h3>
            <div style="white-space: pre-wrap; color: var(--text-secondary); line-height: 1.7; font-size: 0.78rem;">
                ${state.incident_narrative.replace(/\n/g, '<br>')}
            </div>
        </div>`;
    }

    // Data context
    if (state.data_context && Object.keys(state.data_context).length > 0) {
        html += `<div class="agent-detail-section">
            <h3>📊 Discovered Data Context</h3>
            <table class="agent-detail-table"><tr><th>Index</th><th>Sourcetypes</th></tr>`;
        for (const [idx, sts] of Object.entries(state.data_context)) {
            html += `<tr><td><code>${idx}</code></td><td>${sts.map(s => `<code>${s}</code>`).join(', ')}</td></tr>`;
        }
        html += '</table></div>';
    }

    // MITRE techniques
    if (state.mitre_techniques?.length > 0) {
        html += `<div class="agent-detail-section">
            <h3>🗺️ MITRE ATT&CK Techniques</h3>
            <div style="display: flex; gap: 6px; flex-wrap: wrap;">`;
        for (const tech of state.mitre_techniques) {
            html += `<span style="background: rgba(239,68,68,0.1); color: var(--accent-red); padding: 3px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.7rem;">${tech}</span>`;
        }
        html += '</div></div>';
    }

    return html;
}

// ============ EXECUTION LOG ============
function updateExecutionLog(logs) {
    const container = document.getElementById('execution-log');
    if (!container) return;

    // Only add new entries
    const existing = container.children.length;
    const newEntries = logs.slice(existing);

    for (const entry of newEntries) {
        const div = document.createElement('div');
        div.className = 'log-entry';
        const detail = entry.detail || '';
        const highlighted = detail
            .replace(/\[SAIA:[^\]]+\]/g, '<span class="log-saia-tag">$&</span>')
            .replace(/\[MCP:[^\]]+\]/g, '<span class="log-mcp-tag">$&</span>');
        div.innerHTML = `<span class="log-agent">${entry.agent || '?'}</span> ${highlighted}`;
        container.prepend(div);
    }
}

// ============ APPROVAL ============
async function approveIncident(decision) {
    if (!AppState.incidentId) return;

    try {
        const resp = await fetch(`/api/incident/${AppState.incidentId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision }),
        });
        const data = await resp.json();

        // Update buttons
        const buttons = document.getElementById('approval-buttons');
        buttons.innerHTML = `<div style="text-align: center; width: 100%; padding: 8px; color: var(--accent-green); font-weight: 600;">
            ✅ ${decision.toUpperCase()} — Actions executing...</div>`;

        // Continue polling for post-mortem
        setTimeout(pollIncidentStatus, 2000);
    } catch (err) {
        console.error('Approval failed:', err);
    }
}

// ============ POST-MORTEM ============
function showPostmortemButton() {
    const buttons = document.getElementById('approval-buttons');
    if (!buttons.querySelector('.btn-postmortem')) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-demo btn-postmortem';
        btn.style.cssText = 'width: 100%; margin-top: 8px; padding: 10px; font-size: 0.85rem;';
        btn.textContent = '📋 View Post-Mortem Report';
        btn.onclick = () => openPostmortem();
        buttons.classList.remove('hidden');
        buttons.appendChild(btn);
    }
}

function openPostmortem() {
    const state = AppState.lastState;
    if (!state?.postmortem_document) return;

    const panel = document.getElementById('postmortem-panel');
    const content = document.getElementById('postmortem-content');
    content.innerHTML = renderMarkdown(state.postmortem_document);
    panel.classList.remove('hidden');
}

function closePostmortem() {
    document.getElementById('postmortem-panel').classList.add('hidden');
}

// Close modals on overlay click
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
        e.target.classList.add('hidden');
    }
});

// Close modals on Escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.add('hidden'));
    }
});
