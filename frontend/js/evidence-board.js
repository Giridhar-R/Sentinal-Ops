/**
 * SentinelOps — Evidence Board
 * Renders expandable evidence cards with SAIA/MCP tool tags
 */

function updateEvidenceBoard(state) {
    const container = document.getElementById('evidence-list');
    const countBadge = document.getElementById('evidence-count');
    if (!container) return;

    const findings = state.threat_findings || [];
    const rca = state.rca_findings || [];
    const blast = state.blast_radius || [];

    const totalEvidence = findings.length + rca.length + (blast.length > 0 ? 1 : 0);
    countBadge.textContent = totalEvidence;

    if (totalEvidence === 0) return;

    let html = '';

    // Threat findings
    for (const f of findings) {
        const severityClass = (f.severity || 'medium').toLowerCase();
        const borderColor = severityClass === 'critical' ? 'var(--severity-critical)' :
                           severityClass === 'high' ? 'var(--severity-high)' : 'var(--accent-blue)';
        const confidence = f.confidence ? Math.round(f.confidence * 100) : 0;

        html += `<div class="evidence-card" style="border-left-color: ${borderColor};" onclick="this.classList.toggle('expanded')">
            <div class="evidence-card-header">
                <span class="evidence-card-title">${f.title || 'Unknown'}</span>
                <div class="evidence-card-meta">
                    <span class="evidence-tool-tag saia">SAIA</span>
                    <span class="evidence-tool-tag mcp">MCP</span>
                    <span class="evidence-severity ${severityClass}">${(f.severity || '').toUpperCase()}</span>
                </div>
            </div>
            <div class="evidence-card-body">
                <p style="margin-bottom: 6px;">${f.description || ''}</p>
                <p><strong>MITRE:</strong> ${f.mitre_technique || 'N/A'} — ${f.mitre_tactic || ''}</p>
                <p><strong>Confidence:</strong> ${confidence}%</p>
                ${f.iocs ? `<p><strong>IOCs:</strong> ${f.iocs.length} indicators</p>` : ''}
                ${f.evidence_spl ? `<div class="evidence-spl">${f.evidence_spl}</div>` : ''}
            </div>
        </div>`;
    }

    // RCA findings
    for (const f of rca) {
        html += `<div class="evidence-card" style="border-left-color: var(--accent-cyan);" onclick="this.classList.toggle('expanded')">
            <div class="evidence-card-header">
                <span class="evidence-card-title">🔬 Root Cause Analysis</span>
                <div class="evidence-card-meta">
                    <span class="evidence-tool-tag saia">SAIA</span>
                    <span class="evidence-tool-tag mcp">MCP</span>
                    <span class="evidence-severity high">RCA</span>
                </div>
            </div>
            <div class="evidence-card-body">
                <p>${f.root_cause || 'Under investigation'}</p>
                <p style="margin-top: 6px;"><strong>Confidence:</strong> ${f.confidence ? Math.round(f.confidence * 100) + '%' : 'N/A'}</p>
                ${f.causal_chain ? `<p><strong>Causal Chain:</strong> ${f.causal_chain.length} events</p>` : ''}
                ${f.evidence_spl ? `<div class="evidence-spl">${f.evidence_spl}</div>` : ''}
            </div>
        </div>`;
    }

    // Blast radius summary
    if (blast.length > 0) {
        const compromised = blast.filter(e => e.risk_level === 'compromised').length;
        const affected = blast.length - compromised;
        html += `<div class="evidence-card" style="border-left-color: var(--accent-orange);" onclick="this.classList.toggle('expanded')">
            <div class="evidence-card-header">
                <span class="evidence-card-title">💥 Blast Radius — ${blast.length} Entities</span>
                <div class="evidence-card-meta">
                    <span class="evidence-tool-tag saia">SAIA</span>
                    <span class="evidence-severity critical">${compromised} COMPROMISED</span>
                </div>
            </div>
            <div class="evidence-card-body">
                <p><strong>${compromised}</strong> confirmed compromised, <strong>${affected}</strong> potentially affected</p>
                <div style="margin-top: 8px;">
                    ${blast.map(e => {
                        const emoji = e.risk_level === 'compromised' ? '🔴' : '🟡';
                        return `<span style="display: inline-block; font-size: 0.7rem; margin: 2px 4px; padding: 2px 6px; background: rgba(20,30,55,0.4); border-radius: 4px;">${emoji} ${e.name}</span>`;
                    }).join('')}
                </div>
            </div>
        </div>`;
    }

    container.innerHTML = html;
}
