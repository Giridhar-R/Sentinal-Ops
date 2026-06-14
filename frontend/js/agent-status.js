/**
 * SentinelOps — Agent Status Manager
 * Updates agent cards with status, detail text, and progress bars
 */

function updateAllAgentStatuses(agentStatus) {
    for (const [agent, status] of Object.entries(agentStatus)) {
        updateAgentCard(agent, status);
    }
}

function updateAgentCard(agentName, status) {
    const card = document.getElementById(`agent-${agentName}`);
    const badge = document.getElementById(`status-${agentName}`);
    const detail = document.getElementById(`detail-${agentName}`);

    if (!card || !badge) return;

    // Remove old status classes
    card.classList.remove('idle', 'running', 'complete', 'error', 'waiting', 'waiting_approval');
    badge.classList.remove('idle', 'running', 'complete', 'error', 'waiting', 'waiting_approval');

    // Add new status
    card.classList.add(status);
    badge.classList.add(status);

    // Status labels
    const labels = {
        idle: 'Idle',
        running: 'Running',
        complete: 'Complete',
        error: 'Error',
        waiting: 'Waiting',
        waiting_approval: 'Awaiting',
    };
    badge.textContent = labels[status] || status;

    // Update detail from stored agent data
    const data = AppState.agentData[agentName];
    if (data && status === 'complete') {
        const counts = {
            orchestrator: () => 'Synthesis complete — severity assessed',
            threat_hunter: () => `Found ${data.findings.length} threat indicators`,
            rca_agent: () => data.findings.length > 0 ? 'Root cause identified' : 'Analysis complete',
            blast_radius: () => `Mapped ${data.findings.length} affected entities`,
            remediation: () => `${data.findings.length} actions recommended`,
        };
        if (counts[agentName]) {
            detail.textContent = counts[agentName]();
        }
    } else if (status === 'running') {
        const runLabels = {
            orchestrator: 'Discovering indexes & classifying incident...',
            threat_hunter: 'Running SAIA→MCP hunt pipeline...',
            rca_agent: 'Correlating saved searches & timeline...',
            blast_radius: 'Mapping affected entities...',
            remediation: 'Building action plan...',
        };
        detail.textContent = runLabels[agentName] || 'Processing...';
    }
}
