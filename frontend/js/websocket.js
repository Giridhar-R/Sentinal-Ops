/**
 * SentinelOps — WebSocket Manager
 * Handles real-time connection to the backend with auto-reconnect
 */

let ws = null;
let wsReconnectTimer = null;
const WS_URL = `ws://${window.location.host}/ws`;

function initWebSocket() {
    try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            console.log('[WS] Connected');
            updateConnectionStatus(true);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleWSMessage(data);
            } catch (e) {
                console.warn('[WS] Parse error:', e);
            }
        };

        ws.onclose = () => {
            console.log('[WS] Disconnected');
            updateConnectionStatus(false);
            // Auto-reconnect after 3 seconds
            wsReconnectTimer = setTimeout(initWebSocket, 3000);
        };

        ws.onerror = (err) => {
            console.error('[WS] Error:', err);
            updateConnectionStatus(false);
        };
    } catch (e) {
        console.error('[WS] Failed to create:', e);
        updateConnectionStatus(false);
        wsReconnectTimer = setTimeout(initWebSocket, 5000);
    }
}

function updateConnectionStatus(connected) {
    const dot = document.getElementById('ws-status-dot');
    const text = document.getElementById('ws-status-text');
    if (dot) {
        dot.className = `status-dot ${connected ? 'connected' : ''}`;
    }
    if (text) {
        text.textContent = connected ? 'Connected' : 'Reconnecting...';
    }
}

function handleWSMessage(data) {
    const type = data.type || data.event;

    switch (type) {
        case 'agent_status':
            if (data.agent && data.status) {
                updateAgentCard(data.agent, data.status);
                // Update detail text if provided
                if (data.detail) {
                    const detailEl = document.getElementById(`detail-${data.agent}`);
                    if (detailEl) detailEl.textContent = data.detail;
                }
            }
            break;

        case 'evidence_update':
            if (data.state) {
                updateEvidenceBoard(data.state);
                updateTimeline(data.state);
                updateActions(data.state);
                storeAgentData(data.state);
            }
            break;

        case 'log_entry':
            if (data.entry) {
                const logContainer = document.getElementById('execution-log');
                if (logContainer) {
                    const div = document.createElement('div');
                    div.className = 'log-entry';
                    const detail = data.entry.detail || '';
                    const highlighted = detail
                        .replace(/\[SAIA:[^\]]+\]/g, '<span class="log-saia-tag">$&</span>')
                        .replace(/\[MCP:[^\]]+\]/g, '<span class="log-mcp-tag">$&</span>');
                    div.innerHTML = `<span class="log-agent">${data.entry.agent || '?'}</span> ${highlighted}`;
                    logContainer.prepend(div);
                }

                // Update agent SPL display
                if (data.entry.spl_query && data.entry.agent) {
                    const splEl = document.getElementById(`spl-${data.entry.agent}`);
                    if (splEl) {
                        splEl.textContent = data.entry.spl_query;
                        splEl.style.display = 'block';
                    }
                }
            }
            break;

        case 'counter_update':
            if (data.counters) {
                animateCounter('saia-call-count', data.counters.total_saia_calls || 0);
                animateCounter('spl-query-count', data.counters.total_spl_queries || 0);
                animateCounter('saved-search-count', data.counters.total_saved_searches || 0);
            }
            break;

        case 'incident_complete':
            if (data.state) {
                AppState.lastState = data.state;
                updateDashboard(data.state, { status: 'complete' });
            }
            break;

        default:
            console.log('[WS] Unknown message type:', type, data);
    }
}
