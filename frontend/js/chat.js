/**
 * SentinelOps — War Room Chat
 * Sends operator questions via /api/chat endpoint
 * Powered by saia_ask_splunk_question + saia_generate_spl
 */

async function sendChatMessage() {
    const input = document.getElementById('chat-input');
    const message = input.value.trim();
    if (!message) return;

    const messagesContainer = document.getElementById('chat-messages');

    // Add user message
    const userDiv = document.createElement('div');
    userDiv.className = 'chat-message user';
    userDiv.textContent = message;
    messagesContainer.appendChild(userDiv);
    input.value = '';

    // Add typing indicator
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-message system';
    typingDiv.id = 'chat-typing';
    typingDiv.innerHTML = '<span class="saia-tag">saia_ask_splunk_question</span> Processing...';
    messagesContainer.appendChild(typingDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    try {
        const resp = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                incident_id: AppState.incidentId || '',
            }),
        });
        const data = await resp.json();

        // Remove typing indicator
        const typing = document.getElementById('chat-typing');
        if (typing) typing.remove();

        // Add agent response
        const agentDiv = document.createElement('div');
        agentDiv.className = 'chat-message agent';

        let responseHtml = '';
        if (data.answer) {
            responseHtml += `<p>${data.answer}</p>`;
        }
        if (data.spl) {
            responseHtml += `<div style="margin-top: 6px; font-family: var(--font-mono); font-size: 0.68rem; color: var(--accent-purple); background: rgba(139,92,246,0.06); padding: 6px 8px; border-radius: 4px;">${data.spl}</div>`;
        }
        if (data.tool_used) {
            responseHtml += `<div style="margin-top: 4px;"><span class="saia-tag">${data.tool_used}</span></div>`;
        }

        agentDiv.innerHTML = responseHtml || data.response || 'No response';
        messagesContainer.appendChild(agentDiv);
    } catch (err) {
        const typing = document.getElementById('chat-typing');
        if (typing) typing.remove();

        const errorDiv = document.createElement('div');
        errorDiv.className = 'chat-message system';
        errorDiv.textContent = '⚠️ Connection error. Please try again.';
        messagesContainer.appendChild(errorDiv);
    }

    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function updateActions(state) {
    const container = document.getElementById('actions-list');
    if (!container) return;

    const actions = state.remediation_actions || [];
    if (actions.length === 0) return;

    const sorted = [...actions].sort((a, b) => (a.priority || 99) - (b.priority || 99));

    let html = '';
    for (const action of sorted) {
        const priority = action.priority || 5;
        html += `<div class="action-card">
            <div class="action-priority p${priority}">P${priority}</div>
            <div class="action-info">
                <div class="action-title">${action.title || 'Unknown'}</div>
                <div class="action-target">• ${action.target || ''}</div>
            </div>
            ${action.requires_approval ? '<div class="action-lock">🔒</div>' : ''}
        </div>`;
    }

    container.innerHTML = html;
}
