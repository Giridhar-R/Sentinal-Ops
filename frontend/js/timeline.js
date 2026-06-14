/**
 * SentinelOps — Timeline Renderer
 * Renders incident timeline with severity markers and MITRE labels
 */

function updateTimeline(state) {
    const container = document.getElementById('timeline-container');
    if (!container) return;

    const rca = state.rca_findings || [];
    if (rca.length === 0) return;

    const f = rca[0];
    const chain = f.causal_chain || [];
    if (chain.length === 0) return;

    let html = '';
    for (const event of chain) {
        const time = event.time ? event.time.substring(11, 19) : '';
        const mitre = event.mitre || '';
        const eventText = event.event || '';
        const detail = event.detail || '';
        const host = event.host || '';

        // Determine severity marker
        let dotClass = '';
        if (eventText.toLowerCase().includes('compromise') || eventText.toLowerCase().includes('success')) {
            dotClass = 'critical';
        } else if (eventText.toLowerCase().includes('lateral') || eventText.toLowerCase().includes('escalat')) {
            dotClass = 'high';
        }

        html += `<div class="timeline-event">
            <div class="timeline-marker">
                <span class="timeline-time">${time}</span>
                <div class="timeline-dot ${dotClass}"></div>
            </div>
            <div class="timeline-content">
                <div class="timeline-title">${eventText}</div>
                <div class="timeline-detail">${detail}</div>
                ${host ? `<span class="timeline-host">♥ ${host}</span>` : ''}
                ${mitre ? `<span style="font-size:0.6rem; color: var(--accent-red); margin-left: 8px;">${mitre}</span>` : ''}
            </div>
        </div>`;
    }

    container.innerHTML = html;
}
