/**
 * SentinelOps — Post-Mortem Markdown Renderer
 * Converts markdown to styled HTML for the post-mortem modal
 */

function renderMarkdown(md) {
    if (!md) return '<p class="text-muted">No post-mortem data available.</p>';

    let html = md
        // Escape HTML
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')

        // Code blocks (``` ... ```)
        .replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
            return `<pre><code class="lang-${lang || 'text'}">${code.trim()}</code></pre>`;
        })

        // Headers
        .replace(/^#### (.*$)/gm, '<h4>$1</h4>')
        .replace(/^### (.*$)/gm, '<h3>$1</h3>')
        .replace(/^## (.*$)/gm, '<h2>$1</h2>')
        .replace(/^# (.*$)/gm, '<h1>$1</h1>')

        // Horizontal rules
        .replace(/^---$/gm, '<hr>')

        // Bold + italic
        .replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')

        // Inline code
        .replace(/`([^`]+)`/g, '<code>$1</code>')

        // Blockquotes
        .replace(/^&gt; (.*$)/gm, '<blockquote>$1</blockquote>')

        // Ordered lists
        .replace(/^\d+\. (.*)$/gm, '<li class="ol-item">$1</li>')

        // Unordered lists
        .replace(/^- (.*)$/gm, '<li class="ul-item">$1</li>');

    // Wrap consecutive list items
    html = html
        .replace(/((?:<li class="ol-item">.*<\/li>\n?)+)/g, '<ol>$1</ol>')
        .replace(/((?:<li class="ul-item">.*<\/li>\n?)+)/g, '<ul>$1</ul>')
        .replace(/ class="ol-item"/g, '')
        .replace(/ class="ul-item"/g, '');

    // Tables
    html = html.replace(
        /(\|.+\|)\n(\|[-:| ]+\|)\n((?:\|.+\|\n?)+)/g,
        (match, headerRow, separatorRow, bodyRows) => {
            const headers = headerRow.split('|').filter(h => h.trim());
            const rows = bodyRows.trim().split('\n');

            let table = '<table><thead><tr>';
            for (const h of headers) {
                table += `<th>${h.trim()}</th>`;
            }
            table += '</tr></thead><tbody>';

            for (const row of rows) {
                const cells = row.split('|').filter(c => c.trim() !== '' || c.includes(' '));
                // Filter more carefully - split by | but skip empty first/last
                const cleanCells = row.split('|').slice(1, -1);
                table += '<tr>';
                for (const cell of cleanCells) {
                    table += `<td>${cell.trim()}</td>`;
                }
                table += '</tr>';
            }
            table += '</tbody></table>';
            return table;
        }
    );

    // Paragraphs - wrap text not in HTML tags
    const lines = html.split('\n');
    const result = [];
    let inBlock = false;

    for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) {
            if (!inBlock) result.push('');
            continue;
        }
        if (trimmed.startsWith('<h') || trimmed.startsWith('<table') ||
            trimmed.startsWith('<ul') || trimmed.startsWith('<ol') ||
            trimmed.startsWith('<li') || trimmed.startsWith('<pre') ||
            trimmed.startsWith('<hr') || trimmed.startsWith('<blockquote') ||
            trimmed.startsWith('</')) {
            result.push(trimmed);
            inBlock = trimmed.startsWith('<pre') || trimmed.startsWith('<table');
            if (trimmed.includes('</pre>') || trimmed.includes('</table>')) inBlock = false;
        } else if (inBlock) {
            result.push(trimmed);
        } else {
            result.push(`<p>${trimmed}</p>`);
        }
    }

    return result.join('\n');
}
