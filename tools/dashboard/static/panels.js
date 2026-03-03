// panels.js - Individual Panel Renderers

// 1. Overview Panel
window.renderOverview = async (caseId) => {
    const container = document.getElementById('panel-overview');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}`);
        const data = await response.json();

        const intake = data.intake || {};
        const kind = intake.classification?.kind || 'Unknown';
        const hostname = intake.classification?.hostname || 'Unknown';

        let html = `
            <div class="prop-grid">
                <div class="prop-label">Case ID</div>
                <div class="prop-value"><code>${data.id}</code></div>
                
                <div class="prop-label">Evidence Type</div>
                <div class="prop-value"><span class="badge info">${kind}</span></div>
                
                <div class="prop-label">Target Host</div>
                <div class="prop-value">${hostname}</div>
                
                <div class="prop-label">Intake UTC</div>
                <div class="prop-value">${intake.intake_utc || 'N/A'}</div>
            </div>
        `;

        if (data.manifest && data.manifest.tools_run) {
            html += `<h3>Tools Executed (${data.manifest.tools_run.length})</h3><ul>`;
            data.manifest.tools_run.forEach(t => {
                html += `<li>${t.name} (v${t.version}) - ${t.duration_s.toFixed(1)}s</li>`;
            });
            html += '</ul>';
        }

        container.innerHTML = html;

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load overview: ${e.message}</div>`;
    }
};

// 2. Findings Panel (Table with Severity Filter)
let findingsData = [];
window.renderFindings = async (caseId) => {
    const container = document.getElementById('panel-findings');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}/findings`);
        const data = await response.json();
        findingsData = data.findings || [];

        renderFindingsTable(container, findingsData, 'all');

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load findings: ${e.message}</div>`;
    }
};

const renderFindingsTable = (container, data, filter) => {
    let filtered = data;
    if (filter !== 'all') {
        filtered = data.filter(f => f.severity?.toLowerCase() === filter.toLowerCase());
    }

    let html = `
        <div style="margin-bottom: 10px;">
            <select id="severity-filter" onchange="renderFindingsTable(document.getElementById('panel-findings'), findingsData, this.value)">
                <option value="all" ${filter === 'all' ? 'selected' : ''}>All Severities</option>
                <option value="critical" ${filter === 'critical' ? 'selected' : ''}>Critical Only</option>
                <option value="high" ${filter === 'high' ? 'selected' : ''}>High+</option>
                <option value="medium" ${filter === 'medium' ? 'selected' : ''}>Medium+</option>
            </select>
            <span style="float:right; color: var(--text-secondary);">${filtered.length} total</span>
        </div>
        <div style="overflow-x: auto;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
    `;

    if (filtered.length === 0) {
        html += `<tr><td colspan="4" style="text-align:center;">No findings reported.</td></tr>`;
    } else {
        filtered.forEach(f => {
            const sev = (f.severity || f.impact || 'info').toLowerCase();
            const type = f.category || f.type || 'Unknown';
            const desc = f.summary || f.statement || f.description || 'N/A';
            let source = 'N/A';
            if (f.source && f.source.tool) {
                source = `${f.source.tool} ${f.source.rule_title ? '(' + f.source.rule_title + ')' : ''}`;
            } else if (f.source_evidence_id) {
                source = f.source_evidence_id;
            } else if (f.evidence_refs && f.evidence_refs.length > 0) {
                source = f.evidence_refs[0].substring(0, 15) + '...';
            }

            html += `
                <tr>
                    <td><span class="badge ${sev}">${sev}</span></td>
                    <td>${type}</td>
                    <td>${desc}</td>
                    <td><code>${source}</code></td>
                </tr>
            `;
        });
    }

    html += `</tbody></table></div>`;
    container.innerHTML = html;
};

// 3. Notes Panel (Markdown)
window.renderNotes = async (caseId) => {
    const container = document.getElementById('panel-notes');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}/notes`);
        const data = await response.json();

        if (data.notes) {
            // Use marked.js if available, otherwise raw text
            if (typeof marked !== 'undefined') {
                container.innerHTML = `<div class="markdown-body">${marked.parse(data.notes)}</div>`;
            } else {
                container.innerHTML = `<pre>${data.notes}</pre>`;
            }
        } else {
            container.innerHTML = `<div class="loading">No investigation notes found.</div>`;
        }

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load notes: ${e.message}</div>`;
    }
};

// 4. Audit Trail Panel (JSONL Logs)
window.renderAudit = async (caseId) => {
    const container = document.getElementById('panel-audit');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}/audit`);
        const data = await response.json();

        let html = '<div style="display: flex; flex-direction: column; gap: 10px;">';

        if (data.audit && data.audit.length > 0) {
            data.audit.forEach((entry, i) => {
                const toolsText = entry.tool_calls_issued ? `🛠️ Tools: ${entry.tool_calls_issued.join(', ')}` : '💬 Reasoning';
                html += `
                    <div style="border: 1px solid var(--border); border-radius: 6px; padding: 10px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 5px; cursor: pointer;" 
                             onclick="const d = document.getElementById('audit-details-${i}'); d.style.display = d.style.display === 'none' ? 'block' : 'none';">
                            <strong>Step ${i + 1}: ${toolsText}</strong>
                            <span style="color: var(--text-secondary); font-size: 0.8em;">(Click to expand)</span>
                        </div>
                        <div id="audit-details-${i}" style="display: none; margin-top: 10px;">
                            <div style="margin-bottom: 5px;"><strong>Input Hash:</strong> <code>${entry.context_hash}</code></div>
                            <pre style="margin:0;"><code>${JSON.stringify(entry.raw_response, null, 2)}</code></pre>
                        </div>
                    </div>
                `;
            });
        } else {
            html += `<div class="loading">No orchestrator audit logs found for this case.</div>`;
        }

        html += '</div>';
        container.innerHTML = html;

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load audit trail: ${e.message}</div>`;
    }
};

// 5. Agent Thoughts Panel (Readable text of what the agent is doing)
window.renderAgent = async (caseId) => {
    const container = document.getElementById('panel-agent');
    if (!container) return;

    try {
        // We reuse the audit API but extract the human readable text
        const response = await fetch(`/api/cases/${caseId}/audit`);
        const data = await response.json();

        let html = '<div class="agent-thoughts-container" style="display: flex; flex-direction: column; gap: 15px; padding: 10px;">';

        if (data.audit && data.audit.length > 0) {
            data.audit.forEach((entry, i) => {
                let textContent = '';

                // Parse deepseek/litellm response structure
                if (entry.raw_response && entry.raw_response.choices && entry.raw_response.choices.length > 0) {
                    textContent = entry.raw_response.choices[0].message?.content || '';
                } else {
                    textContent = entry.raw_response?.message?.content || entry.raw_response?.content || '';
                }

                if (textContent.trim()) {
                    let formattedText = typeof marked !== 'undefined' ? marked.parse(textContent) : `<pre style="white-space: pre-wrap;">${textContent}</pre>`;
                    html += `
                        <div class="agent-thought-item" style="border-left: 3px solid var(--accent); padding-left: 10px; background: rgba(0,0,0,0.2); border-radius: 4px; padding-top: 5px; padding-bottom: 5px; padding-right: 10px;">
                            <div style="font-size: 0.8em; color: var(--accent); margin-bottom: 5px; font-weight: bold;">[Step ${i + 1}]</div>
                            <div class="markdown-body" style="font-size: 0.9em;">${formattedText}</div>
                        </div>
                    `;
                } else if (entry.tool_calls_issued) {
                    html += `
                        <div class="agent-thought-item" style="border-left: 3px solid var(--warning); padding-left: 10px; background: rgba(0,0,0,0.2); border-radius: 4px; padding-top: 5px; padding-bottom: 5px; padding-right: 10px;">
                            <div style="font-size: 0.8em; color: var(--warning); margin-bottom: 5px; font-weight: bold;">[Step ${i + 1}] ⚙️ Executing Tools</div>
                            <div style="font-size: 0.9em; font-family: monospace;">${entry.tool_calls_issued.join(', ')}</div>
                        </div>
                    `;
                }
            });
        } else {
            html += `<div class="loading">Agent is starting up or waiting for input...</div>`;
        }

        html += '</div>';

        // Auto scroll to bottom only if user hasn't heavily scrolled up
        const isScrolledToBottom = container.scrollHeight - container.clientHeight <= container.scrollTop + 50;

        container.innerHTML = html;

        if (isScrolledToBottom) {
            container.scrollTop = container.scrollHeight;
        }

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load agent thoughts: ${e.message}</div>`;
    }
};
