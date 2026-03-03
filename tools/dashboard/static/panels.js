// panels.js - Individual Panel Renderers

// 1. Overview Panel
window.renderOverview = async (caseId) => {
    const container = document.getElementById('panel-overview');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}`);
        const data = await response.json();

        // Track active state globally to control polling
        window.isCurrentCaseActive = data.is_active;

        const intake = data.intake || {};
        const kind = intake.classification?.kind || 'Unknown';
        const hostname = intake.classification?.hostname || 'Unknown';
        const statusBadge = data.is_active
            ? '<span class="badge warning" style="animation: pulse 2s infinite;">Live Investigation</span>'
            : '<span class="badge info">Finished</span>';

        let html = `
            <div style="margin-bottom: 15px;">${statusBadge}</div>
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

        const prevScroll = container.scrollTop;
        if (container.innerHTML !== html) {
            container.innerHTML = html;
        }
        container.scrollTop = prevScroll;

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load overview: ${e.message}</div>`;
    }
};

// 1.5 Artifacts / Evidence Panel
window.renderArtifacts = async (caseId) => {
    const container = document.getElementById('panel-artifacts');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}`);
        const data = await response.json();

        const intake = data.intake || {};
        const manifest = data.manifest || {};

        let html = '<div style="display: flex; flex-direction: column; gap: 15px;">';

        // Function to categorize and build tables
        const buildCategorizedTables = (evidenceArray) => {
            const categories = {
                '🖥️ Event Logs (EVTX)': [],
                '🧠 Memory Dumps': [],
                '⚙️ Tool Outputs': [],
                '📄 Other Evidence': []
            };

            evidenceArray.forEach(e => {
                const pathStr = (e.relpath || '').toLowerCase();
                const typeStr = (e.type || '').toLowerCase();

                if (pathStr.endsWith('.evtx')) {
                    categories['🖥️ Event Logs (EVTX)'].push(e);
                } else if (pathStr.endsWith('.raw') || pathStr.endsWith('.dd') || pathStr.endsWith('.mem') || typeStr.includes('memory')) {
                    categories['🧠 Memory Dumps'].push(e);
                } else if (pathStr.endsWith('.csv') || pathStr.endsWith('.json') || pathStr.endsWith('.plaso') || typeStr.includes('tool')) {
                    categories['⚙️ Tool Outputs'].push(e);
                } else {
                    categories['📄 Other Evidence'].push(e);
                }
            });

            let t = '';
            for (const [categoryName, items] of Object.entries(categories)) {
                if (items.length === 0) continue;

                t += `<div style="margin-bottom: 10px;">`;
                t += `<div style="font-weight: bold; margin-bottom: 5px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 3px;">${categoryName} (${items.length})</div>`;
                t += `<div style="overflow-x: auto;"><table class="data-table"><thead><tr><th>ID</th><th>Type</th><th>Path</th></tr></thead><tbody>`;

                items.forEach(e => {
                    let shortPath = (e.relpath || 'N/A').length > 40 ? '...' + (e.relpath || 'N/A').substring((e.relpath || 'N/A').length - 37) : (e.relpath || 'N/A');
                    t += `<tr><td><code>${e.evidence_id || 'N/A'}</code></td><td><span class="badge" style="background:var(--bg-panel); border:1px solid var(--border);">${e.type || 'N/A'}</span></td><td title="${e.relpath || ''}"><code>${shortPath}</code></td></tr>`;
                });

                t += '</tbody></table></div></div>';
            }
            return t;
        };

        // Check V30 manifest format first
        if (manifest.evidence && manifest.evidence.length > 0) {
            html += buildCategorizedTables(manifest.evidence);
        }
        // Then check V30 intake format
        else if (intake.evidence && intake.evidence.length > 0) {
            html += buildCategorizedTables(intake.evidence);
        }
        // Finally fallback to legacy format (list of paths)
        else if (intake.inputs && intake.inputs.paths && intake.inputs.paths.length > 0) {
            // Emulate V30 format for legacy categorization
            const emulatedEvidence = intake.inputs.paths.map((p, i) => ({
                evidence_id: `legacy-${i}`,
                type: 'legacy_input',
                relpath: p
            }));
            html += buildCategorizedTables(emulatedEvidence);
        } else {
            html += `<div class="loading">No artifacts or evidence listed for this case.</div>`;
        }

        html += '</div>';

        const prevScroll = container.scrollTop;
        if (container.innerHTML !== html) {
            container.innerHTML = html;
        }
        container.scrollTop = prevScroll;

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load artifacts: ${e.message}</div>`;
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
    const prevScroll = container.scrollTop;
    if (container.innerHTML !== html) {
        container.innerHTML = html;
    }
    container.scrollTop = prevScroll;
};

// 3. Notes Panel (Markdown)
window.renderNotes = async (caseId) => {
    const container = document.getElementById('panel-notes');
    if (!container) return;

    try {
        const response = await fetch(`/api/cases/${caseId}/notes`);
        const data = await response.json();

        let newHtml = '';
        if (data.notes) {
            // Use marked.js if available, otherwise raw text
            if (typeof marked !== 'undefined') {
                newHtml = `<div class="markdown-body">${marked.parse(data.notes)}</div>`;
            } else {
                newHtml = `<pre>${data.notes}</pre>`;
            }
        } else {
            newHtml = `<div class="loading">No investigation notes found.</div>`;
        }

        const prevScroll = container.scrollTop;
        if (container.innerHTML !== newHtml) {
            container.innerHTML = newHtml;
        }
        container.scrollTop = prevScroll;

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

        const prevScroll = container.scrollTop;
        if (container.innerHTML !== html) {
            container.innerHTML = html;
        }
        container.scrollTop = prevScroll;

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
        const prevScroll = container.scrollTop;

        if (container.innerHTML !== html) {
            container.innerHTML = html;
            if (isScrolledToBottom) {
                container.scrollTop = container.scrollHeight;
            } else {
                container.scrollTop = prevScroll;
            }
        }

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load agent thoughts: ${e.message}</div>`;
    }
};
