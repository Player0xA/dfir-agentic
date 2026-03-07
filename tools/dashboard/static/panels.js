// panels.js - Individual Panel Renderers

// 0. Investigation Progress Panel
window.renderProgress = async (caseId) => {
    const container = document.getElementById('panel-progress');
    if (!container) return;

    try {
        const response = await fetch(`/api/investigate/status/${caseId}`);
        const data = await response.json();
        
        let html = '';
        
        if (data.status === 'not_started' || data.status === 'not_found') {
            html = `
                <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
                    <div style="font-size: 2rem; margin-bottom: 1rem;">⏳</div>
                    <p>No investigation running</p>
                    <p style="font-size: 0.8rem;">Click "New Investigation" to start analyzing evidence</p>
                </div>
            `;
        } else if (data.status === 'completed') {
            html = `
                <div style="text-align: center; padding: 1rem;">
                    <div class="badge info" style="font-size: 1rem; padding: 0.5rem 1rem;">✅ Investigation Complete</div>
                    <p style="margin-top: 1rem; color: var(--text-secondary);">Click "View Summary" to see AI analysis</p>
                </div>
            `;
        } else if (data.status === 'error') {
            html = `
                <div style="text-align: center; padding: 1rem;">
                    <div class="badge critical">❌ Investigation Error</div>
                    <p style="margin-top: 1rem; color: var(--severity-critical);">${data.error || 'Unknown error'}</p>
                </div>
            `;
        } else if (data.status === 'running') {
            const progress = data.progress || 0;
            const currentTool = data.current_tool || 'Unknown';
            const currentAction = data.current_action || 'Processing...';
            const completed = data.completed_tools || [];
            const pending = data.pending_tools || [];
            
            html = `
                <div style="margin-bottom: 1rem;">
                    <div class="progress-bar" style="height: 20px; background: var(--bg-surface); border-radius: 10px; overflow: hidden;">
                        <div style="height: 100%; background: var(--accent-gradient); width: ${progress}%; transition: width 0.5s ease; border-radius: 10px;"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 0.5rem; font-size: 0.85rem;">
                        <span style="color: var(--accent-solid); font-weight: 600;">${progress}%</span>
                        <span style="color: var(--text-secondary);">${currentAction}</span>
                    </div>
                </div>
                
                <div style="display: flex; gap: 1rem; font-size: 0.8rem; flex-wrap: wrap;">
                    ${completed.length > 0 ? `
                        <div style="flex: 1; min-width: 150px;">
                            <div style="color: var(--text-muted); margin-bottom: 0.3rem;">Completed</div>
                            ${completed.map(t => `<span class="badge info" style="margin: 2px;">✓ ${t}</span>`).join('')}
                        </div>
                    ` : ''}
                    ${pending.length > 0 ? `
                        <div style="flex: 1; min-width: 150px;">
                            <div style="color: var(--text-muted); margin-bottom: 0.3rem;">Pending</div>
                            ${pending.map(t => `<span class="badge" style="margin: 2px; opacity: 0.5;">○ ${t}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
                
                ${data.pid ? `<div style="margin-top: 1rem; font-size: 0.75rem; color: var(--text-muted);">Process ID: ${data.pid}</div>` : ''}
            `;
        } else {
            html = `<div class="loading">Loading progress...</div>`;
        }
        
        const prevScroll = container.scrollTop;
        if (container.innerHTML !== html) {
            container.innerHTML = html;
        }
        container.scrollTop = prevScroll;
        
    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load progress: ${e.message}</div>`;
    }
};

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

        // Function to build a simple table
        const buildSimpleTable = (evidenceArray) => {
            if (!evidenceArray || evidenceArray.length === 0) return '';

            let t = `<div style="overflow-x: auto;"><table class="data-table"><thead><tr><th>ID</th><th>Path</th></tr></thead><tbody>`;

            evidenceArray.forEach(e => {
                let shortPath = (e.relpath || 'N/A').length > 50 ? '...' + (e.relpath || 'N/A').substring((e.relpath || 'N/A').length - 47) : (e.relpath || 'N/A');
                let eid = e.evidence_id || 'N/A';

                // Truncate UUIDs for cleaner display
                if (eid.length > 12 && eid.includes('-')) {
                    eid = eid.substring(0, 8);
                }

                t += `<tr><td><code>${eid}</code></td><td title="${e.relpath || ''}"><code>${shortPath}</code></td></tr>`;
            });

            t += '</tbody></table></div>';
            return t;
        };

        // Check V30 manifest format first
        if (manifest.evidence && manifest.evidence.length > 0) {
            html += buildSimpleTable(manifest.evidence);
        }
        // Then check V30 intake format
        else if (intake.evidence && intake.evidence.length > 0) {
            html += buildSimpleTable(intake.evidence);
        }
        // Finally fallback to legacy format (list of paths)
        else if (intake.inputs && intake.inputs.paths && intake.inputs.paths.length > 0) {
            // Emulate V30 format for legacy categorization
            const emulatedEvidence = intake.inputs.paths.map((p, i) => {
                const parts = p.replace(/\/$/, '').split('/');
                const name = parts[parts.length - 1] || 'root';
                return {
                    evidence_id: `${name}`,
                    relpath: p
                };
            });
            html += buildSimpleTable(emulatedEvidence);
        } else {
            html += `<div class="loading">No artifacts or evidence listed for this case.</div>`;
        }

        // Also fetch generated artifacts from tools
        try {
            const genRes = await fetch(`/api/cases/${caseId}/generated_artifacts`);
            if (genRes.ok) {
                const genData = await genRes.json();
                if (genData.artifacts && genData.artifacts.length > 0) {

                    html += `<div style="margin-top: 15px; font-weight: bold; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 3px;">⚙️ Tool Outputs & Generated Files (${genData.artifacts.length})</div>`;
                    html += `<div style="overflow-x: auto;"><table class="data-table"><thead><tr><th>File Name</th><th>Path</th><th>Size (KB)</th></tr></thead><tbody>`;

                    genData.artifacts.forEach(a => {
                        let shortPath = (a.relpath || 'N/A').length > 50 ? '...' + (a.relpath || 'N/A').substring((a.relpath || 'N/A').length - 47) : (a.relpath || 'N/A');
                        let kbSize = Math.round((a.size || 0) / 1024);
                        html += `<tr><td><code>${a.name}</code></td><td title="${a.relpath}"><code>${shortPath}</code></td><td>${kbSize}</td></tr>`;
                    });

                    html += '</tbody></table></div>';
                }
            }
        } catch (e) {
            console.warn("Failed to load generated artifacts:", e);
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

        renderFindingsTable(container, findingsData, 'all', '');

    } catch (e) {
        container.innerHTML = `<div class="error">Failed to load findings: ${e.message}</div>`;
    }
};

const renderFindingsTable = (container, data, sevFilter, sourceFilterText) => {
    let filtered = data;

    // Apply Severity Filter
    if (sevFilter !== 'all') {
        filtered = filtered.filter(f => f.severity?.toLowerCase() === sevFilter.toLowerCase());
    }

    // Determine all unique sources for the dropdown
    const allSources = new Set(['all']);
    data.forEach(f => {
        let s = 'N/A';
        if (f.source && f.source.tool) {
            s = f.source.tool;
        } else if (f.source_evidence_id) {
            s = f.source_evidence_id;
        } else if (f.tool_name) {
            s = f.tool_name;
        }
        allSources.add(s);
    });

    // Apply Source Filter
    if (sourceFilterText && sourceFilterText !== 'all') {
        filtered = filtered.filter(f => {
            let source = 'N/A';
            if (f.source && f.source.tool) {
                source = f.source.tool;
            } else if (f.source_evidence_id) {
                source = f.source_evidence_id;
            } else if (f.tool_name) {
                source = f.tool_name;
            }
            return source === sourceFilterText;
        });
    }

    let sourceOptionsHtml = Array.from(allSources).map(s => {
        const label = s === 'all' ? 'All Sources' : s;
        const selected = (sourceFilterText === s || (!sourceFilterText && s === 'all')) ? 'selected' : '';
        return `<option value="${s}" ${selected}>${label}</option>`;
    }).join('');

    let html = `
        <div style="margin-bottom: 10px; display: flex; gap: 10px; align-items: center;">
            <select id="severity-filter" onchange="renderFindingsTable(document.getElementById('panel-findings'), findingsData, this.value, document.getElementById('source-filter').value)">
                <option value="all" ${sevFilter === 'all' ? 'selected' : ''}>All Severities</option>
                <option value="critical" ${sevFilter === 'critical' ? 'selected' : ''}>Critical</option>
                <option value="high" ${sevFilter === 'high' ? 'selected' : ''}>High</option>
                <option value="medium" ${sevFilter === 'medium' ? 'selected' : ''}>Medium</option>
                <option value="low" ${sevFilter === 'low' ? 'selected' : ''}>Low</option>
                <option value="informational" ${sevFilter === 'informational' ? 'selected' : ''}>Info</option>
            </select>
            
            <select id="source-filter" onchange="renderFindingsTable(document.getElementById('panel-findings'), findingsData, document.getElementById('severity-filter').value, this.value)" style="flex-grow: 1; padding: 5px; background: var(--bg); border: 1px solid var(--border); color: var(--text); border-radius: 4px;">
                ${sourceOptionsHtml}
            </select>
            
            <span style="color: var(--text-secondary); white-space: nowrap;">${filtered.length} total</span>
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
            const rawSev = (f.severity || f.impact || 'info').toLowerCase();
            const sev = rawSev; // Restore full severity name
            const sevClass = rawSev;
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
                    <td><span class="badge ${sevClass}">${sev}</span></td>
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
