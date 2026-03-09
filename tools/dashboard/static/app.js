// app.js - Main Application Logic

let grid;
const panels = {};

// Theme Management
const initTheme = () => {
    const savedTheme = localStorage.getItem('dfir-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    const getThemeIcon = (theme) => {
        if (theme === 'dark') return '☀️'; // Next is chill-dark? Or light? 
        // Let's just use icons that represent the NEXT state, or CURRENT. 
        // Previously: dark ? ☀️ : 🌙. This meant: if dark, show sun (click for light). 
        if (theme === 'dark') return '☕'; // Click for chill-dark
        if (theme === 'chill-dark') return '☀️'; // Click for light
        return '🌙'; // Click for dark
    };

    const btn = document.getElementById('btn-theme-toggle');
    if (btn) btn.innerHTML = getThemeIcon(savedTheme);

    document.getElementById('btn-theme-toggle').addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        let newTheme = 'dark';
        if (currentTheme === 'dark') newTheme = 'chill-dark';
        else if (currentTheme === 'chill-dark') newTheme = 'light';
        else newTheme = 'dark';

        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('dfir-theme', newTheme);
        document.getElementById('btn-theme-toggle').innerHTML = getThemeIcon(newTheme);
    });
};

// AI Mode Management
const initAIMode = () => {
    // Load saved AI mode preference, default to OFF
    window.aiModeEnabled = localStorage.getItem('dfir-ai-mode') === 'true';

    const updateAIModeButton = () => {
        const btn = document.getElementById('btn-ai-mode');
        if (btn) {
            btn.innerHTML = window.aiModeEnabled ? '🤖 AI: ON' : '🤖 AI: OFF';
            btn.className = window.aiModeEnabled ? 'btn primary' : 'btn secondary';
            btn.title = window.aiModeEnabled ? 'AI Analysis Mode: ON (requires API key)' : 'AI Analysis Mode: OFF (deterministic only)';
        }
    };

    updateAIModeButton();

    document.getElementById('btn-ai-mode')?.addEventListener('click', () => {
        window.aiModeEnabled = !window.aiModeEnabled;
        localStorage.setItem('dfir-ai-mode', window.aiModeEnabled);
        updateAIModeButton();
        console.log('AI Mode:', window.aiModeEnabled ? 'ON' : 'OFF');
    });
};

// GridStack Initialization
const initGrid = async () => {
    grid = GridStack.init({
        cellHeight: 100,
        margin: 10,
        handle: '.panel-header',
        animate: true,
        float: true // Allow panels to float anywhere
    });

    // Default Layout
    const defaultLayout = [
        { id: 'overview', x: 0, y: 0, w: 4, h: 3 },
        { id: 'progress', x: 0, y: 0, w: 4, h: 3 },
        { id: 'artifacts', x: 4, y: 0, w: 4, h: 3 },
        { id: 'notes', x: 8, y: 0, w: 4, h: 8 },
        { id: 'agent', x: 0, y: 3, w: 4, h: 5 },
        { id: 'findings', x: 4, y: 3, w: 8, h: 5 },
        { id: 'audit', x: 0, y: 8, w: 12, h: 4 }
    ];

    window.dashboardProfiles = {
        "Default": []
    };
    window.activeProfile = "Default";

    const loadLayoutFromData = (data) => {
        grid.removeAll();
        let layoutToUse = [...defaultLayout];

        if (data && data.active_profile && data.profiles) {
            window.dashboardProfiles = data.profiles;
            window.activeProfile = data.active_profile;

            if (data.profiles[window.activeProfile] && data.profiles[window.activeProfile].length > 0) {
                layoutToUse = [...data.profiles[window.activeProfile]];
            }
        }

        // Migration: If a default panel (like 'artifacts') is missing from the saved layout,
        // automatically append it so the user doesn't have to hit "Reset".
        defaultLayout.forEach(defItem => {
            if (!layoutToUse.find(item => item.id === defItem.id)) {
                console.log(`Migrating: Adding missing panel ${defItem.id}`);
                layoutToUse.push(defItem);
            }
        });

        layoutToUse.forEach(item => {
            addPanel(item.id, item.x, item.y, item.w, item.h);
        });

        updateProfileUI();
    };

    const updateProfileUI = () => {
        const selector = document.getElementById('profile-selector');
        selector.innerHTML = '';
        Object.keys(window.dashboardProfiles).forEach(pName => {
            const opt = document.createElement('option');
            opt.value = pName;
            opt.textContent = pName;
            if (pName === window.activeProfile) opt.selected = true;
            selector.appendChild(opt);
        });

        // Show/hide delete button (cannot delete Default)
        document.getElementById('btn-delete-profile').style.display = window.activeProfile === 'Default' ? 'none' : 'inline-block';
    };

    try {
        const response = await fetch('/api/settings');
        const data = await response.json();
        loadLayoutFromData(data);
    } catch (e) {
        console.error("Failed to load settings:", e);
        loadLayoutFromData(null);
    }

    // Profile Dropdown Change
    document.getElementById('profile-selector').addEventListener('change', (e) => {
        window.activeProfile = e.target.value;
        const savedLayout = window.dashboardProfiles[window.activeProfile];

        grid.removeAll();
        let layoutToUse = savedLayout && savedLayout.length > 0 ? [...savedLayout] : [...defaultLayout];

        defaultLayout.forEach(defItem => {
            if (!layoutToUse.find(item => item.id === defItem.id)) layoutToUse.push(defItem);
        });

        layoutToUse.forEach(item => {
            addPanel(item.id, item.x, item.y, item.w, item.h);
        });

        saveSettingsToServer(); // Save the new active profile state
        updateProfileUI();
        loadCaseData(document.getElementById('case-selector').value);
    });

    const saveSettingsToServer = async () => {
        const payload = {
            active_profile: window.activeProfile,
            profiles: window.dashboardProfiles
        };
        try {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            return true;
        } catch (e) {
            console.error("Failed to save layout:", e);
            return false;
        }
    };

    // Attach save layout handler (overwrite current)
    document.getElementById('btn-save-layout').addEventListener('click', async () => {
        const layout = grid.save().map(item => ({
            id: item.id, x: item.x, y: item.y, w: item.w, h: item.h
        }));

        window.dashboardProfiles[window.activeProfile] = layout;

        if (await saveSettingsToServer()) {
            const btn = document.getElementById('btn-save-layout');
            const originalText = btn.innerHTML;
            btn.innerHTML = '✅ Saved';
            setTimeout(() => btn.innerHTML = originalText, 2000);
        }
    });

    // Attach save as handler (new profile)
    document.getElementById('btn-save-as').addEventListener('click', async () => {
        const newName = prompt("Enter a name for the new layout profile:");
        if (!newName || !newName.trim()) return;

        const cleanName = newName.trim();
        if (cleanName === "Default") {
            alert("Cannot overwrite the Default profile name this way.");
            return;
        }

        const layout = grid.save().map(item => ({
            id: item.id, x: item.x, y: item.y, w: item.w, h: item.h
        }));

        window.dashboardProfiles[cleanName] = layout;
        window.activeProfile = cleanName;

        if (await saveSettingsToServer()) {
            updateProfileUI();
        }
    });

    // Delete profile handler
    document.getElementById('btn-delete-profile').addEventListener('click', async () => {
        if (window.activeProfile === 'Default') return;

        if (confirm(`Are you sure you want to delete the layout profile '${window.activeProfile}'?`)) {
            delete window.dashboardProfiles[window.activeProfile];
            window.activeProfile = 'Default';

            if (await saveSettingsToServer()) {
                // Switch back to default view
                const e = new Event('change');
                const sel = document.getElementById('profile-selector');
                sel.value = 'Default';
                sel.dispatchEvent(e);
            }
        }
    });

    // Reset layout handler (resets current view to default)
    document.getElementById('btn-reset-layout').addEventListener('click', () => {
        grid.removeAll();
        defaultLayout.forEach(item => {
            addPanel(item.id, item.x, item.y, item.w, item.h);
        });

        // Save the reset state to the current profile
        window.dashboardProfiles[window.activeProfile] = [];
        saveSettingsToServer();

        loadCaseData(document.getElementById('case-selector').value);
    });
};

// Add a panel to the grid
const addPanel = (id, x, y, w, h) => {
    const titles = {
        'overview': '📋 Case Overview',
        'progress': '⚙️ Investigation Progress',
        'artifacts': '📁 Evidence Artifacts',
        'findings': '🚨 Findings',
        'notes': '📝 Case Notes',
        'audit': '🔍 AI Audit Trail',
        'agent': '🧠 Agent Thoughts'
    };

    const content = `
        <div class="panel-header">
            <div class="panel-title">${titles[id] || id}</div>
            <div class="panel-controls">
                <button onclick="grid.removeWidget(this.closest('.grid-stack-item'))">×</button>
            </div>
        </div>
        <div class="panel-body" id="panel-${id}">
            <div class="loading">Select a case...</div>
        </div>
    `;

    grid.addWidget({ id: id, x: x, y: y, w: w, h: h, content: content });
};

let knownCaseIds = [];

// Case Management
const loadCases = async (isAutoRefresh = false) => {
    try {
        const response = await fetch('/api/cases');
        const data = await response.json();

        const selector = document.getElementById('case-selector');
        const currentValue = selector.value;
        const newLatestId = data.cases.length > 0 ? data.cases[0].id : null;

        // Detect if a brand new case was just ingested
        const isNewCaseStarted = newLatestId && knownCaseIds.length > 0 && !knownCaseIds.includes(newLatestId);

        // Only redraw the dropdown if the number of cases actually changed
        if (knownCaseIds.length !== data.cases.length) {
            knownCaseIds = data.cases.map(c => c.id);
            selector.innerHTML = '<option value="">-- Select a Case --</option>';

            data.cases.forEach(c => {
                const option = document.createElement('option');
                option.value = c.id;
                const typeFlag = c.classification?.kind === 'memory_dump_file' ? '[MEM]' : '[DISK]';
                const shortName = c.name.length > 15 ? c.name.substring(0, 8) + '...' : c.name;
                const shortDate = c.intake_utc ? c.intake_utc.substring(0, 16).replace('T', ' ') : 'N/A';
                option.textContent = `${typeFlag} ${shortName} - ${shortDate}`;
                selector.appendChild(option);
            });
            selector.value = currentValue; // Restore selection after redraw
        }

        if (!isAutoRefresh) {
            // First time load
            if (data.cases.length > 0) {
                selector.value = data.cases[0].id;
                loadCaseData(data.cases[0].id);
                // Enable Run Tools button for the initially loaded case
                const rtBtn = document.getElementById('btn-run-tools');
                if (rtBtn) rtBtn.disabled = false;
            }

            selector.addEventListener('change', (e) => {
                if (e.target.value) {
                    loadCaseData(e.target.value);
                }
            });
        } else {
            // Polling refresh
            if (isNewCaseStarted) {
                // Instantly switch to the new case
                selector.value = newLatestId;
                loadCaseData(newLatestId);
            } else if (currentValue) {
                // Maintain current selection if nothing new happened
                selector.value = currentValue;
            }
        }

    } catch (e) {
        console.error("Failed to load cases:", e);
        if (!isAutoRefresh) document.getElementById('case-selector').innerHTML = '<option value="">Error loading cases</option>';
    }
};

let refreshInterval;

const loadCaseData = (caseId, isAutoRefresh = false) => {
    if (!caseId) return;

    // SMART REFRESH: Reset hashes when switching cases (not auto-refresh)
    // This ensures fresh data is always rendered for a new case
    if (!isAutoRefresh) {
        if (typeof lastFindingsHash !== 'undefined') {
            window.lastFindingsHash = null;
        }
        // Reset progress tracking to prevent stale cached state
        if (typeof lastProgressHash !== 'undefined') {
            window.lastProgressHash = null;
        }
        if (typeof lastProgressStatus !== 'undefined') {
            window.lastProgressStatus = null;
        }
    }

    if (!isAutoRefresh) {
        // Set loading states for panels that auto-refresh
        ['overview', 'progress', 'findings', 'notes', 'audit', 'agent'].forEach(id => {
            const container = document.getElementById(`panel-${id}`);
            if (container) container.innerHTML = '<div class="loading">Loading...</div>';
        });
        // Artifacts panel loads immediately without loading state (uses cache or shows content)
        
        // Enable Run Tools button when a valid case is loaded (not auto-refresh)
        const rtBtn = document.getElementById('btn-run-tools');
        if (rtBtn) rtBtn.disabled = false;
    }

    // Call panel renderers defined in panels.js
    if (window.renderOverview) window.renderOverview(caseId, isAutoRefresh);
    if (window.renderProgress) window.renderProgress(caseId, isAutoRefresh);
    // Artifacts panel: render on initial load, but skip during auto-refresh polling
    if (!isAutoRefresh && window.renderArtifacts) window.renderArtifacts(caseId);
    // Findings: Pass isAutoRefresh flag for smart refresh (hash comparison)
    if (window.renderFindings) window.renderFindings(caseId, isAutoRefresh);
    if (window.renderNotes) window.renderNotes(caseId, isAutoRefresh);
    if (window.renderAudit) window.renderAudit(caseId, isAutoRefresh);
    if (window.renderAgent) window.renderAgent(caseId, isAutoRefresh);

    // Setup auto-refresh loop with adaptive frequency
    if (refreshInterval) clearInterval(refreshInterval);

    // Only set up polling if we know the case is active
    if (window.isCurrentCaseActive === false) {
        return; // Investigation finished, no need to poll
    }

    // Adaptive polling: start fast, slow down over time
    // 0-30s: 2s (responsive)
    // 30-120s: 5s (moderate)
    // 120s+: 10s (slow - tools take time)
    let pollStartTime = Date.now();
    let currentPollInterval = 2000; // Start at 2 seconds

    const getAdaptiveInterval = () => {
        const elapsed = (Date.now() - pollStartTime) / 1000; // seconds
        if (elapsed < 30) return 2000;      // 0-30s: 2s
        if (elapsed < 120) return 5000;     // 30-120s: 5s
        return 10000;                       // 120s+: 10s
    };

    const runAdaptivePoll = () => {
        const interval = getAdaptiveInterval();
        if (interval !== currentPollInterval) {
            // Frequency changed, restart with new interval
            clearInterval(refreshInterval);
            currentPollInterval = interval;
            refreshInterval = setInterval(runAdaptivePoll, interval);
        }

        // Do the actual polling
        loadCases(true).then(() => {
            const currentSelected = document.getElementById('case-selector').value;
            if (currentSelected && currentSelected === caseId) {
                if (window.isCurrentCaseActive !== false) {
                    loadCaseData(currentSelected, true);
                }
            }
        });
    };

    refreshInterval = setInterval(runAdaptivePoll, currentPollInterval);
};

// ========================
// Run Tools Modal Logic
// ========================
let rtSelectedTools = [];
let rtCaseId = null;

async function openRunToolsModal() {
    const caseSelector = document.getElementById('case-selector');
    rtCaseId = caseSelector.value;
    if (!rtCaseId) return;

    // Reset state
    rtSelectedTools = [];
    document.getElementById('rt-error').style.display = 'none';
    document.getElementById('rt-submit').disabled = true;
    document.getElementById('rt-case-name').textContent = rtCaseId;
    document.getElementById('run-tools-modal').style.display = 'flex';
    document.getElementById('rt-tools-list').innerHTML = '<div class="loading">Loading tools...</div>';

    try {
        // Fetch available tools and current case stages in parallel
        const [toolsRes, caseRes] = await Promise.all([
            fetch('/api/tools'),
            fetch(`/api/cases/${rtCaseId}`)
        ]);
        const toolsData = await toolsRes.json();
        const caseData = await caseRes.json();

        const allTools = toolsData.tools || {};
        const stages = caseData.auto_stages || {};
        const evidenceKind = caseData.intake?.classification?.kind || '';

        let html = '';
        Object.entries(allTools).forEach(([toolId, tool]) => {
            const stageStatus = stages[toolId] || stages[toolId.replace('_evtx', '')] || null;
            const isCompleted = stageStatus && (stageStatus === 'ok' || stageStatus.startsWith('ok'));
            const isFailed = stageStatus && stageStatus.startsWith('error');
            const isRelevant = tool.evidence_types?.includes(evidenceKind);

            let statusBadge = '';
            let opacity = '1';
            let checkState = '';

            if (isCompleted) {
                statusBadge = '<span class="badge info" style="font-size: 0.7rem;">✅ Completed</span>';
                opacity = '0.6';
            } else if (isFailed) {
                statusBadge = '<span class="badge critical" style="font-size: 0.7rem;">❌ Failed</span>';
            }

            if (!isRelevant && !isCompleted) {
                opacity = '0.5';
            }

            html += `
                <div class="tool-item" style="display: flex; align-items: center; gap: 0.8rem; padding: 0.7rem 1rem; border: 1px solid var(--border); border-radius: 8px; cursor: pointer; opacity: ${opacity}; transition: all 0.2s;"
                     onclick="rtToggleTool('${toolId}', this)" data-tool-id="${toolId}">
                    <input type="checkbox" ${checkState} style="width: 18px; height: 18px; cursor: pointer;"
                           onclick="event.stopPropagation(); rtToggleTool('${toolId}', this.closest('.tool-item'))">
                    <div style="flex: 1;">
                        <div style="font-weight: 600; font-size: 0.9rem;">${tool.name}</div>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">
                            ${tool.description}
                            ${isRelevant ? ' <span class="badge info" style="font-size: 0.65rem;">recommended</span>' : ''}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.4rem;">
                        <span class="badge ${tool.speed}" style="font-size: 0.65rem;">${tool.speed}</span>
                        ${statusBadge}
                    </div>
                </div>
            `;
        });

        document.getElementById('rt-tools-list').innerHTML = html || '<div class="loading">No tools available</div>';

    } catch (e) {
        document.getElementById('rt-tools-list').innerHTML =
            `<div class="error">Failed to load tools: ${e.message}</div>`;
    }
}

function closeRunToolsModal() {
    document.getElementById('run-tools-modal').style.display = 'none';
    rtSelectedTools = [];
    rtCaseId = null;
}

function rtToggleTool(toolId, el) {
    const idx = rtSelectedTools.indexOf(toolId);
    const checkbox = el.querySelector('input[type="checkbox"]');
    if (idx > -1) {
        rtSelectedTools.splice(idx, 1);
        el.style.borderColor = 'var(--border)';
        el.style.background = '';
        if (checkbox) checkbox.checked = false;
    } else {
        rtSelectedTools.push(toolId);
        el.style.borderColor = 'var(--accent-solid)';
        el.style.background = 'var(--accent-glow)';
        if (checkbox) checkbox.checked = true;
    }
    document.getElementById('rt-submit').disabled = rtSelectedTools.length === 0;
    document.getElementById('rt-submit').textContent = rtSelectedTools.length > 0
        ? `▶ Run ${rtSelectedTools.length} Tool${rtSelectedTools.length > 1 ? 's' : ''}`
        : '▶ Run Selected';
}

async function submitRunTools() {
    if (!rtCaseId || rtSelectedTools.length === 0) return;

    const submitBtn = document.getElementById('rt-submit');
    const errorDiv = document.getElementById('rt-error');
    submitBtn.disabled = true;
    submitBtn.textContent = '⏳ Starting...';
    errorDiv.style.display = 'none';

    try {
        const formData = new FormData();
        formData.append('tools', rtSelectedTools.join(','));

        const response = await fetch(`/api/investigate/${rtCaseId}/run-tools`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({ detail: 'Unknown error' }));
            throw new Error(errData.detail || `HTTP ${response.status}`);
        }

        const result = await response.json();
        console.log('Run tools result:', result);

        // Close modal and switch dashboard to tracking mode
        closeRunToolsModal();

        // Re-enable polling for live progress
        window.isCurrentCaseActive = true;
        loadCaseData(rtCaseId);

    } catch (e) {
        errorDiv.textContent = e.message;
        errorDiv.style.display = 'block';
        submitBtn.disabled = false;
        submitBtn.textContent = `▶ Run ${rtSelectedTools.length} Tool${rtSelectedTools.length > 1 ? 's' : ''}`;
    }
}

// Bootstrap
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initAIMode();
    initGrid().then(() => {
        loadCases();
    });

    // Run Tools button wiring
    const runToolsBtn = document.getElementById('btn-run-tools');
    if (runToolsBtn) {
        runToolsBtn.addEventListener('click', openRunToolsModal);
    }

    // Enable/disable Run Tools button when case selection changes
    document.getElementById('case-selector')?.addEventListener('change', (e) => {
        const btn = document.getElementById('btn-run-tools');
        if (btn) btn.disabled = !e.target.value;
    });
});

// Expose functions globally for use by other scripts
window.loadCases = loadCases;
window.loadCaseData = loadCaseData;
window.addPanel = addPanel;
window.openRunToolsModal = openRunToolsModal;
window.closeRunToolsModal = closeRunToolsModal;
window.rtToggleTool = rtToggleTool;
window.submitRunTools = submitRunTools;
