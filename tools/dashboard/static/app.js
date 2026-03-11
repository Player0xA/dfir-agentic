// app.js - Main Application Logic

let grid;
const panels = {};

// Global polling state (persists across loadCaseData calls)
let refreshInterval;
let pollStartTime = null;
let currentPollInterval = 2000;

// Dashboard cache for smart panel updates (hash-based)
window.dashboardCache = {
    lastFetchTime: 0,
    overview: { data: null, hash: null },
    progress: { data: null, hash: null },
    artifacts: { data: null, hash: null },
    findings: { data: null, hash: null },
    notes: { data: null, hash: null },
    audit: { data: null, hash: null }
};

// Dashboard polling control
let dashboardPollInterval = null;
let isDashboardPolling = false;

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

    document.getElementById('btn-ai-mode').addEventListener('click', () => {
        window.aiModeEnabled = !window.aiModeEnabled;
        localStorage.setItem('dfir-ai-mode', window.aiModeEnabled);
        updateAIModeButton();
    });
};

// Panel Management - Simplified for Production

const initPanels = () => {
    const gridElement = document.querySelector('.grid-stack');
    if (!gridElement) {
        console.error("[Dashboard] Grid container not found");
        return;
    }

    // Initialize GridStack with existing panel elements in HTML
    if (typeof GridStack !== 'undefined') {
        grid = GridStack.init({
            cellHeight: 80,
            minRow: 10,
            margin: 10,
            draggable: { 
                handle: '.panel-header',
                scroll: true
            },
            resizable: { 
                handles: 'se, sw, ne, nw',
                autoHide: true
            },
            float: false,
            column: 12,
            animate: true,
            removable: false,
            acceptWidgets: false
        }, gridElement);
        
        console.log("[Dashboard] GridStack initialized");
        
        // Try to load saved layout
        if (typeof loadSavedLayout === 'function') {
            loadSavedLayout();
        }
    } else {
        console.warn("[Dashboard] GridStack not loaded");
    }
};

// Default panel layout configuration
const DEFAULT_PANEL_LAYOUT = [
    { id: 'panel-overview', title: 'Overview', x: 0, y: 0, w: 6, h: 4, minW: 4, minH: 3 },
    { id: 'panel-progress', title: 'Investigation Progress', x: 6, y: 0, w: 6, h: 5, minW: 4, minH: 4 },
    { id: 'panel-artifacts', title: 'Evidence & Artifacts', x: 0, y: 4, w:6, h: 6, minW: 4, minH: 4 },
    { id: 'panel-findings', title: 'Findings', x: 6, y: 5, w: 6, h: 6, minW: 4, minH: 4 },
    { id: 'panel-notes', title: 'Case Notes', x: 0, y: 10, w: 6, h: 4, minW: 4, minH: 3 },
    { id: 'panel-audit', title: 'Audit Trail', x: 6, y: 11, w: 6, h: 4, minW: 4, minH: 3 },
    { id: 'panel-agent', title: 'Agent Activity', x: 0, y: 14, w: 12, h: 4, minW: 6, minH: 3 }
];

const loadSavedLayout = () => {
    if (!grid) return;
    
    // Don't call grid.load() - it adds duplicate widgets!
    // Panels already exist in HTML and GridStack auto-initializes them
    // We only save layout changes, not restore them
    
    const savedLayout = localStorage.getItem('dfir-layout');
    if (savedLayout) {
        try {
            const layout = JSON.parse(savedLayout);
            // Only update positions of EXISTING panels, don't add new ones
            layout.forEach(item => {
                const widget = grid.find('#' + item.id);
                if (widget && widget.length > 0) {
                    widget[0].update(item);
                }
            });
            console.log("[Dashboard] Updated panel positions from saved layout");
        } catch (e) {
            console.warn("[Dashboard] Failed to apply saved layout:", e.message);
        }
    }
    
    // Save layout on change
    grid.on('change', (event, items) => {
        const layout = grid.save();
        localStorage.setItem('dfir-layout', JSON.stringify(layout));
    });
};

// Note: Panels are now defined in HTML, not created via JavaScript
// initCSSGridFallback and addPanelsToGrid removed to prevent duplication

const resetLayout = () => {
    if (grid) {
        // Clear saved layout - panels will use HTML default positions
        localStorage.removeItem('dfir-layout');
        // Reload to restore HTML default layout
        location.reload();
        console.log("[Dashboard] Layout reset to default");
    }
};

// Settings Management
const saveSettings = async (settings) => {
    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });
        return response.ok;
    } catch (e) {
        console.error("Failed to save settings:", e);
        return false;
    }
};

const loadSettings = async () => {
    try {
        const response = await fetch('/api/settings');
        if (!response.ok) return null;
        return await response.json();
    } catch (e) {
        console.error("Failed to load settings:", e);
        return null;
    }
};

// Global state for known case IDs (to detect new cases)
let knownCaseIds = [];

// =============================================================================
// CONSOLIDATED DASHBOARD POLLING
// Single API call with smart hash-based caching for all panels
// =============================================================================

// Fetch dashboard status from consolidated endpoint
async function fetchDashboardStatus(caseId) {
    try {
        const cacheBuster = `?_t=${Date.now()}`;
        const response = await fetch(`/api/cases/${caseId}/dashboard-status${cacheBuster}`);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return await response.json();
    } catch (e) {
        console.error("[Dashboard] Failed to fetch status:", e);
        return null;
    }
}

// Check if panel data changed by comparing hashes
function hasPanelChanged(panelName, newHash) {
    const cached = window.dashboardCache[panelName];
    if (!cached || cached.hash !== newHash) {
        return true;
    }
    return false;
}

// Update panel with new data if changed
function updatePanelIfChanged(panelName, newData, newHash) {
    if (hasPanelChanged(panelName, newHash)) {
        window.dashboardCache[panelName] = { data: newData, hash: newHash };
        return true; // Data changed, needs re-render
    }
    return false; // No change, skip re-render
}

// Single polling function that fetches and updates all panels
async function pollDashboard(caseId) {
    // Fetch all data in one API call
    const dashboardData = await fetchDashboardStatus(caseId);
    if (!dashboardData) return;
    
    window.dashboardCache.lastFetchTime = Date.now();
    
    // Update global active state
    window.isCurrentCaseActive = dashboardData.is_active;
    
    // Update each panel only if data changed (hash-based)
    let anyPanelUpdated = false;
    
    // 1. Overview Panel
    if (dashboardData.overview) {
        if (updatePanelIfChanged('overview', dashboardData.overview, dashboardData.overview._hash)) {
            if (window.renderOverviewFromData) {
                window.renderOverviewFromData(dashboardData.overview);
                anyPanelUpdated = true;
            } else if (window.renderOverview) {
                // Fallback to legacy function
                window.renderOverview(caseId, true);
                anyPanelUpdated = true;
            }
        }
    }
    
    // 2. Progress Panel (always update for smooth progress bar)
    if (dashboardData.progress) {
        if (updatePanelIfChanged('progress', dashboardData.progress, dashboardData.progress._hash) || 
            dashboardData.progress.status === 'running') {
            if (window.renderProgressFromData) {
                window.renderProgressFromData(dashboardData.progress);
                anyPanelUpdated = true;
            } else if (window.renderProgress) {
                // Fallback to legacy function
                window.renderProgress(caseId, true);
                anyPanelUpdated = true;
            }
        }
    }
    
    // 3. Artifacts Panel
    if (dashboardData.artifacts) {
        if (updatePanelIfChanged('artifacts', dashboardData.artifacts, dashboardData.artifacts._hash)) {
            if (window.renderArtifactsFromData) {
                window.renderArtifactsFromData(dashboardData.artifacts);
                anyPanelUpdated = true;
            } else if (window.renderArtifacts) {
                // Fallback to legacy function
                window.renderArtifacts(caseId, true);
                anyPanelUpdated = true;
            }
        }
    }
    
    // 4. Findings Panel
    if (dashboardData.findings) {
        if (updatePanelIfChanged('findings', dashboardData.findings, dashboardData.findings._hash)) {
            if (window.renderFindingsFromData) {
                window.renderFindingsFromData(dashboardData.findings);
                anyPanelUpdated = true;
            } else if (window.renderFindings) {
                // Fallback to legacy function
                window.renderFindings(caseId, true);
                anyPanelUpdated = true;
            }
        }
    }
    
    // 5. Notes Panel
    if (dashboardData.notes) {
        if (updatePanelIfChanged('notes', dashboardData.notes, dashboardData.notes._hash)) {
            if (window.renderNotesFromData) {
                window.renderNotesFromData(dashboardData.notes);
                anyPanelUpdated = true;
            } else if (window.renderNotes) {
                // Fallback to legacy function
                window.renderNotes(caseId, true);
                anyPanelUpdated = true;
            }
        }
    }
    
    // 6. Audit Panel
    if (dashboardData.audit) {
        if (updatePanelIfChanged('audit', dashboardData.audit, dashboardData.audit._hash)) {
            if (window.renderAuditFromData) {
                window.renderAuditFromData(dashboardData.audit);
                anyPanelUpdated = true;
            } else if (window.renderAudit) {
                // Fallback to legacy function
                window.renderAudit(caseId, true);
                anyPanelUpdated = true;
            }
        }
    }
    
    // Log updates for debugging (only when something changes)
    if (anyPanelUpdated) {
        console.log(`[Dashboard] Panels updated at ${new Date().toLocaleTimeString()}`);
    }
    
    // Stop polling if investigation complete
    if (!dashboardData.is_active && dashboardPollInterval) {
        console.log("[Dashboard] Investigation complete, stopping polling");
        clearInterval(dashboardPollInterval);
        dashboardPollInterval = null;
        isDashboardPolling = false;
        
        // Enable Run Tools button
        const rtBtn = document.getElementById('btn-run-tools');
        if (rtBtn) rtBtn.disabled = false;
    }
}

// Start dashboard polling with adaptive frequency
function startDashboardPolling(caseId) {
    // Stop any existing polling
    if (dashboardPollInterval) {
        clearInterval(dashboardPollInterval);
        dashboardPollInterval = null;
    }
    
    // Reset polling state
    pollStartTime = Date.now();
    currentPollInterval = 2000;
    isDashboardPolling = true;
    let nextPollTime = Date.now();
    
    // Adaptive interval function
    const getAdaptiveInterval = () => {
        const elapsed = (Date.now() - pollStartTime) / 1000;
        if (elapsed < 30) return 2000;      // 0-30s: 2s
        if (elapsed < 120) return 5000;      // 30-120s: 5s
        return 10000;                        // 120s+: 10s
    };
    
    // Polling loop with adaptive timing
    const pollingLoop = async () => {
        const now = Date.now();
        const selector = document.getElementById('case-selector');
        
        // Check if we should stop polling
        if (!selector || selector.value !== caseId) {
            console.log("[Dashboard] Case changed, stopping polling");
            if (dashboardPollInterval) {
                clearInterval(dashboardPollInterval);
                dashboardPollInterval = null;
            }
            isDashboardPolling = false;
            return;
        }
        
        // Check if it's time to poll
        if (now >= nextPollTime) {
            // Update next poll time based on current adaptive interval
            const interval = getAdaptiveInterval();
            nextPollTime = now + interval;
            
            // Log interval change for debugging
            if (interval !== currentPollInterval) {
                console.log(`[Dashboard] Polling interval changed: ${currentPollInterval}ms -> ${interval}ms`);
                currentPollInterval = interval;
            }
            
            // Perform the poll
            await pollDashboard(caseId);
            
            // Check if investigation is complete
            if (!window.isCurrentCaseActive && dashboardPollInterval) {
                console.log("[Dashboard] Investigation complete, stopping polling");
                clearInterval(dashboardPollInterval);
                dashboardPollInterval = null;
                isDashboardPolling = false;
                
                // Enable Run Tools button
                const rtBtn = document.getElementById('btn-run-tools');
                if (rtBtn) rtBtn.disabled = false;
                return;
            }
        }
    };
    
    // Start polling loop (check every 100ms, but only poll at adaptive intervals)
    dashboardPollInterval = setInterval(pollingLoop, 100);
    
    // Do first poll immediately
    nextPollTime = Date.now(); // Force immediate poll
}

// Stop dashboard polling
function stopDashboardPolling() {
    if (dashboardPollInterval) {
        clearInterval(dashboardPollInterval);
        dashboardPollInterval = null;
    }
    isDashboardPolling = false;
}

// Legacy loadCaseData function - now uses consolidated approach
const loadCaseData = (caseId, isAutoRefresh = false) => {
    if (!caseId) return;
    
    if (!isAutoRefresh) {
        // Reset dashboard cache on case switch
        window.dashboardCache = {
            lastFetchTime: 0,
            overview: { data: null, hash: null },
            progress: { data: null, hash: null },
            artifacts: { data: null, hash: null },
            findings: { data: null, hash: null },
            notes: { data: null, hash: null },
            audit: { data: null, hash: null }
        };
        
        // Set loading states for panels
        ['overview', 'progress', 'findings', 'artifacts', 'notes', 'audit', 'agent'].forEach(id => {
            const container = document.getElementById(`panel-${id}`);
            if (container) container.innerHTML = '<div class="loading">Loading...</div>';
        });
        
        // Enable Run Tools button
        const rtBtn = document.getElementById('btn-run-tools');
        if (rtBtn) rtBtn.disabled = false;
    }
    
    // Do initial fetch and start polling
    pollDashboard(caseId).then(() => {
        if (!isAutoRefresh) {
            // Start polling on initial load
            startDashboardPolling(caseId);
        }
    }).catch(err => {
        console.error("[Dashboard] Failed to poll dashboard:", err);
        // Fallback: use legacy rendering if consolidated API fails
        if (!isAutoRefresh) {
            if (window.renderOverview) window.renderOverview(caseId, false);
            if (window.renderProgress) window.renderProgress(caseId, false);
            if (window.renderArtifacts) window.renderArtifacts(caseId, false);
            if (window.renderFindings) window.renderFindings(caseId, false);
            if (window.renderNotes) window.renderNotes(caseId, false);
            if (window.renderAudit) window.renderAudit(caseId, false);
        }
    });
    
    // Note: Agent panel still uses legacy approach for now
    if (window.renderAgent) window.renderAgent(caseId, isAutoRefresh);
};

// Legacy loadCases function - for case list only
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
                    // Stop polling old case before loading new one
                    stopDashboardPolling();
                    loadCaseData(e.target.value);
                }
            });
        } else {
            // Polling refresh
            if (isNewCaseStarted) {
                // Instantly switch to the new case
                selector.value = newLatestId;
                stopDashboardPolling();
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

        // Convert tools object to array (API returns {tool_id: {...}})
        let toolsArray = [];
        if (toolsData.tools && typeof toolsData.tools === 'object') {
            toolsArray = Object.entries(toolsData.tools).map(([id, data]) => ({
                id: id,
                ...data
            }));
        }

        // Get currently running or completed stages from auto.json
        const autoStages = caseData.auto_stages || {};
        const runningTools = Object.entries(autoStages)
            .filter(([tool, status]) => status === 'running')
            .map(([tool]) => tool);
        const completedTools = Object.entries(autoStages)
            .filter(([tool, status]) => status === 'ok' || status.startsWith('ok'))
            .map(([tool]) => tool);

        renderToolsList(toolsArray, runningTools, completedTools);
    } catch (e) {
        console.error("Failed to load tools:", e);
        document.getElementById('rt-tools-list').innerHTML = '<div class="error">Failed to load tools</div>';
    }
}

function renderToolsList(tools, runningTools, completedTools) {
    const container = document.getElementById('rt-tools-list');
    if (!tools || tools.length === 0) {
        container.innerHTML = '<div class="info">No additional tools available</div>';
        return;
    }

    // Categorize tools
    const categories = {
        'Timeline': ['plaso_evtx'],
        'Event Logs': ['chainsaw_evtx', 'hayabusa_evtx'],
        'File System': ['mftecmd'],
        'Registry': ['recmd', 'appcompatcache'],
        'System': ['rbcmd', 'lecmd', 'jlecmd', 'recentfilecache']
    };

    let html = '';
    
    Object.entries(categories).forEach(([category, toolIds]) => {
        const categoryTools = tools.filter(t => toolIds.includes(t.id));
        if (categoryTools.length === 0) return;

        html += `<div style="margin-bottom: 1.5rem;">`;
        html += `<div style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.5rem;">${category}</div>`;
        html += `<div style="display: grid; gap: 0.5rem;">`;

        categoryTools.forEach(tool => {
            const isRunning = runningTools.includes(tool.id);
            const isCompleted = completedTools.includes(tool.id);
            const isDisabled = isRunning || isCompleted;
            
            let statusBadge = '';
            if (isRunning) statusBadge = '<span class="badge warning" style="font-size: 0.7rem; margin-left: auto;">Running</span>';
            else if (isCompleted) statusBadge = '<span class="badge success" style="font-size: 0.7rem; margin-left: auto;">Done</span>';
            
            const tooltip = isDisabled ? 'title="This tool is already running or completed"' : '';
            
            html += `
                <label class="rt-tool-item" style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: var(--bg-surface); border-radius: 6px; cursor: ${isDisabled ? 'not-allowed' : 'pointer'}; opacity: ${isDisabled ? 0.6 : 1};" ${tooltip}>
                    <input type="checkbox" value="${tool.id}" ${isDisabled ? 'disabled' : ''} onchange="updateRTSelection()">
                    <span style="font-weight: 500;">${tool.name}</span>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">${tool.description || ''}</span>
                    ${statusBadge}
                </label>
            `;
        });

        html += `</div></div>`;
    });

    container.innerHTML = html;
}

function updateRTSelection() {
    const checkboxes = document.querySelectorAll('#rt-tools-list input[type="checkbox"]:checked');
    rtSelectedTools = Array.from(checkboxes).map(cb => cb.value);
    document.getElementById('rt-submit').disabled = rtSelectedTools.length === 0;
}

async function submitRunTools() {
    if (rtSelectedTools.length === 0 || !rtCaseId) return;

    document.getElementById('rt-submit').disabled = true;
    document.getElementById('rt-submit').textContent = 'Starting...';

    try {
        const response = await fetch(`/api/investigate/${rtCaseId}/run-tools`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tools: rtSelectedTools })
        });

        if (response.ok) {
            closeRunToolsModal();
            // Show success message
            alert(`Started ${rtSelectedTools.length} tool(s): ${rtSelectedTools.join(', ')}`);
        } else {
            const error = await response.text();
            document.getElementById('rt-error').textContent = `Failed to start tools: ${error}`;
            document.getElementById('rt-error').style.display = 'block';
            document.getElementById('rt-submit').disabled = false;
            document.getElementById('rt-submit').textContent = 'Run Selected Tools';
        }
    } catch (e) {
        document.getElementById('rt-error').textContent = `Network error: ${e.message}`;
        document.getElementById('rt-error').style.display = 'block';
        document.getElementById('rt-submit').disabled = false;
        document.getElementById('rt-submit').textContent = 'Run Selected Tools';
    }
}

function closeRunToolsModal() {
    document.getElementById('run-tools-modal').style.display = 'none';
    document.getElementById('rt-submit').textContent = 'Run Selected Tools';
}

// ========================
// Modal Escape Handler
// ========================
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        // Close any open modals
        const modals = document.querySelectorAll('.modal-overlay');
        modals.forEach(m => m.style.display = 'none');
        // Also close run tools modal
        const runToolsModal = document.getElementById('run-tools-modal');
        if (runToolsModal) runToolsModal.style.display = 'none';
    }
});

// ========================
// Initialization
// ========================
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initAIMode();
    initPanels();
    loadCases();

    // Button event handlers
    document.getElementById('btn-new-investigation')?.addEventListener('click', () => {
        openWizard();
    });

    document.getElementById('btn-run-tools')?.addEventListener('click', openRunToolsModal);
    document.getElementById('rt-cancel')?.addEventListener('click', closeRunToolsModal);
    document.getElementById('rt-submit')?.addEventListener('click', submitRunTools);
    document.getElementById('btn-reset-layout')?.addEventListener('click', resetLayout);
    
    document.getElementById('btn-view-summary')?.addEventListener('click', () => {
        const caseSelector = document.getElementById('case-selector');
        if (caseSelector && caseSelector.value) {
            window.open(`/summary.html?case=${caseSelector.value}`, '_blank');
        } else {
            alert('Please select a case first');
        }
    });

    // Auto-load case from URL parameter
    const urlParams = new URLSearchParams(window.location.search);
    const caseParam = urlParams.get('case');
    if (caseParam) {
        // Wait for cases to load, then select the case
        const trySelectCase = setInterval(() => {
            const selector = document.getElementById('case-selector');
            if (selector && selector.options.length > 1) {
                selector.value = caseParam;
                if (selector.value === caseParam) {
                    loadCaseData(caseParam);
                    clearInterval(trySelectCase);
                }
            }
        }, 100);
        // Stop trying after 5 seconds
        setTimeout(() => clearInterval(trySelectCase), 5000);
    }

    // Expose loadCases for the wizard
    window.loadCases = loadCases;
});
