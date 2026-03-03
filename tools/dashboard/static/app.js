// app.js - Main Application Logic

let grid;
const panels = {};

// Theme Management
const initTheme = () => {
    const savedTheme = localStorage.getItem('dfir-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    const btn = document.getElementById('btn-theme-toggle');
    if (btn) btn.innerHTML = savedTheme === 'dark' ? '☀️' : '🌙';

    document.getElementById('btn-theme-toggle').addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('dfir-theme', newTheme);
        document.getElementById('btn-theme-toggle').innerHTML = newTheme === 'dark' ? '☀️' : '🌙';
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
        { id: 'artifacts', x: 4, y: 0, w: 4, h: 3 },
        { id: 'notes', x: 8, y: 0, w: 4, h: 8 },
        { id: 'agent', x: 0, y: 3, w: 4, h: 5 },
        { id: 'findings', x: 4, y: 3, w: 8, h: 5 },
        { id: 'audit', x: 0, y: 8, w: 12, h: 4 }
    ];

    try {
        const response = await fetch('/api/settings');
        const savedLayout = await response.json();

        let layoutToUse = savedLayout && savedLayout.length > 0 ? [...savedLayout] : [...defaultLayout];

        // Migration: If a default panel (like 'artifacts') is missing from the saved layout,
        // automatically append it so the user doesn't have to hit "Reset".
        if (savedLayout && savedLayout.length > 0) {
            defaultLayout.forEach(defItem => {
                if (!layoutToUse.find(item => item.id === defItem.id)) {
                    console.log(`Migrating: Adding missing panel ${defItem.id}`);
                    layoutToUse.push(defItem);
                }
            });
        }

        layoutToUse.forEach(item => {
            addPanel(item.id, item.x, item.y, item.w, item.h);
        });

    } catch (e) {
        console.error("Failed to load settings:", e);
        defaultLayout.forEach(item => {
            addPanel(item.id, item.x, item.y, item.w, item.h);
        });
    }

    // Attach save layout handler
    document.getElementById('btn-save-layout').addEventListener('click', async () => {
        const layout = grid.save().map(item => ({
            id: item.id,
            x: item.x,
            y: item.y,
            w: item.w,
            h: item.h
        }));

        try {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(layout)
            });
            const btn = document.getElementById('btn-save-layout');
            const originalText = btn.innerHTML;
            btn.innerHTML = '✅ Saved';
            setTimeout(() => btn.innerHTML = originalText, 2000);
        } catch (e) {
            console.error("Failed to save layout:", e);
        }
    });

    // Reset layout handler
    document.getElementById('btn-reset-layout').addEventListener('click', () => {
        grid.removeAll();
        defaultLayout.forEach(item => {
            addPanel(item.id, item.x, item.y, item.w, item.h);
        });
        loadCaseData(document.getElementById('case-selector').value);
    });
};

// Add a panel to the grid
const addPanel = (id, x, y, w, h) => {
    const titles = {
        'overview': '📋 Case Overview',
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

    if (!isAutoRefresh) {
        // Set loading states
        ['overview', 'artifacts', 'findings', 'notes', 'audit', 'agent'].forEach(id => {
            const container = document.getElementById(`panel-${id}`);
            if (container) container.innerHTML = '<div class="loading">Loading...</div>';
        });
    }

    // Call panel renderers defined in panels.js
    if (window.renderOverview) window.renderOverview(caseId);
    if (window.renderArtifacts) window.renderArtifacts(caseId);
    if (window.renderFindings) window.renderFindings(caseId);
    if (window.renderNotes) window.renderNotes(caseId);
    if (window.renderAudit) window.renderAudit(caseId);
    if (window.renderAgent) window.renderAgent(caseId);

    // Setup auto-refresh loop
    if (refreshInterval) clearInterval(refreshInterval);

    // Only set up polling if we know the case is active, or if we haven't loaded it yet.
    // window.isCurrentCaseActive is set by renderOverview. Default to true if undefined.
    if (window.isCurrentCaseActive === false) {
        return; // Investigation finished, no need to poll
    }

    refreshInterval = setInterval(() => {
        // Ping case list first to see if a new one appeared
        loadCases(true).then(() => {
            const currentSelected = document.getElementById('case-selector').value;
            if (currentSelected && currentSelected === caseId) {
                // If it didn't switch, and is still active, refresh the current one
                if (window.isCurrentCaseActive !== false) {
                    loadCaseData(currentSelected, true);
                }
            }
        });
    }, 10000); // 10 seconds
};

// Bootstrap
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initGrid().then(() => {
        loadCases();
    });
});
