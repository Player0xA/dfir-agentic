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
        { id: 'notes', x: 8, y: 0, w: 4, h: 8 },
        { id: 'findings', x: 0, y: 3, w: 8, h: 5 },
        { id: 'audit', x: 0, y: 8, w: 12, h: 4 }
    ];

    try {
        const response = await fetch('/api/settings');
        const savedLayout = await response.json();

        const layoutToUse = savedLayout.length > 0 ? savedLayout : defaultLayout;

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
        'findings': '🚨 Findings',
        'notes': '📝 Case Notes',
        'audit': '🔍 AI Audit Trail'
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

// Case Management
const loadCases = async () => {
    try {
        const response = await fetch('/api/cases');
        const data = await response.json();

        const selector = document.getElementById('case-selector');
        selector.innerHTML = '<option value="">-- Select a Case --</option>';

        data.cases.forEach(c => {
            const option = document.createElement('option');
            option.value = c.id;
            const typeFlag = c.classification?.kind === 'memory_dump_file' ? '[MEM]' : '[DISK]';
            option.textContent = `${typeFlag} ${c.name} (${c.intake_utc})`;
            selector.appendChild(option);
        });

        // Auto-select first case if available
        if (data.cases.length > 0) {
            selector.value = data.cases[0].id;
            loadCaseData(data.cases[0].id);
        }

        selector.addEventListener('change', (e) => {
            if (e.target.value) {
                loadCaseData(e.target.value);
            }
        });

    } catch (e) {
        console.error("Failed to load cases:", e);
        document.getElementById('case-selector').innerHTML = '<option value="">Error loading cases</option>';
    }
};

const loadCaseData = (caseId) => {
    if (!caseId) return;

    // Set loading states
    ['overview', 'findings', 'notes', 'audit'].forEach(id => {
        const container = document.getElementById(`panel-${id}`);
        if (container) container.innerHTML = '<div class="loading">Loading...</div>';
    });

    // Call panel renderers defined in panels.js
    if (window.renderOverview) window.renderOverview(caseId);
    if (window.renderFindings) window.renderFindings(caseId);
    if (window.renderNotes) window.renderNotes(caseId);
    if (window.renderAudit) window.renderAudit(caseId);
};

// Bootstrap
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initGrid().then(() => {
        loadCases();
    });
});
