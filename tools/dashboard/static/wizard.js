// wizard.js - Investigation Wizard Logic

let wizardState = {
    currentStep: 1,
    evidencePaths: [],
    caseName: '',
    displayName: '',
    evidenceType: '',
    selectedTools: [],
    investigationStatus: null
};

// Open/Close Wizard
function openWizard() {
    document.getElementById('wizard-modal').style.display = 'flex';
    resetWizard();
}

function closeWizard() {
    document.getElementById('wizard-modal').style.display = 'none';
    resetWizard();
}

function resetWizard() {
    wizardState = {
        currentStep: 1,
        evidencePaths: [],
        caseName: '',
        displayName: '',
        evidenceType: '',
        selectedTools: [],
        investigationStatus: null
    };
    
    // Reset UI
    document.getElementById('evidence-list').innerHTML = '';
    document.getElementById('case-name').value = '';
    document.getElementById('display-name').value = '';
    document.getElementById('detected-type').textContent = 'Analyzing...';
    document.getElementById('tools-container').innerHTML = '<div class="loading">Loading available tools...</div>';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('progress-text').textContent = 'Initializing...';
    document.getElementById('logs-container').innerHTML = '<div class="log-entry">Waiting to start...</div>';
    document.getElementById('step4-nav').style.display = 'none';
    
    goToStep(1);
}

// Step Navigation
function goToStep(step) {
    wizardState.currentStep = step;
    
    // Update step indicators
    document.querySelectorAll('.step').forEach((el, idx) => {
        if (idx + 1 <= step) {
            el.classList.add('active');
        } else {
            el.classList.remove('active');
        }
    });
    
    // Show/hide step content
    document.querySelectorAll('.wizard-step').forEach(el => {
        el.classList.remove('active');
    });
    document.querySelector(`.wizard-step[data-step="${step}"]`).classList.add('active');
    
    // Step-specific actions
    if (step === 2) {
        generateCaseNameSuggestion();
        classifyEvidence();
    } else if (step === 3) {
        loadRecommendedTools();
    } else if (step === 4) {
        startInvestigation();
    }
    
    updateNextButton();
}

// Evidence Handling
function browseEvidence() {
    document.getElementById('file-input').click();
}

function browseFolder() {
    document.getElementById('folder-input').click();
}

function addEvidencePath(path) {
    if (!wizardState.evidencePaths.includes(path)) {
        wizardState.evidencePaths.push(path);
        renderEvidenceList();
        updateNextButton();
    }
}

function removeEvidence(index) {
    wizardState.evidencePaths.splice(index, 1);
    renderEvidenceList();
    updateNextButton();
}

function renderEvidenceList() {
    const container = document.getElementById('evidence-list');
    if (wizardState.evidencePaths.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 1rem;">No evidence added yet. Drag & drop or browse to add.</div>';
        return;
    }
    
    container.innerHTML = wizardState.evidencePaths.map((path, idx) => `
        <div class="evidence-item">
            <span class="path" title="${path}">${path}</span>
            <button class="remove" onclick="removeEvidence(${idx})" title="Remove">&times;</button>
        </div>
    `).join('');
}

function updateNextButton() {
    const btn = document.getElementById('btn-step1-next');
    if (btn) {
        btn.disabled = wizardState.evidencePaths.length === 0;
    }
}

// Drag and Drop
const dropZone = document.getElementById('drop-zone');

if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });
    
    dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        
        const items = e.dataTransfer.items;
        if (items) {
            for (let item of items) {
                const entry = item.webkitGetAsEntry();
                if (entry) {
                    const path = await getFullPath(entry);
                    addEvidencePath(path);
                }
            }
        }
    });
}

async function getFullPath(entry) {
    // Note: For security, browsers don't provide full filesystem paths
    // In a real implementation, you might need a native bridge or file picker
    // For now, we'll use the name as a placeholder
    return entry.fullPath || entry.name;
}

// File Input Handling
document.getElementById('file-input')?.addEventListener('change', (e) => {
    Array.from(e.target.files).forEach(file => {
        // In a real app, you'd need to handle the file path differently
        // For demo, using the file name
        addEvidencePath(file.name);
    });
});

document.getElementById('folder-input')?.addEventListener('change', (e) => {
    Array.from(e.target.files).forEach(file => {
        // Get directory path from the file's path
        const path = file.webkitRelativePath || file.name;
        const dirPath = path.substring(0, path.lastIndexOf('/'));
        if (dirPath && !wizardState.evidencePaths.includes(dirPath)) {
            addEvidencePath(dirPath);
        }
    });
});

// Case Name Generation
function generateCaseNameSuggestion() {
    // If we have evidence paths, generate a suggestion
    if (wizardState.evidencePaths.length > 0) {
        const firstPath = wizardState.evidencePaths[0];
        const baseName = firstPath.split('/').pop() || firstPath.split('\\').pop() || 'case';
        const cleanBase = baseName.replace(/\.[^/.]+$/, ''); // Remove extension
        const timestamp = new Date().toISOString().split('T')[0].replace(/-/g, '');
        const suggestion = `${cleanBase}-case-${timestamp}`;
        
        document.getElementById('case-name').value = suggestion;
        document.getElementById('display-name').value = cleanBase.charAt(0).toUpperCase() + cleanBase.slice(1) + ' Investigation';
    }
}

// Evidence Classification
async function classifyEvidence() {
    const detectedTypeEl = document.getElementById('detected-type');
    detectedTypeEl.innerHTML = '<span style="color: var(--accent-solid);">Classifying evidence...</span>';
    
    try {
        const formData = new FormData();
        formData.append('paths', wizardState.evidencePaths.join(','));
        
        const response = await fetch('/api/classify', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error('Classification failed');
        }
        
        const data = await response.json();
        if (data.success && data.classification) {
            const c = data.classification;
            wizardState.evidenceType = c.kind;
            
            // Display friendly evidence type
            const typeNames = {
                'windows_triage_dir': 'Windows Triage Directory',
                'windows_evtx_dir': 'Windows EVTX Directory',
                'windows_evtx_file': 'Windows EVTX File',
                'memory_dump_file': 'Memory Dump',
                'disk_image_file': 'Disk Image',
                'pcap_file': 'Network Capture (PCAP)',
                'linux_logs_dir': 'Linux Logs Directory',
                'unknown': 'Unknown'
            };
            
            const friendlyType = typeNames[c.kind] || c.kind;
            const confidence = c.confidence ? `(${c.confidence} confidence)` : '';
            
            detectedTypeEl.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span class="badge info">${friendlyType}</span>
                    <span style="color: var(--text-muted); font-size: 0.85rem;">${confidence}</span>
                </div>
                ${c.recommended_pipeline ? `<div style="margin-top: 8px; font-size: 0.8rem; color: var(--text-secondary);">Recommended: ${c.recommended_pipeline}</div>` : ''}
            `;
        } else {
            detectedTypeEl.textContent = 'Unable to classify evidence';
        }
    } catch (e) {
        console.error('Classification error:', e);
        detectedTypeEl.textContent = 'Classification error: ' + e.message;
    }
}

// Tool Loading
async function loadRecommendedTools() {
    const container = document.getElementById('tools-container');
    container.innerHTML = '<div class="loading">Loading available tools...</div>';
    
    try {
        // For now, use the static AVAILABLE_TOOLS from the server
        // In a real implementation, you'd fetch /api/tools
        const response = await fetch('/api/tools');
        const data = await response.json();
        const tools = data.tools || {};
        
        // Get evidence type for recommendations (simplified)
        const evidenceType = wizardState.evidenceType || 'windows_evtx_dir';
        
        let html = '';
        Object.entries(tools).forEach(([toolId, tool]) => {
            const isRecommended = tool.evidence_types?.includes(evidenceType);
            const isDefault = tool.default;
            
            if (isRecommended || isDefault) {
                html += `
                    <div class="tool-item ${isDefault ? 'selected' : ''}" onclick="toggleTool('${toolId}')">
                        <input type="checkbox" ${isDefault ? 'checked' : ''} 
                               onchange="toggleTool('${toolId}')" 
                               onclick="event.stopPropagation()">
                        <div class="tool-info">
                            <h4>${tool.name}</h4>
                            <p>${tool.description}</p>
                            <div class="tool-meta">
                                <span class="badge ${tool.speed}">${tool.speed}</span>
                                ${isRecommended ? '<span class="badge info">recommended</span>' : ''}
                            </div>
                        </div>
                    </div>
                `;
                
                if (isDefault) {
                    wizardState.selectedTools.push(toolId);
                }
            }
        });
        
        container.innerHTML = html || '<div class="loading">No tools available for this evidence type.</div>';
        
    } catch (e) {
        console.error('Failed to load tools:', e);
        container.innerHTML = '<div class="loading">Failed to load tools. Using defaults.</div>';
    }
}

function toggleTool(toolId) {
    const idx = wizardState.selectedTools.indexOf(toolId);
    if (idx > -1) {
        wizardState.selectedTools.splice(idx, 1);
    } else {
        wizardState.selectedTools.push(toolId);
    }
    
    // Update visual state
    const toolElements = document.querySelectorAll('.tool-item');
    toolElements.forEach(el => {
        const checkbox = el.querySelector('input[type="checkbox"]');
        if (checkbox) {
            el.classList.toggle('selected', checkbox.checked);
        }
    });
}

// Investigation Start - Optimized for fast UI
async function startInvestigation() {
    // Get case names from form
    const caseName = document.getElementById('case-name').value;
    const displayName = document.getElementById('display-name').value;
    
    if (!caseName) {
        alert('Please enter a case name');
        return;
    }
    
    if (wizardState.selectedTools.length === 0) {
        alert('Please select at least one tool');
        return;
    }
    
    // Close wizard IMMEDIATELY - don't wait for server response
    // This makes the UI feel instant
    const caseNameToSelect = caseName;
    closeWizard();
    
    // Show the case immediately in the selector (optimistic update)
    const selector = document.getElementById('case-selector');
    if (selector) {
        // Add the new case to the dropdown immediately
        const option = document.createElement('option');
        option.value = caseNameToSelect;
        option.textContent = `⚡ ${caseNameToSelect} - Starting...`;
        selector.appendChild(option);
        selector.value = caseNameToSelect;
    }
    
    // Now make the API call in the background
    // UI is already updated - user sees the case
    try {
        const formData = new FormData();
        formData.append('paths', wizardState.evidencePaths.join(','));
        formData.append('case_name', caseName);
        formData.append('display_name', displayName);
        formData.append('tools', wizardState.selectedTools.join(','));
        
        // Single combined API call - intake + start investigation
        const response = await fetch('/api/investigate', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error('Investigation failed: ' + await response.text());
        }
        
        const data = await response.json();
        
        // Update selector with actual case name (in case it was sanitized)
        if (data.case_name && data.case_name !== caseNameToSelect) {
            if (selector) {
                const opt = selector.querySelector(`option[value="${caseNameToSelect}"]`);
                if (opt) {
                    opt.value = data.case_name;
                    opt.textContent = `⚡ ${data.display_name || data.case_name} - Starting...`;
                }
                selector.value = data.case_name;
            }
        }
        
        // Refresh the case data to trigger progress panel
        if (typeof loadCaseData === 'function') {
            loadCaseData(data.case_name);
        }
        
    } catch (e) {
        console.error('Investigation error:', e);
        // Remove the optimistic case from selector if it failed
        if (selector) {
            const opt = selector.querySelector(`option[value="${caseNameToSelect}"]`);
            if (opt) opt.remove();
        }
        alert('Error starting investigation: ' + e.message);
    }
}

async function pollInvestigationStatus() {
    const checkStatus = async () => {
        try {
            const response = await fetch(`/api/investigate/status/${wizardState.caseName}`);
            const data = await response.json();
            
            if (data.status === 'completed') {
                updateProgress(100, 'Investigation complete!');
                addLog('Investigation completed successfully');
                showSummary();
                return true;
            } else if (data.status === 'running') {
                // Calculate progress based on completed tools
                const total = data.tools?.length || 1;
                const completed = data.completed_tools?.length || 0;
                const progress = 30 + Math.round((completed / total) * 60);
                
                updateProgress(progress, `Running ${data.current_tool || 'analysis'}...`);
                
                if (data.current_tool) {
                    addLog(`Running: ${data.current_tool}`);
                }
                
                // Add generated files if any
                if (data.generated_files) {
                    data.generated_files.forEach(file => {
                        addGeneratedFile(file.name, file.size);
                    });
                }
                
                return false;
            }
            
            return false;
        } catch (e) {
            console.error('Status check failed:', e);
            return false;
        }
    };
    
    // Poll every 5 seconds
    const interval = setInterval(async () => {
        const isComplete = await checkStatus();
        if (isComplete) {
            clearInterval(interval);
        }
    }, 5000);
    
    // Also check immediately
    checkStatus();
}

function updateProgress(percent, text) {
    document.getElementById('progress-fill').style.width = percent + '%';
    document.getElementById('progress-text').textContent = text;
}

function addLog(message) {
    const container = document.getElementById('logs-container');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
}

function addGeneratedFile(name, size) {
    const container = document.querySelector('.file-list');
    if (!container.querySelector('.file-item')) {
        container.innerHTML = '';
    }
    
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
        <span class="icon">📄</span>
        <span>${name} (${formatFileSize(size)})</span>
    `;
    container.appendChild(item);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function toggleDetails() {
    const content = document.getElementById('details-content');
    const toggle = document.getElementById('details-toggle');
    
    if (content.style.display === 'none') {
        content.style.display = 'block';
        toggle.textContent = '▼';
    } else {
        content.style.display = 'none';
        toggle.textContent = '▶';
    }
}

async function showSummary() {
    try {
        const response = await fetch(`/api/investigate/summary/${wizardState.caseName}`);
        const data = await response.json();
        
        if (data.summary) {
            addLog('AI Summary generated');
            // Store summary for later display
            window.lastInvestigationSummary = data.summary;
        }
        
        // Show view results button
        document.getElementById('step4-nav').style.display = 'flex';
        
    } catch (e) {
        console.error('Failed to load summary:', e);
    }
}

function viewResults() {
    closeWizard();
    
    // Refresh case list and select the new case
    loadCases().then(() => {
        const selector = document.getElementById('case-selector');
        selector.value = wizardState.caseName;
        loadCaseData(wizardState.caseName);
    });
}

// Initialize wizard button
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('btn-new-investigation');
    if (btn) {
        btn.addEventListener('click', openWizard);
    }
});

// Expose functions to global scope
window.openWizard = openWizard;
window.closeWizard = closeWizard;
window.goToStep = goToStep;
window.browseEvidence = browseEvidence;
window.browseFolder = browseFolder;
window.removeEvidence = removeEvidence;
window.toggleTool = toggleTool;
window.startInvestigation = startInvestigation;
window.toggleDetails = toggleDetails;
window.viewResults = viewResults;
