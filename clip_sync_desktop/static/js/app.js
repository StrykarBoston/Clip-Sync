// Initialize Lucide Icons
lucide.createIcons();

// Initialize Socket.IO
const socket = io();

// DOM Elements
const navLinks = document.querySelectorAll('.nav-links li');
const sections = document.querySelectorAll('.content-section');
const logConsole = document.getElementById('log-console');
const clearConsoleBtn = document.getElementById('clear-console');
const peersList = document.getElementById('peers-list');
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const transfersTbody = document.getElementById('transfers-tbody');
const toastContainer = document.getElementById('toast-container');
const settingsForm = document.getElementById('settings-form');
const toggleKeyVisBtn = document.getElementById('toggle-key-vis');
const secretKeyInput = document.getElementById('secret_key');

// Navigation
navLinks.forEach(link => {
    link.addEventListener('click', () => {
        // Remove active class
        navLinks.forEach(l => l.classList.remove('active'));
        sections.forEach(s => s.classList.remove('active'));
        
        // Add active class
        link.classList.add('active');
        const sectionId = link.getAttribute('data-section');
        document.getElementById(sectionId).classList.add('active');
    });
});

// Settings Key Visibility Toggle
toggleKeyVisBtn.addEventListener('click', () => {
    const type = secretKeyInput.getAttribute('type') === 'password' ? 'text' : 'password';
    secretKeyInput.setAttribute('type', type);
    
    const icon = type === 'password' ? 'eye' : 'eye-off';
    toggleKeyVisBtn.innerHTML = `<i data-lucide="${icon}"></i>`;
    lucide.createIcons();
});

// Utility: Show Toast
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'info';
    if (type === 'error') icon = 'alert-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'warning') icon = 'alert-triangle';

    toast.innerHTML = `
        <i data-lucide="${icon}" style="color: var(--${type === 'info' ? 'accent' : type})"></i>
        <div>${message}</div>
    `;
    
    toastContainer.appendChild(toast);
    lucide.createIcons();
    
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ── Socket.IO Event Listeners ──────────────────────────────────────────

socket.on('connect', () => {
    showToast('Connected to ClipSync Engine', 'success');
    fetchInitialData();
});

socket.on('disconnect', () => {
    showToast('Disconnected from Engine', 'error');
});

socket.on('log_event', (data) => {
    const line = document.createElement('div');
    line.className = `log-line log-${data.level}`;
    line.innerHTML = `<span class="log-time">[${data.timestamp}]</span> ${data.message}`;
    logConsole.appendChild(line);
    
    // Keep max 500 lines
    if (logConsole.children.length > 500) {
        logConsole.removeChild(logConsole.firstChild);
    }
    
    // Auto-scroll
    logConsole.scrollTop = logConsole.scrollHeight;
});

clearConsoleBtn.addEventListener('click', () => {
    logConsole.innerHTML = '';
});

socket.on('peer_update', (data) => {
    const peers = data.peers;
    if (peers.length === 0) {
        peersList.innerHTML = '<div class="empty-state">No peers connected</div>';
        return;
    }
    
    peersList.innerHTML = peers.map(p => `
        <div class="peer-item">
            <div class="peer-info">
                <span class="peer-id">${p.device_id.substring(0,8)}...</span>
                <span class="peer-ip">${p.ip}</span>
            </div>
            <i data-lucide="smartphone" style="color: var(--text-secondary)"></i>
        </div>
    `).join('');
    lucide.createIcons();
});

socket.on('stats_update', (data) => {
    document.getElementById('stat-peers').innerText = data.peers_count;
    document.getElementById('stat-syncs').innerText = data.syncs_today;
    
    // Format uptime
    const uptime = data.uptime;
    const h = Math.floor(uptime / 3600);
    const m = Math.floor((uptime % 3600) / 60);
    const s = uptime % 60;
    document.getElementById('stat-uptime').innerText = 
        h > 0 ? `${h}h ${m}m` : (m > 0 ? `${m}m ${s}s` : `${s}s`);
        
    document.getElementById('stat-transfers').innerText = data.active_transfers;
});

socket.on('security_alert', (data) => {
    showToast(`Security: ${data.message}`, data.severity);
});

socket.on('transfer_progress', (data) => {
    // Check if row exists
    let row = document.getElementById(`transfer-${data.transfer_id}`);
    
    if (!row) {
        // Create new row
        row = document.createElement('tr');
        row.id = `transfer-${data.transfer_id}`;
        row.innerHTML = `
            <td>
                <span style="display:flex;align-items:center;gap:4px">
                    <i data-lucide="${data.direction === 'receiving' ? 'arrow-down' : 'arrow-up'}"></i>
                    ${data.direction}
                </span>
            </td>
            <td>${data.filename}</td>
            <td>-</td>
            <td>
                <div style="font-size: 12px; margin-bottom:4px">${data.status} (<span class="pct">${Math.round(data.progress)}%</span>)</div>
                <div class="progress-bar-container">
                    <div class="progress-bar-fill" style="width: ${data.progress}%"></div>
                </div>
            </td>
        `;
        transfersTbody.prepend(row);
        lucide.createIcons();
    } else {
        // Update existing
        row.querySelector('.progress-bar-fill').style.width = `${data.progress}%`;
        row.querySelector('.pct').innerText = `${Math.round(data.progress)}%`;
        if (data.status === 'completed') {
            row.querySelector('.progress-bar-fill').style.background = 'var(--success)';
        }
    }
});

// ── File Upload ────────────────────────────────────────────────────────

dropZone.addEventListener('click', () => fileInput.click());

['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults (e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
});

dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    handleFiles(files);
});

fileInput.addEventListener('change', function() {
    handleFiles(this.files);
});

function handleFiles(files) {
    if (files.length === 0) return;
    
    // Only upload first file for now
    const file = files[0];
    
    // Max 100MB
    if (file.size > 100 * 1024 * 1024) {
        showToast('File too large (Max 100MB)', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    showToast(`Preparing to send ${file.name}...`, 'info');
    
    fetch('/api/send-file', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) showToast(data.error, 'error');
        else showToast(data.message, 'success');
    })
    .catch(err => showToast('Failed to upload file', 'error'));
}


// ── Fetch Initial Data ─────────────────────────────────────────────────

function fetchInitialData() {
    // Settings
    fetch('/api/settings')
        .then(res => res.json())
        .then(data => {
            document.getElementById('current-key-hint').innerText = `Current: ${data.secret_key_masked}`;
            document.getElementById('port').value = data.port;
            document.getElementById('sync_sensitive').value = data.sync_sensitive_data;
            document.getElementById('save-location').innerText = data.save_location;
        });
        
    // Security info
    fetch('/api/security')
        .then(res => res.json())
        .then(data => {
            // OWASP Checklist
            const owaspList = document.getElementById('owasp-list');
            owaspList.innerHTML = Object.entries(data.owasp_compliance).map(([key, val]) => `
                <li><i data-lucide="check-circle-2"></i> <div><strong>${key.replace(/_/g, ' ').toUpperCase()}</strong><br><span style="font-size:12px;color:var(--text-secondary)">${val.detail}</span></div></li>
            `).join('');
            
            // Active Protections
            const protList = document.getElementById('protections-list');
            protList.innerHTML = data.active_protections.map(p => `
                <li><i data-lucide="shield-check"></i> <span>${p}</span></li>
            `).join('');
            
            // Cert info
            const certInfo = document.getElementById('cert-info');
            if (data.tls.status === 'valid') {
                certInfo.innerText = `Issuer: ${data.tls.issuer}\nValid Until: ${data.tls.not_after}\nKey Size: ${data.tls.key_size}\nSAN IPs: ${data.tls.san_ips.join(', ')}`;
            } else {
                certInfo.innerText = "Error loading certificate info.";
            }
            
            lucide.createIcons();
        });
        
    // Transfers
    fetch('/api/transfers')
        .then(res => res.json())
        .then(data => {
            transfersTbody.innerHTML = data.transfers.map(t => `
                <tr id="transfer-${t.transfer_id}">
                    <td>
                        <span style="display:flex;align-items:center;gap:4px">
                            <i data-lucide="${t.direction === 'receiving' ? 'arrow-down' : 'arrow-up'}"></i>
                            ${t.direction}
                        </span>
                    </td>
                    <td>${t.filename}</td>
                    <td>${(t.size / 1024).toFixed(1)} KB</td>
                    <td>
                        <div style="font-size: 12px; margin-bottom:4px">completed (<span class="pct">100%</span>)</div>
                        <div class="progress-bar-container">
                            <div class="progress-bar-fill" style="width: 100%; background: var(--success)"></div>
                        </div>
                    </td>
                </tr>
            `).join('');
            lucide.createIcons();
        });
}

// ── Settings Submit ────────────────────────────────────────────────────

settingsForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const key = secretKeyInput.value;
    const port = document.getElementById('port').value;
    const sync = document.getElementById('sync_sensitive').value;
    
    fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            secret_key: key,
            port: port,
            sync_sensitive_data: sync
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.error) showToast(data.error, 'error');
        else {
            showToast(data.message, 'success');
            secretKeyInput.value = ''; // clear input
            fetchInitialData();
        }
    })
    .catch(err => showToast('Failed to save settings', 'error'));
});

// ── Manual Peer Connect ────────────────────────────────────────────────

const manualConnectBtn = document.getElementById('btn-manual-connect');
if (manualConnectBtn) {
    manualConnectBtn.addEventListener('click', () => {
        const ipInput = document.getElementById('manual_ip');
        const ip = ipInput.value.trim();
        const port = document.getElementById('port').value || 52300;
        
        if (!ip) {
            showToast('Please enter an IP address', 'warning');
            return;
        }
        
        fetch('/api/peers/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, port: parseInt(port) })
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) showToast(data.error, 'error');
            else {
                showToast(data.message, 'success');
                ipInput.value = '';
            }
        })
        .catch(err => showToast('Failed to connect to peer', 'error'));
    });
}
