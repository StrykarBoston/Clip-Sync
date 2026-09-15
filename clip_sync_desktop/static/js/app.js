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
        
});

socket.on('security_alert', (data) => {
    showToast(`Security: ${data.message}`, data.severity);
});

// ── Fetch Initial Data ─────────────────────────────────────────────────

function fetchInitialData() {
    // Settings
    fetch('/api/settings')
        .then(res => res.json())
        .then(data => {
            document.getElementById('current-key-hint').innerText = `Current: ${data.secret_key_masked}`;
            document.getElementById('port').value = data.port;
            document.getElementById('sync_sensitive').value = data.sync_sensitive_data;
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
