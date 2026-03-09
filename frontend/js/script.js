/* ═══════════════════════════════════════════════════════
   SecureShare  –  Shared JavaScript Utilities & Handlers
   ═══════════════════════════════════════════════════════ */

const API_BASE = '';   // Flask serves everything from the same origin

async function getAuthHeaders() {
  if (!window.AppAuth) return {};
  await AppAuth.initAuth();
  const token = AppAuth.getToken();
  if (!token) return {};
  return { Authorization: `Bearer ${token}` };
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const icons = {
    success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
    error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
  };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || icons.info}</span>
    <span class="toast-msg">${message}</span>
    <span class="toast-close" onclick="this.parentElement.remove()">✕</span>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), duration);
}

// ── Copy to clipboard ─────────────────────────────────────────────────────────
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard!', 'success', 2000);
  } catch {
    const el = document.createElement('textarea');
    el.value = text; el.style.position = 'fixed'; el.style.opacity = '0';
    document.body.appendChild(el);
    el.select(); document.execCommand('copy');
    document.body.removeChild(el);
    showToast('Copied!', 'success', 2000);
  }
}

// ── Format helpers ────────────────────────────────────────────────────────────
function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    year: 'numeric', hour: '2-digit', minute: '2-digit'
  });
}

function getFileIcon(name = '') {
  const ext = (name.split('.').pop() || '').toLowerCase();
  const s = (c, d) => `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
  const file = '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>';
  const img = '<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>';
  const music = '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>';
  const video = '<polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>';
  const code = '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>';
  const pkg = '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>';
  const cog = '<circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>';
  const folder = '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>';
  const map = {
    exe: [cog,'#ef4444'], dll: [cog,'#ef4444'],
    pdf: [file,'#dc2626'], doc: [file,'#2563eb'], docx: [file,'#2563eb'],
    xls: [file,'#16a34a'], xlsx: [file,'#16a34a'], csv: [file,'#16a34a'],
    ppt: [file,'#ea580c'], pptx: [file,'#ea580c'],
    zip: [pkg,'#8b5cf6'], rar: [pkg,'#8b5cf6'], '7z': [pkg,'#8b5cf6'], tar: [pkg,'#8b5cf6'], gz: [pkg,'#8b5cf6'],
    png: [img,'#06b6d4'], jpg: [img,'#06b6d4'], jpeg: [img,'#06b6d4'], gif: [img,'#06b6d4'], bmp: [img,'#06b6d4'], webp: [img,'#06b6d4'],
    mp3: [music,'#d946ef'], mp4: [video,'#d946ef'], avi: [video,'#d946ef'], mkv: [video,'#d946ef'],
    py: [code,'#eab308'], js: [code,'#eab308'], ts: [code,'#3b82f6'], html: [code,'#f97316'], css: [code,'#06b6d4'],
    txt: [file,'#71717a'],
  };
  const [d, c] = map[ext] || [folder, '#71717a'];
  return s(c, d);
}

function isImageFile(name = '') {
  return /\.(png|jpg|jpeg|gif|bmp|webp|svg)$/i.test(name);
}

// ── Loading overlay ───────────────────────────────────────────────────────────
function showLoading(msg = 'Processing…') {
  let ov = document.getElementById('loading-overlay');
  if (!ov) {
    ov = document.createElement('div');
    ov.id = 'loading-overlay';
    ov.className = 'loading-overlay';
    ov.innerHTML = `<div class="spinner"></div><p id="loading-msg">${msg}</p>`;
    document.body.appendChild(ov);
  } else {
    document.getElementById('loading-msg').textContent = msg;
    ov.classList.remove('hidden');
  }
}
function hideLoading() {
  const ov = document.getElementById('loading-overlay');
  if (ov) ov.classList.add('hidden');
}

// ── Active nav link ──────────────────────────────────────────────────────────
function markActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(a => {
    a.classList.toggle('active', a.getAttribute('href') === path);
  });
}
document.addEventListener('DOMContentLoaded', markActiveNav);


// ════════════════════════════════════════════════════════════════════════════
//  Upload Page (multi-file, expiry, password)
// ════════════════════════════════════════════════════════════════════════════

function initUploadPage() {
  const uploadBtn = document.getElementById('upload-btn');
  const progWrap = document.getElementById('progress-wrap');
  const progFill = document.getElementById('progress-fill');
  const progPct = document.getElementById('progress-pct');

  if (!uploadBtn) return;

  uploadBtn.addEventListener('click', async () => {
    if (!window.selectedFiles || !window.selectedFiles.length) {
      showToast('Please select at least one file', 'warning');
      return;
    }
    uploadBtn.disabled = true;
    progWrap && progWrap.classList.remove('hidden');

    const expiry = document.getElementById('expiry-select')?.value || '24h';
    const password = document.getElementById('share-password')?.value || '';

    const results = [];
    const total = window.selectedFiles.length;

    for (let i = 0; i < total; i++) {
      const file = window.selectedFiles[i];
      setProgress(Math.round((i / total) * 80), `Uploading ${file.name}…`);

      try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('expiry', expiry);
        if (password) formData.append('password', password);

        const headers = await getAuthHeaders();
        const res = await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open('POST', `${API_BASE}/api/upload`);
          if (headers.Authorization) xhr.setRequestHeader('Authorization', headers.Authorization);
          xhr.upload.onprogress = e => {
            if (e.lengthComputable) {
              const pct = Math.round((i / total + e.loaded / e.total / total) * 80);
              setProgress(pct, `Uploading ${file.name}… ${Math.round(e.loaded / e.total * 100)}%`);
            }
          };
          xhr.onload = () => resolve(xhr);
          xhr.onerror = () => reject(new Error('Network error'));
          xhr.send(formData);
        });

        const data = JSON.parse(res.responseText);
        if (res.status === 401) { window.location.href = '/login'; return; }
        results.push(data);
      } catch (e) {
        results.push({ file: file.name, error: e.message });
      }
    }

    setProgress(100, 'Done!');

    if (results.length === 1) {
      // Single file — go to result page as before
      sessionStorage.setItem('scan_result', JSON.stringify(results[0]));
      setTimeout(() => { window.location.href = '/result'; }, 400);
    } else {
      // Multi-file — save array and go to result
      sessionStorage.setItem('scan_result', JSON.stringify({ results }));
      setTimeout(() => { window.location.href = '/result'; }, 400);
    }
  });

  function setProgress(pct, label) {
    if (progFill) progFill.style.width = `${pct}%`;
    if (progPct) progPct.textContent = label;
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  Result Page  (handles single + multi-file results)
// ════════════════════════════════════════════════════════════════════════════

function initResultPage() {
  const raw = sessionStorage.getItem('scan_result');
  if (!raw) { window.location.href = '/upload'; return; }

  const payload = JSON.parse(raw);

  // Multi-file result
  if (payload.results) {
    renderMultiResult(payload.results);
    return;
  }

  // Single file result
  renderSingleResult(payload);
}

function renderSingleResult(data) {
  const isSafe = data.prediction === 'SAFE';

  const banner = document.getElementById('result-banner');
  const bannerIcon = document.getElementById('result-icon');
  const bannerTitle = document.getElementById('result-title');
  const bannerSub = document.getElementById('result-subtitle');
  if (banner) {
    banner.className = `result-banner ${isSafe ? 'safe' : 'malware'} fade-in`;
    bannerIcon.innerHTML = isSafe
      ? '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'
      : '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
    bannerTitle.textContent = isSafe ? 'File is SAFE' : 'MALWARE Detected!';
    bannerSub.textContent = isSafe
      ? 'Your file passed the AI security scan and is ready to share.'
      : 'This file was identified as malicious and has been blocked.';
  }

  setText('res-filename', data.file || '—');
  setText('res-filetype', (data.type || '—').toUpperCase());
  setText('res-filesize', formatBytes(data.file_size || 0));
  setText('res-confidence', `${Math.round((data.confidence || 0.5) * 100)}%`);

  animateConfRing(data.confidence || 0.5, isSafe);

  if (isSafe) {
    setText('share-code-value', data.share_code || '——————');
    const copyBtn = document.getElementById('copy-code-btn');
    if (copyBtn) copyBtn.addEventListener('click', () => copyToClipboard(data.share_code));

    const qrImg = document.getElementById('qr-image');
    if (qrImg && data.qr_code_url) qrImg.src = data.qr_code_url;

    const dlLink = document.getElementById('download-link');
    if (dlLink) { dlLink.href = data.download_url; dlLink.textContent = data.download_url; }

    setText('expires-at', data.expires_at ? formatDate(data.expires_at) : 'Never');

    if (data.password_protected) {
      const el = document.getElementById('share-code-value');
      if (el && el.parentElement) {
        const badge = document.createElement('div');
        badge.style.cssText = 'margin-top:8px;font-size:.8rem;color:var(--text-muted)';
        badge.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="display:inline;vertical-align:middle;margin-right:4px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Password protected';
        el.parentElement.appendChild(badge);
      }
    }

    // ── Multi-Engine (VirusTotal) panel ──────────────────────────

    const safeSection = document.getElementById('safe-section');
    if (safeSection) safeSection.classList.remove('hidden');
  } else {
    const blockedSection = document.getElementById('blocked-section');
    if (blockedSection) blockedSection.classList.remove('hidden');
  }


  const dlQrBtn = document.getElementById('download-qr-btn');
  if (dlQrBtn && data.qr_code_url) {
    dlQrBtn.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = data.qr_code_url;
      a.download = `qr_${data.share_code}.png`;
      a.click();
    });
  }

  const shareAgainBtn = document.getElementById('share-again-btn');
  if (shareAgainBtn) shareAgainBtn.addEventListener('click', () => {
    sessionStorage.removeItem('scan_result'); window.location.href = '/upload';
  });
}

function renderMultiResult(results) {
  // Replace result banner with a multi-file summary
  const banner = document.getElementById('result-banner');
  if (banner) {
    const safe = results.filter(r => r.prediction === 'SAFE').length;
    const blocked = results.filter(r => r.prediction === 'MALWARE').length;
    const errors = results.filter(r => r.error).length;
    banner.className = `result-banner ${blocked ? 'malware' : 'safe'} fade-in`;
    banner.innerHTML = `
      <span class="result-icon">${blocked
        ? '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
        : '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>'}</span>
      <h2 id="result-title">${results.length} Files Processed</h2>
      <p id="result-subtitle" style="margin-top:8px">
        ${safe} safe &nbsp;·&nbsp; ${blocked} blocked &nbsp;·&nbsp; ${errors} errors
      </p>`;
  }

  // Build a results list in the safe-section
  const safeSection = document.getElementById('safe-section');
  if (safeSection) {
    safeSection.classList.remove('hidden');
    safeSection.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:14px;margin-top:16px">
        ${results.map(r => `
          <div class="card card-sm" style="border-left:4px solid ${r.prediction === 'SAFE' ? 'var(--success)' : r.error ? 'var(--warning)' : 'var(--danger)'}">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
              <div>
                <span style="font-weight:600">${getFileIcon(r.file)} ${r.file || 'Unknown'}</span>
                ${r.share_code ? `<br><span style="font-size:.85rem;color:var(--text-muted)">Code: <strong style="font-family:monospace;letter-spacing:.1em">${r.share_code}</strong>
                  <button onclick="copyToClipboard('${r.share_code}')" class="btn btn-ghost btn-sm" style="margin-left:6px;padding:4px 10px">Copy</button></span>` : ''}
                ${r.expires_at ? `<br><span style="font-size:.78rem;color:var(--text-muted)">Expires: ${formatDate(r.expires_at)}</span>` : ''}
                ${r.error ? `<br><span style="font-size:.85rem;color:var(--danger)">${r.error}</span>` : ''}
              </div>
              <span class="badge ${r.prediction === 'SAFE' ? 'badge-safe' : r.error ? 'badge-pending' : 'badge-malware'}">
                ${r.prediction || (r.error ? 'ERROR' : '—')}
              </span>
            </div>
          </div>`).join('')}
      </div>
      <button class="btn btn-primary w-full mt-24" onclick="sessionStorage.removeItem('scan_result');window.location.href='/upload'">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Upload More Files
      </button>`;
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function animateConfRing(confidence, safe) {
  const circle = document.getElementById('conf-circle');
  const label = document.getElementById('conf-label');
  if (!circle) return;
  const circumference = 226;
  const pct = Math.round(confidence * 100);
  circle.classList.add(safe ? 'safe' : 'malware');
  setTimeout(() => {
    circle.style.strokeDashoffset = circumference - (circumference * confidence);
  }, 100);
  if (label) label.textContent = `${pct}%`;
}

// ════════════════════════════════════════════════════════════════════════════
//  Download Page (with password + image preview)
// ════════════════════════════════════════════════════════════════════════════

function initDownloadPage() {
  const inputs = document.querySelectorAll('.code-input');
  const lookupBtn = document.getElementById('lookup-btn');
  const fileInfo = document.getElementById('file-info-box');
  let currentCode = '';

  if (!inputs.length) return;

  inputs.forEach((inp, i) => {
    inp.addEventListener('keydown', e => {
      if (e.key === 'Backspace' && !inp.value && i > 0) inputs[i - 1].focus();
    });
    inp.addEventListener('input', () => {
      inp.value = inp.value.replace(/\D/, '').slice(0, 1);
      if (inp.value && i < inputs.length - 1) inputs[i + 1].focus();
      checkAllFilled();
    });
    inp.addEventListener('paste', e => {
      e.preventDefault();
      const paste = (e.clipboardData.getData('text') || '').replace(/\D/g, '');
      paste.split('').slice(0, inputs.length).forEach((ch, j) => {
        if (inputs[j]) { inputs[j].value = ch; }
      });
      const last = Math.min(paste.length, inputs.length) - 1;
      if (inputs[last]) inputs[last].focus();
      checkAllFilled();
    });
  });

  function getCode() { return [...inputs].map(i => i.value).join(''); }

  function checkAllFilled() {
    if (getCode().length === 6) lookupCode();
  }

  lookupBtn && lookupBtn.addEventListener('click', () => {
    if (getCode().length !== 6) { showToast('Enter all 6 digits', 'warning'); return; }
    lookupCode();
  });

  // Verify password button
  const verifyBtn = document.getElementById('verify-password-btn');
  verifyBtn && verifyBtn.addEventListener('click', () => {
    const pw = document.getElementById('download-password')?.value || '';
    if (!pw) { showToast('Enter the password', 'warning'); return; }
    lookupCode(pw);
  });

  async function lookupCode(password = '') {
    currentCode = getCode();
    showLoading('Verifying code…');
    try {
      const url = `${API_BASE}/api/check-code/${currentCode}${password ? '?password=' + encodeURIComponent(password) : ''}`;
      const res = await fetch(url);
      const data = await res.json();
      hideLoading();

      if (res.status === 403) {
        showToast(data.error || 'Incorrect password', 'error');
        return;
      }

      if (!data.valid) {
        showToast(data.error || 'Invalid code', 'error');
        return;
      }

      // Password required — show password box
      if (data.password_required) {
        document.getElementById('password-box')?.classList.remove('hidden');
        return;
      }

      // File found! Show info
      document.getElementById('password-box')?.classList.add('hidden');
      if (fileInfo) fileInfo.classList.remove('hidden');
      setText('dl-filename', data.filename);
      setText('dl-filetype', (data.file_type || '').toUpperCase());
      setText('dl-filesize', formatBytes(data.file_size || 0));

      const iconEl = document.getElementById('dl-icon');
      if (iconEl) iconEl.innerHTML = getFileIcon(data.filename);

      const dlBtn = document.getElementById('download-file-btn');
      if (dlBtn) {
        dlBtn.classList.remove('hidden');
        dlBtn.href = `${data.download_url}${password ? '?password=' + encodeURIComponent(password) : ''}`;
        dlBtn.setAttribute('download', data.filename);
      }
      showToast('File found! Click Download to save.', 'success');

    } catch {
      hideLoading();
      showToast('Server error – is the backend running?', 'error');
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  Dashboard Page (with download count, delete button)
// ════════════════════════════════════════════════════════════════════════════

async function loadDashboard() {
  const tbody = document.getElementById('files-tbody');
  const statTotal = document.getElementById('stat-total');
  const statMalware = document.getElementById('stat-malware');
  const statSafe = document.getElementById('stat-safe');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/api/dashboard-stats`, { headers: await getAuthHeaders() });
    const data = await res.json();
    if (statTotal) statTotal.textContent = data.total_scanned || 0;
    if (statMalware) statMalware.textContent = data.malware_blocked || 0;
    if (statSafe) statSafe.textContent = data.safe_shared || 0;

    tbody.innerHTML = '';
    if (!data.recent_uploads || data.recent_uploads.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center" style="padding:32px;color:var(--text-muted)">No files uploaded yet</td></tr>';
      return;
    }
    data.recent_uploads.forEach(f => {
      const isSafe = f.scan_result === 'SAFE';
      tbody.innerHTML += `
        <tr class="slide-up">
          <td>
            <span style="font-size:1.2rem;margin-right:8px">${getFileIcon(f.original_filename)}</span>
            <span title="${f.original_filename}">${truncate(f.original_filename, 24)}</span>
            ${f.password_protected ? '<span title="Password protected" style="margin-left:4px;display:inline-flex;vertical-align:middle"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>' : ''}
          </td>
          <td><span class="badge badge-info">${(f.file_type || 'generic').toUpperCase()}</span></td>
          <td>${formatBytes(f.file_size || 0)}</td>
          <td><span class="badge ${isSafe ? 'badge-safe' : 'badge-malware'}">${f.scan_result || '—'}</span></td>
          <td>${f.confidence != null ? Math.round(f.confidence * 100) + '%' : '—'}</td>
          <td>${f.share_code
          ? `<span class="share-code-inline" onclick="copyToClipboard('${f.share_code}')" title="Click to copy" style="cursor:pointer;font-family:monospace;font-weight:700;letter-spacing:.1em">${f.share_code}</span>`
          : '<span style="color:var(--danger)">Blocked</span>'}</td>
          <td style="text-align:center">${f.download_count || 0}</td>
          <td style="color:var(--text-muted);font-size:.82rem">${formatDate(f.upload_time)}</td>
          <td>
            ${f.id ? `<button onclick="deleteFile('${f.id}','${(f.original_filename || '').replace(/'/g, "\\'")}','${f.filepath || ''}')"
              class="btn btn-danger btn-sm" style="padding:5px 10px"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>` : '—'}
          </td>
        </tr>`;
    });
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="9" class="text-center" style="padding:24px;color:var(--danger)">Failed to load data</td></tr>';
  }
}

function initDashboardPage() {
  const refreshBtn = document.getElementById('refresh-btn');
  refreshBtn && refreshBtn.addEventListener('click', () => {
    loadDashboard();
    if (typeof loadExtras === 'function') loadExtras();
    if (typeof loadStorageStats === 'function') loadStorageStats();
  });
  loadDashboard();
}

function truncate(str, n) { return str && str.length > n ? str.slice(0, n - 1) + '…' : str || ''; }

// ════════════════════════════════════════════════════════════════════════════
//  Profile Page
// ════════════════════════════════════════════════════════════════════════════

async function initProfilePage() {
  const nameInput = document.getElementById('profile-name');
  const emailEl = document.getElementById('profile-email');
  const uidEl = document.getElementById('profile-uid');
  const avatarEl = document.getElementById('profile-avatar');
  const saveBtn = document.getElementById('save-profile-btn');
  const resetBtn = document.getElementById('reset-password-btn');

  if (!nameInput || !saveBtn) return;

  function buildAvatarDataUrl(seedText) {
    const raw = (seedText || 'User').trim();
    const initials = raw
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map(part => part[0].toUpperCase())
      .join('') || 'U';
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="100%" height="100%" fill="#18181b"/><text x="50%" y="54%" font-size="46" fill="#ffffff" text-anchor="middle" dominant-baseline="middle" font-family="Inter,Arial,sans-serif">${initials}</text></svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  }

  try {
    await AppAuth.initAuth();
    const auth = window.firebase.auth();
    const user = auth.currentUser;
    if (!user) {
      window.location.href = '/login';
      return;
    }

    nameInput.value = user.displayName || '';
    if (emailEl) emailEl.textContent = user.email || '—';
    if (uidEl) uidEl.textContent = user.uid || '—';
    if (avatarEl) {
      avatarEl.src = user.photoURL || buildAvatarDataUrl(user.displayName || user.email || user.uid || 'User');
    }
  } catch {
    showToast('Failed to load profile', 'error');
  }

  saveBtn.addEventListener('click', async () => {
    const nextName = (nameInput.value || '').trim();
    if (!nextName) {
      showToast('Display name cannot be empty', 'warning');
      return;
    }

    try {
      const auth = window.firebase.auth();
      const user = auth.currentUser;
      if (!user) {
        window.location.href = '/login';
        return;
      }

      await user.updateProfile({ displayName: nextName });
      const token = await user.getIdToken(true);
      localStorage.setItem('firebase_id_token', token);

      if (avatarEl) {
        avatarEl.src = user.photoURL || buildAvatarDataUrl(nextName || user.email || user.uid || 'User');
      }

      showToast('Profile updated', 'success');
      await AppAuth.addAuthNav();
    } catch {
      showToast('Unable to update profile', 'error');
    }
  });

  resetBtn && resetBtn.addEventListener('click', async () => {
    try {
      const auth = window.firebase.auth();
      const email = auth.currentUser?.email;
      if (!email) {
        showToast('No account email found', 'warning');
        return;
      }
      await auth.sendPasswordResetEmail(email);
      showToast('Password reset email sent', 'success');
    } catch {
      showToast('Could not send reset email', 'error');
    }
  });
}

// ════════════════════════════════════════════════════════════════════════════
//  Auto-init on DOMContentLoaded
// ════════════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  const protectedPages = ['upload', 'dashboard', 'result', 'profile'];

  if (protectedPages.includes(page)) {
    (async () => {
      if (window.AppAuth) {
        await AppAuth.initAuth();
        await AppAuth.addAuthNav();
        await AppAuth.requireAuthForPage();
      }
      if (page === 'upload') initUploadPage();
      if (page === 'result') initResultPage();
      if (page === 'dashboard') initDashboardPage();
      if (page === 'profile') initProfilePage();
    })();
  } else {
    if (page === 'download') initDownloadPage();
    if (window.AppAuth) {
      AppAuth.initAuth().then(() => AppAuth.addAuthNav()).catch(() => {});
    }
  }
});
