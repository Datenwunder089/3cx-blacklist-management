// --- Navigation ---

const navLinks = document.querySelectorAll('[data-page]');
const pages = document.querySelectorAll('.page');

function showPage(pageId) {
  pages.forEach(p => p.classList.toggle('active', p.id === `page-${pageId}`));
  navLinks.forEach(a => a.classList.toggle('active', a.dataset.page === pageId));
  if (pageId === 'blacklist') loadBlacklist();
  if (pageId === 'admin') loadConfig();
}

navLinks.forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    showPage(link.dataset.page);
  });
});

// --- API helper ---

async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// --- Blacklist ---

let blacklistData = [];

async function loadBlacklist() {
  const loading = document.getElementById('blacklist-loading');
  const error = document.getElementById('blacklist-error');
  const empty = document.getElementById('blacklist-empty');
  const table = document.getElementById('blacklist-table');
  const notConfigured = document.getElementById('not-configured');

  loading.style.display = 'flex';
  error.style.display = 'none';
  empty.style.display = 'none';
  table.style.display = 'none';
  notConfigured.style.display = 'none';

  try {
    const cfg = await api('GET', '/api/config');
    if (!cfg.configured) {
      loading.style.display = 'none';
      notConfigured.style.display = 'block';
      return;
    }

    blacklistData = await api('GET', '/api/blacklist');
    loading.style.display = 'none';
    renderBlacklist();
  } catch (err) {
    loading.style.display = 'none';
    if (err.message.includes('konfigurieren')) {
      notConfigured.style.display = 'block';
    } else {
      error.textContent = err.message;
      error.style.display = 'block';
    }
  }
}

function renderBlacklist(filter = '') {
  const table = document.getElementById('blacklist-table');
  const body = document.getElementById('blacklist-body');
  const empty = document.getElementById('blacklist-empty');

  const filtered = blacklistData.filter(entry => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (entry.Number || '').toLowerCase().includes(q) ||
           (entry.Description || '').toLowerCase().includes(q);
  });

  if (filtered.length === 0) {
    table.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  empty.style.display = 'none';
  table.style.display = 'table';

  body.innerHTML = filtered.map(entry => `
    <tr>
      <td class="mono">${escapeHtml(entry.Number || '')}</td>
      <td>${escapeHtml(entry.Description || '—')}</td>
      <td>${entry.blockCalls ? '<span class="badge badge-red">Blockiert</span>' : '<span class="badge badge-gray">Erlaubt</span>'}</td>
      <td>${entry.blockSms ? '<span class="badge badge-red">Blockiert</span>' : '<span class="badge badge-gray">Erlaubt</span>'}</td>
      <td>
        <button class="btn btn-small btn-danger" onclick="confirmDelete('${escapeAttr(entry.Id || entry.id)}', '${escapeAttr(entry.Number)}')">L&ouml;schen</button>
      </td>
    </tr>
  `).join('');
}

document.getElementById('search-input').addEventListener('input', (e) => {
  renderBlacklist(e.target.value);
});

// --- Add Number Modal ---

const modal = document.getElementById('modal-overlay');
const modalForm = document.getElementById('number-form');
const modalError = document.getElementById('modal-error');

document.getElementById('btn-add').addEventListener('click', () => {
  modalForm.reset();
  document.getElementById('inp-block-calls').checked = true;
  modalError.style.display = 'none';
  modal.style.display = 'flex';
});

document.getElementById('modal-close').addEventListener('click', () => { modal.style.display = 'none'; });
document.getElementById('modal-cancel').addEventListener('click', () => { modal.style.display = 'none'; });
modal.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });

modalForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  modalError.style.display = 'none';

  const payload = {
    Number: document.getElementById('inp-number').value.trim(),
    Description: document.getElementById('inp-description').value.trim(),
    blockCalls: document.getElementById('inp-block-calls').checked,
    blockSms: document.getElementById('inp-block-sms').checked,
  };

  try {
    await api('POST', '/api/blacklist', payload);
    modal.style.display = 'none';
    loadBlacklist();
  } catch (err) {
    modalError.textContent = err.message;
    modalError.style.display = 'block';
  }
});

// --- Delete Confirm ---

const confirmOverlay = document.getElementById('confirm-overlay');
let pendingDeleteId = null;

window.confirmDelete = function(id, number) {
  pendingDeleteId = id;
  document.getElementById('confirm-text').textContent = `Soll "${number}" wirklich aus der Blacklist entfernt werden?`;
  confirmOverlay.style.display = 'flex';
};

document.getElementById('confirm-yes').addEventListener('click', async () => {
  if (!pendingDeleteId) return;
  try {
    await api('DELETE', `/api/blacklist/${encodeURIComponent(pendingDeleteId)}`);
    confirmOverlay.style.display = 'none';
    pendingDeleteId = null;
    loadBlacklist();
  } catch (err) {
    alert('Fehler beim Löschen: ' + err.message);
    confirmOverlay.style.display = 'none';
  }
});

document.getElementById('confirm-no').addEventListener('click', () => {
  confirmOverlay.style.display = 'none';
  pendingDeleteId = null;
});

// --- Admin Config ---

const configForm = document.getElementById('config-form');
const configStatus = document.getElementById('config-status');

async function loadConfig() {
  try {
    const cfg = await api('GET', '/api/config');
    if (cfg.configured) {
      document.getElementById('cfg-fqdn').value = cfg.fqdn || '';
      document.getElementById('cfg-client-id').value = cfg.clientId || '';
      document.getElementById('cfg-client-secret').placeholder = cfg.hasSecret
        ? '••••••••  (gespeichert — neu eingeben zum Ändern)'
        : 'API Client Secret';
    }
  } catch { /* ignore */ }
}

configForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  configStatus.style.display = 'none';

  const secret = document.getElementById('cfg-client-secret').value;
  if (!secret) {
    showConfigStatus('Bitte Client Secret eingeben.', 'error');
    return;
  }

  try {
    await api('POST', '/api/config', {
      fqdn: document.getElementById('cfg-fqdn').value.trim(),
      clientId: document.getElementById('cfg-client-id').value.trim(),
      clientSecret: secret,
    });
    showConfigStatus('Konfiguration gespeichert!', 'success');
    document.getElementById('cfg-client-secret').value = '';
    document.getElementById('cfg-client-secret').placeholder = '••••••••  (gespeichert — neu eingeben zum Ändern)';
  } catch (err) {
    showConfigStatus(err.message, 'error');
  }
});

document.getElementById('btn-test').addEventListener('click', async () => {
  configStatus.style.display = 'none';
  showConfigStatus('Teste Verbindung...', 'info');
  try {
    const result = await api('POST', '/api/config/test');
    showConfigStatus(result.message, 'success');
  } catch (err) {
    showConfigStatus('Verbindungstest fehlgeschlagen: ' + err.message, 'error');
  }
});

function showConfigStatus(msg, type) {
  configStatus.textContent = msg;
  configStatus.className = `form-status status-${type}`;
  configStatus.style.display = 'block';
}

// --- Helpers ---

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return String(str || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

// --- Init ---
loadBlacklist();
