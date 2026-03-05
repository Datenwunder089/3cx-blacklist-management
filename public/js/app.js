// --- Auth State ---

let currentUser = null;

async function checkAuth() {
  try {
    const res = await fetch('/api/auth/status');
    const data = await res.json();
    if (!data.authenticated) {
      location.href = '/login.html';
      return false;
    }
    currentUser = data.user;
    document.getElementById('user-display-name').textContent = currentUser.displayName || currentUser.username;

    const badge = document.getElementById('user-role-badge');
    badge.textContent = currentUser.role === 'admin' ? 'Admin' : 'Benutzer';
    badge.className = 'role-badge ' + (currentUser.role === 'admin' ? 'role-admin' : 'role-user');

    // Show admin-only elements
    if (currentUser.role === 'admin') {
      document.getElementById('nav-users').style.display = '';
      document.getElementById('microsoft-config-form').style.display = '';
    }

    return true;
  } catch {
    location.href = '/login.html';
    return false;
  }
}

// --- Logout ---

document.getElementById('btn-logout').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  location.href = '/login.html';
});

// --- Navigation ---

const navLinks = document.querySelectorAll('[data-page]');
const pages = document.querySelectorAll('.page');

function showPage(pageId) {
  pages.forEach(p => p.classList.toggle('active', p.id === `page-${pageId}`));
  navLinks.forEach(a => a.classList.toggle('active', a.dataset.page === pageId));
  if (pageId === 'blacklist') loadBlacklist();
  if (pageId === 'admin') { loadConfig(); loadMicrosoftConfig(); }
  if (pageId === 'users') loadUsers();
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
  if (res.status === 401) {
    location.href = '/login.html';
    throw new Error('Sitzung abgelaufen');
  }
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
let pendingDeleteType = null; // 'blacklist' or 'user'

window.confirmDelete = function(id, number) {
  pendingDeleteId = id;
  pendingDeleteType = 'blacklist';
  document.getElementById('confirm-text').textContent = `Soll "${number}" wirklich aus der Blacklist entfernt werden?`;
  confirmOverlay.style.display = 'flex';
};

window.confirmDeleteUser = function(id, username) {
  pendingDeleteId = id;
  pendingDeleteType = 'user';
  document.getElementById('confirm-text').textContent = `Soll der Benutzer "${username}" wirklich gelöscht werden?`;
  confirmOverlay.style.display = 'flex';
};

document.getElementById('confirm-yes').addEventListener('click', async () => {
  if (!pendingDeleteId) return;
  try {
    if (pendingDeleteType === 'blacklist') {
      await api('DELETE', `/api/blacklist/${encodeURIComponent(pendingDeleteId)}`);
      confirmOverlay.style.display = 'none';
      pendingDeleteId = null;
      loadBlacklist();
    } else if (pendingDeleteType === 'user') {
      await api('DELETE', `/api/users/${encodeURIComponent(pendingDeleteId)}`);
      confirmOverlay.style.display = 'none';
      pendingDeleteId = null;
      loadUsers();
    }
  } catch (err) {
    alert('Fehler: ' + err.message);
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

// --- Microsoft Config ---

const msConfigForm = document.getElementById('microsoft-config-form');
const msConfigStatus = document.getElementById('ms-config-status');

async function loadMicrosoftConfig() {
  if (currentUser.role !== 'admin') return;
  try {
    const cfg = await api('GET', '/api/config/microsoft');
    document.getElementById('ms-tenant-id').value = cfg.tenantId || '';
    document.getElementById('ms-client-id').value = cfg.clientId || '';
    document.getElementById('ms-client-secret').placeholder = cfg.hasSecret
      ? '••••••••  (gespeichert — neu eingeben zum Ändern)'
      : 'Azure AD Client Secret';
    document.getElementById('ms-auto-provision').checked = cfg.allowAutoProvision || false;
  } catch { /* ignore */ }
}

msConfigForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  msConfigStatus.style.display = 'none';

  try {
    const body = {
      tenantId: document.getElementById('ms-tenant-id').value.trim(),
      clientId: document.getElementById('ms-client-id').value.trim(),
      allowAutoProvision: document.getElementById('ms-auto-provision').checked,
    };
    const secret = document.getElementById('ms-client-secret').value;
    if (secret) body.clientSecret = secret;

    await api('POST', '/api/config/microsoft', body);
    showMsConfigStatus('Microsoft-Login Konfiguration gespeichert!', 'success');
    document.getElementById('ms-client-secret').value = '';
    document.getElementById('ms-client-secret').placeholder = '••••••••  (gespeichert — neu eingeben zum Ändern)';
  } catch (err) {
    showMsConfigStatus(err.message, 'error');
  }
});

function showMsConfigStatus(msg, type) {
  msConfigStatus.textContent = msg;
  msConfigStatus.className = `form-status status-${type}`;
  msConfigStatus.style.display = 'block';
}

// --- User Management ---

async function loadUsers() {
  if (currentUser.role !== 'admin') return;
  try {
    const users = await api('GET', '/api/users');
    const table = document.getElementById('users-table');
    const body = document.getElementById('users-body');

    body.innerHTML = users.map(u => `
      <tr>
        <td class="mono">${escapeHtml(u.username)}</td>
        <td>${escapeHtml(u.displayName || '—')}</td>
        <td>${escapeHtml(u.email || '—')}</td>
        <td><span class="badge ${u.role === 'admin' ? 'badge-blue' : 'badge-gray'}">${u.role === 'admin' ? 'Admin' : 'Benutzer'}</span></td>
        <td>${u.microsoftId ? '<span class="badge badge-green">Verknüpft</span>' : '<span class="badge badge-gray">—</span>'}</td>
        <td>
          <button class="btn btn-small btn-secondary" onclick="editUser('${escapeAttr(u.id)}')">Bearbeiten</button>
          <button class="btn btn-small btn-danger" onclick="confirmDeleteUser('${escapeAttr(u.id)}', '${escapeAttr(u.username)}')">Löschen</button>
        </td>
      </tr>
    `).join('');

    table.style.display = 'table';
    window._usersCache = users;
  } catch (err) {
    alert('Fehler beim Laden der Benutzer: ' + err.message);
  }
}

// User Modal
const userModal = document.getElementById('user-modal-overlay');
const userForm = document.getElementById('user-form');
const userModalError = document.getElementById('user-modal-error');

document.getElementById('btn-add-user').addEventListener('click', () => {
  userForm.reset();
  document.getElementById('user-edit-id').value = '';
  document.getElementById('user-modal-title').textContent = 'Benutzer anlegen';
  document.getElementById('user-inp-username').disabled = false;
  document.getElementById('user-password-hint').textContent = 'Mindestens 8 Zeichen. Leer lassen wenn nur Microsoft-Login genutzt wird.';
  userModalError.style.display = 'none';
  userModal.style.display = 'flex';
});

window.editUser = function(id) {
  const user = (window._usersCache || []).find(u => u.id === id);
  if (!user) return;

  document.getElementById('user-edit-id').value = user.id;
  document.getElementById('user-modal-title').textContent = 'Benutzer bearbeiten';
  document.getElementById('user-inp-username').value = user.username;
  document.getElementById('user-inp-username').disabled = true;
  document.getElementById('user-inp-displayname').value = user.displayName || '';
  document.getElementById('user-inp-email').value = user.email || '';
  document.getElementById('user-inp-role').value = user.role;
  document.getElementById('user-inp-password').value = '';
  document.getElementById('user-password-hint').textContent = 'Leer lassen um das Passwort nicht zu ändern.';
  userModalError.style.display = 'none';
  userModal.style.display = 'flex';
};

document.getElementById('user-modal-close').addEventListener('click', () => { userModal.style.display = 'none'; });
document.getElementById('user-modal-cancel').addEventListener('click', () => { userModal.style.display = 'none'; });
userModal.addEventListener('click', (e) => { if (e.target === userModal) userModal.style.display = 'none'; });

userForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  userModalError.style.display = 'none';

  const editId = document.getElementById('user-edit-id').value;

  try {
    if (editId) {
      // Update existing user
      const body = {
        displayName: document.getElementById('user-inp-displayname').value.trim(),
        email: document.getElementById('user-inp-email').value.trim(),
        role: document.getElementById('user-inp-role').value,
      };
      const pw = document.getElementById('user-inp-password').value;
      if (pw) body.password = pw;
      await api('PUT', `/api/users/${encodeURIComponent(editId)}`, body);
    } else {
      // Create new user
      const body = {
        username: document.getElementById('user-inp-username').value.trim(),
        displayName: document.getElementById('user-inp-displayname').value.trim(),
        email: document.getElementById('user-inp-email').value.trim(),
        role: document.getElementById('user-inp-role').value,
      };
      const pw = document.getElementById('user-inp-password').value;
      if (pw) body.password = pw;
      await api('POST', '/api/users', body);
    }
    userModal.style.display = 'none';
    loadUsers();
  } catch (err) {
    userModalError.textContent = err.message;
    userModalError.style.display = 'block';
  }
});

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

(async () => {
  const ok = await checkAuth();
  if (ok) loadBlacklist();
})();
