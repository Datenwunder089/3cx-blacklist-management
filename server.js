const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;
const DATA_DIR = path.join(__dirname, 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const USERS_PATH = path.join(DATA_DIR, 'users.json');
const AUTH_CONFIG_PATH = path.join(DATA_DIR, 'auth-config.json');

// Ensure data directory exists
fs.mkdirSync(DATA_DIR, { recursive: true });

// --- Session Secret (persistent) ---

const SESSION_SECRET_PATH = path.join(DATA_DIR, '.session-secret');
function getSessionSecret() {
  try {
    return fs.readFileSync(SESSION_SECRET_PATH, 'utf8');
  } catch {
    const secret = crypto.randomBytes(48).toString('hex');
    fs.writeFileSync(SESSION_SECRET_PATH, secret, { mode: 0o600 });
    return secret;
  }
}

// --- Middleware ---

app.use(express.json());

app.use(session({
  secret: getSessionSecret(),
  resave: false,
  saveUninitialized: false,
  name: '3cx_session',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
}));

// Rate limiter for login attempts: 5 per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Zu viele Login-Versuche. Bitte in 15 Minuten erneut versuchen.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
});

// --- User storage helpers ---

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2), { mode: 0o600 });
}

function findUserByUsername(username) {
  return readUsers().find(u => u.username.toLowerCase() === username.toLowerCase());
}

// --- Brute-force tracking per account ---

const failedAttempts = new Map(); // username -> { count, lockedUntil }

function checkAccountLock(username) {
  const key = username.toLowerCase();
  const record = failedAttempts.get(key);
  if (!record) return { locked: false };
  if (record.lockedUntil && Date.now() < record.lockedUntil) {
    const remainingSec = Math.ceil((record.lockedUntil - Date.now()) / 1000);
    return { locked: true, remainingSec };
  }
  if (record.lockedUntil && Date.now() >= record.lockedUntil) {
    failedAttempts.delete(key);
  }
  return { locked: false };
}

function recordFailedAttempt(username) {
  const key = username.toLowerCase();
  const record = failedAttempts.get(key) || { count: 0 };
  record.count++;
  // Lock after 5 failed attempts: 5 min for first lock, doubles each time (max 60 min)
  if (record.count >= 5) {
    const lockMinutes = Math.min(60, 5 * Math.pow(2, Math.floor((record.count - 5) / 3)));
    record.lockedUntil = Date.now() + lockMinutes * 60 * 1000;
  }
  failedAttempts.set(key, record);
}

function clearFailedAttempts(username) {
  failedAttempts.delete(username.toLowerCase());
}

// --- Auth config helpers ---

function readAuthConfig() {
  try {
    return JSON.parse(fs.readFileSync(AUTH_CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function writeAuthConfig(config) {
  fs.writeFileSync(AUTH_CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

// --- Auth middleware ---

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  res.status(401).json({ error: 'Nicht authentifiziert.' });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') {
    return next();
  }
  res.status(403).json({ error: 'Keine Berechtigung.' });
}

// --- Static files: login page is public, rest requires auth ---

// Serve login page without auth
app.get('/login.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/css/login.css', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'css', 'login.css'));
});

// Auth check endpoint (public)
app.get('/api/auth/status', (req, res) => {
  if (req.session && req.session.user) {
    return res.json({
      authenticated: true,
      user: {
        username: req.session.user.username,
        displayName: req.session.user.displayName,
        role: req.session.user.role,
      },
    });
  }
  res.json({ authenticated: false });
});

// Check if initial setup is needed (no users exist yet)
app.get('/api/auth/needs-setup', (_req, res) => {
  const users = readUsers();
  res.json({ needsSetup: users.length === 0 });
});

// Microsoft auth config (public - frontend needs tenant/clientId)
app.get('/api/auth/microsoft-config', (_req, res) => {
  const authConfig = readAuthConfig();
  if (authConfig.microsoft && authConfig.microsoft.tenantId && authConfig.microsoft.clientId) {
    res.json({
      enabled: true,
      tenantId: authConfig.microsoft.tenantId,
      clientId: authConfig.microsoft.clientId,
    });
  } else {
    res.json({ enabled: false });
  }
});

// --- Initial setup: create first admin user ---

app.post('/api/auth/setup', async (req, res) => {
  const users = readUsers();
  if (users.length > 0) {
    return res.status(400).json({ error: 'Setup bereits abgeschlossen.' });
  }

  const { username, password, displayName } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Benutzername und Passwort erforderlich.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen lang sein.' });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const user = {
    id: uuidv4(),
    username: username.trim(),
    displayName: (displayName || username).trim(),
    passwordHash: hashedPassword,
    role: 'admin',
    createdAt: new Date().toISOString(),
  };

  writeUsers([user]);

  // Log in immediately
  req.session.user = { id: user.id, username: user.username, displayName: user.displayName, role: user.role };
  res.json({ success: true });
});

// --- Local login ---

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Benutzername und Passwort erforderlich.' });
  }

  // Check account lockout
  const lockStatus = checkAccountLock(username);
  if (lockStatus.locked) {
    return res.status(429).json({
      error: `Konto vorübergehend gesperrt. Bitte in ${lockStatus.remainingSec} Sekunden erneut versuchen.`,
    });
  }

  const user = findUserByUsername(username);
  if (!user) {
    recordFailedAttempt(username);
    // Constant-time delay to prevent user enumeration
    await bcrypt.hash('dummy', 12);
    return res.status(401).json({ error: 'Benutzername oder Passwort falsch.' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    recordFailedAttempt(username);
    return res.status(401).json({ error: 'Benutzername oder Passwort falsch.' });
  }

  clearFailedAttempts(username);
  req.session.user = { id: user.id, username: user.username, displayName: user.displayName, role: user.role };
  res.json({
    success: true,
    user: { username: user.username, displayName: user.displayName, role: user.role },
  });
});

// --- Microsoft OAuth2 Authorization Code Flow ---

app.get('/api/auth/microsoft/login', (req, res) => {
  const authConfig = readAuthConfig();
  const ms = authConfig.microsoft;
  if (!ms || !ms.tenantId || !ms.clientId || !ms.clientSecret) {
    return res.status(400).json({ error: 'Microsoft Login nicht konfiguriert.' });
  }

  // Generate state for CSRF protection
  const state = crypto.randomBytes(32).toString('hex');
  req.session.oauthState = state;

  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/microsoft/callback`;
  const params = new URLSearchParams({
    client_id: ms.clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'openid profile email',
    state: state,
  });

  const authUrl = `https://login.microsoftonline.com/${encodeURIComponent(ms.tenantId)}/oauth2/v2.0/authorize?${params}`;
  res.redirect(authUrl);
});

app.get('/api/auth/microsoft/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.redirect(`/login.html?error=${encodeURIComponent(error_description || error)}`);
  }

  // Verify CSRF state
  if (!state || state !== req.session.oauthState) {
    return res.redirect('/login.html?error=' + encodeURIComponent('Ungültiger OAuth State. Bitte erneut versuchen.'));
  }
  delete req.session.oauthState;

  const authConfig = readAuthConfig();
  const ms = authConfig.microsoft;
  if (!ms) {
    return res.redirect('/login.html?error=' + encodeURIComponent('Microsoft Login nicht konfiguriert.'));
  }

  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/microsoft/callback`;

  try {
    // Exchange code for tokens
    const tokenBody = new URLSearchParams({
      client_id: ms.clientId,
      client_secret: ms.clientSecret,
      code: code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
      scope: 'openid profile email',
    }).toString();

    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(ms.tenantId)}/oauth2/v2.0/token`;
    const tokenRes = await apiRequest('POST', tokenUrl, {
      'Content-Type': 'application/x-www-form-urlencoded',
    }, tokenBody);

    if (tokenRes.status !== 200) {
      const errData = JSON.parse(tokenRes.body);
      throw new Error(errData.error_description || 'Token-Austausch fehlgeschlagen');
    }

    const tokenData = JSON.parse(tokenRes.body);

    // Decode ID token to get user info (JWT payload)
    const idTokenParts = tokenData.id_token.split('.');
    const payload = JSON.parse(Buffer.from(idTokenParts[1], 'base64url').toString());

    const email = payload.email || payload.preferred_username || '';
    const displayName = payload.name || email;
    const microsoftId = payload.sub;

    // Check if this Microsoft user is allowed (exists in users list or auto-provisioning)
    let users = readUsers();
    let user = users.find(u => u.microsoftId === microsoftId);

    if (!user) {
      // Also try matching by email
      user = users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase());
    }

    if (!user) {
      // Check if allowAutoProvision is enabled
      if (ms.allowAutoProvision) {
        user = {
          id: uuidv4(),
          username: email,
          email: email,
          displayName: displayName,
          microsoftId: microsoftId,
          role: 'user',
          createdAt: new Date().toISOString(),
        };
        users.push(user);
        writeUsers(users);
      } else {
        return res.redirect('/login.html?error=' + encodeURIComponent('Kein Zugang. Ihr Microsoft-Konto ist nicht für diese Anwendung freigeschaltet. Bitte kontaktieren Sie den Administrator.'));
      }
    } else {
      // Update microsoftId if not set yet
      if (!user.microsoftId) {
        user.microsoftId = microsoftId;
        writeUsers(users);
      }
    }

    req.session.user = { id: user.id, username: user.username, displayName: user.displayName || displayName, role: user.role };
    res.redirect('/');
  } catch (err) {
    res.redirect('/login.html?error=' + encodeURIComponent(err.message));
  }
});

// --- Logout ---

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('3cx_session');
    res.json({ success: true });
  });
});

// --- Protected static files ---

app.use((req, res, next) => {
  // Allow public assets
  if (req.path === '/login.html' || req.path.startsWith('/css/login.css')) {
    return next();
  }

  // API routes are handled by their own middleware
  if (req.path.startsWith('/api/')) {
    return next();
  }

  // All other static files require auth
  if (!req.session || !req.session.user) {
    return res.redirect('/login.html');
  }

  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// --- Config helpers ---

function readConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return null;
  }
}

function writeConfig(config) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// --- HTTP helper to call 3CX API ---

function apiRequest(method, urlString, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const transport = url.protocol === 'https:' ? https : http;

    const options = {
      method,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      headers: { ...headers },
    };

    if (body) {
      const data = typeof body === 'string' ? body : JSON.stringify(body);
      if (!options.headers['Content-Type']) {
        options.headers['Content-Type'] = 'application/json';
      }
      options.headers['Content-Length'] = Buffer.byteLength(data);
    }

    const req = transport.request(options, (res) => {
      let responseBody = '';
      res.on('data', (chunk) => { responseBody += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, body: responseBody });
      });
    });

    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(new Error('Request timeout')); });

    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

// --- Token management ---

let cachedToken = null;
let tokenExpiry = 0;

async function getAccessToken(config) {
  if (cachedToken && Date.now() < tokenExpiry) {
    return cachedToken;
  }

  const tokenUrl = `${config.fqdn}/connect/token`;
  const formBody = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: config.clientId,
    client_secret: config.clientSecret,
  }).toString();

  const res = await apiRequest('POST', tokenUrl, {
    'Content-Type': 'application/x-www-form-urlencoded',
  }, formBody);

  if (res.status !== 200) {
    cachedToken = null;
    tokenExpiry = 0;
    const detail = res.body ? ` – ${res.body}` : '';
    throw new Error(`Token-Anfrage fehlgeschlagen (HTTP ${res.status})${detail}`);
  }

  const data = JSON.parse(res.body);
  cachedToken = data.access_token;
  tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  return cachedToken;
}

// --- API Routes: Config ---

app.get('/api/config', requireAuth, (_req, res) => {
  const config = readConfig();
  if (!config) return res.json({ configured: false });
  res.json({
    configured: true,
    fqdn: config.fqdn,
    clientId: config.clientId,
    hasSecret: !!config.clientSecret,
  });
});

app.post('/api/config', requireAdmin, (req, res) => {
  const { fqdn, clientId, clientSecret } = req.body;

  if (!fqdn || !clientId || !clientSecret) {
    return res.status(400).json({ error: 'Alle Felder sind erforderlich.' });
  }

  let normalizedFqdn = fqdn.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(normalizedFqdn)) {
    normalizedFqdn = 'https://' + normalizedFqdn;
  }

  writeConfig({ fqdn: normalizedFqdn, clientId, clientSecret });
  cachedToken = null;
  tokenExpiry = 0;
  res.json({ success: true });
});

app.post('/api/config/test', requireAdmin, async (_req, res) => {
  const config = readConfig();
  if (!config) return res.status(400).json({ error: 'Keine Konfiguration vorhanden.' });

  try {
    await getAccessToken(config);
    res.json({ success: true, message: 'Verbindung erfolgreich! Token erhalten.' });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// --- API Routes: Microsoft Auth Config (admin only) ---

app.get('/api/config/microsoft', requireAdmin, (_req, res) => {
  const authConfig = readAuthConfig();
  const ms = authConfig.microsoft || {};
  res.json({
    tenantId: ms.tenantId || '',
    clientId: ms.clientId || '',
    hasSecret: !!ms.clientSecret,
    allowAutoProvision: ms.allowAutoProvision || false,
  });
});

app.post('/api/config/microsoft', requireAdmin, (req, res) => {
  const { tenantId, clientId, clientSecret, allowAutoProvision } = req.body;
  const authConfig = readAuthConfig();

  authConfig.microsoft = {
    tenantId: (tenantId || '').trim(),
    clientId: (clientId || '').trim(),
    clientSecret: clientSecret ? clientSecret.trim() : (authConfig.microsoft && authConfig.microsoft.clientSecret) || '',
    allowAutoProvision: !!allowAutoProvision,
  };

  writeAuthConfig(authConfig);
  res.json({ success: true });
});

// --- API Routes: User Management (admin only) ---

app.get('/api/users', requireAdmin, (_req, res) => {
  const users = readUsers().map(u => ({
    id: u.id,
    username: u.username,
    displayName: u.displayName,
    email: u.email || '',
    role: u.role,
    microsoftId: u.microsoftId ? true : false,
    createdAt: u.createdAt,
  }));
  res.json(users);
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, password, displayName, email, role } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Benutzername ist erforderlich.' });
  }

  const users = readUsers();
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(400).json({ error: 'Benutzername bereits vergeben.' });
  }

  const user = {
    id: uuidv4(),
    username: username.trim(),
    displayName: (displayName || username).trim(),
    email: (email || '').trim(),
    role: role === 'admin' ? 'admin' : 'user',
    createdAt: new Date().toISOString(),
  };

  // Password is optional if user will only use Microsoft login
  if (password) {
    if (password.length < 8) {
      return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen lang sein.' });
    }
    user.passwordHash = await bcrypt.hash(password, 12);
  }

  users.push(user);
  writeUsers(users);

  res.status(201).json({
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    email: user.email,
    role: user.role,
  });
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const users = readUsers();
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Benutzer nicht gefunden.' });

  const { displayName, email, role, password } = req.body;

  if (displayName !== undefined) users[idx].displayName = displayName.trim();
  if (email !== undefined) users[idx].email = email.trim();
  if (role !== undefined) {
    // Prevent removing the last admin
    if (users[idx].role === 'admin' && role !== 'admin') {
      const adminCount = users.filter(u => u.role === 'admin').length;
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Es muss mindestens ein Administrator existieren.' });
      }
    }
    users[idx].role = role === 'admin' ? 'admin' : 'user';
  }

  if (password) {
    if (password.length < 8) {
      return res.status(400).json({ error: 'Passwort muss mindestens 8 Zeichen lang sein.' });
    }
    users[idx].passwordHash = await bcrypt.hash(password, 12);
  }

  writeUsers(users);
  res.json({ success: true });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const users = readUsers();
  const user = users.find(u => u.id === req.params.id);

  if (!user) return res.status(404).json({ error: 'Benutzer nicht gefunden.' });

  // Prevent deleting the last admin
  if (user.role === 'admin') {
    const adminCount = users.filter(u => u.role === 'admin').length;
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Der letzte Administrator kann nicht gelöscht werden.' });
    }
  }

  // Prevent self-deletion
  if (req.session.user.id === user.id) {
    return res.status(400).json({ error: 'Sie können sich nicht selbst löschen.' });
  }

  writeUsers(users.filter(u => u.id !== req.params.id));
  res.json({ success: true });
});

// --- Change own password ---

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Neues Passwort muss mindestens 8 Zeichen lang sein.' });
  }

  const users = readUsers();
  const user = users.find(u => u.id === req.session.user.id);
  if (!user) return res.status(404).json({ error: 'Benutzer nicht gefunden.' });

  // If user has a password, require current password
  if (user.passwordHash) {
    if (!currentPassword) {
      return res.status(400).json({ error: 'Aktuelles Passwort erforderlich.' });
    }
    const valid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Aktuelles Passwort ist falsch.' });
    }
  }

  user.passwordHash = await bcrypt.hash(newPassword, 12);
  writeUsers(users);
  res.json({ success: true });
});

// --- API Routes: Blacklist ---

function ensureConfigured(_req, res, next) {
  const config = readConfig();
  if (!config) return res.status(400).json({ error: 'Bitte zuerst die API-Zugangsdaten konfigurieren.' });
  _req.appConfig = config;
  next();
}

app.get('/api/blacklist', requireAuth, ensureConfigured, async (req, res) => {
  try {
    const token = await getAccessToken(req.appConfig);
    const url = `${req.appConfig.fqdn}/xapi/v1/BlackListNumbers`;
    const result = await apiRequest('GET', url, { Authorization: `Bearer ${token}` });

    if (result.status === 401) {
      cachedToken = null;
      tokenExpiry = 0;
      return res.status(401).json({ error: 'Token abgelaufen. Bitte erneut versuchen.' });
    }
    if (result.status !== 200) {
      return res.status(result.status).json({ error: `3CX API Fehler: HTTP ${result.status}` });
    }

    const data = JSON.parse(result.body);
    res.json(data.value || data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/blacklist', requireAuth, ensureConfigured, async (req, res) => {
  try {
    const token = await getAccessToken(req.appConfig);
    const url = `${req.appConfig.fqdn}/xapi/v1/BlackListNumbers`;
    const result = await apiRequest('POST', url, {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    }, JSON.stringify(req.body));

    if (result.status === 401) {
      cachedToken = null;
      tokenExpiry = 0;
      return res.status(401).json({ error: 'Token abgelaufen. Bitte erneut versuchen.' });
    }
    if (result.status >= 400) {
      return res.status(result.status).json({ error: `3CX API Fehler: HTTP ${result.status} – ${result.body}` });
    }

    const data = result.body ? JSON.parse(result.body) : {};
    res.status(201).json(data);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.delete('/api/blacklist/:id', requireAuth, ensureConfigured, async (req, res) => {
  try {
    const token = await getAccessToken(req.appConfig);
    const id = encodeURIComponent(req.params.id);
    const url = `${req.appConfig.fqdn}/xapi/v1/BlackListNumbers(${id})`;
    const result = await apiRequest('DELETE', url, { Authorization: `Bearer ${token}` });

    if (result.status === 401) {
      cachedToken = null;
      tokenExpiry = 0;
      return res.status(401).json({ error: 'Token abgelaufen. Bitte erneut versuchen.' });
    }
    if (result.status >= 400) {
      return res.status(result.status).json({ error: `3CX API Fehler: HTTP ${result.status}` });
    }

    res.json({ success: true });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// --- SPA fallback ---

app.get('*', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`3CX Blacklist Management läuft auf http://localhost:${PORT}`);
});
