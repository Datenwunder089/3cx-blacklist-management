const express = require('express');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 3000;
const CONFIG_PATH = path.join(__dirname, 'data', 'config.json');

app.use(express.json());
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
  // Expire 60s before actual expiry for safety
  tokenExpiry = Date.now() + (data.expires_in - 60) * 1000;
  return cachedToken;
}

// --- API Routes: Config ---

app.get('/api/config', (_req, res) => {
  const config = readConfig();
  if (!config) return res.json({ configured: false });
  // Never return the secret to the frontend
  res.json({
    configured: true,
    fqdn: config.fqdn,
    clientId: config.clientId,
    hasSecret: !!config.clientSecret,
  });
});

app.post('/api/config', (req, res) => {
  const { fqdn, clientId, clientSecret } = req.body;

  if (!fqdn || !clientId || !clientSecret) {
    return res.status(400).json({ error: 'Alle Felder sind erforderlich.' });
  }

  // Normalize FQDN: ensure https:// prefix, strip trailing slash
  let normalizedFqdn = fqdn.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(normalizedFqdn)) {
    normalizedFqdn = 'https://' + normalizedFqdn;
  }

  writeConfig({ fqdn: normalizedFqdn, clientId, clientSecret });
  // Invalidate cached token
  cachedToken = null;
  tokenExpiry = 0;
  res.json({ success: true });
});

app.post('/api/config/test', async (_req, res) => {
  const config = readConfig();
  if (!config) return res.status(400).json({ error: 'Keine Konfiguration vorhanden.' });

  try {
    const token = await getAccessToken(config);
    res.json({ success: true, message: 'Verbindung erfolgreich! Token erhalten.' });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

// --- API Routes: Blacklist ---

function ensureConfigured(_req, res, next) {
  const config = readConfig();
  if (!config) return res.status(400).json({ error: 'Bitte zuerst die API-Zugangsdaten konfigurieren.' });
  _req.appConfig = config;
  next();
}

// GET blacklist
app.get('/api/blacklist', ensureConfigured, async (req, res) => {
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

// POST new blacklist entry
app.post('/api/blacklist', ensureConfigured, async (req, res) => {
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

// DELETE blacklist entry
app.delete('/api/blacklist/:id', ensureConfigured, async (req, res) => {
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

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`3CX Blacklist Management läuft auf http://localhost:${PORT}`);
});
