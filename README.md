# 3CX Blacklist Management

Web-basierte Verwaltung der 3CX Rufnummern-Blacklist über die 3CX xAPI.
Die App bietet lokale Benutzerkonten (mit Rollen) sowie optional Microsoft-Login (Azure AD)
und pflegt die Blacklist-Einträge (`BlackListNumbers`: nur `Number` und `Description`) direkt
über die xAPI.

## Technik

- Node.js 22, Express 4
- Sessions über `express-session`
- Passwort-Hashing mit `bcryptjs`
- ID-Token-Prüfung (Microsoft-Login) via `jose` (JWKS)

## Einrichtung (Entwicklung)

```bash
git clone <repo-url>
cd 3cx-blacklist-dashboard
npm install
npm start
```

Die App ist danach unter `http://localhost:5000` erreichbar (Standard-Port 5000,
überschreibbar über die Umgebungsvariable `PORT`).

### Erst-Einrichtung des Admin-Kontos

Beim ersten Aufruf (solange noch keine Benutzer existieren) wird eine Ersteinrichtung
angeboten: Der erste angelegte Benutzer erhält automatisch die Rolle **admin**. Danach ist
die Ersteinrichtung gesperrt.

### 3CX xAPI konfigurieren

Als Admin unter **Einstellungen**:

- **FQDN** der 3CX-Instanz (z. B. `https://meine-firma.3cx.de`)
- **Client ID** und **Client Secret** eines 3CX-API-Clients (Client-Credentials-Flow)

Die Zugangsdaten werden serverseitig in `data/config.json` (Modus `0600`) gespeichert und nie
an den Browser gesendet. Mit „Verbindung testen“ lässt sich die Token-Anfrage prüfen.

### Microsoft-Login (optional)

Als Admin unter **Einstellungen → Microsoft Login**:

- Tenant ID, Client ID (Application ID) und Client Secret einer Azure-App-Registrierung
- Redirect-URI der App-Registrierung: `<Basis-URL>/api/auth/microsoft/callback`
- „Automatische Benutzeranlage“ vergibt Neu-Anmeldern die Rolle `user`.

Bestehende lokale Admin-Konten werden **nicht** automatisch allein per E-Mail-Treffer mit einem
Microsoft-Konto verknüpft – die Verknüpfung muss bewusst hergestellt werden.

## Betrieb

- Läuft als systemd-Dienst `3cx-blacklist.service` auf Port 5000
  (`Environment=PORT=5000`, `Restart=on-failure`), ausgeführt als `azureuser`.
- Datenverzeichnis: `data/`
  - `config.json` – 3CX-API-Zugangsdaten (Modus `0600`)
  - `auth-config.json` – Microsoft-Login-Konfiguration (Modus `0600`)
  - `users.json` – Benutzerkonten inkl. Passwort-Hashes (Modus `0600`)
  - `.session-secret` – persistentes Session-Secret (Modus `0600`)
- Backup: das komplette `data/`-Verzeichnis sichern (enthält Secrets und Benutzer).

## Sicherheitshinweise

- Secrets (`config.json`, `auth-config.json`, `users.json`, `.session-secret`) liegen mit
  Datei-Modus `0600` im `data/`-Verzeichnis. Verzeichnis nicht weltlesbar halten.
- Die App terminiert **kein** TLS selbst. Für den Betrieb über das Internet sollte sie hinter
  einen Reverse-Proxy mit TLS gelegt werden; anschließend `app.set('trust proxy', 1)` setzen
  und das Session-Cookie auf `secure: true` umstellen. (Aktuell bewusst deaktiviert, da der
  Zugriff über HTTP erfolgt.)
- Login-Versuche sind ratenbegrenzt; fehlgeschlagene Versuche werden nur für existierende
  Konten gezählt (Schutz gegen gezieltes Aussperren fremder Konten).
- Die `.env`/`.env.example` im Repo sind derzeit ohne Wirkung (kein `dotenv`); die reale
  Konfiguration kommt aus der systemd-Unit.
