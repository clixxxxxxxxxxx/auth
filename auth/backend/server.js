/**
 * VaultAuth - License Key Authentication Backend v2.3
 * Adds: Applications system (appId + appSecret per project)
 * C++ must pass appId + appSecret on every API call
 */

const express   = require('express');
const crypto    = require('crypto');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'] }));

const CONFIG = {
  ADMIN_SECRET:   process.env.ADMIN_SECRET   || 'CHANGE_THIS_ADMIN_SECRET_IN_PRODUCTION',
  APP_SECRET:     process.env.APP_SECRET     || 'CHANGE_THIS_APP_SECRET_32CHARS_MIN',
  PORT:           process.env.PORT,
  JSONBIN_BIN_ID: process.env.JSONBIN_BIN_ID,
  JSONBIN_KEY:    process.env.JSONBIN_KEY,
};

const JSONBIN_URL = `https://api.jsonbin.io/v3/b/${CONFIG.JSONBIN_BIN_ID}`;

// ─────────────────────────────────────────────
//  DB with in-memory cache
// ─────────────────────────────────────────────
let _dbCache = null;

async function loadDB() {
  try {
    const res  = await fetch(JSONBIN_URL + '/latest', { headers: { 'X-Access-Key': CONFIG.JSONBIN_KEY } });
    const data = await res.json();
    if (data.record && data.record.licenses) {
      if (!data.record.bannedHWIDs)  data.record.bannedHWIDs  = [];
      if (!data.record.bannedIPs)    data.record.bannedIPs    = [];
      if (!data.record.applications) data.record.applications = {};
      _dbCache = data.record;
      return _dbCache;
    }
    if (_dbCache) { console.warn('loadDB: using cache'); return _dbCache; }
    return { licenses: {}, activations: {}, blacklist: [], bannedHWIDs: [], bannedIPs: [], applications: {} };
  } catch (e) {
    console.error('loadDB error:', e.message);
    if (_dbCache) return _dbCache;
    return { licenses: {}, activations: {}, blacklist: [], bannedHWIDs: [], bannedIPs: [], applications: {} };
  }
}

async function saveDB(db) {
  try {
    if (!db || !db.licenses || typeof db.licenses !== 'object') {
      console.error('saveDB: refusing to save invalid db'); return;
    }
    _dbCache = db;
    await fetch(JSONBIN_URL, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Access-Key': CONFIG.JSONBIN_KEY },
      body: JSON.stringify(db)
    });
  } catch (e) { console.error('saveDB error:', e.message); }
}

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function generateKey(prefix = 'VAULT') {
  const segs = [];
  for (let i = 0; i < 4; i++) segs.push(crypto.randomBytes(3).toString('hex').toUpperCase());
  return `${prefix}-${segs.join('-')}`;
}
function genAppId()     { return 'APP-' + crypto.randomBytes(4).toString('hex').toUpperCase(); }
function genAppSecret() { return crypto.randomBytes(24).toString('hex'); }
function hmacSign(data) { return crypto.createHmac('sha256', CONFIG.APP_SECRET).update(data).digest('hex'); }
function hashHWID(hwid) { return crypto.createHash('sha256').update(hwid + CONFIG.APP_SECRET).digest('hex'); }
function nowISO()       { return new Date().toISOString(); }
function daysFromNow(d) { const x = new Date(); x.setDate(x.getDate() + d); return x.toISOString(); }
function isExpired(l)   { if (!l.expiresAt) return false; return new Date() > new Date(l.expiresAt); }
function getIP(req)     { return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown'; }

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.adminSecret;
  if (secret !== CONFIG.ADMIN_SECRET) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
}

// Application auth middleware — validates appId + appSecret on public endpoints
async function appAuth(req, res, next) {
  const appId     = req.body?.appId     || req.headers['x-app-id'];
  const appSecret = req.body?.appSecret || req.headers['x-app-secret'];
  if (!appId || !appSecret) return res.status(401).json({ success: false, message: 'Missing application credentials (appId, appSecret).' });
  const db  = await loadDB();
  const app = db.applications[appId];
  if (!app)                  return res.status(401).json({ success: false, message: 'Invalid application ID.' });
  if (app.secret !== appSecret) return res.status(401).json({ success: false, message: 'Invalid application secret.' });
  if (app.disabled)          return res.status(403).json({ success: false, message: 'Application is disabled.' });
  req.vaultApp = app;
  req.vaultAppId = appId;
  next();
}

const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { success: false, message: 'Too many requests.' } });

// ─────────────────────────────────────────────
//  /api/verify — C++ PRIMARY ENDPOINT
//  Requires: appId, appSecret, key, hwid
// ─────────────────────────────────────────────
app.post('/api/verify', authLimiter, appAuth, async (req, res) => {
  const { key, hwid, username, appVersion } = req.body;
  if (!key || !hwid) return res.status(400).json({ success: false, message: 'Missing key or hwid.' });

  const ip       = getIP(req);
  const db       = await loadDB();
  const license  = db.licenses[key];
  const hwidHash = hashHWID(hwid);

  if (db.bannedIPs.includes(ip))       return res.json({ success: false, message: 'Your IP address has been banned.' });
  if (db.bannedHWIDs.includes(hwidHash)) return res.json({ success: false, message: 'Your machine has been banned.' });
  if (!license)                         return res.json({ success: false, message: 'Invalid license key.' });
  if (db.blacklist.includes(key))       return res.json({ success: false, message: 'This license key has been banned.' });
  if (isExpired(license))               return res.json({ success: false, message: 'License key has expired.' });

  // Enforce app scoping — key must belong to this app (or be unscoped legacy key)
  if (license.appId && license.appId !== req.vaultAppId) {
    return res.json({ success: false, message: 'License key does not belong to this application.' });
  }

  if (!license.hwidHash) {
    license.hwidHash    = hwidHash;
    license.hwidRaw     = hwid;
    license.username    = username || 'Unknown-PC';
    license.activatedAt = nowISO();
    license.ip          = ip;
    console.log(`[VaultAuth] Bound: ${key} -> ${license.username} (${ip}) [${req.vaultApp.name}]`);
  } else if (license.hwidHash !== hwidHash) {
    return res.json({ success: false, message: 'Key already activated on another machine. Contact support to reset.' });
  }

  license.lastSeen   = nowISO();
  license.lastIP     = ip;
  license.username   = username   || license.username;
  license.appVersion = appVersion || license.appVersion || 'unknown';

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'verify', timestamp: nowISO(), username: license.username, appVersion: license.appVersion, ip });

  await saveDB(db);

  const sessionPayload = `${key}:${hwidHash}:${Date.now()}`;
  const sessionToken   = hmacSign(sessionPayload);

  return res.json({
    success: true, message: 'License verified.',
    data: {
      username: license.username, plan: license.plan || 'standard',
      expiresAt: license.expiresAt || null, activatedAt: license.activatedAt,
      appName: req.vaultApp.name,
      sessionToken, sessionPayload,
    }
  });
});

// ─────────────────────────────────────────────
//  /api/validate — HEARTBEAT
// ─────────────────────────────────────────────
app.post('/api/validate', authLimiter, appAuth, async (req, res) => {
  const { key, sessionPayload, sessionToken } = req.body;
  if (!key || !sessionPayload || !sessionToken) return res.status(400).json({ success: false, message: 'Missing fields.' });

  try {
    const expected = hmacSign(sessionPayload);
    if (!crypto.timingSafeEqual(Buffer.from(sessionToken), Buffer.from(expected)))
      return res.json({ success: false, message: 'Invalid session token.' });
  } catch { return res.json({ success: false, message: 'Token error.' }); }

  const ip  = getIP(req);
  const db  = await loadDB();
  const lic = db.licenses[key];

  if (!lic)                             return res.json({ success: false, message: 'Invalid license.' });
  if (db.blacklist.includes(key))       return res.json({ success: false, message: 'License banned.' });
  if (isExpired(lic))                   return res.json({ success: false, message: 'License expired.' });
  if (db.bannedIPs.includes(ip))        return res.json({ success: false, message: 'IP banned.' });
  if (lic.hwidHash && db.bannedHWIDs.includes(lic.hwidHash)) return res.json({ success: false, message: 'Machine banned.' });

  lic.lastSeen = nowISO();
  lic.lastIP   = ip;
  await saveDB(db);

  return res.json({ success: true, message: 'Valid.', data: { username: lic.username, plan: lic.plan || 'standard', expiresAt: lic.expiresAt || null } });
});

// ─────────────────────────────────────────────
//  /api/activate — WEB REGISTRATION (no app auth needed)
// ─────────────────────────────────────────────
app.post('/api/activate', authLimiter, async (req, res) => {
  const { key, username, appVersion } = req.body;
  if (!key || !username) return res.status(400).json({ success: false, message: 'Missing required fields.' });

  const db  = await loadDB();
  const lic = db.licenses[key];

  if (!lic)                    return res.json({ success: false, message: 'Invalid license key.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License key has been banned.' });
  if (isExpired(lic))          return res.json({ success: false, message: 'License key has expired.' });

  lic.username    = username;
  lic.activatedAt = lic.activatedAt || nowISO();
  lic.lastSeen    = nowISO();
  lic.appVersion  = appVersion || 'web';

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'web-activate', timestamp: nowISO(), username });
  await saveDB(db);

  const sessionPayload = `${key}:${Date.now()}`;
  const sessionToken   = hmacSign(sessionPayload);

  return res.json({
    success: true, message: 'License activated successfully.',
    data: { username: lic.username, plan: lic.plan || 'standard', expiresAt: lic.expiresAt || null, activatedAt: lic.activatedAt, sessionToken, sessionPayload }
  });
});

// ─────────────────────────────────────────────
//  ADMIN — APPLICATIONS
// ─────────────────────────────────────────────
app.post('/api/admin/apps/create', adminAuth, async (req, res) => {
  const { name, version = '1.0.0', description = '' } = req.body;
  if (!name) return res.json({ success: false, message: 'App name required.' });
  const db     = await loadDB();
  const appId  = genAppId();
  const secret = genAppSecret();
  db.applications[appId] = {
    name, version, description,
    secret,
    createdAt: nowISO(),
    disabled: false,
    keyCount: 0,
  };
  await saveDB(db);
  return res.json({ success: true, appId, secret, app: db.applications[appId] });
});

app.get('/api/admin/apps', adminAuth, async (req, res) => {
  const db   = await loadDB();
  const list = Object.entries(db.applications || {}).map(([id, data]) => ({ id, ...data }));
  return res.json({ success: true, apps: list });
});

app.post('/api/admin/apps/toggle/:id', adminAuth, async (req, res) => {
  const db  = await loadDB();
  const a   = db.applications[req.params.id];
  if (!a) return res.json({ success: false, message: 'App not found.' });
  a.disabled = !a.disabled;
  await saveDB(db);
  return res.json({ success: true, disabled: a.disabled, message: a.disabled ? 'Application disabled.' : 'Application enabled.' });
});

app.post('/api/admin/apps/regen/:id', adminAuth, async (req, res) => {
  const db = await loadDB();
  const a  = db.applications[req.params.id];
  if (!a) return res.json({ success: false, message: 'App not found.' });
  a.secret = genAppSecret();
  await saveDB(db);
  return res.json({ success: true, secret: a.secret, message: 'Secret regenerated.' });
});

app.delete('/api/admin/apps/:id', adminAuth, async (req, res) => {
  const db = await loadDB();
  if (!db.applications[req.params.id]) return res.json({ success: false, message: 'App not found.' });
  delete db.applications[req.params.id];
  await saveDB(db);
  return res.json({ success: true, message: 'Application deleted.' });
});

// ─────────────────────────────────────────────
//  ADMIN — KEYS
// ─────────────────────────────────────────────
app.post('/api/admin/generate', adminAuth, async (req, res) => {
  const { count = 1, plan = 'standard', durationDays = null, prefix = 'VAULT', allowMultiple = false, note = '', appId = null } = req.body;
  const db = await loadDB(); const keys = [];
  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = generateKey(prefix);
    db.licenses[key] = {
      plan, createdAt: nowISO(), expiresAt: durationDays ? daysFromNow(durationDays) : null,
      activatedAt: null, hwidHash: null, hwidRaw: null, username: null,
      allowMultiple, note, lastSeen: null, appVersion: null, ip: null, lastIP: null,
      appId: appId || null,
    };
    keys.push(key);
    // Update app key count
    if (appId && db.applications[appId]) db.applications[appId].keyCount = (db.applications[appId].keyCount || 0) + 1;
  }
  await saveDB(db);
  return res.json({ success: true, keys });
});

app.get('/api/admin/licenses', adminAuth, async (req, res) => {
  const db   = await loadDB();
  const list = Object.entries(db.licenses).map(([key, data]) => ({
    key, ...data, expired: isExpired(data), banned: db.blacklist.includes(key),
    hwidBanned: data.hwidHash ? db.bannedHWIDs.includes(data.hwidHash) : false,
    ipBanned:   data.lastIP   ? db.bannedIPs.includes(data.lastIP)    : false,
    appName:    data.appId && db.applications[data.appId] ? db.applications[data.appId].name : null,
  }));
  return res.json({ success: true, licenses: list, total: list.length });
});

app.get('/api/admin/license/:key', adminAuth, async (req, res) => {
  const db  = await loadDB();
  const lic = db.licenses[req.params.key];
  if (!lic) return res.json({ success: false, message: 'Not found.' });
  return res.json({
    success: true,
    license: { key: req.params.key, ...lic, appName: lic.appId && db.applications[lic.appId] ? db.applications[lic.appId].name : null },
    history: db.activations[req.params.key] || [],
    banned:     db.blacklist.includes(req.params.key),
    hwidBanned: lic.hwidHash ? db.bannedHWIDs.includes(lic.hwidHash) : false,
    ipBanned:   lic.lastIP   ? db.bannedIPs.includes(lic.lastIP)    : false,
    expired:    isExpired(lic),
  });
});

app.post('/api/admin/reset/:key', adminAuth, async (req, res) => {
  const db  = await loadDB();
  const lic = db.licenses[req.params.key];
  if (!lic) return res.json({ success: false, message: 'Not found.' });
  lic.hwidHash = null; lic.hwidRaw = null;
  if (!db.activations[req.params.key]) db.activations[req.params.key] = [];
  db.activations[req.params.key].push({ event: 'admin_reset', timestamp: nowISO() });
  await saveDB(db);
  return res.json({ success: true, message: 'Machine binding cleared.' });
});

app.post('/api/admin/ban/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  if (!db.licenses[req.params.key]) return res.json({ success: false, message: 'Not found.' });
  if (!db.blacklist.includes(req.params.key)) db.blacklist.push(req.params.key);
  await saveDB(db);
  return res.json({ success: true, message: 'Key banned.' });
});

app.post('/api/admin/unban/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  db.blacklist = db.blacklist.filter(k => k !== req.params.key);
  await saveDB(db);
  return res.json({ success: true, message: 'Key unbanned.' });
});

app.delete('/api/admin/license/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  if (!db.licenses[req.params.key]) return res.json({ success: false, message: 'Not found.' });
  delete db.licenses[req.params.key];
  delete db.activations[req.params.key];
  await saveDB(db);
  return res.json({ success: true, message: 'License deleted.' });
});

// ─────────────────────────────────────────────
//  ADMIN — HWID / IP BANS
// ─────────────────────────────────────────────
app.post('/api/admin/ban-hwid', adminAuth, async (req, res) => {
  const { hwidHash, keyToBanFrom } = req.body;
  const db = await loadDB();
  let hash = hwidHash;
  if (!hash && keyToBanFrom && db.licenses[keyToBanFrom]) hash = db.licenses[keyToBanFrom].hwidHash;
  if (!hash) return res.json({ success: false, message: 'No HWID hash provided.' });
  if (!db.bannedHWIDs.includes(hash)) db.bannedHWIDs.push(hash);
  await saveDB(db);
  return res.json({ success: true, message: 'HWID banned.' });
});

app.post('/api/admin/unban-hwid', adminAuth, async (req, res) => {
  const { hwidHash } = req.body;
  const db = await loadDB();
  db.bannedHWIDs = db.bannedHWIDs.filter(h => h !== hwidHash);
  await saveDB(db);
  return res.json({ success: true, message: 'HWID unbanned.' });
});

app.post('/api/admin/ban-ip', adminAuth, async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ success: false, message: 'No IP provided.' });
  const db = await loadDB();
  if (!db.bannedIPs.includes(ip)) db.bannedIPs.push(ip);
  await saveDB(db);
  return res.json({ success: true, message: `IP ${ip} banned.` });
});

app.post('/api/admin/unban-ip', adminAuth, async (req, res) => {
  const { ip } = req.body;
  const db = await loadDB();
  db.bannedIPs = db.bannedIPs.filter(i => i !== ip);
  await saveDB(db);
  return res.json({ success: true, message: `IP ${ip} unbanned.` });
});

app.get('/api/admin/banlists', adminAuth, async (req, res) => {
  const db = await loadDB();
  return res.json({ success: true, bannedHWIDs: db.bannedHWIDs || [], bannedIPs: db.bannedIPs || [], blacklist: db.blacklist || [] });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const db       = await loadDB();
  const licenses = Object.values(db.licenses);
  return res.json({
    success: true,
    stats: {
      total:       licenses.length,
      activated:   licenses.filter(l => l.hwidHash).length,
      expired:     licenses.filter(l => isExpired(l)).length,
      banned:      db.blacklist.length,
      lifetime:    licenses.filter(l => !l.expiresAt).length,
      bannedHWIDs: (db.bannedHWIDs || []).length,
      bannedIPs:   (db.bannedIPs   || []).length,
      apps:        Object.keys(db.applications || {}).length,
    }
  });
});

app.listen(CONFIG.PORT, '0.0.0.0', () => {
  console.log(`[VaultAuth] Server v2.3 running on port ${CONFIG.PORT}`);
});
