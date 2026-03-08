/**
 * VaultAuth - License Key Authentication Backend v2.1
 * Node.js + Express REST API
 * Uses JSONBin.io as persistent database with in-memory cache
 */

const express = require('express');
const crypto  = require('crypto');
const cors    = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'] }));

// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────
const CONFIG = {
  ADMIN_SECRET:   process.env.ADMIN_SECRET   || 'CHANGE_THIS_ADMIN_SECRET_IN_PRODUCTION',
  APP_SECRET:     process.env.APP_SECRET     || 'CHANGE_THIS_APP_SECRET_32CHARS_MIN',
  PORT:           process.env.PORT,
  JSONBIN_BIN_ID: process.env.JSONBIN_BIN_ID,
  JSONBIN_KEY:    process.env.JSONBIN_KEY,
};

const JSONBIN_URL = `https://api.jsonbin.io/v3/b/${CONFIG.JSONBIN_BIN_ID}`;

// ─────────────────────────────────────────────
//  JSONBIN DATABASE  (with in-memory cache)
//  Cache prevents rate-limit failures from
//  wiping keys by never saving empty data.
// ─────────────────────────────────────────────
let _dbCache = null;

async function loadDB() {
  try {
    const res  = await fetch(JSONBIN_URL + '/latest', {
      headers: { 'X-Access-Key': CONFIG.JSONBIN_KEY }
    });
    const data = await res.json();

    if (data.record && data.record.licenses) {
      _dbCache = data.record;
      return _dbCache;
    }

    // Bad / rate-limited response — use cache if available
    if (_dbCache) {
      console.warn('loadDB: bad response from JSONBin, serving from cache');
      return _dbCache;
    }

    return { licenses: {}, activations: {}, blacklist: [] };
  } catch (e) {
    console.error('loadDB error:', e.message);
    if (_dbCache) return _dbCache;
    return { licenses: {}, activations: {}, blacklist: [] };
  }
}

async function saveDB(db) {
  try {
    // Safety guard: never overwrite JSONBin with empty/invalid data
    if (!db || !db.licenses || typeof db.licenses !== 'object') {
      console.error('saveDB: refusing to save empty or invalid db object');
      return;
    }

    // Update cache first so subsequent reads are instant
    _dbCache = db;

    await fetch(JSONBIN_URL, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Access-Key': CONFIG.JSONBIN_KEY
      },
      body: JSON.stringify(db)
    });
  } catch (e) {
    console.error('saveDB error:', e.message);
  }
}

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function generateKey(prefix = 'VAULT') {
  const segs = [];
  for (let i = 0; i < 4; i++)
    segs.push(crypto.randomBytes(3).toString('hex').toUpperCase());
  return `${prefix}-${segs.join('-')}`;
}

function hmacSign(data) {
  return crypto.createHmac('sha256', CONFIG.APP_SECRET).update(data).digest('hex');
}

function hashHWID(hwid) {
  return crypto.createHash('sha256').update(hwid + CONFIG.APP_SECRET).digest('hex');
}

function nowISO()         { return new Date().toISOString(); }
function daysFromNow(d)   { const x = new Date(); x.setDate(x.getDate() + d); return x.toISOString(); }
function isExpired(lic)   { if (!lic.expiresAt) return false; return new Date() > new Date(lic.expiresAt); }

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.adminSecret;
  if (secret !== CONFIG.ADMIN_SECRET)
    return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
}

// ─────────────────────────────────────────────
//  RATE LIMITING
// ─────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  message: { success: false, message: 'Too many requests, slow down.' }
});

// ─────────────────────────────────────────────
//  /api/verify  — PRIMARY C++ ENDPOINT
//  Auto-binds HWID on first use.
// ─────────────────────────────────────────────
app.post('/api/verify', authLimiter, async (req, res) => {
  const { key, hwid, username, appVersion } = req.body;
  if (!key || !hwid)
    return res.status(400).json({ success: false, message: 'Missing key or hwid.' });

  const db      = await loadDB();
  const license = db.licenses[key];

  if (!license)                    return res.json({ success: false, message: 'Invalid license key.' });
  if (db.blacklist.includes(key))  return res.json({ success: false, message: 'This license key has been banned.' });
  if (isExpired(license))          return res.json({ success: false, message: 'License key has expired.' });

  const hwidHash = hashHWID(hwid);

  if (!license.hwidHash) {
    // First use — bind to this machine
    license.hwidHash    = hwidHash;
    license.username    = username || 'Unknown-PC';
    license.activatedAt = nowISO();
    console.log(`[VaultAuth] Key bound: ${key} -> ${license.username}`);
  } else if (license.hwidHash !== hwidHash) {
    return res.json({
      success: false,
      message: 'This key is already activated on another machine. Contact support to reset.'
    });
  }

  license.lastSeen   = nowISO();
  license.username   = username   || license.username;
  license.appVersion = appVersion || license.appVersion || 'unknown';

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({
    event: 'verify', timestamp: nowISO(),
    username: license.username, appVersion: license.appVersion,
  });

  await saveDB(db);

  const sessionPayload = `${key}:${hwidHash}:${Date.now()}`;
  const sessionToken   = hmacSign(sessionPayload);

  return res.json({
    success: true, message: 'License verified.',
    data: {
      username:    license.username,
      plan:        license.plan || 'standard',
      expiresAt:   license.expiresAt   || null,
      activatedAt: license.activatedAt || null,
      sessionToken, sessionPayload,
    }
  });
});

// ─────────────────────────────────────────────
//  /api/validate  — HEARTBEAT
// ─────────────────────────────────────────────
app.post('/api/validate', authLimiter, async (req, res) => {
  const { key, sessionPayload, sessionToken } = req.body;
  if (!key || !sessionPayload || !sessionToken)
    return res.status(400).json({ success: false, message: 'Missing fields.' });

  try {
    const expected = hmacSign(sessionPayload);
    if (!crypto.timingSafeEqual(Buffer.from(sessionToken), Buffer.from(expected)))
      return res.json({ success: false, message: 'Invalid session token.' });
  } catch { return res.json({ success: false, message: 'Token error.' }); }

  const db      = await loadDB();
  const license = db.licenses[key];

  if (!license)                   return res.json({ success: false, message: 'Invalid license.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License banned.' });
  if (isExpired(license))         return res.json({ success: false, message: 'License expired.' });

  license.lastSeen = nowISO();
  await saveDB(db);

  return res.json({
    success: true, message: 'Valid.',
    data: { username: license.username, plan: license.plan || 'standard', expiresAt: license.expiresAt || null }
  });
});

// ─────────────────────────────────────────────
//  /api/activate  — WEB REGISTRATION PAGE
// ─────────────────────────────────────────────
app.post('/api/activate', authLimiter, async (req, res) => {
  const { key, username, appVersion } = req.body;
  if (!key || !username)
    return res.status(400).json({ success: false, message: 'Missing required fields.' });

  const db      = await loadDB();
  const license = db.licenses[key];

  if (!license)                   return res.json({ success: false, message: 'Invalid license key.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License key has been banned.' });
  if (isExpired(license))         return res.json({ success: false, message: 'License key has expired.' });

  license.username    = username;
  license.activatedAt = license.activatedAt || nowISO();
  license.lastSeen    = nowISO();
  license.appVersion  = appVersion || 'web';

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'web-activate', timestamp: nowISO(), username });

  await saveDB(db);

  const sessionPayload = `${key}:${Date.now()}`;
  const sessionToken   = hmacSign(sessionPayload);

  return res.json({
    success: true, message: 'License activated successfully.',
    data: {
      username:    license.username,
      plan:        license.plan || 'standard',
      expiresAt:   license.expiresAt   || null,
      activatedAt: license.activatedAt || null,
      sessionToken, sessionPayload,
    }
  });
});

// ─────────────────────────────────────────────
//  ADMIN ENDPOINTS
// ─────────────────────────────────────────────
app.post('/api/admin/generate', adminAuth, async (req, res) => {
  const { count = 1, plan = 'standard', durationDays = null, prefix = 'VAULT', allowMultiple = false, note = '' } = req.body;
  const db   = await loadDB();
  const keys = [];
  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = generateKey(prefix);
    db.licenses[key] = {
      plan, createdAt: nowISO(),
      expiresAt: durationDays ? daysFromNow(durationDays) : null,
      activatedAt: null, hwidHash: null, username: null,
      allowMultiple, note, lastSeen: null, appVersion: null,
    };
    keys.push(key);
  }
  await saveDB(db);
  return res.json({ success: true, keys });
});

app.get('/api/admin/licenses', adminAuth, async (req, res) => {
  const db   = await loadDB();
  const list = Object.entries(db.licenses).map(([key, data]) => ({
    key, ...data, expired: isExpired(data), banned: db.blacklist.includes(key),
  }));
  return res.json({ success: true, licenses: list, total: list.length });
});

app.get('/api/admin/license/:key', adminAuth, async (req, res) => {
  const db      = await loadDB();
  const license = db.licenses[req.params.key];
  if (!license) return res.json({ success: false, message: 'Not found.' });
  return res.json({
    success: true,
    license: { key: req.params.key, ...license },
    history: db.activations[req.params.key] || [],
    banned:  db.blacklist.includes(req.params.key),
    expired: isExpired(license),
  });
});

app.post('/api/admin/reset/:key', adminAuth, async (req, res) => {
  const db      = await loadDB();
  const license = db.licenses[req.params.key];
  if (!license) return res.json({ success: false, message: 'Not found.' });
  license.hwidHash = null;
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

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const db       = await loadDB();
  const licenses = Object.values(db.licenses);
  return res.json({
    success: true,
    stats: {
      total:     licenses.length,
      activated: licenses.filter(l => l.hwidHash).length,
      expired:   licenses.filter(l => isExpired(l)).length,
      banned:    db.blacklist.length,
      lifetime:  licenses.filter(l => !l.expiresAt).length,
    }
  });
});

app.listen(CONFIG.PORT, '0.0.0.0', () => {
  console.log(`[VaultAuth] Server v2.1 running on port ${CONFIG.PORT}`);
  console.log(`[VaultAuth] JSONBin ID: ${CONFIG.JSONBIN_BIN_ID}`);
});
