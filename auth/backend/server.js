/**
 * VaultAuth - License Key Authentication Backend
 * Node.js + Express REST API
 * 
 * Deploy this to any Node.js host (Railway, Render, VPS, etc.)
 * Set environment variables in .env file
 */

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors({
origin: ['https://dapper-tarsier-0a75ee.netlify.app'],
  methods: ['GET', 'POST', 'DELETE'],
}));

// ─────────────────────────────────────────────
//  CONFIG  (edit these or use environment vars)
// ─────────────────────────────────────────────
const CONFIG = {
  ADMIN_SECRET: process.env.ADMIN_SECRET || 'CHANGE_THIS_ADMIN_SECRET_IN_PRODUCTION',
  APP_SECRET:   process.env.APP_SECRET   || 'CHANGE_THIS_APP_SECRET_32CHARS_MIN',
  PORT:         process.env.PORT          || 3000,
  DATA_FILE:    process.env.DATA_FILE     || path.join(__dirname, 'data.json'),
};

// ─────────────────────────────────────────────
//  SIMPLE FILE-BASED DATABASE
//  Replace with PostgreSQL/MongoDB for scale
// ─────────────────────────────────────────────
function loadDB() {
  try {
    if (fs.existsSync(CONFIG.DATA_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG.DATA_FILE, 'utf8'));
    }
  } catch (e) {}
  return { licenses: {}, activations: {}, blacklist: [] };
}

function saveDB(db) {
  fs.writeFileSync(CONFIG.DATA_FILE, JSON.stringify(db, null, 2));
}

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function generateKey(prefix = 'VAULT') {
  const segments = [];
  for (let i = 0; i < 4; i++) {
    segments.push(crypto.randomBytes(3).toString('hex').toUpperCase());
  }
  return `${prefix}-${segments.join('-')}`;
}

function hmacSign(data) {
  return crypto.createHmac('sha256', CONFIG.APP_SECRET).update(data).digest('hex');
}

function getMachineHash(hwid) {
  return crypto.createHash('sha256').update(hwid + CONFIG.APP_SECRET).digest('hex');
}

function nowISO() { return new Date().toISOString(); }
function daysFromNow(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function isExpired(license) {
  if (!license.expiresAt) return false; // lifetime
  return new Date() > new Date(license.expiresAt);
}

function adminAuth(req, res, next) {
  const secret = req.headers['x-admin-secret'] || req.body?.adminSecret;
  if (secret !== CONFIG.ADMIN_SECRET) {
    return res.status(403).json({ success: false, message: 'Forbidden' });
  }
  next();
}

// ─────────────────────────────────────────────
//  RATE LIMITING
// ─────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  message: { success: false, message: 'Too many requests, slow down.' }
});

// ─────────────────────────────────────────────
//  PUBLIC API ENDPOINTS (called by C++ app)
// ─────────────────────────────────────────────

/**
 * POST /api/activate
 * Body: { key, hwid, username, appVersion }
 * Registers a key to a machine + username
 */
app.post('/api/activate', authLimiter, (req, res) => {
  const { key, hwid, username, appVersion } = req.body;

  if (!key || !hwid || !username) {
    return res.status(400).json({ success: false, message: 'Missing required fields.' });
  }

  const db = loadDB();
  const license = db.licenses[key];

  if (!license) {
    return res.json({ success: false, message: 'Invalid license key.' });
  }

  if (db.blacklist.includes(key)) {
    return res.json({ success: false, message: 'License key has been banned.' });
  }

  if (isExpired(license)) {
    return res.json({ success: false, message: 'License key has expired.' });
  }

  const machineHash = getMachineHash(hwid);

  // Already activated on this machine?
  if (license.machineHash && license.machineHash !== machineHash) {
    if (!license.allowMultiple) {
      return res.json({
        success: false,
        message: 'License already activated on another machine. Contact support to reset.'
      });
    }
  }

  // Activate
  license.machineHash = machineHash;
  license.username = username;
  license.activatedAt = license.activatedAt || nowISO();
  license.lastSeen = nowISO();
  license.appVersion = appVersion || 'unknown';

  // Log activation
  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({
    event: 'activate',
    timestamp: nowISO(),
    username,
    hwid: machineHash.slice(0, 12) + '...',
    appVersion
  });

  saveDB(db);

  // Build signed session token
  const sessionPayload = `${key}:${machineHash}:${Date.now()}`;
  const token = hmacSign(sessionPayload);

  return res.json({
    success: true,
    message: 'License activated successfully.',
    data: {
      username: license.username,
      plan: license.plan || 'standard',
      expiresAt: license.expiresAt || null,
      activatedAt: license.activatedAt,
      sessionToken: token,
      sessionPayload,
    }
  });
});

/**
 * POST /api/validate
 * Body: { key, hwid, sessionPayload, sessionToken }
 * Fast heartbeat check — call every few minutes from C++ app
 */
app.post('/api/validate', authLimiter, (req, res) => {
  const { key, hwid, sessionPayload, sessionToken } = req.body;

  if (!key || !hwid || !sessionPayload || !sessionToken) {
    return res.status(400).json({ success: false, message: 'Missing fields.' });
  }

  // Verify HMAC
  const expectedToken = hmacSign(sessionPayload);
  if (!crypto.timingSafeEqual(Buffer.from(sessionToken), Buffer.from(expectedToken))) {
    return res.json({ success: false, message: 'Invalid session token.' });
  }

  const db = loadDB();
  const license = db.licenses[key];

  if (!license) return res.json({ success: false, message: 'Invalid license.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License banned.' });
  if (isExpired(license)) return res.json({ success: false, message: 'License expired.' });

  const machineHash = getMachineHash(hwid);
  if (license.machineHash && license.machineHash !== machineHash) {
    return res.json({ success: false, message: 'Machine mismatch.' });
  }

  // Update last seen
  license.lastSeen = nowISO();
  saveDB(db);

  return res.json({
    success: true,
    message: 'Valid.',
    data: {
      username: license.username,
      plan: license.plan || 'standard',
      expiresAt: license.expiresAt || null,
    }
  });
});

/**
 * POST /api/deactivate
 * Body: { key, hwid, sessionPayload, sessionToken }
 * Unbinds the machine so key can be used elsewhere
 */
app.post('/api/deactivate', authLimiter, (req, res) => {
  const { key, hwid, sessionPayload, sessionToken } = req.body;

  const expectedToken = hmacSign(sessionPayload);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sessionToken), Buffer.from(expectedToken))) {
      return res.json({ success: false, message: 'Invalid session token.' });
    }
  } catch { return res.json({ success: false, message: 'Token error.' }); }

  const db = loadDB();
  const license = db.licenses[key];
  if (!license) return res.json({ success: false, message: 'Invalid license.' });

  license.machineHash = null;
  license.username = license.username; // keep username

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'deactivate', timestamp: nowISO() });

  saveDB(db);
  return res.json({ success: true, message: 'License deactivated. You may now activate on another machine.' });
});

// ─────────────────────────────────────────────
//  ADMIN API ENDPOINTS
// ─────────────────────────────────────────────

/** POST /api/admin/generate — create one or more keys */
app.post('/api/admin/generate', adminAuth, (req, res) => {
  const {
    count = 1,
    plan = 'standard',
    durationDays = null, // null = lifetime
    prefix = 'VAULT',
    allowMultiple = false,
    note = ''
  } = req.body;

  const db = loadDB();
  const keys = [];

  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = generateKey(prefix);
    db.licenses[key] = {
      plan,
      createdAt: nowISO(),
      expiresAt: durationDays ? daysFromNow(durationDays) : null,
      activatedAt: null,
      machineHash: null,
      username: null,
      allowMultiple,
      note,
      lastSeen: null,
      appVersion: null,
    };
    keys.push(key);
  }

  saveDB(db);
  return res.json({ success: true, keys });
});

/** GET /api/admin/licenses — list all licenses */
app.get('/api/admin/licenses', adminAuth, (req, res) => {
  const db = loadDB();
  const list = Object.entries(db.licenses).map(([key, data]) => ({
    key,
    ...data,
    expired: isExpired(data),
    banned: db.blacklist.includes(key),
  }));
  return res.json({ success: true, licenses: list, total: list.length });
});

/** GET /api/admin/license/:key — get single license details */
app.get('/api/admin/license/:key', adminAuth, (req, res) => {
  const db = loadDB();
  const license = db.licenses[req.params.key];
  if (!license) return res.json({ success: false, message: 'Not found.' });
  return res.json({
    success: true,
    license: { key: req.params.key, ...license },
    history: db.activations[req.params.key] || [],
    banned: db.blacklist.includes(req.params.key),
    expired: isExpired(license),
  });
});

/** POST /api/admin/reset/:key — unbind machine from key */
app.post('/api/admin/reset/:key', adminAuth, (req, res) => {
  const db = loadDB();
  const license = db.licenses[req.params.key];
  if (!license) return res.json({ success: false, message: 'Not found.' });
  license.machineHash = null;
  if (!db.activations[req.params.key]) db.activations[req.params.key] = [];
  db.activations[req.params.key].push({ event: 'admin_reset', timestamp: nowISO() });
  saveDB(db);
  return res.json({ success: true, message: 'Machine binding cleared.' });
});

/** POST /api/admin/ban/:key — ban a key */
app.post('/api/admin/ban/:key', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.licenses[req.params.key]) return res.json({ success: false, message: 'Not found.' });
  if (!db.blacklist.includes(req.params.key)) db.blacklist.push(req.params.key);
  saveDB(db);
  return res.json({ success: true, message: 'Key banned.' });
});

/** POST /api/admin/unban/:key */
app.post('/api/admin/unban/:key', adminAuth, (req, res) => {
  const db = loadDB();
  db.blacklist = db.blacklist.filter(k => k !== req.params.key);
  saveDB(db);
  return res.json({ success: true, message: 'Key unbanned.' });
});

/** DELETE /api/admin/license/:key — permanently delete */
app.delete('/api/admin/license/:key', adminAuth, (req, res) => {
  const db = loadDB();
  if (!db.licenses[req.params.key]) return res.json({ success: false, message: 'Not found.' });
  delete db.licenses[req.params.key];
  delete db.activations[req.params.key];
  saveDB(db);
  return res.json({ success: true, message: 'License deleted.' });
});

/** GET /api/admin/stats */
app.get('/api/admin/stats', adminAuth, (req, res) => {
  const db = loadDB();
  const licenses = Object.values(db.licenses);
  return res.json({
    success: true,
    stats: {
      total: licenses.length,
      activated: licenses.filter(l => l.machineHash).length,
      expired: licenses.filter(l => isExpired(l)).length,
      banned: db.blacklist.length,
      lifetime: licenses.filter(l => !l.expiresAt).length,
    }
  });
});

// Serve the dashboard
//app.use(express.static(path.join(__dirname, '../frontend')));

app.listen(CONFIG.PORT, () => {
  console.log(`\n🔐 VaultAuth Server running on port ${CONFIG.PORT}`);
  console.log(`   Admin Secret: ${CONFIG.ADMIN_SECRET}`);
  console.log(`   Data file: ${CONFIG.DATA_FILE}\n`);
});
