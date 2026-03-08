/**
 * VaultAuth Backend v2.4
 * + Discord webhooks
 * + Max auth attempts / auto-ban
 * + Version gating per app
 * + Bulk admin actions
 */

const express   = require('express');
const crypto    = require('crypto');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'] }));

const CONFIG = {
  ADMIN_SECRET:   process.env.ADMIN_SECRET   || 'CHANGE_THIS',
  APP_SECRET:     process.env.APP_SECRET     || 'CHANGE_THIS_32CHARS',
  PORT:           process.env.PORT,
  JSONBIN_BIN_ID: process.env.JSONBIN_BIN_ID,
  JSONBIN_KEY:    process.env.JSONBIN_KEY,
  DISCORD_WEBHOOK: process.env.DISCORD_WEBHOOK || '',
};

const JSONBIN_URL = `https://api.jsonbin.io/v3/b/${CONFIG.JSONBIN_BIN_ID}`;

// ─────────────────────────────────────────────
//  DB
// ─────────────────────────────────────────────
let _dbCache = null;

async function loadDB() {
  try {
    const res  = await fetch(JSONBIN_URL + '/latest', { headers: { 'X-Access-Key': CONFIG.JSONBIN_KEY } });
    const data = await res.json();
    if (data.record && data.record.licenses) {
      const r = data.record;
      if (!r.bannedHWIDs)    r.bannedHWIDs    = [];
      if (!r.bannedIPs)      r.bannedIPs      = [];
      if (!r.applications)   r.applications   = {};
      if (!r.authAttempts)   r.authAttempts   = {};
      _dbCache = r;
      return _dbCache;
    }
    if (_dbCache) return _dbCache;
    return { licenses: {}, activations: {}, blacklist: [], bannedHWIDs: [], bannedIPs: [], applications: {}, authAttempts: {} };
  } catch (e) {
    console.error('loadDB error:', e.message);
    if (_dbCache) return _dbCache;
    return { licenses: {}, activations: {}, blacklist: [], bannedHWIDs: [], bannedIPs: [], applications: {}, authAttempts: {} };
  }
}

async function saveDB(db) {
  try {
    if (!db || !db.licenses || typeof db.licenses !== 'object') { console.error('saveDB: invalid db'); return; }
    _dbCache = db;
    await fetch(JSONBIN_URL, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-Access-Key': CONFIG.JSONBIN_KEY },
      body: JSON.stringify(db)
    });
  } catch (e) { console.error('saveDB error:', e.message); }
}

// ─────────────────────────────────────────────
//  DISCORD
// ─────────────────────────────────────────────
async function sendDiscord(embeds) {
  if (!CONFIG.DISCORD_WEBHOOK) return;
  try {
    await fetch(CONFIG.DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds })
    });
  } catch (e) { console.error('Discord webhook error:', e.message); }
}

function discordEmbed(title, description, color, fields = []) {
  return [{
    title,
    description,
    color,
    fields,
    timestamp: new Date().toISOString(),
    footer: { text: 'VaultAuth' }
  }];
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
function hmacSign(d)    { return crypto.createHmac('sha256', CONFIG.APP_SECRET).update(d).digest('hex'); }
function hashHWID(h)    { return crypto.createHash('sha256').update(h + CONFIG.APP_SECRET).digest('hex'); }
function nowISO()       { return new Date().toISOString(); }
function daysFromNow(d) { const x = new Date(); x.setDate(x.getDate() + d); return x.toISOString(); }
function isExpired(l)   { if (!l.expiresAt) return false; return new Date() > new Date(l.expiresAt); }
function getIP(req)     { return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown'; }

function adminAuth(req, res, next) {
  const s = req.headers['x-admin-secret'] || req.body?.adminSecret;
  if (s !== CONFIG.ADMIN_SECRET) return res.status(403).json({ success: false, message: 'Forbidden' });
  next();
}

async function appAuth(req, res, next) {
  const appId     = req.body?.appId     || req.headers['x-app-id'];
  const appSecret = req.body?.appSecret || req.headers['x-app-secret'];
  if (!appId || !appSecret) return res.status(401).json({ success: false, message: 'Missing application credentials.' });
  const db  = await loadDB();
  const app = db.applications[appId];
  if (!app)                     return res.status(401).json({ success: false, message: 'Invalid application ID.' });
  if (app.secret !== appSecret) return res.status(401).json({ success: false, message: 'Invalid application secret.' });
  if (app.disabled)             return res.status(403).json({ success: false, message: 'Application is disabled.' });
  req.vaultApp   = app;
  req.vaultAppId = appId;
  next();
}

const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, message: { success: false, message: 'Too many requests.' } });

// ─────────────────────────────────────────────
//  /api/verify
// ─────────────────────────────────────────────
app.post('/api/verify', authLimiter, appAuth, async (req, res) => {
  const { key, hwid, username, appVersion } = req.body;
  if (!key || !hwid) return res.status(400).json({ success: false, message: 'Missing key or hwid.' });

  const ip       = getIP(req);
  const db       = await loadDB();
  const license  = db.licenses[key];
  const hwidHash = hashHWID(hwid);
  const appCfg   = req.vaultApp;

  // ── IP / HWID bans ────────────────────────
  if (db.bannedIPs.includes(ip))         return res.json({ success: false, message: 'Your IP address has been banned.' });
  if (db.bannedHWIDs.includes(hwidHash)) return res.json({ success: false, message: 'Your machine has been banned.' });

  // ── Key checks ────────────────────────────
  if (!license) {
    // Track failed attempt
    if (!db.authAttempts[key]) db.authAttempts[key] = { count: 0, firstAt: nowISO() };
    db.authAttempts[key].count++;
    db.authAttempts[key].lastAt = nowISO();
    await saveDB(db);
    sendDiscord(discordEmbed('❌ Invalid Key Attempt', `Key \`${key}\` was tried but does not exist.`, 0xf05d7a, [
      { name: 'IP', value: ip, inline: true },
      { name: 'App', value: appCfg.name, inline: true }
    ]));
    return res.json({ success: false, message: 'Invalid license key.' });
  }

  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'This license key has been banned.' });
  if (isExpired(license))         return res.json({ success: false, message: 'License key has expired.' });

  // ── Max auth attempts ─────────────────────
  const maxAttempts = appCfg.maxAuthAttempts || 0;
  if (maxAttempts > 0) {
    const attempts = db.authAttempts[key]?.failCount || 0;
    if (attempts >= maxAttempts) {
      if (!db.blacklist.includes(key)) {
        db.blacklist.push(key);
        await saveDB(db);
        sendDiscord(discordEmbed('🔨 Key Auto-Banned', `Key \`${key}\` was auto-banned after ${attempts} failed attempts.`, 0xf05d7a, [
          { name: 'IP', value: ip, inline: true },
          { name: 'App', value: appCfg.name, inline: true }
        ]));
      }
      return res.json({ success: false, message: `Key banned after too many failed attempts.` });
    }
  }

  // ── Version gating ────────────────────────
  if (appCfg.minVersion && appVersion) {
    const toNum = v => v.split('.').map(Number).reduce((a, b, i) => a + b * Math.pow(1000, 2 - i), 0);
    if (toNum(appVersion) < toNum(appCfg.minVersion)) {
      sendDiscord(discordEmbed('⚠️ Outdated Version Blocked', `User tried to auth with v${appVersion} but minimum is v${appCfg.minVersion}.`, 0xf5a623, [
        { name: 'Key', value: key, inline: true },
        { name: 'App', value: appCfg.name, inline: true }
      ]));
      return res.json({ success: false, message: `Your app version (${appVersion}) is outdated. Please update to v${appCfg.minVersion} or newer.` });
    }
  }

  // ── App scoping ───────────────────────────
  if (license.appId && license.appId !== req.vaultAppId) {
    return res.json({ success: false, message: 'License key does not belong to this application.' });
  }

  // ── HWID bind ─────────────────────────────
  const isFirstBind = !license.hwidHash;
  if (!license.hwidHash) {
    license.hwidHash    = hwidHash;
    license.hwidRaw     = hwid;
    license.username    = username || 'Unknown-PC';
    license.activatedAt = nowISO();
    license.ip          = ip;
  } else if (license.hwidHash !== hwidHash) {
    // Track HWID mismatch as failed attempt
    if (!db.authAttempts[key]) db.authAttempts[key] = { failCount: 0 };
    db.authAttempts[key].failCount = (db.authAttempts[key].failCount || 0) + 1;
    await saveDB(db);
    sendDiscord(discordEmbed('⚠️ HWID Mismatch', `Key \`${key}\` was used on a different machine.`, 0xf5a623, [
      { name: 'Key', value: key, inline: true },
      { name: 'IP', value: ip, inline: true },
      { name: 'App', value: appCfg.name, inline: true }
    ]));
    return res.json({ success: false, message: 'Key already activated on another machine. Contact support to reset.' });
  }

  // Reset fail count on success
  if (db.authAttempts[key]) db.authAttempts[key].failCount = 0;

  license.lastSeen   = nowISO();
  license.lastIP     = ip;
  license.username   = username   || license.username;
  license.appVersion = appVersion || license.appVersion || 'unknown';

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'verify', timestamp: nowISO(), username: license.username, appVersion: license.appVersion, ip });

  await saveDB(db);

  if (isFirstBind) {
    sendDiscord(discordEmbed('✅ New Activation', `Key \`${key}\` was activated for the first time.`, 0x3ecf8e, [
      { name: 'User', value: license.username, inline: true },
      { name: 'Plan', value: license.plan || 'standard', inline: true },
      { name: 'IP', value: ip, inline: true },
      { name: 'App', value: appCfg.name, inline: true },
      { name: 'Version', value: appVersion || 'unknown', inline: true }
    ]));
  }

  const sessionPayload = `${key}:${hwidHash}:${Date.now()}`;
  const sessionToken   = hmacSign(sessionPayload);

  return res.json({
    success: true, message: 'License verified.',
    data: {
      username: license.username, plan: license.plan || 'standard',
      expiresAt: license.expiresAt || null, activatedAt: license.activatedAt,
      appName: appCfg.name, sessionToken, sessionPayload,
    }
  });
});

// ─────────────────────────────────────────────
//  /api/validate
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

  if (!lic)                    return res.json({ success: false, message: 'Invalid license.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License banned.' });
  if (isExpired(lic))          return res.json({ success: false, message: 'License expired.' });
  if (db.bannedIPs.includes(ip))  return res.json({ success: false, message: 'IP banned.' });
  if (lic.hwidHash && db.bannedHWIDs.includes(lic.hwidHash)) return res.json({ success: false, message: 'Machine banned.' });

  lic.lastSeen = nowISO(); lic.lastIP = ip;
  await saveDB(db);

  return res.json({ success: true, message: 'Valid.', data: { username: lic.username, plan: lic.plan || 'standard', expiresAt: lic.expiresAt || null } });
});

// ─────────────────────────────────────────────
//  /api/activate (web)
// ─────────────────────────────────────────────
app.post('/api/activate', authLimiter, async (req, res) => {
  const { key, username } = req.body;
  if (!key || !username) return res.status(400).json({ success: false, message: 'Missing fields.' });
  const db  = await loadDB();
  const lic = db.licenses[key];
  if (!lic)                    return res.json({ success: false, message: 'Invalid license key.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License key has been banned.' });
  if (isExpired(lic))          return res.json({ success: false, message: 'License key has expired.' });
  lic.username    = username;
  lic.activatedAt = lic.activatedAt || nowISO();
  lic.lastSeen    = nowISO();
  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'web-activate', timestamp: nowISO(), username });
  await saveDB(db);
  const sessionPayload = `${key}:${Date.now()}`;
  const sessionToken   = hmacSign(sessionPayload);
  return res.json({ success: true, message: 'Activated.', data: { username: lic.username, plan: lic.plan || 'standard', expiresAt: lic.expiresAt || null, sessionToken, sessionPayload } });
});

// ─────────────────────────────────────────────
//  ADMIN — APPS
// ─────────────────────────────────────────────
app.post('/api/admin/apps/create', adminAuth, async (req, res) => {
  const { name, version = '1.0.0', description = '', minVersion = '', maxAuthAttempts = 0 } = req.body;
  if (!name) return res.json({ success: false, message: 'App name required.' });
  const db = await loadDB();
  const appId = genAppId(); const secret = genAppSecret();
  db.applications[appId] = { name, version, description, secret, createdAt: nowISO(), disabled: false, minVersion, maxAuthAttempts: parseInt(maxAuthAttempts) || 0 };
  await saveDB(db);
  return res.json({ success: true, appId, secret, app: db.applications[appId] });
});

app.get('/api/admin/apps', adminAuth, async (req, res) => {
  const db = await loadDB();
  return res.json({ success: true, apps: Object.entries(db.applications || {}).map(([id, d]) => ({ id, ...d })) });
});

app.post('/api/admin/apps/update/:id', adminAuth, async (req, res) => {
  const db = await loadDB(); const a = db.applications[req.params.id];
  if (!a) return res.json({ success: false, message: 'App not found.' });
  const { minVersion, maxAuthAttempts, discordWebhook, version, description } = req.body;
  if (minVersion       !== undefined) a.minVersion        = minVersion;
  if (maxAuthAttempts  !== undefined) a.maxAuthAttempts   = parseInt(maxAuthAttempts) || 0;
  if (discordWebhook   !== undefined) a.discordWebhook    = discordWebhook;
  if (version          !== undefined) a.version           = version;
  if (description      !== undefined) a.description       = description;
  await saveDB(db);
  return res.json({ success: true, message: 'App updated.', app: a });
});

app.post('/api/admin/apps/toggle/:id', adminAuth, async (req, res) => {
  const db = await loadDB(); const a = db.applications[req.params.id];
  if (!a) return res.json({ success: false, message: 'App not found.' });
  a.disabled = !a.disabled; await saveDB(db);
  return res.json({ success: true, disabled: a.disabled, message: a.disabled ? 'App disabled.' : 'App enabled.' });
});

app.post('/api/admin/apps/regen/:id', adminAuth, async (req, res) => {
  const db = await loadDB(); const a = db.applications[req.params.id];
  if (!a) return res.json({ success: false, message: 'App not found.' });
  a.secret = genAppSecret(); await saveDB(db);
  return res.json({ success: true, secret: a.secret });
});

app.delete('/api/admin/apps/:id', adminAuth, async (req, res) => {
  const db = await loadDB();
  if (!db.applications[req.params.id]) return res.json({ success: false, message: 'Not found.' });
  delete db.applications[req.params.id]; await saveDB(db);
  return res.json({ success: true, message: 'App deleted.' });
});

// ─────────────────────────────────────────────
//  ADMIN — DISCORD WEBHOOK (global)
// ─────────────────────────────────────────────
app.post('/api/admin/discord/test', adminAuth, async (req, res) => {
  const { webhookUrl } = req.body;
  const url = webhookUrl || CONFIG.DISCORD_WEBHOOK;
  if (!url) return res.json({ success: false, message: 'No webhook URL provided.' });
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: discordEmbed('🔔 VaultAuth Test', 'Webhook is working correctly!', 0x7c6af7) })
    });
    return res.json({ success: true, message: 'Test message sent.' });
  } catch (e) { return res.json({ success: false, message: e.message }); }
});

// ─────────────────────────────────────────────
//  ADMIN — KEYS (single)
// ─────────────────────────────────────────────
app.post('/api/admin/generate', adminAuth, async (req, res) => {
  const { count = 1, plan = 'standard', durationDays = null, prefix = 'VAULT', allowMultiple = false, note = '', appId = null } = req.body;
  const db = await loadDB(); const keys = [];
  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = generateKey(prefix);
    db.licenses[key] = { plan, createdAt: nowISO(), expiresAt: durationDays ? daysFromNow(durationDays) : null, activatedAt: null, hwidHash: null, hwidRaw: null, username: null, allowMultiple, note, lastSeen: null, appVersion: null, ip: null, lastIP: null, appId: appId || null };
    keys.push(key);
    if (appId && db.applications[appId]) db.applications[appId].keyCount = (db.applications[appId].keyCount || 0) + 1;
  }
  await saveDB(db);
  return res.json({ success: true, keys });
});

app.post('/api/admin/extend/:key', adminAuth, async (req, res) => {
  const { days } = req.body;
  if (!days || days <= 0) return res.json({ success: false, message: 'Invalid days value.' });
  const db  = await loadDB();
  const lic = db.licenses[req.params.key];
  if (!lic) return res.json({ success: false, message: 'Key not found.' });
  const base = lic.expiresAt && new Date(lic.expiresAt) > new Date() ? new Date(lic.expiresAt) : new Date();
  base.setDate(base.getDate() + parseInt(days));
  lic.expiresAt = base.toISOString();
  await saveDB(db);
  return res.json({ success: true, message: `Extended by ${days} days.`, expiresAt: lic.expiresAt });
});

app.get('/api/admin/licenses', adminAuth, async (req, res) => {
  const db   = await loadDB();
  const list = Object.entries(db.licenses).map(([key, data]) => ({
    key, ...data,
    expired:    isExpired(data),
    banned:     db.blacklist.includes(key),
    hwidBanned: data.hwidHash ? db.bannedHWIDs.includes(data.hwidHash) : false,
    ipBanned:   data.lastIP   ? db.bannedIPs.includes(data.lastIP)    : false,
    appName:    data.appId && db.applications[data.appId] ? db.applications[data.appId].name : null,
    failCount:  db.authAttempts[key]?.failCount || 0,
  }));
  return res.json({ success: true, licenses: list, total: list.length });
});

app.get('/api/admin/license/:key', adminAuth, async (req, res) => {
  const db  = await loadDB(); const lic = db.licenses[req.params.key];
  if (!lic) return res.json({ success: false, message: 'Not found.' });
  return res.json({
    success: true,
    license: { key: req.params.key, ...lic, appName: lic.appId && db.applications[lic.appId] ? db.applications[lic.appId].name : null, failCount: db.authAttempts[req.params.key]?.failCount || 0 },
    history: db.activations[req.params.key] || [],
    banned:     db.blacklist.includes(req.params.key),
    hwidBanned: lic.hwidHash ? db.bannedHWIDs.includes(lic.hwidHash) : false,
    ipBanned:   lic.lastIP   ? db.bannedIPs.includes(lic.lastIP)    : false,
    expired:    isExpired(lic),
  });
});

app.post('/api/admin/reset/:key', adminAuth, async (req, res) => {
  const db = await loadDB(); const lic = db.licenses[req.params.key];
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
  await saveDB(db); return res.json({ success: true, message: 'Key banned.' });
});

app.post('/api/admin/unban/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  db.blacklist = db.blacklist.filter(k => k !== req.params.key);
  await saveDB(db); return res.json({ success: true, message: 'Key unbanned.' });
});

app.delete('/api/admin/license/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  if (!db.licenses[req.params.key]) return res.json({ success: false, message: 'Not found.' });
  delete db.licenses[req.params.key]; delete db.activations[req.params.key];
  await saveDB(db); return res.json({ success: true, message: 'Deleted.' });
});

// ─────────────────────────────────────────────
//  ADMIN — BULK ACTIONS
// ─────────────────────────────────────────────
app.post('/api/admin/bulk', adminAuth, async (req, res) => {
  const { keys, action } = req.body;
  if (!keys?.length || !action) return res.json({ success: false, message: 'Missing keys or action.' });
  const db = await loadDB(); let affected = 0;

  for (const key of keys) {
    if (!db.licenses[key] && action !== 'delete') continue;
    switch (action) {
      case 'ban':
        if (!db.blacklist.includes(key)) { db.blacklist.push(key); affected++; }
        break;
      case 'unban':
        db.blacklist = db.blacklist.filter(k => k !== key); affected++;
        break;
      case 'delete':
        if (db.licenses[key]) { delete db.licenses[key]; delete db.activations[key]; affected++; }
        break;
      case 'reset':
        if (db.licenses[key]) { db.licenses[key].hwidHash = null; db.licenses[key].hwidRaw = null; affected++; }
        break;
      case 'resetfails':
        if (db.authAttempts[key]) { db.authAttempts[key].failCount = 0; affected++; }
        break;
    }
  }

  await saveDB(db);
  return res.json({ success: true, message: `Bulk ${action}: ${affected} key(s) affected.`, affected });
});

// ─────────────────────────────────────────────
//  ADMIN — HWID / IP BANS
// ─────────────────────────────────────────────
app.post('/api/admin/ban-hwid', adminAuth, async (req, res) => {
  const { hwidHash, keyToBanFrom } = req.body;
  const db = await loadDB(); let hash = hwidHash;
  if (!hash && keyToBanFrom && db.licenses[keyToBanFrom]) hash = db.licenses[keyToBanFrom].hwidHash;
  if (!hash) return res.json({ success: false, message: 'No HWID hash.' });
  if (!db.bannedHWIDs.includes(hash)) db.bannedHWIDs.push(hash);
  await saveDB(db); return res.json({ success: true, message: 'HWID banned.' });
});

app.post('/api/admin/unban-hwid', adminAuth, async (req, res) => {
  const { hwidHash } = req.body; const db = await loadDB();
  db.bannedHWIDs = db.bannedHWIDs.filter(h => h !== hwidHash);
  await saveDB(db); return res.json({ success: true, message: 'HWID unbanned.' });
});

app.post('/api/admin/ban-ip', adminAuth, async (req, res) => {
  const { ip } = req.body; if (!ip) return res.json({ success: false, message: 'No IP.' });
  const db = await loadDB();
  if (!db.bannedIPs.includes(ip)) db.bannedIPs.push(ip);
  await saveDB(db); return res.json({ success: true, message: `IP ${ip} banned.` });
});

app.post('/api/admin/unban-ip', adminAuth, async (req, res) => {
  const { ip } = req.body; const db = await loadDB();
  db.bannedIPs = db.bannedIPs.filter(i => i !== ip);
  await saveDB(db); return res.json({ success: true, message: `IP ${ip} unbanned.` });
});

app.get('/api/admin/banlists', adminAuth, async (req, res) => {
  const db = await loadDB();
  return res.json({ success: true, bannedHWIDs: db.bannedHWIDs || [], bannedIPs: db.bannedIPs || [], blacklist: db.blacklist || [] });
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const db = await loadDB(); const licenses = Object.values(db.licenses);
  return res.json({
    success: true,
    stats: {
      total: licenses.length, activated: licenses.filter(l => l.hwidHash).length,
      expired: licenses.filter(l => isExpired(l)).length, banned: db.blacklist.length,
      lifetime: licenses.filter(l => !l.expiresAt).length,
      bannedHWIDs: (db.bannedHWIDs||[]).length, bannedIPs: (db.bannedIPs||[]).length,
      apps: Object.keys(db.applications||{}).length,
    }
  });
});

app.listen(CONFIG.PORT, '0.0.0.0', () => console.log(`[VaultAuth] v2.4 on port ${CONFIG.PORT}`));
