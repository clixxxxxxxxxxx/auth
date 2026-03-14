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
  ADMIN_SECRET:          process.env.ADMIN_SECRET          || 'CHANGE_THIS',
  APP_SECRET:            process.env.APP_SECRET            || 'CHANGE_THIS_32CHARS',
  PORT:                  process.env.PORT,
  JSONBIN_BIN_ID:        process.env.JSONBIN_BIN_ID,
  JSONBIN_KEY:           process.env.JSONBIN_KEY,
  DISCORD_WEBHOOK:       process.env.DISCORD_WEBHOOK       || '',
  DISCORD_CLIENT_ID:     process.env.DISCORD_CLIENT_ID     || '1482484114618716354',
  DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET || '',
  DISCORD_REDIRECT_URI:  process.env.DISCORD_REDIRECT_URI  || '',
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
async function sendDiscord(embeds, webhookUrl) {
  const url = webhookUrl || CONFIG.DISCORD_WEBHOOK;
  if (!url) return;
  try {
    await fetch(url, {
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
    footer: { text: 'VaultAuth • License System', icon_url: 'https://i.imgur.com/AfFp7pu.png' }
  }];
}

// Rich styled embed builder for admin events
function richEmbed({ title, description, color, fields = [], thumbnail = null }) {
  const embed = {
    title,
    description,
    color,
    fields,
    timestamp: new Date().toISOString(),
    footer: { text: 'VaultAuth • Admin Event Logger' },
  };
  if (thumbnail) embed.thumbnail = { url: thumbnail };
  return [embed];
}

// Resolve the best webhook URL: app-level → global config → db global
function getWebhook(db, appId = null) {
  if (appId && db.applications?.[appId]?.discordWebhook)
    return db.applications[appId].discordWebhook;
  if (CONFIG.DISCORD_WEBHOOK) return CONFIG.DISCORD_WEBHOOK;
  // fallback: first app that has a webhook set
  if (db.applications) {
    for (const a of Object.values(db.applications)) {
      if (a.discordWebhook) return a.discordWebhook;
    }
  }
  return null;
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

  // ── Discord link required ─────────────────
  if (license && !license.discordId) {
    return res.json({ success: false, message: 'License not yet linked to a Discord account. Please visit the link page first.' });
  }

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
  const prevWebhook = a.discordWebhook;
  if (minVersion       !== undefined) a.minVersion        = minVersion;
  if (maxAuthAttempts  !== undefined) a.maxAuthAttempts   = parseInt(maxAuthAttempts) || 0;
  if (discordWebhook   !== undefined) a.discordWebhook    = discordWebhook;
  if (version          !== undefined) a.version           = version;
  if (description      !== undefined) a.description       = description;
  await saveDB(db);

  // Notify new webhook that it's now the active receiver
  if (discordWebhook && discordWebhook !== prevWebhook) {
    sendDiscord(richEmbed({
      title: '🔔 Webhook Configured',
      description: `This channel is now the **active notification receiver** for **${a.name}**.\n\nAll license events, bans, and alerts will be delivered here.`,
      color: 0x7c6af7,
      fields: [
        { name: '📦 Application', value: a.name, inline: true },
        { name: '🆔 App ID', value: req.params.id, inline: true },
        { name: '📅 Configured At', value: `<t:${Math.floor(Date.now()/1000)}:F>`, inline: false },
      ]
    }), discordWebhook);
  }

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
app.post('/api/admin/discord/set', adminAuth, async (req, res) => {
  const { webhookUrl } = req.body;
  if (!webhookUrl) return res.json({ success: false, message: 'No webhook URL provided.' });
  const prev = CONFIG.DISCORD_WEBHOOK;
  CONFIG.DISCORD_WEBHOOK = webhookUrl;
  // Notify the new webhook it's now active
  if (webhookUrl !== prev) {
    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ embeds: richEmbed({
          title: '🔔 Global Webhook Configured',
          description: 'This channel is now the **global notification receiver** for VaultAuth.\n\nAll system-wide license events, bans, and security alerts will be delivered here.',
          color: 0x7c6af7,
          fields: [
            { name: '📅 Configured At', value: `<t:${Math.floor(Date.now()/1000)}:F>`, inline: false },
            { name: '📡 Status', value: '✅ Active & Listening', inline: true },
          ]
        }) })
      });
    } catch (e) { return res.json({ success: false, message: 'Webhook URL is invalid or unreachable: ' + e.message }); }
  }
  return res.json({ success: true, message: 'Global webhook saved and notified.' });
});

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

  const appName = appId && db.applications[appId] ? db.applications[appId].name : 'Unscoped';
  const expiry  = durationDays ? `${durationDays} days` : 'Lifetime';
  sendDiscord(richEmbed({
    title: '🗝️ License Key(s) Created',
    description: keys.length === 1
      ? `A new license key has been generated and is ready for use.`
      : `**${keys.length}** new license keys have been generated.`,
    color: 0x3ecf8e,
    fields: [
      { name: '🔑 Key(s)', value: keys.length <= 5 ? keys.map(k => `\`${k}\``).join('\n') : `\`${keys[0]}\`\n... and ${keys.length - 1} more`, inline: false },
      { name: '📦 Application', value: appName, inline: true },
      { name: '🏷️ Plan', value: plan, inline: true },
      { name: '⏳ Expiry', value: expiry, inline: true },
      { name: '📝 Note', value: note || '—', inline: false },
    ]
  }), getWebhook(db, appId));

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
  const lic = db.licenses[req.params.key];
  if (!lic) return res.json({ success: false, message: 'Not found.' });
  if (!db.blacklist.includes(req.params.key)) db.blacklist.push(req.params.key);
  await saveDB(db);
  const appName = lic.appId && db.applications[lic.appId] ? db.applications[lic.appId].name : 'Unscoped';
  sendDiscord(richEmbed({
    title: '🔨 License Key Banned',
    description: `A license key has been added to the blacklist and will be rejected on all future auth attempts.`,
    color: 0xf05d7a,
    fields: [
      { name: '🔑 Key',          value: `\`${req.params.key}\``,       inline: false },
      { name: '👤 Username',     value: lic.username || '—',            inline: true  },
      { name: '📦 Application',  value: appName,                        inline: true  },
      { name: '🏷️ Plan',         value: lic.plan || 'standard',         inline: true  },
      { name: '🖥️ HWID Bound',   value: lic.hwidHash ? '✅ Yes' : '❌ No', inline: true },
      { name: '🌐 Last IP',      value: lic.lastIP || '—',              inline: true  },
    ]
  }), getWebhook(db, lic.appId));
  return res.json({ success: true, message: 'Key banned.' });
});

app.post('/api/admin/unban/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  const lic = db.licenses[req.params.key];
  db.blacklist = db.blacklist.filter(k => k !== req.params.key);
  await saveDB(db);
  if (lic) {
    const appName = lic.appId && db.applications[lic.appId] ? db.applications[lic.appId].name : 'Unscoped';
    sendDiscord(richEmbed({
      title: '✅ License Key Unbanned',
      description: `A license key has been removed from the blacklist and can authenticate again.`,
      color: 0x3ecf8e,
      fields: [
        { name: '🔑 Key',         value: `\`${req.params.key}\``, inline: false },
        { name: '👤 Username',    value: lic.username || '—',     inline: true  },
        { name: '📦 Application', value: appName,                 inline: true  },
      ]
    }), getWebhook(db, lic.appId));
  }
  return res.json({ success: true, message: 'Key unbanned.' });
});

app.delete('/api/admin/license/:key', adminAuth, async (req, res) => {
  const db = await loadDB();
  const lic = db.licenses[req.params.key];
  if (!lic) return res.json({ success: false, message: 'Not found.' });
  const appName = lic.appId && db.applications[lic.appId] ? db.applications[lic.appId].name : 'Unscoped';
  delete db.licenses[req.params.key]; delete db.activations[req.params.key];
  await saveDB(db);
  sendDiscord(richEmbed({
    title: '🗑️ License Key Deleted',
    description: `A license key has been permanently removed from the system.`,
    color: 0xf05d7a,
    fields: [
      { name: '🔑 Key', value: `\`${req.params.key}\``, inline: false },
      { name: '👤 Username', value: lic.username || '—', inline: true },
      { name: '📦 Application', value: appName, inline: true },
      { name: '🏷️ Plan', value: lic.plan || 'standard', inline: true },
      { name: '📅 Created', value: lic.createdAt ? lic.createdAt.slice(0, 10) : '—', inline: true },
      { name: '🖥️ HWID Bound', value: lic.hwidHash ? '✅ Yes' : '❌ No', inline: true },
      { name: '⏳ Was Expiring', value: lic.expiresAt ? lic.expiresAt.slice(0, 10) : 'Lifetime', inline: true },
    ]
  }), getWebhook(db, lic.appId));
  return res.json({ success: true, message: 'Deleted.' });
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

  if (affected > 0) {
    const actionLabels = { ban: '🔨 Bulk Ban', unban: '✅ Bulk Unban', delete: '🗑️ Bulk Delete', reset: '🔄 Bulk Machine Reset', resetfails: '🔄 Bulk Fail Count Reset' };
    const actionColors = { ban: 0xf05d7a, unban: 0x3ecf8e, delete: 0xf05d7a, reset: 0xf5a623, resetfails: 0xf5a623 };
    sendDiscord(richEmbed({
      title: actionLabels[action] || `⚙️ Bulk ${action}`,
      description: `A bulk admin action was performed on **${affected}** license key(s).`,
      color: actionColors[action] || 0x7c6af7,
      fields: [
        { name: '⚙️ Action',        value: action,                                                   inline: true },
        { name: '🔢 Keys Affected', value: String(affected),                                         inline: true },
        { name: '🔑 Sample Keys',   value: keys.slice(0, 5).map(k => `\`${k}\``).join('\n') || '—', inline: false },
      ]
    }), getWebhook(db));
  }

  return res.json({ success: true, message: `Bulk ${action}: ${affected} key(s) affected.`, affected });
});

// ─────────────────────────────────────────────
//  ADMIN — HWID / IP BANS
// ─────────────────────────────────────────────
app.post('/api/admin/ban-hwid', adminAuth, async (req, res) => {
  const { hwidHash, keyToBanFrom } = req.body;
  const db = await loadDB(); let hash = hwidHash;
  let linkedKey = null, linkedUser = null, linkedApp = null;
  if (!hash && keyToBanFrom && db.licenses[keyToBanFrom]) {
    hash = db.licenses[keyToBanFrom].hwidHash;
    linkedKey  = keyToBanFrom;
    linkedUser = db.licenses[keyToBanFrom].username;
    const aid  = db.licenses[keyToBanFrom].appId;
    linkedApp  = aid && db.applications[aid] ? db.applications[aid].name : null;
  }
  if (!hash) return res.json({ success: false, message: 'No HWID hash.' });
  if (!db.bannedHWIDs.includes(hash)) db.bannedHWIDs.push(hash);
  await saveDB(db);
  sendDiscord(richEmbed({
    title: '🖥️ HWID Banned',
    description: `A hardware ID has been added to the ban list. The associated machine will be blocked from all future authentication attempts.`,
    color: 0xf05d7a,
    fields: [
      { name: '🔒 HWID Hash', value: `\`${hash.slice(0, 32)}...\``, inline: false },
      ...(linkedKey  ? [{ name: '🔑 Linked Key',  value: `\`${linkedKey}\``,  inline: true }] : []),
      ...(linkedUser ? [{ name: '👤 Username',     value: linkedUser,          inline: true }] : []),
      ...(linkedApp  ? [{ name: '📦 Application',  value: linkedApp,           inline: true }] : []),
    ]
  }), getWebhook(db));
  return res.json({ success: true, message: 'HWID banned.' });
});

app.post('/api/admin/unban-hwid', adminAuth, async (req, res) => {
  const { hwidHash } = req.body; const db = await loadDB();
  db.bannedHWIDs = db.bannedHWIDs.filter(h => h !== hwidHash);
  await saveDB(db);
  sendDiscord(richEmbed({
    title: '✅ HWID Unbanned',
    description: `A hardware ID has been removed from the ban list.`,
    color: 0x3ecf8e,
    fields: [
      { name: '🔓 HWID Hash', value: `\`${hwidHash.slice(0, 32)}...\``, inline: false },
    ]
  }), getWebhook(db));
  return res.json({ success: true, message: 'HWID unbanned.' });
});

app.post('/api/admin/ban-ip', adminAuth, async (req, res) => {
  const { ip } = req.body; if (!ip) return res.json({ success: false, message: 'No IP.' });
  const db = await loadDB();
  if (!db.bannedIPs.includes(ip)) db.bannedIPs.push(ip);
  await saveDB(db);
  sendDiscord(richEmbed({
    title: '🌐 IP Address Banned',
    description: `An IP address has been added to the ban list. All requests from this address will be rejected.`,
    color: 0xf05d7a,
    fields: [
      { name: '🚫 IP Address', value: `\`${ip}\``, inline: true },
      { name: '📅 Banned At', value: `<t:${Math.floor(Date.now()/1000)}:F>`, inline: true },
    ]
  }), getWebhook(db));
  return res.json({ success: true, message: `IP ${ip} banned.` });
});

app.post('/api/admin/unban-ip', adminAuth, async (req, res) => {
  const { ip } = req.body; const db = await loadDB();
  db.bannedIPs = db.bannedIPs.filter(i => i !== ip);
  await saveDB(db);
  sendDiscord(richEmbed({
    title: '✅ IP Address Unbanned',
    description: `An IP address has been removed from the ban list.`,
    color: 0x3ecf8e,
    fields: [
      { name: '🔓 IP Address', value: `\`${ip}\``, inline: true },
      { name: '📅 Unbanned At', value: `<t:${Math.floor(Date.now()/1000)}:F>`, inline: true },
    ]
  }), getWebhook(db));
  return res.json({ success: true, message: `IP ${ip} unbanned.` });
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

// ─────────────────────────────────────────────
//  DISCORD OAUTH2 — License Linking
// ─────────────────────────────────────────────

// Temp in-memory store: state → discord user profile (expires after 10 min)
const oauthSessions = new Map();
function cleanOAuthSessions() {
  const now = Date.now();
  for (const [k, v] of oauthSessions) {
    if (now - v.createdAt > 10 * 60 * 1000) oauthSessions.delete(k);
  }
}
setInterval(cleanOAuthSessions, 60 * 1000);

// GET /api/discord/oauth — redirect user to Discord
app.get('/api/discord/oauth', (req, res) => {
  if (!CONFIG.DISCORD_CLIENT_ID || !CONFIG.DISCORD_REDIRECT_URI)
    return res.status(500).send('Discord OAuth not configured.');
  const state = crypto.randomBytes(16).toString('hex');
  // Store state with a placeholder so we can validate it on callback
  oauthSessions.set(state, { createdAt: Date.now(), user: null });
  const params = new URLSearchParams({
    client_id:     CONFIG.DISCORD_CLIENT_ID,
    redirect_uri:  CONFIG.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope:         'identify',
    state,
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

// GET /api/discord/callback — Discord redirects here after auth
app.get('/api/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state || !oauthSessions.has(state))
    return res.redirect('/link.html?error=invalid_state');

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     CONFIG.DISCORD_CLIENT_ID,
        client_secret: CONFIG.DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  CONFIG.DISCORD_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.redirect('/link.html?error=token_failed');

    // Fetch user profile
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userRes.json();
    if (!user.id) return res.redirect('/link.html?error=user_failed');

    // Store user in session keyed by state
    oauthSessions.set(state, {
      createdAt: Date.now(),
      user: {
        id:       user.id,
        username: user.username,
        avatar:   user.avatar
          ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
          : `https://cdn.discordapp.com/embed/avatars/${parseInt(user.discriminator || 0) % 5}.png`,
      },
    });

    res.redirect(`/link.html?state=${state}`);
  } catch (e) {
    console.error('Discord callback error:', e.message);
    res.redirect('/link.html?error=server_error');
  }
});

// GET /api/discord/session?state=xxx — frontend polls this to get user info
app.get('/api/discord/session', (req, res) => {
  const { state } = req.query;
  if (!state || !oauthSessions.has(state))
    return res.json({ success: false, message: 'Session not found.' });
  const session = oauthSessions.get(state);
  if (!session.user)
    return res.json({ success: false, message: 'OAuth not completed.' });
  return res.json({ success: true, user: session.user });
});

// POST /api/link-license — tie a key to a Discord account (one-time)
app.post('/api/link-license', authLimiter, async (req, res) => {
  const { key, state } = req.body;
  if (!key || !state) return res.status(400).json({ success: false, message: 'Missing key or state.' });

  const session = oauthSessions.get(state);
  if (!session || !session.user)
    return res.json({ success: false, message: 'Discord session expired or invalid. Please re-authenticate.' });

  const db  = await loadDB();
  const lic = db.licenses[key];

  if (!lic)                       return res.json({ success: false, message: 'Invalid license key.' });
  if (db.blacklist.includes(key)) return res.json({ success: false, message: 'License key has been banned.' });
  if (isExpired(lic))             return res.json({ success: false, message: 'License key has expired.' });
  if (lic.discordId)              return res.json({ success: false, message: 'This license key is already linked to a Discord account.' });

  // Check if this Discord account already has a key linked
  const alreadyLinked = Object.values(db.licenses).find(l => l.discordId === session.user.id);
  if (alreadyLinked)
    return res.json({ success: false, message: 'Your Discord account is already linked to a license key.' });

  lic.discordId       = session.user.id;
  lic.discordUsername = session.user.username;
  lic.discordAvatar   = session.user.avatar;
  lic.linkedAt        = nowISO();
  lic.username        = lic.username || session.user.username;

  if (!db.activations[key]) db.activations[key] = [];
  db.activations[key].push({ event: 'discord-link', timestamp: nowISO(), discordId: session.user.id, discordUsername: session.user.username });

  await saveDB(db);

  // Invalidate the OAuth session so it can't be reused
  oauthSessions.delete(state);

  sendDiscord(richEmbed({
    title: '🔗 License Linked to Discord',
    description: `A license key has been linked to a Discord account.`,
    color: 0x7c6af7,
    thumbnail: session.user.avatar,
    fields: [
      { name: '🔑 Key',             value: `\`${key}\``,              inline: false },
      { name: '👤 Discord',         value: session.user.username,     inline: true  },
      { name: '🆔 Discord ID',      value: session.user.id,           inline: true  },
      { name: '🏷️ Plan',            value: lic.plan || 'standard',    inline: true  },
    ]
  }), getWebhook(db, lic.appId));

  return res.json({
    success: true,
    message: 'License linked successfully.',
    data: { username: lic.username, plan: lic.plan || 'standard', expiresAt: lic.expiresAt || null }
  });
});

app.listen(CONFIG.PORT, '0.0.0.0', () => console.log(`[VaultAuth] v2.4 on port ${CONFIG.PORT}`));
