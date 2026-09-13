// GROSSTAR key auth - free Render version (no DB, file-based)
// Endpoints:
//   GET  /               -> status
//   POST /auth           {key,hwid} -> {ok, expires_at|reason}
//   POST /heartbeat      {key,hwid} -> {ok}
//   POST /admin/create   {admin, key, days} -> create key (admin token in env ADMIN_TOKEN)
//   POST /admin/ban      {admin, key} -> ban key
//   POST /admin/reset    {admin, key} -> clear HWID lock
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '64kb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'troque-isso';
const AUTH_SECRET = process.env.AUTH_SECRET || 'troque-este-secret-32-chars-min';
const DB_FILE = path.join(__dirname, 'keys.json');

function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch { return { keys: [] }; }
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
if (!fs.existsSync(DB_FILE)) saveDB({ keys: [] });

function findKey(db, key) {
  return db.keys.find(k => k.key === key);
}

function sign(key, hwid, expires_at) {
  return crypto.createHmac('sha256', AUTH_SECRET)
    .update(key + '|' + (hwid || '') + '|' + (expires_at || '')).digest('hex');
}

app.get('/', (req, res) => res.json({ ok: true, service: 'grosstar-auth' }));

function checkAuth(key, hwid) {
  const db = loadDB();
  const rec = findKey(db, key);
  if (!rec) return { ok: false, reason: 'invalid key', save: false };
  if (rec.banned) return { ok: false, reason: 'banned', save: false };
  if (rec.expires_at && Date.now() > new Date(rec.expires_at).getTime())
    return { ok: false, reason: 'expired', save: false };
  if (!rec.hwid) { rec.hwid = hwid || null; saveDB(db); }
  else if (hwid && rec.hwid !== hwid)
    return { ok: false, reason: 'hwid mismatch', save: false };
  return { ok: true, expires_at: rec.expires_at || null, save: true };
}

app.post('/auth', (req, res) => {
  const { key, hwid } = req.body || {};
  if (!key) return res.json({ ok: false, reason: 'missing key' });
  const r = checkAuth(String(key).trim(), hwid ? String(hwid) : null);
  if (r.ok) r.sig = sign(String(key).trim(), hwid ? String(hwid) : null, r.expires_at);
  res.json(r);
});

app.post('/heartbeat', (req, res) => {
  const { key, hwid } = req.body || {};
  if (!key) return res.json({ ok: false });
  const r = checkAuth(String(key).trim(), hwid ? String(hwid) : null);
  if (!r.ok) return res.json({ ok: false });
  res.json({ ok: true, expires_at: r.expires_at, sig: sign(String(key).trim(), hwid ? String(hwid) : null, r.expires_at) });
});

function needAdmin(req, res) {
  if ((req.body && req.body.admin) !== ADMIN_TOKEN) {
    res.status(401).json({ ok: false, reason: 'unauthorized' });
    return false;
  }
  return true;
}

app.post('/admin/create', (req, res) => {
  if (!needAdmin(req, res)) return;
  const { key, days } = req.body;
  if (!key) return res.json({ ok: false, reason: 'missing key' });
  const db = loadDB();
  if (findKey(db, key)) return res.json({ ok: false, reason: 'exists' });
  const exp = days ? new Date(Date.now() + Number(days) * 864e5).toISOString() : null;
  db.keys.push({ key, hwid: null, expires_at: exp, banned: false });
  saveDB(db);
  res.json({ ok: true, key, expires_at: exp });
});

app.post('/admin/ban', (req, res) => {
  if (!needAdmin(req, res)) return;
  const db = loadDB();
  const rec = findKey(db, req.body.key);
  if (!rec) return res.json({ ok: false });
  rec.banned = true; saveDB(db);
  res.json({ ok: true });
});

app.post('/admin/reset', (req, res) => {
  if (!needAdmin(req, res)) return;
  const db = loadDB();
  const rec = findKey(db, req.body.key);
  if (!rec) return res.json({ ok: false });
  rec.hwid = null; saveDB(db);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log('grosstar-auth on :' + PORT));
