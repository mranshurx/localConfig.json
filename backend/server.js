const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '1mb' }));
app.use(cors());

/* ================= STORAGE ================= */
const HARD = {
  owner:  'mranshurx',
  repo:   'pc5-android',
  branch: 'main',
  file:   'data/keys.json',
  token:  '',
  providerId: 'ZGD3YGrW'
};

/* Lock-down is the default, not a switch. If the admin clears providerid the
   fallback keeps hide-settings alive instead of silently dropping it. */
const FALLBACK_PROVIDER_ID = 'ZGD3YGrW';

/* ================= SUBSCRIPTION FORMAT ================= */
/*
  'json'    — raw Xray JSON. The exact imported config, served verbatim.
  'b64link' — base64( socks link ). One clean server row, settings hidden.

  JSON mode is the default now: the whole canonical profile (inbounds,
  routing table, outbound) reaches the client instead of a single
  share link, so nothing depends on the client rebuilding the config.
*/
const SUB_FORMAT = 'json';

/* Subscription body encryption (AES-128-GCM, Happ scheme).
   JSON mode does NOT support it — Happ parses the ciphertext as config text and
   reports unknown content — so the switch is hard-gated off here regardless of
   what the environment says. */
const SUB_KEY_ID  = process.env.SUB_KEY_ID  || 'key02';
const SUB_AES_KEY = Buffer.from(process.env.SUB_AES_KEY || 'key02:+]%4ij#P"/', 'utf8');
const SUB_IV      = Buffer.from('kkkkkkkkkkkk', 'utf8');
const SUB_ENCRYPT = SUB_FORMAT !== 'json' && process.env.SUB_ENCRYPT === '1';

const LOCAL_CFG = path.join(__dirname, 'github.json');
const REPO_CFG_PATH = 'data/config.json';
const CFG_KEYS = ['owner', 'repo', 'branch', 'file', 'token', 'providerId'];

function envOverrides() {
  const o = {};
  if (process.env.GITHUB_OWNER) o.owner = process.env.GITHUB_OWNER;
  if (process.env.GITHUB_REPO) o.repo = process.env.GITHUB_REPO;
  if (process.env.GITHUB_BRANCH) o.branch = process.env.GITHUB_BRANCH;
  if (process.env.GITHUB_KEYS_PATH) o.file = process.env.GITHUB_KEYS_PATH;
  if (process.env.GITHUB_TOKEN) o.token = process.env.GITHUB_TOKEN.trim();
  if (process.env.HAPP_PROVIDER_ID) o.providerId = process.env.HAPP_PROVIDER_ID.trim();
  return o;
}

let cfg = { ...HARD, ...envOverrides() };

function loadCfg() {
  try {
    if (fs.existsSync(LOCAL_CFG)) {
      const saved = JSON.parse(fs.readFileSync(LOCAL_CFG, 'utf8'));
      for (const k of CFG_KEYS) {
        if (saved[k]) cfg[k] = String(saved[k]).trim();
      }
      console.log('[cfg] loaded from local github.json');
    }
  } catch (e) { console.warn('[cfg] could not read github.json:', e.message); }
}
function saveCfg() {
  try { fs.writeFileSync(LOCAL_CFG, JSON.stringify(cfg, null, 2)); }
  catch (e) { console.warn('[cfg] could not persist github.json:', e.message); }
}

/* Persist the storage config into the repo so it survives Render restarts. */
async function pushCfgToRepo(creds, snapshot) {
  const c = creds || cfg;
  const body = snapshot || cfg;
  if (!c.token) return;
  try {
    const url = `https://api.github.com/repos/${c.owner}/${c.repo}/contents/${REPO_CFG_PATH}`;
    const cur = await fetch(url, { headers: apiHeaders(c, false) });
    let sha = null;
    if (cur.ok) {
      const j = await cur.json().catch(() => ({}));
      sha = j.sha || null;
    }
    const put = {
      message: 'chore(cfg): update storage config',
      content: Buffer.from(JSON.stringify(body, null, 2), 'utf8').toString('base64'),
      branch: c.branch
    };
    if (sha) put.sha = sha;
    const r = await fetch(url, { method: 'PUT', headers: apiHeaders(c, true), body: JSON.stringify(put) });
    if (!r.ok) console.warn('[cfg] repo persist failed:', r.status);
    else console.log('[cfg] storage config mirrored to repo');
  } catch (e) { console.warn('[cfg] repo persist failed:', e.message); }
}

/* Restore the storage config from the repo when the disk copy is gone. */
let lastPull = 0;
async function pullCfgFromRepo() {
  if (cfg.token) return;
  if (Date.now() - lastPull < 20000) return;
  lastPull = Date.now();
  try {
    const raw = `https://raw.githubusercontent.com/${HARD.owner}/${HARD.repo}/${HARD.branch}/${REPO_CFG_PATH}?t=${Date.now()}`;
    const r = await fetch(raw, { headers: { 'User-Agent': 'pc5-android' } });
    if (!r.ok) return;
    const j = await r.json();
    for (const k of CFG_KEYS) {
      if (j[k]) cfg[k] = String(j[k]).trim();
    }
    saveCfg();
    console.log('[cfg] storage config restored from repo');
  } catch (e) { console.warn('[cfg] repo restore failed:', e.message); }
}

/* Adopt a token supplied by the panel so client requests can write too. */
function adoptToken(req) {
  const t = req.body && req.body.gh && req.body.gh.token;
  if (!t || !String(t).trim()) return;
  const v = String(t).trim();
  if (v === cfg.token) return;
  cfg.token = v;
  saveCfg();
  pushCfgToRepo(cfg, cfg).catch(() => {});
}

function credsFrom(req) {
  const out = { ...cfg };
  const gh = (req.body && req.body.gh) || {};
  for (const k of ['owner', 'repo', 'branch', 'file', 'token']) {
    if (gh[k] && String(gh[k]).trim()) out[k] = String(gh[k]).trim();
  }
  if (!out.branch) out.branch = 'main';
  if (!out.file) out.file = 'data/keys.json';
  if (!out.owner) out.owner = HARD.owner;
  if (!out.repo) out.repo = HARD.repo;
  if (!out.token) out.token = HARD.token || process.env.GITHUB_TOKEN || '';
  out.token = out.token.trim();
  return out;
}
/* Token is deliberately NOT part of the signature: client and admin must share one cache. */
function sigOf(c) { return `${c.owner}/${c.repo}@${c.branch}:${c.file}`; }
function ready(c) { return !!(c.owner && c.repo); }

function tokenShape(t) {
  if (!t) return 'missing';
  if (t.startsWith('ghp_')) return t.length === 40 ? 'classic (looks valid)' : `classic but ${t.length} chars, expected 40`;
  if (t.startsWith('github_pat_')) return 'fine-grained';
  if (t.startsWith('gho_')) return 'oauth';
  return 'unknown prefix';
}

/* ================= ADMIN KEY (remote — no hardcoded secret) ================= */
const ADMIN_KEY_URL = process.env.ADMIN_KEY_URL ||
  'https://raw.githubusercontent.com/mranshurx/new-engine/refs/heads/main/key.txt';
const ADMIN_KEY_TTL = 30000;

let adminKeyState = { value: '', ver: '', at: 0 };

function parseAdminKey(raw) {
  const first = (raw || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)[0] || '';
  let v = first.replace(/^[A-Za-z _-]{0,24}\s*[:=]\s*/, '');
  v = v.replace(/^["'`]+|["'`]+$/g, '').trim();
  return v;
}

function verOf(v) {
  return crypto.createHash('sha256').update(v).digest('hex').slice(0, 16);
}

async function getAdminKey(force) {
  const fresh = adminKeyState.value && Date.now() - adminKeyState.at < ADMIN_KEY_TTL;
  if (!force && fresh) return adminKeyState;

  try {
    const url = `${ADMIN_KEY_URL}${ADMIN_KEY_URL.includes('?') ? '&' : '?'}t=${Date.now()}`;
    const r = await fetch(url, {
      headers: { 'User-Agent': 'pc5-android', 'Cache-Control': 'no-cache' },
      cache: 'no-store'
    });
    if (!r.ok) throw new Error(`GET ${r.status}`);
    const value = parseAdminKey(await r.text());
    if (!value) throw new Error('empty key file');
    if (value !== adminKeyState.value) console.log(`[admin] key rotated -> ${verOf(value)}`);
    adminKeyState = { value, ver: verOf(value), at: Date.now() };
  } catch (e) {
    console.warn('[admin] key source unreachable:', e.message, '— using last known key');
  }
  return adminKeyState;
}

async function requireAdmin(req, res) {
  const state = await getAdminKey(false);
  if (!state.value) {
    res.status(503).json({ error: 'Admin key source unreachable. Try again shortly.' });
    return null;
  }
  const supplied = String((req.body && req.body.adminPass) || '').trim();
  if (supplied !== state.value) {
    res.status(401).json({ error: 'Invalid Admin Password.' });
    return null;
  }
  adoptToken(req);
  return state;
}

/*
  Provider ID — required for hide-settings, which is what removes the server
  address and the whole settings sheet from the client. Hardcoded below and
  overridable via env HAPP_PROVIDER_ID or the admin panel.
*/
function providerId() {
  const v = String(cfg.providerId || process.env.HAPP_PROVIDER_ID || '').trim();
  return v || FALLBACK_PROVIDER_ID;
}

const FRONTEND_DIR = fs.existsSync(path.join(__dirname, '..', 'frontend'))
  ? path.join(__dirname, '..', 'frontend')
  : path.join(__dirname, 'frontend');

const DEFAULT_MAINT = { enabled: false, message: 'System under maintenance.', since: null };
const EMPTY_FEATURES = { aimbot: '', location: '' };
const EMPTY_DB = () => ({ keys: [], maintenance: { ...DEFAULT_MAINT }, features: { ...EMPTY_FEATURES } });

/* ================= GITHUB API ================= */
function apiHeaders(c, json) {
  const h = {
    'User-Agent': 'pc5-android',
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  if (c.token) h.Authorization = `Bearer ${c.token}`;
  if (json) h['Content-Type'] = 'application/json';
  return h;
}

function ghPath(c) {
  return c.file.split('/').map(encodeURIComponent).join('/');
}

async function ghRead(c) {
  if (!ready(c)) return null;
  const encoded = ghPath(c);

  if (!c.token) {
    const raw = `https://raw.githubusercontent.com/${c.owner}/${c.repo}/${encodeURIComponent(c.branch)}/${encoded}?t=${Date.now()}`;
    const r = await fetch(raw, { headers: { 'User-Agent': 'pc5-android' } });
    if (r.status === 404) return { text: null, sha: null };
    if (!r.ok) throw new Error(`raw GET ${r.status}`);
    return { text: await r.text(), sha: null };
  }

  const url = `https://api.github.com/repos/${c.owner}/${c.repo}/contents/${encoded}?ref=${encodeURIComponent(c.branch)}`;
  const r = await fetch(url, { headers: apiHeaders(c, false) });
  if (r.status === 404) return { text: null, sha: null };
  if (r.status === 401) throw new Error('401 bad credentials — token revoked, expired, or mistyped. Classic tokens are auto-revoked when committed to a public repo.');
  if (r.status === 403) throw new Error('403 forbidden — token lacks Contents permission, or rate limit hit');
  if (!r.ok) throw new Error(`Storage GET ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const j = await r.json();
  return { text: Buffer.from(j.content || '', 'base64').toString('utf8'), sha: j.sha || null };
}

async function ghWriteOnce(c, text, sha, useBranch) {
  const encoded = ghPath(c);
  const body = {
    message: 'chore(keys): update license database',
    content: Buffer.from(text, 'utf8').toString('base64')
  };
  if (useBranch) body.branch = c.branch;
  if (sha) body.sha = sha;

  const r = await fetch(`https://api.github.com/repos/${c.owner}/${c.repo}/contents/${encoded}`, {
    method: 'PUT',
    headers: apiHeaders(c, true),
    body: JSON.stringify(body)
  });
  if (r.status === 409 || r.status === 422) {
    return { conflict: true, status: r.status, detail: (await r.text()).slice(0, 300) };
  }
  if (r.status === 401) throw new Error('401 bad credentials — token revoked, expired, or mistyped');
  if (r.status === 403) throw new Error('403 forbidden — token needs Contents: Read and write');
  if (!r.ok) throw new Error(`Storage PUT ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const j = await r.json().catch(() => ({}));
  return { ok: true, sha: (j.content && j.content.sha) || null };
}

async function ghWrite(c, text, sha) {
  if (!ready(c)) throw new Error('Storage not configured');

  /* A client request carries no token — recover the stored one before failing. */
  if (!c.token) {
    await pullCfgFromRepo();
    if (cfg.token) c = { ...c, token: cfg.token };
  }
  if (!c.token) throw new Error('No storage token — save one in the admin panel');

  let r = await ghWriteOnce(c, text, sha, true);

  if (r && r.conflict && r.status === 422) {
    console.warn('[gh] 422 with branch, retrying without it:', r.detail);
    r = await ghWriteOnce(c, text, sha, false);
  }
  return r;
}

/* ================= CACHE + SERIALIZED WRITES ================= */
let cache = { data: null, sha: null, at: 0, sig: '' };
const TTL = 5000;
let queue = Promise.resolve();
function enqueue(fn) { queue = queue.then(fn, fn); return queue; }

async function getDb(force, c) {
  c = c || cfg;
  if (!ready(c)) return EMPTY_DB();
  const sig = sigOf(c);

  if (!force && cache.data && cache.sig === sig && Date.now() - cache.at < TTL) return cache.data;

  const f = await ghRead(c);
  let db;
  try { db = f && f.text ? JSON.parse(f.text) : null; } catch (e) { db = null; }
  if (!db || typeof db !== 'object') db = EMPTY_DB();
  if (!Array.isArray(db.keys)) db.keys = [];
  if (!db.maintenance) db.maintenance = { ...DEFAULT_MAINT };
  if (!('since' in db.maintenance)) db.maintenance.since = null;
  if (!db.features || typeof db.features !== 'object') db.features = { ...EMPTY_FEATURES };
  if (typeof db.features.aimbot !== 'string') db.features.aimbot = '';
  if (typeof db.features.location !== 'string') db.features.location = '';
  db.keys.forEach(migrateRecord);

  cache = { data: db, sha: f ? f.sha : null, at: Date.now(), sig };
  return db;
}

async function putDb(db, c) {
  c = c || cfg;
  const text = JSON.stringify(db, null, 2);
  const sig = sigOf(c);
  return enqueue(async () => {
    let sha = (cache.sig === sig) ? cache.sha : null;
    if (!sha) {
      const f = await ghRead(c);
      sha = f ? f.sha : null;
    }
    let r = await ghWrite(c, text, sha);
    if (r && r.conflict) {
      const f = await ghRead(c);
      r = await ghWrite(c, text, f ? f.sha : null);
    }
    if (!r || !r.ok) throw new Error('Storage write failed');
    cache = { data: db, sha: r.sha, at: Date.now(), sig };
    return r;
  });
}

/* Work on a clone: if the write throws, the cache keeps the untouched source state
   and the next call retries cleanly instead of reading a half-applied mutation. */
async function mutate(c, fn) {
  const db = await getDb(true, c);
  const work = JSON.parse(JSON.stringify(db));
  const out = await fn(work);
  await putDb(work, c);
  return out;
}

/* ================= DURATION ================= */
function parseDuration(body) {
  body = body || {};
  if (body.days != null) {
    const d = Number(body.days);
    if (Number.isFinite(d) && d > 0) return Math.round(d * 24);
  }
  for (const field of ['durationHours', 'duration', 'hours']) {
    if (body[field] != null) {
      const n = Number(body[field]);
      if (Number.isFinite(n) && n > 0) return Math.round(n);
    }
  }
  console.warn('[duration] nothing usable in body — defaulting to 24h:', JSON.stringify(body));
  return 24;
}
function normalizeHours(h) {
  const n = Number(h);
  return (Number.isFinite(n) && n > 0) ? Math.round(n) : 24;
}

/* ================= DEVICE LIMIT ================= */
/* 0 = unlimited devices, 1 = single device (HWID locked on first unlock) */
function parseDeviceLimit(body) {
  body = body || {};
  const v = body.deviceLimit;
  if (v === 'single' || v === 'one' || v === '1' || v === 1) return 1;
  if (body.maxDevices != null) {
    const n = Number(body.maxDevices);
    if (n === 1) return 1;
  }
  return 0;
}

/* Normalize whatever the client sends into a compact id we can store safely. */
function deviceOf(req) {
  const raw = String(
    (req.query && (req.query.did || req.query.device || req.query.hwid)) ||
    req.headers['x-device-id'] || ''
  ).trim();
  return raw.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 48);
}
function deviceUa(req) {
  return String((req.headers && req.headers['user-agent']) || '').slice(0, 200);
}

function migrateRecord(r) {
  if (r.durationHours == null) {
    const c = r.createdAt ? new Date(r.createdAt).getTime() : 0;
    const e = r.expiresAt ? new Date(r.expiresAt).getTime() : 0;
    const d = (e - c) / 3600000;
    r.durationHours = (d > 0 && Math.round(d) !== 24) ? Math.round(d) : 24;
  } else {
    r.durationHours = normalizeHours(r.durationHours);
  }
  if (r.startedAt == null) r.startedAt = r.activatedAt || null;
  if (r.expiresAt && !r.activatedAt) r.activatedAt = r.createdAt || new Date().toISOString();

  if (r.maxDevices == null) {
    r.maxDevices = (r.deviceLimit === 'single' || r.deviceLimit === 1 || r.deviceLimit === 'one') ? 1 : 0;
  }
  r.maxDevices = (Number(r.maxDevices) === 1) ? 1 : 0;
  r.deviceLimit = r.maxDevices === 1 ? 'single' : 'unlimited';
  if (!Array.isArray(r.devices)) r.devices = [];
  r.devices = r.devices
    .filter(d => d && d.id)
    .map(d => ({ id: String(d.id).slice(0, 48), firstSeen: d.firstSeen || null, lastSeen: d.lastSeen || null, ua: d.ua || '' }));
}

/* ================= KEY RESOLUTION ================= */
/* Binds the device on a single-device key the first time it is seen. */
async function bindDevice(c, key, did, ua) {
  return mutate(c, db => {
    const rec = db.keys.find(k => k.key === key);
    if (!rec) return null;
    if (!Array.isArray(rec.devices)) rec.devices = [];
    const now = new Date().toISOString();
    const known = rec.devices.find(d => d.id === did);
    if (known) {
      known.lastSeen = now;
      if (ua) known.ua = ua;
    } else if (rec.maxDevices === 1 && rec.devices.length === 0) {
      rec.devices.push({ id: did, firstSeen: now, lastSeen: now, ua: ua || '' });
      console.log(`[device] locked ${rec.key} -> ${did}`);
    }
    return rec;
  });
}

/* ================= MAINTENANCE CLOCK ================= */
/*
  Wall time spent in maintenance is never charged to the buyer. Two halves:

  - live  : effectiveExpiry() adds the *running* maintenance window on the fly,
            so no key reads as expired while the pause is in progress.
  - settle: when maintenance is switched off the window is written into every
            key's expiresAt, so the credit survives restarts and later reads.

  Only the overlap between the pause and the key's own active span is credited,
  so a key that was already dead before maintenance started gets nothing, and a
  key sold *during* maintenance only gets credited from its activation.
*/

function maintStart(db) {
  const m = (db && db.maintenance) || {};
  if (!m.enabled || !m.since) return null;
  const t = new Date(m.since).getTime();
  return Number.isFinite(t) ? t : null;
}

function effectiveExpiry(rec, since) {
  if (!rec || !rec.expiresAt) return null;
  const exp = new Date(rec.expiresAt).getTime();
  if (!Number.isFinite(exp)) return null;
  if (!since) return exp;
  const act = rec.activatedAt ? new Date(rec.activatedAt).getTime() : since;
  const from = Math.max(since, Number.isFinite(act) ? act : since);
  if (from >= exp) return exp;
  return exp + (Date.now() - from);
}

function settleMaintenance(db, startMs, endMs) {
  let credited = 0;
  for (const rec of db.keys) {
    if (!rec.expiresAt) continue;
    const exp = new Date(rec.expiresAt).getTime();
    if (!Number.isFinite(exp)) continue;
    const act = rec.activatedAt ? new Date(rec.activatedAt).getTime() : startMs;
    const from = Math.max(startMs, Number.isFinite(act) ? act : startMs);
    const to = Math.min(endMs, exp);
    const credit = to - from;
    if (credit <= 0) continue;
    rec.expiresAt = new Date(exp + credit).toISOString();
    rec.maintenancePausedMs = (Number(rec.maintenancePausedMs) || 0) + credit;
    credited++;
  }
  return credited;
}

/*
  Returns { ok, reason, record }.
  reason: invalid | expired | no-device | device-mismatch
*/
async function accessKey(key, c, did, ua) {
  let db = await getDb(false, c);
  let r = db.keys.find(k => k.key === key);
  if (!r) return { ok: false, reason: 'invalid' };

  if (!r.activatedAt) {
    const now = Date.now();
    const hours = normalizeHours(r.durationHours);
    const startedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + hours * 3600000).toISOString();
    const before = r;

    try {
      r = await mutate(c, fresh => {
        const rec = fresh.keys.find(k => k.key === key);
        if (!rec) return null;
        if (rec.activatedAt) return rec;
        rec.activatedAt = startedAt;
        rec.startedAt = startedAt;
        rec.durationHours = hours;
        rec.expiresAt = expiresAt;
        console.log(`[key] activated ${rec.key} -> ${rec.durationHours}h, expires ${rec.expiresAt}`);
        return rec;
      });
      if (!r) return { ok: false, reason: 'invalid' };
    } catch (e) {
      /* Never block the buyer on a storage hiccup — serve it in memory,
         the cache still holds the unactivated record so the next call retries. */
      console.warn('[key] activation write failed, serving in-memory:', e.message);
      r = { ...before, activatedAt: startedAt, startedAt, durationHours: hours, expiresAt };
    }
  }

  /* Test against the paused clock, not the raw stamp, so a key cannot die
     while the service is down. */
  const expMs = effectiveExpiry(r, maintStart(db));
  if (expMs == null || Date.now() > expMs) {
    return { ok: false, reason: 'expired', record: r };
  }

  if (r.maxDevices === 1) {
    if (!did) return { ok: false, reason: 'no-device', record: r };

    const bound = (r.devices || [])[0];
    if (bound && bound.id !== did) {
      return { ok: false, reason: 'device-mismatch', record: r };
    }

    if (!bound) {
      try {
        const updated = await bindDevice(c, key, did, ua);
        if (updated) r = updated;
        else r = { ...r, devices: [{ id: did, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), ua: ua || '' }] };
      } catch (e) {
        console.warn('[device] lock write failed, serving in-memory:', e.message);
        r = { ...r, devices: [{ id: did, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), ua: ua || '' }] };
      }
    }
  }

  return { ok: true, record: r };
}

const REASON_TEXT = {
  'invalid': 'Invalid key.',
  'expired': 'Key has expired.',
  'no-device': 'Device could not be identified. Reopen the app.',
  'device-mismatch': 'This key is locked to another device.'
};

/* ================= ROUTING CONFIG ================= */
/*
  Upstream: SOCKS5 on 189.72.183.154, port 8443, TLS with SNI
  serv.aimhack.shop, and a user:pass credential.

  /sub is delivered as raw Xray JSON (SUB_FORMAT = 'json'). The whole canonical
  profile — inbounds, outbound, routing table — reaches Happ intact, so nothing
  depends on the client rebuilding the config from a share link.

  With providerid + hide-settings the profile cannot be opened in the client,
  so the address, port and credential never reach the user's eyes.

  If you switch back to 'b64link', the body becomes base64( socks link )
  and encryption becomes available again — see SUB_ENCRYPT above.
*/
const DEFAULT_NODE_AUTH = 'AMHK-20CA-7B9E-0330:AMHK-20CA-7B9E-0330';
const NODE_HOST = '189.72.183.154';
const NODE_PORT = 8443;
const NODE_SNI = 'serv.aimhack.shop';
const PROFILE_NAME = 'PC5 ANDROID';

/* Auth handed to the node while the key is dead. The server rejects it, so the
   handshake dies and the client reports a genuine failure instead of a fake ping. */
const DEAD_AUTH = 'PC5-BLOCKED:0';

const PER_APP_LIST = 'com.garena.game.ffi,com.dts.freefiremax';

/* ================= BASE XRAY CONFIG (imported) ================= */
/*
  Canonical tunnel profile, kept verbatim from the exported config so the
  routing table and outbound live in exactly one place.

  buildConfig() deep-clones this and patches only the fields that vary per
  request (remarks label, socks credential, address, port). Nothing here is ever
  mutated in place, so a blocked key, a feature auth or a host override can
  never leak into the next response.
*/
const BASE_CONFIG = {
  log: {
    loglevel: 'warning'
  },
  inbounds: [
    {
      tag: 'socks',
      listen: '127.0.0.1',
      port: 10808,
      protocol: 'socks',
      settings: {
        auth: 'noauth',
        udp: true
      },
      sniffing: {
        enabled: true,
        destOverride: ['http', 'tls', 'quic'],
        routeOnly: false
      }
    },
    {
      tag: 'http',
      listen: '127.0.0.1',
      port: 10809,
      protocol: 'http',
      sniffing: {
        enabled: true,
        destOverride: ['http', 'tls', 'quic'],
        routeOnly: false
      }
    }
  ],
  outbounds: [
    {
      tag: 'proxy',
      protocol: 'socks',
      settings: {
        servers: [
          {
            address: '189.72.183.154',
            port: 8443,
            users: [
              {
                user: 'AMHK-20CA-7B9E-0330',
                pass: 'AMHK-20CA-7B9E-0330'
              }
            ]
          }
        ]
      },
      streamSettings: {
        network: 'tcp',
        security: 'tls',
        tlsSettings: {
          serverName: 'serv.aimhack.shop'
        }
      }
    },
    {
      tag: 'direct',
      protocol: 'freedom'
    }
  ],
  routing: {
    domainStrategy: 'AsIs',
    rules: [
      {
        type: 'field',
        domain: [
          'full:clientbp.ggpolarbear.com',
          'full:loginbp.ggpolarbear.com',
          'full:core-bs.ggpolarbear.com',
          'full:core-bs.freefiremobile.com',
          'full:core-tata.freefireind.in',
          'full:core-gmc.freefiremobile.com',
          'full:client.ind.freefiremobile.com',
          'full:client.us.freefiremobile.com',
          'full:sgnetwork.ggblueshark.com',
          'full:menetwork.ggblueshark.com',
          'full:bdnetwork.ggpolarbear.com',
          'full:100067.connect.garena.com',
          'full:100067.msdk.garena.com',
          'full:clientbp.ppmainecoonghj.com',
          'full:loginbp.ppmainecoonghj.com',
          'full:ffmconnect.ppmainecoonghj.com',
          'full:ffmmsdk.ppmainecoonghj.com',
          'regexp:^(clientbp|loginbp|core-[a-z0-9]+|[a-z]+network|ffmconnect|ffmmsdk)\\.'
        ],
        outboundTag: 'proxy'
      },
      {
        type: 'field',
        ip: [
          '0.0.0.0/24',
          '101.32.114.0/23',
          '101.33.44.0/22',
          '102.217.238.0/24',
          '103.103.244.0/24',
          '103.108.100.0/22',
          '103.117.4.0/22',
          '103.123.54.0/23',
          '103.127.228.0/22',
          '103.16.32.0/22',
          '103.215.127.0/24',
          '103.219.200.0/22',
          '103.237.102.0/23',
          '103.247.204.0/22',
          '103.248.57.0/24',
          '103.248.58.0/23',
          '103.52.145.0/24',
          '103.60.16.0/22',
          '103.62.54.0/24',
          '103.69.179.0/24',
          '104.166.132.0/23',
          '104.166.144.0/22',
          '104.166.148.0/22',
          '104.166.175.0/24',
          '104.166.185.0/24',
          '104.166.191.0/24',
          '107.151.141.0/24',
          '107.151.192.0/24',
          '107.151.193.0/24',
          '107.151.240.0/24',
          '107.151.241.0/24',
          '107.151.242.0/24',
          '124.108.136.0/22',
          '124.108.140.0/23',
          '124.108.149.0/24',
          '124.108.150.0/23',
          '124.108.152.0/21',
          '124.108.160.0/21',
          '124.108.172.0/22',
          '124.108.191.0/24',
          '124.156.200.0/22',
          '124.156.204.0/22',
          '124.158.133.0/24',
          '124.158.134.0/23',
          '124.158.142.0/23',
          '128.1.113.0/24',
          '128.1.189.0/24',
          '128.1.200.0/24',
          '128.1.63.0/24',
          '128.14.102.0/23',
          '128.14.136.0/23',
          '128.14.206.0/24',
          '128.14.38.0/24',
          '128.14.63.0/24',
          '128.14.89.0/24',
          '129.226.144.0/24',
          '129.226.200.0/22',
          '129.226.220.0/22',
          '134.168.233.0/24',
          '134.168.234.0/24',
          '139.180.158.0/24',
          '143.92.112.0/23',
          '143.92.116.0/23',
          '143.92.118.0/24',
          '143.92.120.0/21',
          '148.153.101.0/24',
          '148.153.11.0/24',
          '148.153.112.0/23',
          '148.153.116.0/23',
          '148.153.143.0/24',
          '148.153.168.0/22',
          '148.153.206.0/23',
          '148.153.222.0/24',
          '148.153.246.0/24',
          '148.153.248.0/23',
          '148.153.67.0/24',
          '148.153.84.0/23',
          '148.153.92.0/23',
          '148.222.64.0/20',
          '148.222.80.0/22',
          '148.222.84.0/23',
          '148.222.88.0/21',
          '149.28.55.0/24',
          '15.235.220.0/24',
          '15.235.231.0/24',
          '15.235.233.0/24',
          '150.109.24.0/22',
          '150.129.42.0/24',
          '152.233.63.0/24',
          '154.203.154.0/23',
          '154.206.73.0/24',
          '154.223.134.0/23',
          '154.93.32.0/24',
          '154.93.46.0/24',
          '154.93.86.0/24',
          '154.95.68.0/24',
          '154.95.81.0/24',
          '156.227.242.0/24',
          '156.59.144.0/23',
          '156.59.154.0/24',
          '156.59.194.0/23',
          '156.59.242.0/23',
          '156.59.251.0/24',
          '156.59.64.0/22',
          '156.59.70.0/23',
          '162.128.241.0/24',
          '162.128.242.0/24',
          '162.128.249.0/24',
          '162.128.32.0/24',
          '162.128.54.0/24',
          '162.128.61.0/24',
          '162.128.80.0/24',
          '162.128.82.0/24',
          '163.227.196.0/24',
          '163.53.247.0/24',
          '169.197.96.0/22',
          '185.23.183.0/24',
          '192.169.117.0/24',
          '192.169.124.0/23',
          '193.118.34.0/23',
          '194.26.72.0/24',
          '198.44.169.0/24',
          '199.182.238.0/24',
          '202.181.64.0/23',
          '202.181.67.0/24',
          '202.181.68.0/24',
          '202.181.70.0/23',
          '202.181.72.0/21',
          '202.181.80.0/21',
          '202.73.16.0/21',
          '202.81.100.0/23',
          '202.81.104.0/21',
          '202.81.112.0/20',
          '202.81.96.0/22',
          '204.3.212.0/24',
          '207.148.69.0/24',
          '210.17.80.0/24',
          '23.236.112.0/23',
          '23.251.37.0/24',
          '23.251.41.0/24',
          '23.251.51.0/24',
          '23.251.61.0/24',
          '23.90.133.0/24',
          '23.90.134.0/24',
          '23.90.141.0/24',
          '34.126.122.0/24',
          '34.126.175.0/24',
          '34.126.239.0/24',
          '34.126.81.0/24',
          '34.87.109.0/24',
          '34.87.170.0/24',
          '34.87.24.0/24',
          '35.185.188.0/24',
          '35.187.246.0/24',
          '35.198.211.0/24',
          '35.198.221.0/24',
          '38.54.120.0/24',
          '38.54.21.0/24',
          '38.54.44.0/23',
          '38.54.70.0/24',
          '38.54.78.0/23',
          '43.128.121.0/24',
          '43.129.35.0/24',
          '43.129.43.0/24',
          '43.133.146.0/24',
          '43.133.150.0/24',
          '43.133.153.0/24',
          '43.133.154.0/24',
          '43.133.40.0/24',
          '43.133.41.0/24',
          '43.134.101.0/24',
          '43.134.103.0/24',
          '43.134.118.0/24',
          '43.134.168.0/24',
          '43.134.170.0/24',
          '43.134.182.0/24',
          '43.134.232.0/24',
          '43.134.233.0/24',
          '43.134.241.0/24',
          '43.134.28.0/24',
          '43.134.45.0/24',
          '43.134.64.0/24',
          '43.134.90.0/24',
          '43.134.94.0/24',
          '43.152.104.0/24',
          '43.152.105.0/24',
          '43.153.208.0/24',
          '43.153.209.0/24',
          '43.153.215.0/24',
          '43.156.134.0/24',
          '43.156.14.0/24',
          '43.156.141.0/24',
          '43.156.151.0/24',
          '43.156.167.0/24',
          '43.156.177.0/24',
          '43.156.199.0/24',
          '43.156.200.0/24',
          '43.156.203.0/24',
          '43.156.205.0/24',
          '43.156.209.0/24',
          '43.156.26.0/24',
          '43.156.31.0/24',
          '43.156.40.0/24',
          '43.156.7.0/24',
          '43.157.195.0/24',
          '43.157.197.0/24',
          '43.157.200.0/24',
          '43.157.204.0/24',
          '43.157.206.0/24',
          '43.157.208.0/24',
          '43.157.209.0/24',
          '43.157.210.0/24',
          '43.157.211.0/24',
          '43.157.224.0/24',
          '43.157.227.0/24',
          '43.157.228.0/24',
          '43.157.230.0/24',
          '43.157.242.0/24',
          '43.157.250.0/24',
          '43.157.251.0/24',
          '43.163.105.0/24',
          '43.163.108.0/24',
          '43.163.119.0/24',
          '43.163.126.0/24',
          '43.163.88.0/24',
          '43.163.96.0/24',
          '43.173.0.0/23',
          '43.173.170.0/24',
          '43.173.171.0/24',
          '43.173.2.0/23',
          '43.173.29.0/24',
          '43.252.184.0/22',
          '43.252.210.0/24',
          '45.119.216.0/22',
          '45.119.240.0/22',
          '45.121.212.0/24',
          '45.251.28.0/22',
          '59.153.158.0/24',
          '60.199.50.0/24',
          '66.253.15.0/24',
          '82.200.131.0/24',
          '98.96.251.0/24',
          '98.98.12.0/22',
          '98.98.140.0/23',
          '98.98.162.0/24',
          '98.98.189.0/24',
          '98.98.220.0/23',
          '98.98.29.0/24',
          '98.98.32.0/24',
          '98.98.33.0/24',
          '98.98.34.0/24'
        ],
        outboundTag: 'proxy'
      },
      {
        type: 'field',
        network: 'tcp',
        port: '39000-39999',
        outboundTag: 'proxy'
      },
      {
        type: 'field',
        network: 'udp',
        port: '10000-10999',
        outboundTag: 'proxy'
      },
      {
        type: 'field',
        domain: [
          'full:event-vodka.freefireind.in',
          'full:indevent.ggblueshark.com',
          'full:sgevent.ggblueshark.com',
          'full:meevent.ggblueshark.com',
          'full:thevent.ggblueshark.com',
          'full:sacevent.ggblueshark.com',
          'full:idevent.ggblueshark.com',
          'full:bdevent.ggpolarbear.com',
          'regexp:event\\.gg(blueshark|polarbear)\\.com$',
          'full:gin.freefireind.in',
          'full:gin.freefiremobile.com',
          'full:vodka.freefireind.in',
          'full:dl.castle.freefiremobile.com',
          'full:dl.cdn.freefiremobile.com',
          'full:dl-core.cdn.freefiremobile.com',
          'full:dl.gmc.freefiremobile.com',
          'full:dl.aw.freefiremobile.com',
          'full:dl.dir.freefiremobile.com',
          'full:dl.bs.freefiremobile.com',
          'full:dl.ak.freefiremobile.com',
          'full:dl-sg-production.freefiremobile.com',
          'full:dl-tata.freefireind.in',
          'full:dl-bs.ggpolarbear.com',
          'domain:freefiremobile-a.akamaihd.net',
          'full:client.aimhack.shop'
        ],
        outboundTag: 'direct'
      },
      {
        type: 'field',
        network: 'tcp,udp',
        outboundTag: 'direct'
      }
    ]
  }
};

/* Splits a user:pass credential, tolerating colons inside the password. */
function splitAuth(cred) {
  const i = cred.indexOf(':');
  if (i < 0) return [cred, ''];
  return [cred.slice(0, i), cred.slice(i + 1)];
}

/* Full Xray config — clones BASE_CONFIG, then applies the per-request
   label / credential / address / port. Fresh object every call. */
function buildConfig(blocked, label, auth, host, port) {
  const addr = host || NODE_HOST;
  const prt = Number(port) || NODE_PORT;
  const cred = blocked ? DEAD_AUTH : (auth || DEFAULT_NODE_AUTH);
  const [user, pass] = splitAuth(cred);

  const outCfg = JSON.parse(JSON.stringify(BASE_CONFIG));
  outCfg.remarks = label;

  const proxyOut = Array.isArray(outCfg.outbounds)
    ? outCfg.outbounds.find(o => o && o.tag === 'proxy') || outCfg.outbounds[0]
    : null;

  if (proxyOut && proxyOut.settings) {
    const s = proxyOut.settings;
    if (Array.isArray(s.servers) && s.servers[0]) {
      s.servers[0].address = addr;
      s.servers[0].port = prt;
      if (Array.isArray(s.servers[0].users) && s.servers[0].users[0]) {
        s.servers[0].users[0].user = user;
        s.servers[0].users[0].pass = pass;
      }
    }
    if ('address' in s) s.address = addr;
    if ('port' in s) s.port = prt;
  }

  /* SNI is fixed on the proxy outbound — a host override must not leave the
     handshake pointing at the old name. */
  if (proxyOut && proxyOut.streamSettings && proxyOut.streamSettings.tlsSettings) {
    proxyOut.streamSettings.tlsSettings.serverName = NODE_SNI;
  }

  return outCfg;
}

/* The same proxy outbound as a socks share link — used by 'b64link' mode.
   SOCKS links carry base64url( user:pass ) as the userinfo. */
function buildLink(blocked, label, auth, host, port) {
  const addr = host || NODE_HOST;
  const prt = Number(port) || NODE_PORT;
  const cred = blocked ? DEAD_AUTH : (auth || DEFAULT_NODE_AUTH);
  const b64 = Buffer.from(cred, 'utf8').toString('base64url');
  return `socks://${b64}@${addr}:${prt}#${encodeURIComponent(label)}`;
}

/*
  Always emits a valid body — a blocked key gets a real outbound with a rejected
  credential rather than an empty body, so the profile stays mounted and simply
  fails to connect.

  JSON mode returns the config object. b64link mode returns base64( link ).
  No comment lines: directives travel in the response headers instead, where
  they cannot corrupt the payload.
*/
function subConfig(blocked, label, auth, host, port) {
  const outCfg = buildConfig(blocked, label, auth, host, port);
  if (SUB_FORMAT === 'json') return JSON.stringify(outCfg, null, 2);
  return Buffer.from(buildLink(blocked, label, auth, host, port), 'utf8').toString('base64');
}

/* AES-128-GCM. Happ wants the tag in its own header, base64'd — not appended
   to the ciphertext, and not inside the body. Only used in b64link mode. */
function encryptBody(text) {
  const cipher = crypto.createCipheriv('aes-128-gcm', SUB_AES_KEY, SUB_IV);
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { body: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

/* ================= FEATURE MODES ================= */
/* aimbot | location. Each mode may carry its own socks user:pass. */
const FEATURE_MODES = ['aimbot', 'location'];
const FEATURE_LABEL = { aimbot: 'AIMBOT', location: 'LOCATION + AIMBOT' };

function cleanAuth(v) {
  const s = String(v == null ? '' : v).trim();
  if (!s) return '';
  if (!s.includes(':')) return null;              /* must be user:pass */
  const [u, p] = s.split(':');
  if (!u.trim() || !p.trim()) return null;
  return s.slice(0, 160);
}

/* Auth for a mode. Empty string means "use the built-in default". */
function authFor(db, mode) {
  const f = (db && db.features) || {};
  if (mode && FEATURE_MODES.includes(mode) && f[mode]) return f[mode];
  return '';
}

/* ================= SUBSCRIPTION BODY ================= */
const PROFILE_TITLE = 'PC5 ANDROID';

/* ================= HAPP CRYPT ================= */
/* crypto.happ.su returns a happ://cryptN/... deep link wrapping the sub URL. */
const happLinkCache = new Map();
const HAPP_CACHE_TTL = 10 * 60 * 1000;
const HAPP_CACHE_MAX = 500;

function happCacheGet(k) {
  const hit = happLinkCache.get(k);
  if (!hit) return null;
  if (Date.now() - hit.at > HAPP_CACHE_TTL) { happLinkCache.delete(k); return null; }
  return hit.link;
}
function happCacheSet(k, link) {
  if (happLinkCache.size >= HAPP_CACHE_MAX) {
    const oldest = happLinkCache.keys().next().value;
    if (oldest) happLinkCache.delete(oldest);
  }
  happLinkCache.set(k, { link, at: Date.now() });
}
/* Drop every cached link for a key so a mode/auth change is picked up at once. */
function happCacheDrop(key) {
  for (const k of [...happLinkCache.keys()]) {
    if (!key || k.startsWith(key + '|')) happLinkCache.delete(k);
  }
}

function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  return `${proto}://${req.get('host')}`;
}

function encryptHappLink(subUrl) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };

    const body = JSON.stringify({ url: subUrl });
    const req = https.request({
      hostname: 'crypto.happ.su', path: '/api-v2.php', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          const link = j && j.encrypted_link ? String(j.encrypted_link).trim() : null;
          done(link && link.startsWith('happ://') ? link : null);
        } catch (e) { done(null); }
      });
      res.on('error', () => done(null));
    });
    req.on('error', () => done(null));
    req.setTimeout(6000, () => { req.destroy(); done(null); });
    req.write(body);
    req.end();
  });
}

/* ================= PUBLIC API ================= */
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const db = await getDb(false, credsFrom(req));
    const m = { ...DEFAULT_MAINT, ...(db.maintenance || {}) };
    const since = maintStart(db);
    if (since) m.pausedMs = Math.max(0, Date.now() - since);
    res.json(m);
  } catch (e) {
    res.json(DEFAULT_MAINT);
  }
});

/* Which modes currently have an auth configured — drives the client badges. */
app.get('/api/features', async (req, res) => {
  try {
    const db = await getDb(false, credsFrom(req));
    const f = db.features || {};
    res.json({ aimbot: !!f.aimbot, location: !!f.location });
  } catch (e) {
    res.json({ aimbot: false, location: false });
  }
});

app.get('/api/happ-link', async (req, res) => {
  const { key } = req.query;
  const mode = String(req.query.mode || '').toLowerCase();
  if (!key) return res.json({ ok: false, reason: 'no-key' });
  try {
    const c = credsFrom(req);
    const did = deviceOf(req);
    const out = await accessKey(key, c, did, deviceUa(req));
    if (!out.ok) return res.json({ ok: false, reason: out.reason, message: REASON_TEXT[out.reason] });

    const m = FEATURE_MODES.includes(mode) ? mode : '';
    /* k = license, key = AES key id. Encryption only adds `key` when it is on. */
    const subUrl = `${baseUrl(req)}/sub?k=${encodeURIComponent(key)}${did ? `&did=${encodeURIComponent(did)}` : ''}${m ? `&mode=${m}` : ''}${SUB_ENCRYPT ? `&key=${encodeURIComponent(SUB_KEY_ID)}` : ''}`;
    const cacheKey = `${key}|${did}|${m}|${SUB_ENCRYPT ? SUB_KEY_ID : '-'}`;
    const cachedLink = happCacheGet(cacheKey);
    if (cachedLink) return res.json({ ok: true, link: cachedLink, raw: subUrl, mode: m, encrypted: true });

    let link = await encryptHappLink(subUrl);
    if (!link) link = await encryptHappLink(subUrl);   // one retry, then accept the raw URL
    if (link) happCacheSet(cacheKey, link);
    return res.json({ ok: true, link: link || subUrl, raw: subUrl, encrypted: !!link, mode: m });
  } catch (e) {
    return res.json({ ok: false, reason: 'storage-error', detail: e.message });
  }
});

app.get('/sub', async (req, res) => {
  res.setHeader('profile-update-interval', '1');
  res.setHeader('profile-title', PROFILE_TITLE);
  res.setHeader('subscription-auto-update-enable', '1');
  res.setHeader('subscription-auto-update-open-enable', '1');
  res.setHeader('per-app-proxy-mode', 'on');
  res.setHeader('per-app-proxy-list', PER_APP_LIST);
  res.setHeader('subscriptions-collapse', '0');
  res.setHeader('Cache-Control', 'no-store');

  /*
    Unconditional. hide-settings only applies with a providerid, so both go
    out together or neither does.
  */
  res.setHeader('providerid', providerId());
  res.setHeader('hide-settings', '1');
  res.setHeader('manual-block-user-agent', '1');
  res.setHeader('subscription-always-hwid-enable', '1');
  res.setHeader('dont-use-filter', '1');

  res.setHeader('content-disposition', 'attachment; filename="pc5-android.txt"');
  res.setHeader('Content-Type', SUB_FORMAT === 'json'
    ? 'application/json; charset=utf-8'
    : 'text/plain; charset=utf-8');

  const reqMode = String(req.query.mode || '').toLowerCase();
  const mode = FEATURE_MODES.includes(reqMode) ? reqMode : '';

  let body;
  try {
    const c = credsFrom(req);
    const db = await getDb(false, c);
    const m = db.maintenance || DEFAULT_MAINT;

    if (m.enabled) {
      res.setHeader('x-pc5-status', 'maintenance');
      body = subConfig(true, `${PROFILE_NAME} — MAINTENANCE`);
    } else {
      /* k = license. Bare `key` is either the AES key id or a legacy link. */
      const legacy = String(req.query.key || '');
      const key = String(req.query.k || (/^key\d+$/.test(legacy) ? '' : legacy)).trim();
      const did = deviceOf(req);
      const out = key ? await accessKey(key, c, did, deviceUa(req)) : { ok: false, reason: 'invalid' };
      if (!out.ok) {
        res.setHeader('x-pc5-status', out.reason);
        body = subConfig(true, `${PROFILE_NAME} — ${(REASON_TEXT[out.reason] || 'SUBSCRIPTION EXPIRED').toUpperCase()}`);
      } else {
        /* Advertised expiry uses the paused clock so the date does not creep
           forward in the client while the service is down. */
        const liveExpiry = effectiveExpiry(out.record, maintStart(db));
        const tag = mode ? ` · ${FEATURE_LABEL[mode]}` : '';
        res.setHeader('x-pc5-status', 'ok');
        if (mode) res.setHeader('x-pc5-mode', mode);
        res.setHeader('subscription-userinfo', `upload=0; download=0; total=107374182400; expire=${Math.floor(liveExpiry / 1000)}`);
        body = subConfig(false, PROFILE_NAME + tag, authFor(db, mode));
      }
    }
  } catch (e) {
    res.setHeader('x-pc5-status', 'storage-error');
    body = subConfig(true, `${PROFILE_NAME} — SUBSCRIPTION EXPIRED OR TERMINATED`);
  }

  /* JSON mode is never encrypted — SUB_ENCRYPT is already false for it. */
  if (SUB_ENCRYPT) {
    const enc = encryptBody(body);
    res.setHeader('encrypt-tag', enc.tag);
    return res.status(200).send(enc.body);
  }
  return res.status(200).send(body);
});

app.get('/api/check-key', async (req, res) => {
  try {
    const c = credsFrom(req);
    const db = await getDb(false, c);
    const m = db.maintenance || DEFAULT_MAINT;
    const since = maintStart(db);
    const { key } = req.query;

    if (!key) {
      return res.json({
        valid: false,
        maintenance: !!m.enabled,
        message: m.enabled ? m.message : "Please enter an access key."
      });
    }

    const known = db.keys.find(k => k.key === key);
    if (!known) {
      return res.json({ valid: false, maintenance: !!m.enabled, message: m.enabled ? m.message : "Invalid key." });
    }

    const out = await accessKey(key, c, deviceOf(req), deviceUa(req));
    const record = out.record || known;
    const expMs = effectiveExpiry(record, since);
    const remainingMs = expMs == null ? null : Math.max(0, expMs - Date.now());

    const payload = {
      key: record.key,
      startedAt: record.startedAt || record.activatedAt,
      activatedAt: record.activatedAt,
      expiresAt: record.expiresAt,
      durationHours: record.durationHours,
      remainingMs,
      deviceLimit: record.maxDevices === 1 ? 'single' : 'unlimited',
      deviceLocked: record.maxDevices === 1 && (record.devices || []).length > 0,
      deviceCount: (record.devices || []).length,
      features: { aimbot: !!db.features.aimbot, location: !!db.features.location }
    };

    /* Maintenance still reports the key as good and hands over a frozen
       remainingMs, so the countdown holds instead of draining to zero. */
    if (m.enabled) {
      return res.json({
        ...payload,
        valid: out.ok,
        maintenance: true,
        paused: true,
        pausedMs: since ? Math.max(0, Date.now() - since) : 0,
        message: m.message
      });
    }

    if (!out.ok) {
      return res.json({
        ...payload,
        valid: false,
        reason: out.reason,
        message: REASON_TEXT[out.reason] || "Invalid key."
      });
    }

    return res.json({ ...payload, valid: true, message: "Access Key Validated!" });
  } catch (e) {
    return res.json({ valid: false, message: "Storage error: " + e.message });
  }
});

/* ================= ADMIN ================= */
app.post('/api/admin/login', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  return res.json({ success: true, ver: state.ver });
});

app.post('/api/admin/verify', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  return res.json({ success: true, ver: state.ver });
});

/* Sets or clears the providerid. Clearing falls back to the hardcoded one. */
app.post('/api/admin/provider-id', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const raw = String((req.body && req.body.providerId) || '').trim();
  const next = raw.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64);

  cfg.providerId = next;
  saveCfg();
  happLinkCache.clear();
  console.log(`[happ] providerid -> ${next ? next.slice(0, 8) + '…' : 'cleared (using fallback)'}`);
  await pushCfgToRepo(cfg, cfg).catch(() => {});
  return res.json({ success: true, providerId: providerId(), hideSettings: true });
});

app.post('/api/admin/diag', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const c = credsFrom(req);
  const info = {
    storage: 'github',
    owner: c.owner,
    repo: c.repo,
    branch: c.branch,
    file: c.file,
    tokenSet: !!c.token,
    tokenLength: c.token ? c.token.length : 0,
    tokenShape: tokenShape(c.token),
    tokenSource: process.env.GITHUB_TOKEN && c.token === process.env.GITHUB_TOKEN.trim()
      ? 'env GITHUB_TOKEN'
      : (c.token === HARD.token ? 'hardcoded' : 'panel override'),
    adminKeyVer: state.ver,
    subFormat: SUB_FORMAT,
    subEncrypt: SUB_ENCRYPT,
    subKeyId: SUB_KEY_ID,
    providerId: providerId() ? 'set' : 'missing',
    hideSettings: true,
    upstream: `${NODE_HOST}:${NODE_PORT}`
  };

  try {
    const f = await ghRead(c);
    info.reachable = true;
    info.fileExists = f ? f.text !== null : false;
    if (f && f.text) {
      try { info.keys = JSON.parse(f.text).keys.length; } catch (e) { info.keys = 'unparsable JSON'; }
    } else {
      info.keys = 0;
    }
    info.hint = 'Read OK. If writes fail, the token needs Contents: Read and write.';
  } catch (e) {
    info.reachable = false;
    info.error = e.message;
    info.hint = 'Read failed. 401 = token dead or mistyped. 403 = permissions. 404 = wrong owner/repo/path/branch.';
  }
  return res.json(info);
});

app.post('/api/admin/github-config', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const incoming = req.body.gh || {};
  const next = { ...cfg };
  for (const k of ['owner', 'repo', 'branch', 'file', 'token']) {
    if (incoming[k] && String(incoming[k]).trim()) next[k] = String(incoming[k]).trim();
  }

  try {
    const f = await ghRead(next);
    if (f && f.text === null) {
      await ghWrite(next, JSON.stringify(EMPTY_DB(), null, 2), null);
    }
  } catch (e) {
    return res.status(400).json({ success: false, error: e.message });
  }

  cfg = next;
  saveCfg();
  cache = { data: null, sha: null, at: 0, sig: '' };
  console.log(`[cfg] storage set to ${cfg.owner}/${cfg.repo}:${cfg.file}`);
  await pushCfgToRepo(cfg, cfg);
  return res.json({ success: true, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch, file: cfg.file, persisted: true });
});

app.post('/api/admin/github-reset', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const prev = { ...cfg };
  cfg = { ...HARD, ...envOverrides() };
  try { fs.unlinkSync(LOCAL_CFG); } catch (e) {}
  cache = { data: null, sha: null, at: 0, sig: '' };
  console.log('[cfg] reset to hardcoded repo + env token');
  if (prev.token) await pushCfgToRepo(prev, { ...cfg, token: '' });
  return res.json({ success: true, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch, file: cfg.file });
});

app.post('/api/admin/github-test', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const c = credsFrom(req);
  try {
    const f = await ghRead(c);
    if (f && f.text === null) {
      const w = await ghWrite(c, JSON.stringify(EMPTY_DB(), null, 2), null);
      if (!w.ok) return res.json({ success: false, error: 'read ok, write failed' });
      cache = { data: null, sha: null, at: 0, sig: '' };
      return res.json({ success: true, created: true, keys: 0, writable: true });
    }
    const db = await getDb(true, c);
    return res.json({ success: true, keys: db.keys.length, writable: !!c.token });
  } catch (e) {
    return res.json({ success: false, error: e.message });
  }
});

app.post('/api/admin/create-key', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const { startNow } = req.body;
  const c = credsFrom(req);
  const durationHours = parseDuration(req.body);
  const maxDevices = parseDeviceLimit(req.body);
  console.log('[create-key] body =', JSON.stringify(req.body), '=> durationHours =', durationHours, 'maxDevices =', maxDevices);

  try {
    const record = await mutate(c, db => {
      let key;
      do { key = "PC5-" + Math.random().toString(36).substring(2, 8).toUpperCase(); }
      while (db.keys.find(k => k.key === key));

      const now = Date.now();
      const started = !!startNow;
      const rec = {
        key,
        durationHours,
        maxDevices,
        deviceLimit: maxDevices === 1 ? 'single' : 'unlimited',
        devices: [],
        createdAt: new Date(now).toISOString(),
        startedAt: started ? new Date(now).toISOString() : null,
        activatedAt: started ? new Date(now).toISOString() : null,
        expiresAt: started ? new Date(now + durationHours * 3600000).toISOString() : null
      };
      db.keys.push(rec);
      return rec;
    });
    return res.json({ success: true, record, durationHours, maxDevices });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

app.post('/api/admin/list-keys', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  try {
    const db = await getDb(true, credsFrom(req));
    const keys = [...db.keys].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    return res.json({ keys, maintenance: db.maintenance, features: db.features });
  } catch (e) {
    return res.status(500).json({ error: "Read failed: " + e.message, keys: [] });
  }
});

/* Saves the socks user:pass used for each feature mode. */
app.post('/api/admin/feature-auth', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const c = credsFrom(req);
  const incoming = req.body || {};
  const aimbot = cleanAuth(incoming.aimbot);
  const location = cleanAuth(incoming.location);

  if (aimbot === null) return res.status(400).json({ error: 'Aimbot auth must look like user:pass' });
  if (location === null) return res.status(400).json({ error: 'Location auth must look like user:pass' });

  try {
    const out = await mutate(c, db => {
      if (!db.features || typeof db.features !== 'object') db.features = { ...EMPTY_FEATURES };
      db.features.aimbot = aimbot;
      db.features.location = location;
      return { ...db.features };
    });
    /* Cached links embed the old auth. */
    happCacheDrop();
    console.log('[features] aimbot ->', aimbot ? 'set' : 'cleared', '| location ->', location ? 'set' : 'cleared');
    return res.json({ success: true, features: out });
  } catch (e) {
    return res.status(500).json({ error: 'Write failed: ' + e.message });
  }
});

app.post('/api/admin/revoke-key', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);

  try {
    await mutate(c, db => {
      const idx = db.keys.findIndex(k => k.key === key);
      if (idx >= 0) db.keys.splice(idx, 1);
    });
    happCacheDrop(key);
    return res.json({ success: true, message: `Key ${key} revoked.` });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

app.post('/api/admin/repair-key', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);
  const durationHours = parseDuration(req.body);

  try {
    const rec = await mutate(c, db => {
      const r = db.keys.find(k => k.key === key);
      if (!r) return null;
      r.durationHours = durationHours;
      r.activatedAt = null;
      r.startedAt = null;
      r.expiresAt = null;
      r.maintenancePausedMs = 0;
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
    happCacheDrop(key);
    return res.json({ success: true, record: rec, durationHours });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

/* Clears the bound device so a single-device key can be used elsewhere. */
app.post('/api/admin/reset-device', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);

  try {
    const rec = await mutate(c, db => {
      const r = db.keys.find(k => k.key === key);
      if (!r) return null;
      r.devices = [];
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
    happCacheDrop(key);
    return res.json({ success: true, message: `Device lock cleared for ${key}.` });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

/* Flips an existing key between unlimited and single-device. */
app.post('/api/admin/set-device-limit', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);
  const maxDevices = parseDeviceLimit(req.body);

  try {
    const rec = await mutate(c, db => {
      const r = db.keys.find(k => k.key === key);
      if (!r) return null;
      r.maxDevices = maxDevices;
      r.deviceLimit = maxDevices === 1 ? 'single' : 'unlimited';
      if (maxDevices === 0) r.devices = [];
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
    happCacheDrop(key);
    return res.json({ success: true, record: rec, maxDevices });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

app.post('/api/admin/maintenance', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { enabled, message } = req.body;
  const c = credsFrom(req);

  try {
    const m = await mutate(c, db => {
      const prev = db.maintenance || DEFAULT_MAINT;
      const nowMs = Date.now();
      const wantOn = !!enabled;
      const msg = message || prev.message || 'System under maintenance.';

      if (wantOn) {
        /* `since` is stamped once and kept — repeated saves while already on
           must not restart the window or the earlier minutes get refunded twice. */
        db.maintenance = {
          enabled: true,
          message: msg,
          since: prev.enabled ? (prev.since || new Date(nowMs).toISOString()) : new Date(nowMs).toISOString()
        };
        return db.maintenance;
      }

      if (prev.enabled) {
        const raw = prev.since ? new Date(prev.since).getTime() : nowMs;
        const start = Number.isFinite(raw) ? Math.min(raw, nowMs) : nowMs;
        const credited = settleMaintenance(db, start, nowMs);
        db.maintenance = {
          enabled: false,
          message: msg,
          since: null,
          lastPausedMs: Math.max(0, nowMs - start),
          lastPausedKeys: credited,
          lastEndedAt: new Date(nowMs).toISOString()
        };
        console.log(`[maint] resumed — credited ${credited} key(s) for ${Math.round((nowMs - start) / 1000)}s`);
        return db.maintenance;
      }

      db.maintenance = { enabled: false, message: msg, since: null };
      return db.maintenance;
    });

    /* Cached Happ links embed the dead auth, so drop them on every toggle. */
    happLinkCache.clear();
    return res.json({ success: true, maintenance: m });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

/* ================= FRONTEND ================= */
app.get('/admin', (req, res) => res.sendFile(path.join(FRONTEND_DIR, 'admin.html')));
app.use(express.static(FRONTEND_DIR));

/* ================= BOOT ================= */
process.on('unhandledRejection', (e) => {
  console.warn('[unhandledRejection]', (e && e.message) || e);
});
process.on('uncaughtException', (e) => {
  console.warn('[uncaughtException]', (e && e.stack) || e);
});

const PORT = process.env.PORT || 3000;

(async () => {
  loadCfg();
  await pullCfgFromRepo();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server active on port ${PORT}`);
    console.log(`[cfg] storage -> ${cfg.owner}/${cfg.repo}:${cfg.file}`);
    console.log(`[cfg] token -> ${tokenShape(cfg.token)}`);
    console.log(`[admin] key source -> ${ADMIN_KEY_URL}`);
    console.log(`[upstream] socks -> ${NODE_HOST}:${NODE_PORT} (sni ${NODE_SNI})`);
    console.log(`[sub] format -> ${SUB_FORMAT} | providerid -> ${providerId()}`);
    console.log(`[sub] encrypt -> ${SUB_ENCRYPT ? `on (key id ${SUB_KEY_ID})` : 'off (json mode)'}`);
    getAdminKey(true);
  });
})();
