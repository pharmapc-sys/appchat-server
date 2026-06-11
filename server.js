/**
 * AppChat private chat server.
 *
 * WebSocket server with user accounts and 1-to-1 private messages:
 *
 *  - {t:"register", user, pass, phone} creates an account. Phone numbers are validated
 *    and normalised to E.164 for France (+33) and Lebanon (+961) only. Passwords are
 *    stored hashed (scrypt). Reply: {t:"auth_ok", uid, user, phone, token}.
 *  - {t:"login", user, pass} or {t:"auth", token} authenticates an existing account.
 *  - {t:"find", phone} looks a user up by phone number (the only discovery mechanism).
 *  - {t:"msg", to, mid, text, ts} sends a private message; it is persisted with a
 *    monotonic `seq` and delivered ONLY to the sender's and recipient's sockets.
 *    Media messages add kind ("img"/"voice"), data (base64) and dur (seconds).
 *  - {t:"recv", mid} / {t:"read", peer} are delivery/read receipts; the sender's
 *    sockets get {t:"status", mid, status} (2 = delivered, 3 = read).
 *  - {t:"hello", since} replays every message involving this user with seq > since,
 *    so history is synchronised after being offline, then the latest receipt
 *    statuses of the user's own messages.
 *  - {t:"fcm", token} stores the device's FCM push token. When a message arrives for a
 *    user with no open socket, an empty high-priority "wake up" push is sent (the
 *    message content never goes through Google); the app then fetches from us.
 *    Requires the FCM_SERVICE_ACCOUNT env var (Firebase service-account JSON).
 *
 * Persistence: Postgres when DATABASE_URL is set (free tiers of Neon/Supabase work),
 * otherwise newline-delimited JSON files next to this script.
 */
const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const MSG_FILE = process.env.MSG_FILE || path.join(__dirname, 'messages.jsonl');
const USERS_FILE = process.env.USERS_FILE || path.join(__dirname, 'users.jsonl');

// --- phone numbers: France and Lebanon only, normalised to E.164 ---

function normalizePhone(raw) {
  let p = String(raw || '').replace(/[\s.\-()]/g, '');
  if (p.startsWith('00')) p = '+' + p.slice(2);
  if (/^0[1-9]\d{8}$/.test(p)) p = '+33' + p.slice(1);   // French national: 10 digits
  else if (/^0\d{7}$/.test(p)) p = '+961' + p.slice(1);  // Lebanese national: 8 digits
  if (/^\+33[1-9]\d{8}$/.test(p)) return p;              // France
  if (/^\+961\d{7,8}$/.test(p)) return p;                // Lebanon
  return null;
}

// --- password hashing (scrypt, no external dependency) ---

function hashPass(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pass, salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function checkPass(pass, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const h = crypto.scryptSync(pass, salt, 32);
  return crypto.timingSafeEqual(h, Buffer.from(hash, 'hex'));
}

// --- FCM push (optional) ---

const FCM_SA = (() => {
  if (!process.env.FCM_SERVICE_ACCOUNT) return null;
  try { return JSON.parse(process.env.FCM_SERVICE_ACCOUNT); }
  catch (e) { console.error('FCM_SERVICE_ACCOUNT is not valid JSON:', e.message); return null; }
})();

let fcmAccess = { token: null, exp: 0 };

/** OAuth2 access token for the FCM v1 API (RS256 JWT signed with the service account). */
async function fcmAccessToken() {
  if (fcmAccess.token && Date.now() < fcmAccess.exp - 60_000) return fcmAccess.token;
  const b64 = (s) => Buffer.from(s).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const header = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = b64(JSON.stringify({
    iss: FCM_SA.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  }));
  const sig = crypto.createSign('RSA-SHA256')
    .update(`${header}.${claims}`).sign(FCM_SA.private_key).toString('base64url');
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}` +
      `&assertion=${header}.${claims}.${sig}`,
  });
  if (!res.ok) throw new Error(`oauth ${res.status}: ${await res.text()}`);
  const json = await res.json();
  fcmAccess = { token: json.access_token, exp: Date.now() + json.expires_in * 1000 };
  return fcmAccess.token;
}

/**
 * Empty data-only push: just wakes the app, which fetches the messages from us.
 * Returns 'gone' when the token is no longer valid so the caller can drop it.
 */
async function fcmWake(deviceToken) {
  const access = await fcmAccessToken();
  const res = await fetch(
    `https://fcm.googleapis.com/v1/projects/${FCM_SA.project_id}/messages:send`,
    {
      method: 'POST',
      headers: { authorization: `Bearer ${access}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        message: {
          token: deviceToken,
          data: { t: 'wake' },
          android: { priority: 'HIGH' },
        },
      }),
    }
  );
  if (res.status === 404 || res.status === 410) return 'gone';
  if (!res.ok) console.error(`fcm send failed (${res.status}): ${await res.text()}`);
  return 'ok';
}

// --- storage backends ---

/** Postgres-backed storage (free tier of Neon/Supabase is enough). */
async function pgStorage() {
  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
    max: 3,
  });
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      uid      TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass     TEXT NOT NULL,
      phone    TEXT UNIQUE NOT NULL,
      token    TEXT NOT NULL,
      created  BIGINT NOT NULL
    )`);
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm TEXT');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      seq      BIGINT PRIMARY KEY,
      mid      TEXT UNIQUE NOT NULL,
      from_uid TEXT NOT NULL,
      to_uid   TEXT NOT NULL,
      text     TEXT NOT NULL,
      ts       BIGINT NOT NULL
    )`);
  await pool.query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'text'");
  await pool.query("ALTER TABLE messages ADD COLUMN IF NOT EXISTS data TEXT NOT NULL DEFAULT ''");
  await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS dur INT NOT NULL DEFAULT 0');
  await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS status INT NOT NULL DEFAULT 1');
  const users = (await pool.query('SELECT uid, username, pass, phone, token, created, fcm FROM users')).rows
    .map((r) => ({ ...r, created: Number(r.created) }));
  const messages = (await pool.query(
    'SELECT seq, mid, from_uid, to_uid, text, ts, kind, data, dur, status FROM messages ORDER BY seq'
  )).rows.map((r) => ({
    from: r.from_uid, to: r.to_uid, mid: r.mid, text: r.text,
    ts: Number(r.ts), seq: Number(r.seq),
    kind: r.kind || 'text', data: r.data || '', dur: Number(r.dur) || 0,
    status: Number(r.status) || 1,
  }));
  return {
    kind: `postgres (${new URL(DATABASE_URL).hostname})`,
    users,
    messages,
    saveUser(u) {
      pool.query(
        `INSERT INTO users (uid, username, pass, phone, token, created, fcm)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (uid) DO UPDATE SET pass = $3, token = $5, fcm = $7`,
        [u.uid, u.username, u.pass, u.phone, u.token, u.created, u.fcm || null]
      ).catch((e) => console.error('pg saveUser failed:', e.message));
    },
    appendMessage(e) {
      pool.query(
        `INSERT INTO messages (seq, mid, from_uid, to_uid, text, ts, kind, data, dur, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (mid) DO NOTHING`,
        [e.seq, e.mid, e.from, e.to, e.text, e.ts, e.kind, e.data, e.dur, e.status]
      ).catch((err) => console.error('pg insert failed:', err.message));
    },
    updateStatus(mid, status) {
      pool.query(
        'UPDATE messages SET status = $2 WHERE mid = $1 AND status < $2',
        [mid, status]
      ).catch((err) => console.error('pg status failed:', err.message));
    },
  };
}

/** File-backed storage. Users are append-only records, the latest one per uid wins. */
function fileStorage() {
  const readJsonl = (file) => {
    const out = [];
    if (fs.existsSync(file)) {
      for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        try { out.push(JSON.parse(line)); } catch { /* skip corrupt line */ }
      }
    }
    return out;
  };
  const byUid = new Map();
  for (const u of readJsonl(USERS_FILE)) byUid.set(u.uid, u);
  // Status updates are appended as {smid, status} patch lines, applied on load.
  const messages = [];
  const byMid = new Map();
  for (const rec of readJsonl(MSG_FILE)) {
    if (rec.smid) {
      const m = byMid.get(rec.smid);
      if (m && rec.status > (m.status || 1)) m.status = rec.status;
    } else {
      rec.kind = rec.kind || 'text';
      rec.data = rec.data || '';
      rec.dur = rec.dur || 0;
      rec.status = rec.status || 1;
      messages.push(rec);
      byMid.set(rec.mid, rec);
    }
  }
  const usersOut = fs.createWriteStream(USERS_FILE, { flags: 'a' });
  const msgOut = fs.createWriteStream(MSG_FILE, { flags: 'a' });
  return {
    kind: `files (${path.dirname(MSG_FILE)})`,
    users: [...byUid.values()],
    messages,
    saveUser(u) { usersOut.write(JSON.stringify(u) + '\n'); },
    appendMessage(e) { msgOut.write(JSON.stringify(e) + '\n'); },
    updateStatus(mid, status) { msgOut.write(JSON.stringify({ smid: mid, status }) + '\n'); },
  };
}

// --- server ---

async function main() {
  const db = DATABASE_URL ? await pgStorage() : fileStorage();

  const users = new Map();   // uid -> user
  const byName = new Map();  // lowercase username -> user
  const byPhone = new Map(); // E.164 phone -> user
  const byToken = new Map(); // session token -> user
  for (const u of db.users) {
    users.set(u.uid, u);
    byName.set(u.username.toLowerCase(), u);
    byPhone.set(u.phone, u);
    byToken.set(u.token, u);
  }

  const log = db.messages;
  const seenMids = new Set(log.map((e) => e.mid));
  let seq = log.length ? log[log.length - 1].seq : 0;

  const sockets = new Map(); // uid -> Set<ws>

  function send(ws, obj) {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  }

  function fail(ws, code, msg) {
    send(ws, { t: 'error', code, msg });
  }

  /** Wire format of a stored message, with the sender's current username resolved. */
  function wire(e) {
    return {
      t: 'msg', from: e.from, fromName: users.get(e.from)?.username || '?',
      to: e.to, mid: e.mid, text: e.text, ts: e.ts, seq: e.seq,
      kind: e.kind || 'text', data: e.data || '', dur: e.dur || 0,
      status: e.status || 1,
    };
  }

  function deliver(uid, payload) {
    const set = sockets.get(uid);
    if (set) for (const ws of set) send(ws, payload);
  }

  /**
   * Wake [user]'s phone via FCM. Throttled per user (a burst of messages triggers a
   * single fetch on the phone anyway); an invalid token is dropped from the account.
   */
  const lastPush = new Map(); // uid -> ms timestamp
  function pushWake(user) {
    if (!FCM_SA || !user || !user.fcm) return;
    const now = Date.now();
    if (now - (lastPush.get(user.uid) || 0) < 15_000) return;
    lastPush.set(user.uid, now);
    fcmWake(user.fcm)
      .then((status) => {
        if (status === 'gone') {
          user.fcm = null;
          db.saveUser(user);
        }
      })
      .catch((e) => console.error('fcm push failed:', e.message));
  }

  function attach(ws, user) {
    ws.uid = user.uid;
    if (!sockets.has(user.uid)) sockets.set(user.uid, new Set());
    sockets.get(user.uid).add(ws);
    console.log(`auth ok: ${user.username} (${sockets.get(user.uid).size} socket(s))`);
    send(ws, { t: 'auth_ok', uid: user.uid, user: user.username, phone: user.phone, token: user.token });
  }

  const wss = new WebSocketServer({ port: PORT });

  wss.on('connection', (ws, req) => {
    const ip = req.socket.remoteAddress;
    console.log(`+ conn ${ip}`);

    ws.on('message', (data) => {
      let m;
      try { m = JSON.parse(data.toString()); } catch { return; }

      // --- authentication ---

      if (m.t === 'register') {
        const username = String(m.user || '').trim();
        const pass = String(m.pass || '');
        const phone = normalizePhone(m.phone);
        if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
          return fail(ws, 'bad_user', "Pseudo invalide (3-24 lettres, chiffres ou _).");
        }
        if (pass.length < 6) {
          return fail(ws, 'bad_pass', 'Mot de passe trop court (6 caractères minimum).');
        }
        if (!phone) {
          return fail(ws, 'bad_phone', 'Numéro invalide. Formats acceptés : France (+33) et Liban (+961).');
        }
        if (byName.has(username.toLowerCase())) {
          return fail(ws, 'user_taken', 'Ce pseudo est déjà pris.');
        }
        if (byPhone.has(phone)) {
          return fail(ws, 'phone_taken', 'Ce numéro est déjà associé à un compte.');
        }
        const user = {
          uid: crypto.randomUUID(),
          username,
          pass: hashPass(pass),
          phone,
          token: crypto.randomBytes(24).toString('hex'),
          created: Date.now(),
        };
        users.set(user.uid, user);
        byName.set(username.toLowerCase(), user);
        byPhone.set(phone, user);
        byToken.set(user.token, user);
        db.saveUser(user);
        console.log(`new user ${username} (${phone})`);
        return attach(ws, user);
      }

      if (m.t === 'login') {
        const user = byName.get(String(m.user || '').trim().toLowerCase());
        if (!user || !checkPass(String(m.pass || ''), user.pass)) {
          return fail(ws, 'bad_credentials', 'Pseudo ou mot de passe incorrect.');
        }
        return attach(ws, user);
      }

      if (m.t === 'auth') {
        const user = byToken.get(String(m.token || ''));
        if (!user) return fail(ws, 'bad_token', 'Session expirée, reconnectez-vous.');
        return attach(ws, user);
      }

      // --- everything below requires authentication ---

      if (!ws.uid) return fail(ws, 'unauthorized', 'Connectez-vous d’abord.');

      if (m.t === 'hello') {
        const since = Number(m.since) || 0;
        for (const e of log) {
          if (e.seq > since && (e.from === ws.uid || e.to === ws.uid)) send(ws, wire(e));
        }
        // Receipts that may have arrived while this user was offline: replay the
        // statuses of their own recent messages (the app keeps the highest value).
        let sent = 0;
        for (let i = log.length - 1; i >= 0 && sent < 300; i--) {
          const e = log[i];
          if (e.from !== ws.uid || (e.status || 1) <= 1) continue;
          send(ws, { t: 'status', mid: e.mid, status: e.status });
          sent += 1;
        }
        return;
      }

      // Delivery receipt: the recipient's device received this message.
      if (m.t === 'recv') {
        const e = log.find((x) => x.mid === String(m.mid || ''));
        const who = users.get(ws.uid)?.username;
        if (!e || e.to !== ws.uid || (e.status || 1) >= 2) {
          console.log(`recv de ${who}: ignoré (inconnu/déjà fait)`);
          return;
        }
        e.status = 2;
        db.updateStatus(e.mid, 2);
        const n = sockets.get(e.from)?.size || 0;
        console.log(`recv: ${who} a reçu un msg de ${users.get(e.from)?.username} → status 2 (sockets expéditeur: ${n})`);
        deliver(e.from, { t: 'status', mid: e.mid, status: 2 });
        return;
      }

      // Read receipt: every message from [peer] to this user has been seen.
      if (m.t === 'read') {
        const peer = String(m.peer || '');
        let n = 0;
        for (const e of log) {
          if (e.from !== peer || e.to !== ws.uid || (e.status || 1) >= 3) continue;
          e.status = 3;
          db.updateStatus(e.mid, 3);
          deliver(peer, { t: 'status', mid: e.mid, status: 3 });
          n += 1;
        }
        console.log(`read: ${users.get(ws.uid)?.username} a lu ${n} msg de ${users.get(peer)?.username} (sockets expéditeur: ${sockets.get(peer)?.size || 0})`);
        return;
      }

      if (m.t === 'fcm') {
        const token = String(m.token || '');
        const user = users.get(ws.uid);
        if (user && token && user.fcm !== token) {
          user.fcm = token;
          db.saveUser(user);
        }
        return;
      }

      if (m.t === 'find') {
        const phone = normalizePhone(m.phone);
        const found = phone ? byPhone.get(phone) : undefined;
        return send(ws, {
          t: 'found',
          phone: String(m.phone || ''),
          user: found ? { uid: found.uid, user: found.username, phone: found.phone } : null,
        });
      }

      if (m.t === 'msg') {
        const to = String(m.to || '');
        const mid = String(m.mid || '');
        if (!mid || !users.has(to)) return;
        const kind = ['text', 'img', 'voice', 'file', 'loc'].includes(m.kind) ? m.kind : 'text';
        const data = kind === 'text' ? '' : String(m.data || '');
        if (data.length > 3_000_000) return; // ~2.2 MB binary: refuse oversized media
        // Already stored: just echo it back so the sender can mark it delivered.
        if (seenMids.has(mid)) {
          const existing = log.find((e) => e.mid === mid);
          if (existing && existing.from === ws.uid) send(ws, wire(existing));
          return;
        }
        seq += 1;
        const entry = {
          from: ws.uid,
          to,
          mid,
          text: String(m.text || ''),
          ts: Number(m.ts) || Date.now(),
          seq,
          kind,
          data,
          dur: Math.max(0, Number(m.dur) || 0),
          status: 1,
        };
        log.push(entry);
        seenMids.add(mid);
        db.appendMessage(entry);
        const payload = wire(entry);
        const rcptSockets = sockets.get(to)?.size || 0;
        console.log(`msg ${entry.kind} de ${users.get(ws.uid)?.username} → ${users.get(to)?.username} (sockets destinataire: ${rcptSockets})`);
        deliver(to, payload);
        if (to !== ws.uid) deliver(ws.uid, payload); // echo to all the sender's devices
        // Recipient has no live connection: wake their phone so it fetches from us.
        if (to !== ws.uid && !rcptSockets) pushWake(users.get(to));
        return;
      }
    });

    const detach = () => {
      if (ws.uid) sockets.get(ws.uid)?.delete(ws);
      console.log(`- conn ${ip}`);
    };
    ws.on('close', detach);
    ws.on('error', detach);
  });

  console.log(
    `AppChat private relay on ws://0.0.0.0:${PORT}  ` +
    `(storage: ${db.kind}, ${users.size} users, ${log.length} messages)`
  );
}

main().catch((err) => {
  console.error('fatal:', err);
  process.exit(1);
});
