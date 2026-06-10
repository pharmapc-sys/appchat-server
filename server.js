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
 *  - {t:"hello", since} replays every message involving this user with seq > since,
 *    so history is synchronised after being offline.
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      seq      BIGINT PRIMARY KEY,
      mid      TEXT UNIQUE NOT NULL,
      from_uid TEXT NOT NULL,
      to_uid   TEXT NOT NULL,
      text     TEXT NOT NULL,
      ts       BIGINT NOT NULL
    )`);
  const users = (await pool.query('SELECT uid, username, pass, phone, token, created FROM users')).rows
    .map((r) => ({ ...r, created: Number(r.created) }));
  const messages = (await pool.query(
    'SELECT seq, mid, from_uid, to_uid, text, ts FROM messages ORDER BY seq'
  )).rows.map((r) => ({
    from: r.from_uid, to: r.to_uid, mid: r.mid, text: r.text,
    ts: Number(r.ts), seq: Number(r.seq),
  }));
  return {
    kind: `postgres (${new URL(DATABASE_URL).hostname})`,
    users,
    messages,
    saveUser(u) {
      pool.query(
        `INSERT INTO users (uid, username, pass, phone, token, created)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (uid) DO UPDATE SET pass = $3, token = $5`,
        [u.uid, u.username, u.pass, u.phone, u.token, u.created]
      ).catch((e) => console.error('pg saveUser failed:', e.message));
    },
    appendMessage(e) {
      pool.query(
        `INSERT INTO messages (seq, mid, from_uid, to_uid, text, ts)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (mid) DO NOTHING`,
        [e.seq, e.mid, e.from, e.to, e.text, e.ts]
      ).catch((err) => console.error('pg insert failed:', err.message));
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
  const usersOut = fs.createWriteStream(USERS_FILE, { flags: 'a' });
  const msgOut = fs.createWriteStream(MSG_FILE, { flags: 'a' });
  return {
    kind: `files (${path.dirname(MSG_FILE)})`,
    users: [...byUid.values()],
    messages: readJsonl(MSG_FILE),
    saveUser(u) { usersOut.write(JSON.stringify(u) + '\n'); },
    appendMessage(e) { msgOut.write(JSON.stringify(e) + '\n'); },
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
    };
  }

  function deliver(uid, payload) {
    const set = sockets.get(uid);
    if (set) for (const ws of set) send(ws, payload);
  }

  function attach(ws, user) {
    ws.uid = user.uid;
    if (!sockets.has(user.uid)) sockets.set(user.uid, new Set());
    sockets.get(user.uid).add(ws);
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
        };
        log.push(entry);
        seenMids.add(mid);
        db.appendMessage(entry);
        const payload = wire(entry);
        deliver(to, payload);
        if (to !== ws.uid) deliver(ws.uid, payload); // echo to all the sender's devices
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
