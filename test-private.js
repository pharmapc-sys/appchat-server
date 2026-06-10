/* End-to-end test of the private chat protocol against a local server. */
const WebSocket = require('ws');
const URL = 'ws://127.0.0.1:18099';

let failures = 0;
function check(label, ok) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failures += 1;
}

function client() {
  const ws = new WebSocket(URL);
  const queue = [];
  const waiters = [];
  ws.on('message', (d) => {
    const m = JSON.parse(d.toString());
    const w = waiters.shift();
    if (w) w(m); else queue.push(m);
  });
  return {
    ws,
    open: () => new Promise((r) => ws.on('open', r)),
    send: (o) => ws.send(JSON.stringify(o)),
    next: () =>
      queue.length
        ? Promise.resolve(queue.shift())
        : new Promise((resolve, reject) => {
            waiters.push(resolve);
            setTimeout(() => reject(new Error('timeout waiting for message')), 3000);
          }),
    quiet: (ms = 500) =>
      new Promise((r) => setTimeout(() => r(queue.length === 0), ms)),
  };
}

async function main() {
  // --- Alice registers with a French number ---
  const alice = client();
  await alice.open();
  alice.send({ t: 'register', user: 'alice', pass: 'secret123', phone: '06 12 34 56 78' });
  let r = await alice.next();
  check('register alice (FR local format) → auth_ok', r.t === 'auth_ok' && r.user === 'alice' && r.phone === '+33612345678');
  const aliceTok = r.token;

  // --- Bob registers with a Lebanese number ---
  const bob = client();
  await bob.open();
  bob.send({ t: 'register', user: 'bob', pass: 'secret123', phone: '+961 70 123 456' });
  r = await bob.next();
  check('register bob (LB) → auth_ok', r.t === 'auth_ok' && r.phone === '+96170123456');
  const bobUid = r.uid;

  // --- invalid registrations ---
  const bad = client();
  await bad.open();
  bad.send({ t: 'register', user: 'eve', pass: 'secret123', phone: '+1 555 0100' });
  r = await bad.next();
  check('register with US number rejected', r.t === 'error' && r.code === 'bad_phone');
  bad.send({ t: 'register', user: 'alice', pass: 'secret123', phone: '+33698765432' });
  r = await bad.next();
  check('duplicate username rejected', r.t === 'error' && r.code === 'user_taken');
  bad.send({ t: 'register', user: 'eve2', pass: 'secret123', phone: '0612345678' });
  r = await bad.next();
  check('duplicate phone rejected', r.t === 'error' && r.code === 'phone_taken');
  bad.send({ t: 'find', phone: '+33612345678' });
  r = await bad.next();
  check('find without auth rejected', r.t === 'error' && r.code === 'unauthorized');

  // --- search by phone ---
  alice.send({ t: 'find', phone: '00961 70 123 456' });
  r = await alice.next();
  check('alice finds bob by phone (00 prefix)', r.t === 'found' && r.user && r.user.uid === bobUid);
  alice.send({ t: 'find', phone: '+33699999999' });
  r = await alice.next();
  check('unknown number → user:null', r.t === 'found' && r.user === null);

  // --- private message alice → bob ---
  alice.send({ t: 'msg', to: bobUid, mid: 'm1', text: 'salut bob', ts: Date.now() });
  const echoA = await alice.next();
  const recvB = await bob.next();
  check('sender gets echo with seq', echoA.t === 'msg' && echoA.mid === 'm1' && echoA.seq === 1);
  check('recipient receives message', recvB.t === 'msg' && recvB.text === 'salut bob' && recvB.fromName === 'alice');

  // --- privacy: a third user must NOT receive or replay it ---
  const eve = client();
  await eve.open();
  eve.send({ t: 'register', user: 'eve', pass: 'secret123', phone: '+96171999999' });
  await eve.next(); // auth_ok
  eve.send({ t: 'hello', since: 0 });
  check('eve replay is empty (privacy)', await eve.quiet());

  // --- login + offline replay ---
  const alice2 = client();
  await alice2.open();
  alice2.send({ t: 'login', user: 'ALICE', pass: 'secret123' });
  r = await alice2.next();
  check('login (case-insensitive) → auth_ok', r.t === 'auth_ok' && r.uid === echoA.from);
  alice2.send({ t: 'hello', since: 0 });
  r = await alice2.next();
  check('replay returns the private message', r.t === 'msg' && r.mid === 'm1');

  const alice3 = client();
  await alice3.open();
  alice3.send({ t: 'login', user: 'alice', pass: 'wrong' });
  r = await alice3.next();
  check('wrong password rejected', r.t === 'error' && r.code === 'bad_credentials');

  // --- token re-auth (app reconnect path) ---
  const alice4 = client();
  await alice4.open();
  alice4.send({ t: 'auth', token: aliceTok });
  r = await alice4.next();
  check('token re-auth → auth_ok', r.t === 'auth_ok' && r.user === 'alice');

  // --- duplicate mid: echoed once, not re-stored ---
  alice.send({ t: 'msg', to: bobUid, mid: 'm1', text: 'salut bob', ts: Date.now() });
  r = await alice.next();
  check('duplicate mid echoed with same seq', r.mid === 'm1' && r.seq === 1);

  console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL TESTS PASSED');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
