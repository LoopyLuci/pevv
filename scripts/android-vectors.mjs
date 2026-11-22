#!/usr/bin/env node
/**
 * Generates the golden test vectors the Android app is tested against, using the TypeScript code as the
 * source of truth: android/app/src/test/resources/vectors/*.json.
 *
 *   node scripts/android-vectors.mjs          write the vectors
 *   node scripts/android-vectors.mjs --check  fail if the files on disk are not what this script would write
 *                                             (random IVs make every run differ, so this only checks the shape)
 *
 * The vectors hold throw-away test secrets only (known passwords such as "correct horse battery staple"); no real vault is read.
 * The TypeScript is loaded through a Vite SSR server, so no build step and no extra dependency is needed.
 */
import { createServer } from 'vite';
import { mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'android', 'app', 'src', 'test', 'resources', 'vectors');
const check = process.argv.includes('--check');

const server = await createServer({
  root,
  configFile: false,
  logLevel: 'error',
  appType: 'custom',
  server: { middlewareMode: true, hmr: false, ws: false, watch: null },
  optimizeDeps: { noDiscovery: true },
  resolve: { alias: { '@': join(root, 'src') } },
});

const load = (p) => server.ssrLoadModule(p);
const hex = (b) => Buffer.from(b).toString('hex');
const T = 1_700_000_000_000;

try {
  const [B, C, V, R, M, TO, , D, Q, PP, X] = await Promise.all([
    load('/src/pevv/bytes.ts'), load('/src/pevv/crypto.ts'), load('/src/pevv/vault.ts'), load('/src/pevv/recovery.ts'),
    load('/src/pevv/model.ts'), load('/src/pevv/totp.ts'), load('/src/pevv/usbkey.ts'), load('/src/pevv/devices.ts'),
    load('/src/pevv/qr.ts'), load('/src/pevv/passkeyProvider.ts'), load('/src/pevv/extra.ts'),
  ]);

  const out = {};
  const b64 = B.b64;
  const salt16 = (n) => b64(Uint8Array.from({ length: 16 }, (_, i) => (i * 7 + n) & 255));
  const fastArgon = (n) => ({ alg: 'argon2id', m: 19456, t: 2, p: 1, salt: salt16(n) });
  const kekHex = async (raw, saltB64, info) => {
    const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
    return hex(new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: B.unb64(saltB64), info: B.utf8(info) }, base, 256)));
  };

  /* ───────────── primitives ───────────── */
  const kdfCases = [];
  const addKdf = async (name, password, kdf) => {
    const raw = await C.stretch(password, kdf);
    kdfCases.push({ name, password, kdf, stretchHex: hex(raw), passwordKekHex: await kekHex(raw, kdf.salt, 'luciverse/pevv/v1/password-kek') });
  };
  await addKdf('argon2id-floor', 'correct horse battery staple', fastArgon(1));
  await addKdf('argon2id-default-params', 'correct horse battery staple', { alg: 'argon2id', ...C.ARGON2_DEFAULT, salt: salt16(2) });
  await addKdf('argon2id-nfc-composed', 'café-pässwörd ✓', fastArgon(3));
  await addKdf('argon2id-nfc-decomposed', 'café-pässwörd ✓', fastArgon(3));
  await addKdf('argon2id-parallel-2', 'p@ss', { alg: 'argon2id', m: 19456, t: 2, p: 2, salt: salt16(4) });
  await addKdf('pbkdf2-floor', 'correct horse battery staple', { alg: 'pbkdf2-sha256', iter: 600000, salt: salt16(5) });
  out.kdf = kdfCases;

  const ikm = Uint8Array.from({ length: 32 }, (_, i) => i);
  const hkdfCases = [];
  for (const [s, info] of [[salt16(9), 'luciverse/pevv/v1/prf-kek'], [salt16(10), 'luciverse/pevv/v1/usb-kek'], [salt16(11), 'luciverse/pevv/v1/recovery-key-kek']]) {
    hkdfCases.push({ ikmHex: hex(ikm), salt: s, info, okmHex: await kekHex(ikm, s, info) });
  }
  out.hkdf = hkdfCases;

  // AES-GCM with a fixed IV and AAD (the format is iv | ct+tag, base64).
  {
    const key = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
    const iv = Uint8Array.from({ length: 12 }, (_, i) => i + 1);
    const aad = 'luciverse/pevv/v1/entry/vid/eid/3';
    const plain = B.utf8('{"type":"note","title":"héllo"}');
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: B.utf8(aad), tagLength: 128 }, k, plain));
    out.aes = { keyHex: hex(key), aad, plainUtf8: B.fromUtf8(plain), sealed: { iv: b64(iv), ct: b64(ct) } };
  }

  out.base32 = [Uint8Array.of(), Uint8Array.of(1), Uint8Array.of(1, 2, 3), Uint8Array.from({ length: 13 }, (_, i) => i * 19), Uint8Array.from({ length: 32 }, (_, i) => i * 8 + 1)]
    .map((b) => ({ hex: hex(b), base32: B.base32Encode(b) }));

  const code = 'ABCDE-FGH23-45672-ABCDE';
  const codeSalt = salt16(20);
  out.recovery = {
    code, salt: codeSalt, hash: await R.codeHash(code, codeSalt), normalized: R.normalizeCode('abcde fgh23-4567 2abcde'),
    key: B.base32Encode(Uint8Array.from({ length: 32 }, (_, i) => (i * 11 + 7) & 255)).match(/.{1,4}/g).join('-'),
  };
  out.recovery.keyBytesHex = hex(R.recoveryKeyBytes(out.recovery.key));
  out.recovery.codeKekHex = await kekHex(B.utf8(R.normalizeCode(code)), codeSalt, 'luciverse/pevv/v1/recovery-code-kek');
  out.recovery.keyKekHex = await kekHex(R.recoveryKeyBytes(out.recovery.key), codeSalt, 'luciverse/pevv/v1/recovery-key-kek');

  // RFC 6238 appendix B (SHA-1, SHA-256, SHA-512) plus our own seconds.
  const rfcSecrets = { 'SHA-1': '12345678901234567890', 'SHA-256': '12345678901234567890123456789012', 'SHA-512': '1234567890123456789012345678901234567890123456789012345678901234' };
  const totp = [];
  for (const [alg, sec] of Object.entries(rfcSecrets)) {
    const cfg = { secret: B.base32Encode(B.utf8(sec)), digits: 8, period: 30, algorithm: alg };
    for (const t of [59, 1111111109, 1234567890, 2000000000]) totp.push({ cfg, unixMs: t * 1000, code: await TO.totpAt(cfg, t * 1000) });
  }
  const cfg6 = { secret: 'JBSWY3DPEHPK3PXP' };
  for (const t of [0, 29, 30, 1700000000]) totp.push({ cfg: cfg6, unixMs: t * 1000, code: await TO.totpAt(cfg6, t * 1000) });
  out.totp = {
    cases: totp,
    uris: [
      { uri: 'otpauth://totp/Ex:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Ex&algorithm=SHA256&digits=8&period=60', cfg: TO.parseOtpauth('otpauth://totp/Ex:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Ex&algorithm=SHA256&digits=8&period=60') },
      { uri: 'jbsw y3dp-ehpk 3pxp', cfg: TO.parseOtpauth('jbsw y3dp-ehpk 3pxp') },
      { uri: TO.otpauthUri({ secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 45, algorithm: 'SHA-512' }, 'bob@example.com'), cfg: { secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 45, algorithm: 'SHA-512' } },
    ],
    limiter: [0, 4, 5, 6, 7, 12, 30].map((f) => ({ fails: f, delay: TO.limiterDelay(f) })),
  };

  /* ───────────── whole vaults ───────────── */
  const kindData = (type, patch) => ({ ...M.emptyEntry(type, T), ...patch });
  const entryFixtures = [
    kindData('login', { title: 'Example', site: 'https://example.com', username: 'alice@example.com', password: 'p@ss wörd ✓', totp: 'JBSWY3DPEHPK3PXP', notes: 'line1\nline2', tags: ['work'], favorite: true, folder: 'Work', futureField: { nested: [1, 2, { a: 'b' }], flag: true }, autoType: { windows: ['PuTTY*'], process: 'putty.exe' } }),
    kindData('env', { title: 'DB_URL', name: 'DB_URL', value: 'postgres://u:p@h/db?x="1"', env: 'prod' }),
    kindData('note', { title: 'Secret note', notes: 'multi\nline 😀 note' }),
    kindData('apikey', { title: 'Stripe', service: 'stripe', key: 'sk_test_123' }),
    kindData('card', { title: 'Visa', cardholder: 'A Person', number: '4111111111111111', expiry: '12/30', cvv: '123', pin: '0000' }),
    kindData('ssh', { title: 'Server', privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----', publicKey: 'ssh-ed25519 AAAAC3Nza me@host', passphrase: 'pp' }),
    kindData('identity', { title: 'Me', fullName: 'A Person', email: 'a@example.com', phone: '+1 555 0100', address: '1 Road\nTown' }),
  ];
  const passkeyMade = await PP.createPasskey({ rpId: 'example.org', rpName: 'Example', userHandle: B.b64url(Uint8Array.of(1, 2, 3, 4)), userName: 'alice', userDisplayName: 'Alice', userVerified: true }, T);
  entryFixtures.push(passkeyMade.data);

  async function buildVault(password, kdf, withExtras) {
    let { file, session } = await V.createVault(password, kdf);
    let meta = await V.readMeta(file, session);
    const ids = [];
    for (const data of entryFixtures) {
      const r = await V.putEntry(file, session, meta, null, data);
      file = r.file; meta = r.meta; ids.push(r.entry.id);
    }
    // an edit (ver 2) and a delete, so versions and the index are exercised
    const edited = await V.putEntry(file, session, meta, ids[1], { ...entryFixtures[1], value: 'edited-value' });
    file = edited.file; meta = edited.meta;
    const gone = await V.putEntry(file, session, meta, null, kindData('note', { title: 'to be deleted' }));
    file = gone.file; meta = gone.meta;
    const removed = await V.removeEntry(file, session, meta, gone.entry.id);
    file = removed.file; meta = removed.meta;
    const extras = {};
    if (withExtras) {
      const rc = await V.replaceRecoveryCodes(file, session, meta, 3);
      file = rc.file; extras.recoveryCodes = rc.codes;
      const rk = await V.replaceRecoveryKey(file, session, meta);
      file = rk.file; extras.recoveryKey = rk.key;
      const usb = await V.addUsbKey(file, session, meta, 'Backup stick', 'unlock');
      file = usb.file; meta = usb.meta; extras.usbKeyFile = usb.text;
      const gate = await V.addUsbKey(file, session, meta, 'Second factor stick', 'second-factor');
      file = gate.file; meta = gate.meta; extras.usbGateFile = gate.text;
      const prfOut = Uint8Array.from({ length: 32 }, (_, i) => (i * 5 + 3) & 255);
      file = await V.addPrfSlot(file, session, meta, 'cred-abc_123', prfOut);
      extras.prf = { credId: 'cred-abc_123', outputHex: hex(prfOut) };
      const t = await V.setTotp(file, session, meta, { secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30 });
      file = t.file; meta = t.meta;
      meta = { ...meta, devices: [{ id: 'aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb', name: 'Desktop', kind: 'desktop', added: T, seen: T + 5, agent: 'Chrome · Windows' }], revokedDevices: ['dddddddd-1111-2222-3333-eeeeeeeeeeee'], futureMetaField: [1, 2, 3] };
      file = await V.saveMeta(file, session, meta);
      file = { ...file, passkeys: [{ id: 'cred-abc_123', name: 'Phone key', mode: 'prf', publicKey: 'MFkw', alg: -7, transports: ['internal'], prfSalt: salt16(33), created: T, lastUsed: null, signCount: 0, rpId: 'example.com' }] };
    }
    const dec = await V.decryptAll(file, session);
    return {
      password,
      file,
      vaultKeyHex: hex(session.raw),
      extras,
      expected: {
        entries: dec.entries.map((e) => ({ id: e.id, ver: e.ver, data: Object.fromEntries(Object.entries(e).filter(([k]) => k !== 'id' && k !== 'ver')) })),
        meta: dec.meta,
        totp: dec.totp,
        warnings: dec.warnings,
      },
    };
  }

  const argonVault = await buildVault('correct horse battery staple', fastArgon(40), true);
  out['vault-argon2id'] = argonVault;
  out['vault-pbkdf2'] = await buildVault('pb kdf ünicode', { alg: 'pbkdf2-sha256', iter: 600000, salt: salt16(41) }, false);

  /* ───────────── exports, kit, key file, handoff, QR ───────────── */
  const decAll = await V.decryptAll(argonVault.file, await V.sessionFromRaw(B.toBytes(Buffer.from(argonVault.vaultKeyHex, 'hex'))));
  const exportV2 = await V.exportPortable(argonVault.file, 'export-pass-é', fastArgon(50));
  const exportV1 = await V.exportEncrypted(decAll.entries, decAll.meta, 'export-pass-v1', fastArgon(51));
  const kit = await R.buildKit(argonVault.file.id, argonVault.extras.recoveryKey, 'kit pass ✓', fastArgon(52));
  const small = await V.createVault('qr-small', fastArgon(60));
  const smallPut = await V.putEntry(small.file, small.session, await V.readMeta(small.file, small.session), null, entryFixtures[0]);
  const smallFile = smallPut.file;
  const fileText = JSON.stringify(smallFile);
  const hand = await Q.sealHandoff(fileText, T, 180000);
  const frames = await Q.packVault(smallFile);
  out.transfer = {
    exportV2: { password: 'export-pass-é', file: exportV2, vaultId: argonVault.file.id },
    exportV1: { password: 'export-pass-v1', file: exportV1, itemCount: decAll.entries.length },
    kit: { passphrase: 'kit pass ✓', file: kit, recoveryKey: argonVault.extras.recoveryKey },
    handoff: { key: hand.key, envelope: hand.envelope, plain: fileText, now: hand.envelope.exp - 1000, expired: hand.envelope.exp + 1 },
    frames: { frames, vaultText: fileText },
    scans: [
      { text: `https://pevv.example/app?pevvq=${encodeURIComponent(frames[0])}#pevvq=${encodeURIComponent(frames[0])}`, kind: 'frame', value: frames[0] },
      { text: `H.${hand.key}.abcdefghijklmnop`, kind: 'handoff', key: hand.key, xfer: 'abcdefghijklmnop' },
      { text: `https://pevv.example/?pevvq=${encodeURIComponent(`H.${hand.key}`)}`, kind: 'handoff', key: hand.key, xfer: null },
      { text: 'H.short', kind: 'none' },
      { text: 'hello', kind: 'none' },
    ],
    shareUrl: [
      { token: 'H.abc.def', base: 'https://pevv.example/app', url: Q.shareUrl('H.abc.def', 'https://pevv.example/app') },
      { token: 'H.abc.def', base: 'https://pevv.example/app?x=1#old', url: Q.shareUrl('H.abc.def', 'https://pevv.example/app?x=1#old') },
    ],
    usbKey: { text: argonVault.extras.usbKeyFile, gateText: argonVault.extras.usbGateFile },
  };
  out.transfer.usbKey.gateCheck = decAll.meta.usbKeys[0]?.check ?? null;

  /* ───────────── devices and reconcile ───────────── */
  const dev = (id, name, seen, added, kind = 'phone') => ({ id, name, kind, added, seen, agent: 'x' });
  const A1 = 'aaaaaaaa-0000-0000-0000-000000000001', A2 = 'aaaaaaaa-0000-0000-0000-000000000002', A3 = 'aaaaaaaa-0000-0000-0000-000000000003';
  const rosterCases = [
    [{ devices: [dev(A1, 'One', 10, 5)], revokedDevices: [] }, { devices: [dev(A1, 'One renamed', 20, 7), dev(A2, 'Two', 15, 15)], revokedDevices: [] }],
    [{ devices: [dev(A1, 'One', 10, 5), dev(A3, 'Three', 30, 1)], revokedDevices: [] }, { devices: [dev(A2, 'Two', 15, 15)], revokedDevices: [A3, 'not an id', A3] }],
    [{ devices: [dev(A1, 'One', 10, 0)], revokedDevices: [] }, { devices: [dev(A1, 'One', 10, 9)], revokedDevices: [] }],
    [{ devices: [dev(A1, 'One', 10, 5)], revokedDevices: [] }, { devices: [dev(A1, 'One', 10, 5)], revokedDevices: [] }],
  ];
  const manyA = Array.from({ length: 45 }, (_, i) => dev(`bbbbbbbb-0000-0000-0000-${String(i).padStart(12, '0')}`, `D${i}`, 100 + i, 1));
  rosterCases.push([{ devices: manyA.slice(0, 30), revokedDevices: [] }, { devices: manyA.slice(20), revokedDevices: [] }]);
  out.roster = rosterCases.map(([a, b]) => ({ a, b, merged: D.mergeRoster(a, b), same: D.sameRoster(a, b), sameMerged: D.sameRoster(a, D.mergeRoster(a, b)) }));
  out.asDevices = {
    input: [{ id: A1, name: ' \u0001Name\u0002 ', kind: 'watch', added: 1, seen: 2, agent: 'z'.repeat(100) }, { id: 'zz', name: 'bad' }, { id: A2, name: '' }, 5, null],
  };
  out.asDevices.expected = D.asDevices(out.asDevices.input);
  out.needsWrite = [
    { prev: dev(A1, 'a', 1000, 1), next: dev(A1, 'a', 1000 + 1000, 1) },
    { prev: dev(A1, 'a', 1000, 1), next: dev(A1, 'b', 1500, 1) },
    { prev: dev(A1, 'a', 1000, 1), next: dev(A1, 'a', 1000 + 3_600_001, 1) },
    { prev: null, next: dev(A1, 'a', 5, 1) },
  ].map((c) => ({ ...c, needs: D.deviceNeedsWrite(c.prev ?? undefined, c.next) }));

  // Reconcile: the rule `adoptRemote`/`reconcileRemote` apply, evaluated on real files made by the TS engine.
  const base = argonVault.file;
  const newer = { ...base, rev: base.rev + 3 };
  const older = { ...base, rev: base.rev - 1 };
  const other = { ...base, id: 'f'.repeat(24), rev: base.rev + 10 };
  const recCase = (name, local, remote, o) => ({ name, local: local && { id: local.id, rev: local.rev }, remote: { id: remote.id, rev: remote.rev }, ...o });
  out.reconcile = [
    recCase('higher rev, same vault, locked, sync on', base, newer, { unlocked: false, source: 'cloud', prefSync: true, revokedLocally: false, expect: 'adopt' }),
    recCase('higher rev, locked, sync off, cloud', base, newer, { unlocked: false, source: 'cloud', prefSync: false, revokedLocally: false, expect: 'ignore' }),
    recCase('higher rev, locked, peer', base, newer, { unlocked: false, source: 'peer', prefSync: false, revokedLocally: false, expect: 'adopt' }),
    recCase('lower rev', base, older, { unlocked: false, source: 'peer', prefSync: true, revokedLocally: false, expect: 'ignore' }),
    recCase('same rev', base, base, { unlocked: true, source: 'peer', prefSync: true, revokedLocally: false, expect: 'merge-roster' }),
    recCase('another vault', base, other, { unlocked: true, source: 'peer', prefSync: true, revokedLocally: false, expect: 'ignore' }),
    recCase('no local vault, cloud', null, newer, { unlocked: false, source: 'cloud', prefSync: false, revokedLocally: false, expect: 'adopt' }),
    recCase('no local vault, peer', null, newer, { unlocked: false, source: 'peer', prefSync: false, revokedLocally: false, expect: 'ignore' }),
    recCase('revoked here', base, newer, { unlocked: true, source: 'cloud', prefSync: true, revokedLocally: true, expect: 'ignore' }),
    recCase('unlocked, higher rev, sync off, cloud', base, newer, { unlocked: true, source: 'cloud', prefSync: false, revokedLocally: false, expect: 'merge-roster' }),
    recCase('unlocked, higher rev, peer', base, newer, { unlocked: true, source: 'peer', prefSync: false, revokedLocally: false, expect: 'adopt' }),
  ];

  /* ───────────── passkey provider ───────────── */
  const clientHash = Uint8Array.from({ length: 32 }, (_, i) => i * 3);
  const assertion = await PP.signAssertion(passkeyMade.data, clientHash, true);
  out.passkey = {
    aaguid: PP.PASSKEY_PROVIDER_AAGUID,
    item: passkeyMade.data,
    creationAuthDataHex: hex(passkeyMade.authData),
    publicKeyHex: hex(B.unb64url(passkeyMade.data.passkeyPublicKey)),
    cosePublicKeyHex: hex(PP.coseKeyEs256(B.unb64url(passkeyMade.data.passkeyPublicKey).slice(1, 33), B.unb64url(passkeyMade.data.passkeyPublicKey).slice(33, 65))),
    clientDataHashHex: hex(clientHash),
    assertion: { authDataHex: hex(assertion.authData), signatureHex: hex(assertion.signature), signCount: assertion.signCount },
    rpIdHashHex: hex(await PP.sha256(B.utf8('example.org'))),
  };

  /* ───────────── imports and .env ───────────── */
  const csvChrome = 'name,url,username,password,note\nExample,https://example.com,alice,pw1,hello\nNo pass,https://x.test,bob,,\n';
  const csvBitwarden = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Git,"two\nlines",,0,https://git.test,carol,gpw,JBSWY3DPEHPK3PXP\n,,note,A note,just text,,0,,,,\n';
  const csvCards = 'name,url,username,password,cardnumber,cvc,expirydate,cardholdername\nCard one,,,,4111 1111 1111 1111,123,1230,Dee\n';
  const bwJson = JSON.stringify({ folders: [{ id: 'f1', name: 'Fam' }], items: [
    { type: 1, name: 'Mail', notes: 'n', folderId: 'f1', login: { uris: [{ uri: 'https://mail.test' }], username: 'eve', password: 'epw', totp: 'JBSWY3DPEHPK3PXP' } },
    { type: 2, name: 'Pin', notes: 'secret' },
    { type: 3, name: 'Amex', card: { cardholderName: 'E', number: '3782 822463 10005', code: '1234', expMonth: '3', expYear: '2031' } },
    { type: 4, name: 'Identity skipped' },
  ] });
  const protonJson = JSON.stringify({ vaults: { v1: { name: 'Personal', items: [
    { data: { type: 'login', metadata: { name: 'Proton login', note: 'pn' }, content: { urls: ['https://p.test', 'https://q.test'], itemUsername: 'fred', itemEmail: 'f@p.test', password: 'ppw', totpUri: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' } } },
    { data: { type: 'note', metadata: { name: 'Pnote', note: 'body' }, content: {} } },
    { data: { type: 'creditCard', metadata: { name: 'Pcard', note: '' }, content: { cardholderName: 'F', number: '5555 5555 5555 4444', verificationNumber: '999', expirationDate: '0829', pin: '1' } } },
    { data: { type: 'identity', metadata: { name: 'x' }, content: {} } },
  ] } } });
  out.imports = [csvChrome, csvBitwarden, csvCards, bwJson, protonJson].map((text, i) => ({ name: ['chrome', 'bitwarden-csv', 'cards-csv', 'bitwarden-json', 'proton-json'][i], text, result: X.importManagerExport(text, T) }));
  const envText = '# c\nexport A=1\nB="two words"\nC=\'single\'\nD=plain # trailing\nBAD LINE\n1X=no\nE="multi\nline"\nF="esc\\n\\"q\\""\n';
  out.dotenv = { text: envText, parsed: M.parseDotenv(envText), serialized: M.serializeDotenv([{ name: 'A', value: 'plain/ok' }, { name: 'B', value: 'with space' }, { name: 'C', value: 'q"uote\nnl\\bs' }, { name: '1bad', value: 'x' }]) };
  out.generator = { luhn: ['4111111111111111', '4111111111111112', '378282246310005'].map((n) => ({ n, ok: X.luhnValid(n) })) };

  /* ───────────── write ───────────── */
  mkdirSync(outDir, { recursive: true });
  const written = [];
  for (const [name, value] of Object.entries(out)) {
    const body = `${JSON.stringify(value, null, 2)}\n`;
    const path = join(outDir, `${name}.json`);
    if (!check) writeFileSync(path, body);
    written.push(`${name}.json`);
  }
  if (check) {
    const present = new Set(readdirSync(outDir));
    const missing = written.filter((f) => !present.has(f));
    if (missing.length) { console.error(`missing vector files: ${missing.join(', ')}`); process.exitCode = 1; }
    else console.log(`vector files present: ${written.length}`);
  } else console.log(`wrote ${written.length} vector files to ${outDir}`);
} finally {
  await server.close();
}
