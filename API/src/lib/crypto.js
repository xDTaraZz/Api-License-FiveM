'use strict';

const crypto = require('crypto');

function hmacHex(secret, message) {
  return crypto.createHmac('sha256', String(secret)).update(String(message), 'utf8').digest('hex');
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length || a.length === 0) return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function newSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function newEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  return { publicKeyHex: pubRaw.toString('hex'), privateKeyHex: privRaw.toString('hex') };
}

function ed25519SignHex(privateKeyHex, message) {
  const seed = Buffer.from(privateKeyHex, 'hex');
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed,
  ]);
  const key = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return crypto.sign(null, Buffer.from(String(message), 'utf8'), key).toString('hex');
}

function newProductId() {
  return 'prod_' + crypto.randomBytes(4).toString('hex');
}

function newLicenseToken(prefix = 'Exotic') {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const groups = 4;
  const groupLen = 4;
  const bytes = crypto.randomBytes(groups * groupLen);
  let out = prefix;
  for (let g = 0; g < groups; g++) {
    let chunk = '';
    for (let i = 0; i < groupLen; i++) chunk += alphabet[bytes[g * groupLen + i] % alphabet.length];
    out += '-' + chunk;
  }
  return out;
}

module.exports = {
  hmacHex, timingSafeEqualHex, newSecret, newProductId, newLicenseToken,
  newEd25519KeyPair, ed25519SignHex,
};

if (require.main === module) {
  const assert = require('node:assert');
  const KAT_KEY = 'key';
  const KAT_MSG = 'The quick brown fox jumps over the lazy dog';
  const KAT_EXPECTED = 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8';
  const got = hmacHex(KAT_KEY, KAT_MSG);
  assert.strictEqual(got, KAT_EXPECTED, 'HMAC-SHA256 known-answer test FAILED');
  assert.strictEqual(timingSafeEqualHex(got, KAT_EXPECTED), true);
  assert.strictEqual(timingSafeEqualHex(got, 'deadbeef'), false);
  console.log('crypto self-test OK');
}
