'use strict';

const express = require('express');
const db = require('../db');
const { newProductId, newSecret, newLicenseToken, newEd25519KeyPair } = require('../lib/crypto');
const logger = require('../lib/logger');

const router = express.Router();

const IPV = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9A-Fa-f:]{2,45}$/;
const LIC_COLS =
  'token, product_id, status, ip_locked, last_ip, last_seen_at, owner_name, owner_contact, note, features, created_at, expires_at';

router.use((req, res, next) => {
  if (req.method !== 'GET') {
    res.on('finish', () => {
      db.query(
        'INSERT INTO admin_audit (actor_fp, method, route, ip, status) VALUES (?,?,?,?,?)',
        [req.adminFp || null, req.method, (req.originalUrl || '').slice(0, 255), req.clientIp || null, res.statusCode]
      ).catch((e) => logger.error('admin audit failed', { error: e.message }));
    });
  }
  next();
});

function fail(res, status, code, message) {
  return res.status(status).json({ ok: false, code, message });
}

async function findLicense(token) {
  return db.queryOne('SELECT id, token FROM licenses WHERE token = ? LIMIT 1', [token]);
}

router.post('/products', async (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name) return fail(res, 400, 'bad_request', 'name is required');

  const id = newProductId();
  const secret = newSecret();
  const { publicKeyHex, privateKeyHex } = newEd25519KeyPair();
  const version = typeof req.body?.version === 'string' && req.body.version.trim()
    ? req.body.version.trim().slice(0, 20) : '1.0.0';
  try {
    await db.query(
      'INSERT INTO products (id, name, secret, version, ed_private, ed_public) VALUES (?,?,?,?,?,?)',
      [id, name, secret, version, privateKeyHex, publicKeyHex]
    );
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return fail(res, 409, 'duplicate', 'product name already exists');
    logger.error('create product failed', { error: e.message });
    return fail(res, 500, 'server_error', 'could not create product');
  }
  return res.json({ ok: true, product: { id, name, secret, ed_public: publicKeyHex } });
});

router.get('/products', async (_req, res) => {
  const rows = await db.query(
    'SELECT id, name, created_at, (SELECT COUNT(*) FROM licenses l WHERE l.product_id = products.id) AS licenses FROM products ORDER BY created_at DESC'
  );
  return res.json({ ok: true, products: rows });
});

router.get('/products/:id/secret', async (req, res) => {
  const row = await db.queryOne(
    'SELECT id, name, secret, version, ed_public, ed_private FROM products WHERE id = ? LIMIT 1', [req.params.id]);
  if (!row) return fail(res, 404, 'not_found', 'no such product');
  if (!row.ed_public || !row.ed_private) {
    const { publicKeyHex, privateKeyHex } = newEd25519KeyPair();
    await db.query('UPDATE products SET ed_private = ?, ed_public = ? WHERE id = ?', [privateKeyHex, publicKeyHex, row.id]);
    row.ed_public = publicKeyHex;
  }
  delete row.ed_private;
  return res.json({ ok: true, product: row });
});

router.put('/products/:id/version', async (req, res) => {
  const version = typeof req.body?.version === 'string' ? req.body.version.trim().slice(0, 20) : '';
  const r = await db.query('UPDATE products SET version = ? WHERE id = ?', [version || null, req.params.id]);
  if (!r.affectedRows) {
    const exists = await db.queryOne('SELECT id FROM products WHERE id = ?', [req.params.id]);
    if (!exists) return fail(res, 404, 'not_found', 'no such product');
  }
  return res.json({ ok: true, version: version || null });
});

router.delete('/products/:id', async (req, res) => {
  const row = await db.queryOne('SELECT id FROM products WHERE id = ? LIMIT 1', [req.params.id]);
  if (!row) return fail(res, 404, 'not_found', 'no such product');
  await db.query('DELETE FROM products WHERE id = ?', [req.params.id]);
  return res.json({ ok: true, deleted: req.params.id });
});

router.post('/licenses', async (req, res) => {
  const b = req.body || {};
  const productId = (b.product_id || '').trim();
  if (!productId) return fail(res, 400, 'bad_request', 'product_id is required');

  const product = await db.queryOne('SELECT id FROM products WHERE id = ?', [productId]);
  if (!product) return fail(res, 404, 'unknown_product', 'no such product_id');

  const token = newLicenseToken();
  const ip = (b.ip || '').trim() || null;
  if (ip && !IPV.test(ip)) return fail(res, 400, 'bad_request', 'invalid ip');
  let features = null;
  if (b.features) {
    features = JSON.stringify(b.features);
    if (features.length > 4096) return fail(res, 400, 'bad_request', 'features too large');
  }
  const expiresAt = b.expires_at ? new Date(b.expires_at) : null;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) {
    return fail(res, 400, 'bad_request', 'expires_at is not a valid date');
  }

  try {
    await db.query(
      `INSERT INTO licenses (token, product_id, owner_name, owner_contact, ip_locked, expires_at, features, note)
       VALUES (?,?,?,?,?,?,?,?)`,
      [token, productId, b.owner_name || null, b.owner_contact || null, ip, expiresAt, features, b.note || null]
    );
  } catch (e) {
    logger.error('create license failed', { error: e.message });
    return fail(res, 500, 'server_error', 'could not create license');
  }
  return res.json({ ok: true, license: { token, product_id: productId, ip_locked: ip } });
});

router.get('/licenses', async (req, res) => {
  const { token, product_id } = req.query;
  if (!token && !product_id) return fail(res, 400, 'filter_required', 'token or product_id is required');
  const rows = token
    ? await db.query(`SELECT ${LIC_COLS} FROM licenses WHERE token = ?`, [token])
    : await db.query(`SELECT ${LIC_COLS} FROM licenses WHERE product_id = ? ORDER BY created_at DESC LIMIT 1000`, [product_id]);
  return res.json({ ok: true, licenses: rows });
});

async function setStatus(req, res, status) {
  const r = await findLicense(req.params.token);
  if (!r) return fail(res, 404, 'not_found', 'no such token');
  await db.query('UPDATE licenses SET status = ? WHERE id = ?', [status, r.id]);
  return res.json({ ok: true, token: r.token, status });
}

router.post('/licenses/:token/revoke', (req, res) => setStatus(req, res, 'revoked'));
router.post('/licenses/:token/suspend', (req, res) => setStatus(req, res, 'suspended'));
router.post('/licenses/:token/activate', (req, res) => setStatus(req, res, 'active'));

router.post('/licenses/:token/reset-ip', async (req, res) => {
  const r = await findLicense(req.params.token);
  if (!r) return fail(res, 404, 'not_found', 'no such token');
  await db.query('UPDATE licenses SET ip_locked = NULL WHERE id = ?', [r.id]);
  return res.json({ ok: true, token: r.token, ip_locked: null });
});

router.post('/licenses/:token/set-ip', async (req, res) => {
  const ip = (req.body?.ip || '').trim() || null;
  if (ip && !IPV.test(ip)) return fail(res, 400, 'bad_request', 'invalid ip');
  const r = await findLicense(req.params.token);
  if (!r) return fail(res, 404, 'not_found', 'no such token');
  await db.query('UPDATE licenses SET ip_locked = ? WHERE id = ?', [ip, r.id]);
  return res.json({ ok: true, token: r.token, ip_locked: ip });
});

router.delete('/licenses/:token', async (req, res) => {
  const r = await findLicense(req.params.token);
  if (!r) return fail(res, 404, 'not_found', 'no such token');
  await db.query('DELETE FROM licenses WHERE id = ?', [r.id]);
  return res.json({ ok: true, deleted: r.token });
});

router.get('/logs', async (req, res) => {
  const { token } = req.query;
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 100, 1), 1000);
  const rows = token
    ? await db.query('SELECT id, token, ip, action, result, message, created_at FROM verify_logs WHERE token = ? ORDER BY id DESC LIMIT ?', [token, limit])
    : await db.query('SELECT id, token, ip, action, result, message, created_at FROM verify_logs ORDER BY id DESC LIMIT ?', [limit]);
  return res.json({ ok: true, logs: rows });
});

module.exports = router;
