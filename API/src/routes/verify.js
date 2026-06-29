'use strict';

const crypto = require('crypto');
const express = require('express');
const db = require('../db');
const { config } = require('../config');
const { hmacHex, timingSafeEqualHex, ed25519SignHex } = require('../lib/crypto');
const logger = require('../lib/logger');
const discord = require('../lib/discord');

const router = express.Router();

const DUMMY_SECRET = '0'.repeat(64);
const IPV = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9A-Fa-f:]{2,45}$/;
const NONCE_RE = /^[a-f0-9]{16,64}$/i;
const SIG_RE = /^[a-f0-9]{64}$/;
const CODE_RE = /^[A-Za-z0-9_]{1,30}$/;

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function isPublicIp(ip) {
  if (typeof ip !== 'string') return false;
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = +m[1], b = +m[2];
  if (a === 10) return false;
  if (a === 127) return false;
  if (a === 0) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

async function pruneLogs() {
  let n;
  do {
    const r = await db
      .query('DELETE FROM verify_logs WHERE created_at < UTC_TIMESTAMP() - INTERVAL 30 DAY LIMIT 5000')
      .catch(() => ({ affectedRows: 0 }));
    n = r.affectedRows || 0;
  } while (n === 5000);
  await db.query('DELETE FROM used_nonces WHERE expires_at < UTC_TIMESTAMP() LIMIT 5000').catch(() => {});
}
const retentionSweep = setInterval(() => { pruneLogs(); }, 6 * 60 * 60 * 1000);
retentionSweep.unref?.();

function audit(token, ip, action, result, message) {
  db.query(
    'INSERT INTO verify_logs (token, ip, action, result, message) VALUES (?,?,?,?,?)',
    [token || null, ip || null, action || null, result, (message || '').slice(0, 180)]
  ).catch((e) => logger.error('audit insert failed', { error: e.message }));
}

function signed(secret, state, edPrivate) {
  const payload = JSON.stringify(state);
  const out = { payload, sig: hmacHex(secret, payload) };
  if (edPrivate) {
    try { out.ed = ed25519SignHex(edPrivate, payload); }
    catch (e) { logger.error('ed25519 sign failed', { error: e.message }); }
  }
  return out;
}

function unwrapSig(h) {
  if (typeof h !== 'string' || h.length < 2) return '';
  const n = parseInt(h.slice(0, 2), 16);
  if (!Number.isInteger(n) || n < 0 || n > 64) return '';
  return h.slice(2 + n, 2 + n + 64).toLowerCase();
}

function nowEpoch() {
  return Math.floor(Date.now() / 1000);
}

function toEpoch(dt) {
  return dt ? Math.floor(new Date(dt).getTime() / 1000) : null;
}

router.post('/verify', async (req, res) => {
  const raw = req.rawBody || '';
  const body = req.body || {};

  const token = typeof body.token === 'string' && body.token.length <= 64 ? body.token : null;
  const nonce = typeof body.nonce === 'string' && NONCE_RE.test(body.nonce) ? body.nonce : null;
  const ts = Number.parseInt(body.ts, 10);
  const action = typeof body.action === 'string' ? body.action.slice(0, 40) : 'verify';
  const signature = unwrapSig(req.get('X-Signature') || '');

  const connIp = req.clientIp;
  const reportedIp = typeof body.ip === 'string' && IPV.test(body.ip.trim()) ? body.ip.trim() : null;
  const ip = reportedIp || connIp;

  if (!nonce || !Number.isFinite(ts) || !SIG_RE.test(signature)) {
    return res.status(400).json({ ok: false, code: 'bad_request' });
  }
  if (!token) {
    audit(token, ip, action, 'no_token', null);
    discord.notify('security', {
      tone: 'warn',
      title: '🔸 Verify with empty token (license not set / fresh install)',
      dedupeKey: `no_token:${ip}`,
      fields: {
        IP: ip,
        Resource: typeof body.resource === 'string' ? body.resource.slice(0, 80) : '-',
        Hostname: typeof body.hostname === 'string' ? body.hostname.slice(0, 100) : '-',
      },
    });
    return res.status(401).json({ ok: false, code: 'unauthorized' });
  }

  let row;
  try {
    row = await db.queryOne(
      `SELECT l.*, p.secret AS product_secret, p.name AS product_name, p.version AS product_version, p.ed_private AS ed_private
         FROM licenses l JOIN products p ON p.id = l.product_id
        WHERE l.token = ? LIMIT 1`,
      [token]
    );
  } catch (e) {
    logger.error('verify db error', { error: e.message });
    return res.status(500).json({ ok: false, code: 'server_error' });
  }

  const secret = row ? row.product_secret : null;
  const edPriv = row ? row.ed_private : null;
  const expectedSig = hmacHex(secret || DUMMY_SECRET, raw);
  const sigOk = !!secret && timingSafeEqualHex(signature, expectedSig);
  if (!row || !sigOk) {
    const why = !row ? 'bad_token' : 'bad_signature';
    audit(token, ip, action, why, row ? row.product_name : null);
    discord.notify('security', {
      tone: why === 'bad_signature' ? 'bad' : 'warn',
      title: why === 'bad_signature'
        ? '🛑 Unauthorized — valid token, wrong secret (fake API / reverse attempt)'
        : '🔸 Unauthorized — unknown token',
      dedupeKey: `${why}:${token || '-'}:${ip}`,
      fields: {
        Reason: why,
        Product: row ? row.product_name : '(unknown token)',
        Token: discord.maskToken(token),
        IP: ip,
        Resource: typeof body.resource === 'string' ? body.resource.slice(0, 80) : '-',
        Hostname: typeof body.hostname === 'string' ? body.hostname.slice(0, 100) : '-',
      },
    });
    return res.status(401).json({ ok: false, code: 'unauthorized' });
  }

  if (reportedIp && connIp && reportedIp !== connIp && isPublicIp(connIp)) {
    audit(token, ip, action, 'ip_spoof_suspect', `reported=${reportedIp} conn=${connIp}`);
    discord.notify('security', {
      tone: 'warn',
      title: '🕵️ IP spoof suspected — reported IP ≠ connection IP',
      dedupeKey: `spoof:${token}:${reportedIp}:${connIp}`,
      fields: {
        Product: row.product_name,
        Token: discord.maskToken(token),
        'Reported (ipify)': reportedIp,
        'Connection IP': connIp,
        Resource: typeof body.resource === 'string' ? body.resource.slice(0, 80) : '-',
      },
    });
  }

  const skew = Math.abs(nowEpoch() - ts);
  if (skew > config.security.signatureWindowSeconds) {
    audit(token, ip, action, 'stale_timestamp', `skew=${skew}s`);
    return res.status(200).json(signed(secret, {
      ok: false, code: 'stale_timestamp', nonce, server_time: nowEpoch(), message: 'Clock skew too large',
    }, edPriv));
  }

  const nonceTtl = config.security.signatureWindowSeconds + 5;
  let fresh;
  try {
    fresh = await db.query(
      `INSERT IGNORE INTO used_nonces (nonce, expires_at) VALUES (?, UTC_TIMESTAMP() + INTERVAL ${nonceTtl} SECOND)`,
      [nonce]
    );
  } catch (e) {
    logger.error('nonce store error', { error: e.message });
    return res.status(500).json({ ok: false, code: 'server_error' });
  }
  if (!fresh.affectedRows) {
    audit(token, ip, action, 'replay', null);
    return res.status(200).json(signed(secret, {
      ok: false, code: 'replay', nonce, server_time: nowEpoch(), message: 'Nonce already used',
    }, edPriv));
  }

  const baseFail = (code, message) => {
    audit(token, ip, action, code, message);
    if (['revoked', 'suspended', 'expired', 'ip_mismatch'].includes(code)) {
      discord.notify('security', {
        tone: code === 'ip_mismatch' ? 'warn' : 'bad',
        title: code === 'ip_mismatch' ? '⚠️ IP Mismatch — possible key sharing' : `⛔ License ${code}`,
        dedupeKey: `${code}:${token}:${ip}`,
        fields: {
          Product: row.product_name,
          Token: discord.maskToken(token),
          Owner: row.owner_name || '-',
          'Locked IP': row.ip_locked || '-',
          'Request IP': ip,
          Resource: typeof body.resource === 'string' ? body.resource.slice(0, 80) : '-',
        },
      });
    }
    return res.status(200).json(signed(secret, {
      ok: false, code, nonce, server_time: nowEpoch(), token, status: row.status, message,
    }, edPriv));
  };

  if (row.status !== 'active') {
    return baseFail(row.status === 'revoked' ? 'revoked' : 'suspended', `License is ${row.status}`);
  }

  const expEpoch = toEpoch(row.expires_at);
  if (expEpoch !== null && expEpoch < nowEpoch()) {
    return baseFail('expired', 'License expired');
  }

  if (row.ip_locked && row.ip_locked !== ip) {
    return baseFail('ip_mismatch', 'IP not authorized');
  }

  const wasUnbound = !row.ip_locked;
  try {
    if (!row.ip_locked) {
      const r = await db.query(
        'UPDATE licenses SET ip_locked=?, last_ip=?, last_seen_at=UTC_TIMESTAMP() WHERE id=? AND ip_locked IS NULL',
        [ip, reportedIp || connIp, row.id]
      );
      if (!r.affectedRows) {
        const cur = await db.queryOne('SELECT ip_locked FROM licenses WHERE id=?', [row.id]);
        if (!cur || cur.ip_locked !== ip) return baseFail('ip_mismatch', 'IP not authorized');
      }
      row.ip_locked = ip;
    } else {
      await db.query(
        'UPDATE licenses SET last_ip=?, last_seen_at=UTC_TIMESTAMP() WHERE id=?',
        [reportedIp || connIp, row.id]
      );
    }
  } catch (e) {
    logger.error('verify update error', { error: e.message });
    return res.status(500).json({ ok: false, code: 'server_error' });
  }

  let features = {};
  if (row.features) {
    try {
      features = typeof row.features === 'string' ? JSON.parse(row.features) : row.features;
    } catch { features = {}; }
  }

  const state = {
    ok: true,
    code: 'ok',
    nonce,
    req_hash: sha256hex(raw),
    server_time: nowEpoch(),
    grant_exp: nowEpoch() + 300,
    token,
    product: row.product_name,
    owner: row.owner_name || null,
    status: row.status,
    expires_at: expEpoch,
    ip: row.ip_locked,
    features,
    resource: typeof body.resource === 'string' ? body.resource.slice(0, 80) : null,
    latest_version: row.product_version || null,
    message: 'License verified',
  };

  audit(token, ip, action, 'ok', null);

  discord.notify('activation', {
    tone: 'ok',
    title: wasUnbound ? '🟢 New activation' : '✅ License verified',
    dedupeKey: wasUnbound ? null : `ok:${token}:${ip}`,
    fields: {
      Product: row.product_name,
      Token: discord.maskToken(token),
      Owner: row.owner_name || '-',
      IP: row.ip_locked,
      Resource: state.resource || '-',
      Version: row.product_version || '-',
      Hostname: typeof body.hostname === 'string' ? body.hostname.slice(0, 100) : '-',
    },
  });

  return res.status(200).json(signed(secret, state, edPriv));
});

router.post('/violation', async (req, res) => {
  const raw = req.rawBody || '';
  const body = req.body || {};
  const token = typeof body.token === 'string' && body.token.length <= 64 ? body.token : null;
  const rawCode = typeof body.code === 'string' ? body.code : 'unknown';
  const code = CODE_RE.test(rawCode) ? rawCode : 'unknown';
  const signature = unwrapSig(req.get('X-Signature') || '');
  const ip = req.clientIp;

  res.status(204).end();

  if (!token || !SIG_RE.test(signature)) return;
  let row;
  try {
    row = await db.queryOne(
      'SELECT p.secret AS secret, p.name AS product_name, l.owner_name AS owner_name FROM licenses l JOIN products p ON p.id = l.product_id WHERE l.token = ? LIMIT 1',
      [token]
    );
  } catch { return; }
  if (!row) return;
  if (!timingSafeEqualHex(signature, hmacHex(row.secret, raw))) return;

  const hostname = typeof body.hostname === 'string' ? body.hostname.slice(0, 120) : '';
  audit(token, ip, 'violation', ('tamper:' + code).slice(0, 40), hostname);

  discord.notify('violation', {
    tone: 'bad',
    title: '🚨 Tamper / bypass detected',
    dedupeKey: `${code}:${token}:${ip}`,
    fields: {
      'Detection': code,
      Product: row.product_name,
      Token: discord.maskToken(token),
      Owner: row.owner_name || '-',
      IP: ip,
      Hostname: hostname || '-',
    },
  });
});

module.exports = router;