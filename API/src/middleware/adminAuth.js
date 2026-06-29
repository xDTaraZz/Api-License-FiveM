'use strict';

const crypto = require('crypto');
const { config } = require('../config');
const { timingSafeEqualHex } = require('../lib/crypto');

const ALLOW = (process.env.ADMIN_ALLOW_IPS || '').split(',').map((s) => s.trim()).filter(Boolean);

function constantTimeMatch(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest('hex');
  const hb = crypto.createHash('sha256').update(String(b)).digest('hex');
  return timingSafeEqualHex(ha, hb);
}

function adminAuth(req, res, next) {
  if (ALLOW.length && !ALLOW.includes(req.ip) && !ALLOW.includes(req.clientIp)) {
    return res.status(403).json({ ok: false, code: 'forbidden' });
  }
  const provided = req.get('X-Admin-Key') || '';
  if (!config.security.adminKey || !constantTimeMatch(provided, config.security.adminKey)) {
    return res.status(401).json({ ok: false, code: 'unauthorized' });
  }
  req.adminFp = crypto.createHash('sha256').update(provided).digest('hex').slice(0, 16);
  return next();
}

module.exports = adminAuth;
