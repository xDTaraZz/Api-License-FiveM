'use strict';

const WINDOW_MS = 60000;
const MAX = 120;
const MAX_KEYS = 20000;

const buckets = new Map();

const sweep = setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
}, WINDOW_MS);
sweep.unref?.();

function rateLimit(req, res, next) {
  const key = req.ip || req.clientIp || 'unknown';
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || b.resetAt <= now) {
    if (buckets.size >= MAX_KEYS) {
      buckets.delete(buckets.keys().next().value);
    }
    b = { count: 0, resetAt: now + WINDOW_MS };
    buckets.set(key, b);
  }
  b.count += 1;
  if (b.count > MAX) {
    res.setHeader('Retry-After', String(Math.ceil((b.resetAt - now) / 1000)));
    return res.status(429).json({ ok: false, code: 'rate_limited' });
  }
  return next();
}

module.exports = rateLimit;
