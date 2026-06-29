'use strict';

const path = require('path');
const express = require('express');
const { config, assertProductionSanity } = require('./config');
const db = require('./db');
const logger = require('./lib/logger');
const adminAuth = require('./middleware/adminAuth');
const rateLimit = require('./middleware/rateLimit');
const verifyRoute = require('./routes/verify');
const adminRoute = require('./routes/admin');

const app = express();
app.disable('x-powered-by');

const tp = config.http.trustProxy;
if (tp && tp !== '0') {
  app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : tp.split(',').map((s) => s.trim()));
}

app.use(express.json({
  limit: '1mb',
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); },
}));

app.use((req, _res, next) => {
  let ip = req.ip || req.socket?.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  req.clientIp = ip;
  next();
});

app.use((_req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  next();
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/health', (_req, res) => res.json({ ok: true, service: 'nexus-license', time: Date.now() }));

app.use('/api', rateLimit, verifyRoute);
app.use('/admin', rateLimit, adminAuth, adminRoute);

app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ ok: false, code: 'bad_json' });
  }
  logger.error('unhandled error', { error: err?.message });
  return res.status(500).json({ ok: false, code: 'server_error' });
});

app.use((_req, res) => res.status(404).json({ ok: false, code: 'not_found' }));

async function main() {
  assertProductionSanity();
  await db.ping();

  const server = app.listen(config.http.port, config.http.host, () => {
    logger.info('NEXUS License API listening', {
      url: `http://${config.http.host}:${config.http.port}`,
      trustProxy: config.http.trustProxy,
    });
  });

  const shutdown = (sig) => {
    logger.info(`received ${sig}, shutting down`);
    server.close(async () => {
      await db.close().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 8000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  logger.error('fatal boot error', { error: err.message });
  console.error(err);
  process.exit(1);
});
