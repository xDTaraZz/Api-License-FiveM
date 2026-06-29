'use strict';

require('dotenv').config();

function int(name, def) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : def;
}

const config = {
  http: {
    port: int('PORT', 3000),
    host: process.env.HOST || '0.0.0.0',
    trustProxy: process.env.TRUST_PROXY || '0',
  },
  db: {
    host: process.env.DB_HOST || '127.0.0.1',
    port: int('DB_PORT', 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'nexus_license',
    connectionLimit: int('DB_CONNECTION_LIMIT', 10),
  },
  security: {
    adminKey: process.env.ADMIN_KEY || '',
    signatureWindowSeconds: int('SIGNATURE_WINDOW_SECONDS', 30),
  },
  discord: {
    activations: process.env.DISCORD_WEBHOOK_ACTIVATIONS || '',
    violations: process.env.DISCORD_WEBHOOK_VIOLATIONS || '',
    security: process.env.DISCORD_WEBHOOK_SECURITY || '',
  },
};

function assertProductionSanity() {
  const problems = [];
  if (!config.security.adminKey || config.security.adminKey.length < 16) {
    problems.push('ADMIN_KEY is missing or too short (need >= 16 chars).');
  }
  if (config.security.adminKey === 'change-me-to-a-long-random-string') {
    problems.push('ADMIN_KEY still has the example value.');
  }
  if (problems.length) {
    throw new Error('Configuration error:\n  - ' + problems.join('\n  - '));
  }
}

module.exports = { config, assertProductionSanity };
