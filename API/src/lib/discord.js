'use strict';

const https = require('https');
const { URL } = require('url');
const { config } = require('../config');
const logger = require('./logger');

const CHANNELS = {
  activation: () => config.discord.activations,
  violation: () => config.discord.violations,
  security: () => config.discord.security,
};

const COLORS = {
  ok: 0x2ecc71,
  warn: 0xf1c40f,
  bad: 0xe74c3c,
  info: 0x5865f2,
};

const seen = new Map();
const DEDUPE_MS = 60000;
const MAX_SEEN = 5000;

function throttled(key) {
  const now = Date.now();
  const last = seen.get(key);
  if (last && now - last < DEDUPE_MS) return true;
  if (seen.size >= MAX_SEEN) seen.delete(seen.keys().next().value);
  seen.set(key, now);
  return false;
}

function maskToken(token) {
  if (typeof token !== 'string' || token.length === 0) return '-';
  return token.slice(0, 200);
}

function post(url, payload) {
  let target;
  try {
    target = new URL(url);
  } catch {
    return;
  }
  const data = Buffer.from(JSON.stringify(payload), 'utf8');
  const req = https.request(
    {
      hostname: target.hostname,
      path: target.pathname + target.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': data.length },
      timeout: 5000,
    },
    (res) => { res.on('data', () => {}); res.on('end', () => {}); }
  );
  req.on('error', (e) => logger.error('discord webhook failed', { error: e.message }));
  req.on('timeout', () => req.destroy());
  req.write(data);
  req.end();
}

function fieldsFrom(obj) {
  return Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .slice(0, 25)
    .map(([name, value]) => ({ name, value: String(value).slice(0, 1024), inline: true }));
}

function notify(channel, { tone = 'info', title, fields = {}, dedupeKey } = {}) {
  const url = (CHANNELS[channel] || (() => ''))();
  if (!url) return;
  if (dedupeKey && throttled(`${channel}:${dedupeKey}`)) return;

  const embed = {
    title: String(title || 'License event').slice(0, 256),
    color: COLORS[tone] || COLORS.info,
    fields: fieldsFrom(fields),
    footer: { text: 'xDTaraZ License' },
    timestamp: new Date().toISOString(),
  };
  post(url, { username: 'xDTaraZ License', embeds: [embed] });
}

module.exports = { notify, maskToken };
