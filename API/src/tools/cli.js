'use strict';

const fs = require('fs');
const path = require('path');
const mariadb = require('mariadb');
const { config } = require('../config');
const { newProductId, newSecret, newLicenseToken } = require('../lib/crypto');

function parseFlags(args) {
  const flags = {};
  const positional = [];
  for (const a of args) {
    const m = /^--([^=]+)=(.*)$/.exec(a);
    if (m) flags[m[1]] = m[2];
    else positional.push(a);
  }
  return { flags, positional };
}

async function withDb(useDatabase, fn) {
  const conn = await mariadb.createConnection({
    host: config.db.host,
    port: config.db.port,
    user: config.db.user,
    password: config.db.password,
    database: useDatabase ? config.db.database : undefined,
    multipleStatements: true,
    timezone: 'Z',
    bigIntAsNumber: true,
  });
  try {
    return await fn(conn);
  } finally {
    await conn.end();
  }
}

const commands = {
  async migrate() {
    const sql = fs.readFileSync(path.join(__dirname, '..', '..', 'database', 'schema.sql'), 'utf8');
    await withDb(false, (c) => c.query(sql));
    console.log('schema applied');
  },

  'gen-secret'() {
    console.log(newSecret());
  },

  async 'create-product'(args) {
    const { positional } = parseFlags(args);
    const name = positional.join(' ').trim();
    if (!name) throw new Error('usage: create-product "<name>"');
    const id = newProductId();
    const secret = newSecret();
    await withDb(true, (c) => c.query('INSERT INTO products (id, name, secret) VALUES (?,?,?)', [id, name, secret]));
    console.log('PRODUCT_ID     =', id);
    console.log('PRODUCT_SECRET =', secret);
  },

  async 'create-license'(args) {
    const { flags, positional } = parseFlags(args);
    const productId = positional[0];
    if (!productId) throw new Error('usage: create-license <product_id> [--ip=] [--owner=] [--contact=] [--days=N] [--note=]');
    const token = newLicenseToken();
    let expiresAt = null;
    if (flags.days) {
      const d = new Date(Date.now() + Number(flags.days) * 86400000);
      expiresAt = d.toISOString().slice(0, 19).replace('T', ' ');
    }
    await withDb(true, (c) =>
      c.query(
        'INSERT INTO licenses (token, product_id, owner_name, owner_contact, ip_locked, expires_at, note) VALUES (?,?,?,?,?,?,?)',
        [token, productId, flags.owner || null, flags.contact || null, flags.ip || null, expiresAt, flags.note || null]));
    console.log('TOKEN      =', token);
    console.log('ip_locked  =', flags.ip || '(bind on first connect)');
    console.log('expires_at =', expiresAt || 'lifetime');
  },

  async 'list-products'() {
    await withDb(true, async (c) => {
      const rows = await c.query('SELECT id, name, created_at FROM products ORDER BY created_at DESC');
      console.table(rows);
    });
  },

  async 'list-licenses'(args) {
    const productId = args[0];
    await withDb(true, async (c) => {
      const rows = productId
        ? await c.query('SELECT token, status, ip_locked, last_seen_at, expires_at FROM licenses WHERE product_id = ? ORDER BY created_at DESC', [productId])
        : await c.query('SELECT token, product_id, status, ip_locked, last_seen_at, expires_at FROM licenses ORDER BY created_at DESC LIMIT 200');
      console.table(rows);
    });
  },

  async revoke(args) {
    const token = args[0];
    if (!token) throw new Error('usage: revoke <token>');
    const r = await withDb(true, (c) => c.query('UPDATE licenses SET status = ? WHERE token = ?', ['revoked', token]));
    console.log(r.affectedRows ? `revoked ${token}` : 'token not found');
  },

  async 'reset-ip'(args) {
    const token = args[0];
    if (!token) throw new Error('usage: reset-ip <token>');
    const r = await withDb(true, (c) => c.query('UPDATE licenses SET ip_locked = NULL WHERE token = ?', [token]));
    console.log(r.affectedRows ? `ip lock cleared for ${token}` : 'token not found');
  },
};

async function run() {
  const [cmd, ...args] = process.argv.slice(2);
  const fn = commands[cmd];
  if (!fn) {
    console.log('commands: ' + Object.keys(commands).join(', '));
    process.exit(cmd ? 1 : 0);
  }
  try {
    await fn(args);
    process.exit(0);
  } catch (e) {
    console.error('error: ' + e.message);
    process.exit(1);
  }
}

run();
