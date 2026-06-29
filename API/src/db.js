'use strict';

const mariadb = require('mariadb');
const { config } = require('./config');
const logger = require('./lib/logger');

const pool = mariadb.createPool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  connectionLimit: config.db.connectionLimit,
  bigIntAsNumber: true,
  insertIdAsNumber: true,
  timezone: 'Z',
});

async function query(sql, params = []) {
  return pool.query(sql, params);
}

async function queryOne(sql, params = []) {
  const rows = await query(sql, params);
  return rows && rows.length ? rows[0] : null;
}

async function ping() {
  const conn = await pool.getConnection();
  try {
    await conn.ping();
  } finally {
    conn.release();
  }
  logger.info('MariaDB pool ready', { host: config.db.host, db: config.db.database });
}

async function close() {
  await pool.end();
}

module.exports = { pool, query, queryOne, ping, close };
