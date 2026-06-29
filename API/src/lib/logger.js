'use strict';

function ts() {
  return new Date().toISOString();
}

function fmt(level, msg, meta) {
  let line = `${ts()} [${level}] ${msg}`;
  if (meta && Object.keys(meta).length) line += ' ' + JSON.stringify(meta);
  return line;
}

module.exports = {
  info: (msg, meta) => console.log(fmt('INFO', msg, meta)),
  warn: (msg, meta) => console.warn(fmt('WARN', msg, meta)),
  error: (msg, meta) => console.error(fmt('ERROR', msg, meta)),
};
