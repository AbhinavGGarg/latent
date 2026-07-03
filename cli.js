#!/usr/bin/env node
'use strict';
/*
 * LATENT — cli.js
 * One-command launcher: boots server.js from this package's directory, waits
 * a beat, then opens the report in the default browser. Pure Node stdlib,
 * zero dependencies, Node >= 18. PORT env respected (default 8820).
 */
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

// Same dir resolution server.js uses (dir of the invoked script), plus a
// realpath step so an npx/npm bin symlink still lands in the package dir.
let self = path.resolve(process.argv[1] || __filename);
try {
  self = fs.realpathSync(self);
} catch (_) {
  /* keep the resolved path */
}
const BASE = path.dirname(self);
const SERVER = path.join(BASE, 'server.js');

const PORT = Number(process.env.PORT) || 8820;
const URL = `http://localhost:${PORT}`;

console.log(`latent v0.1.0 — read your machine, get receipts (${URL})`);

const child = spawn(process.execPath, [SERVER], {
  stdio: 'inherit',
  env: process.env,
});

child.on('error', (err) => {
  console.error(`latent: failed to start server.js (${err.message})`);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  process.exit(signal ? 0 : code == null ? 0 : code);
});

// Forward Ctrl+C to the server; we exit when the child does (handler above).
process.on('SIGINT', () => {
  child.kill('SIGINT');
});

function openBrowser(url) {
  let cmd, args;
  if (process.platform === 'darwin') {
    cmd = 'open';
    args = [url];
  } else if (process.platform === 'win32') {
    cmd = 'cmd';
    args = ['/c', 'start', '', url];
  } else {
    cmd = 'xdg-open';
    args = [url];
  }
  try {
    const opener = spawn(cmd, args, { stdio: 'ignore', detached: true });
    opener.on('error', () => {
      console.log(`Open ${url} in your browser.`);
    });
    opener.unref();
  } catch (_) {
    console.log(`Open ${url} in your browser.`);
  }
}

setTimeout(() => {
  if (child.exitCode === null && child.signalCode === null) openBrowser(URL);
}, 800);
