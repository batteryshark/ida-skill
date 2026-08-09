#!/usr/bin/env node
// bridge.mjs
// Manages the idalib worker process lifecycle: start, stop, status.
//
// The worker is a persistent Python process that loads idalib once and serves
// commands over localhost TCP without reopening the database for every query.
//
// Usage:
//   node bridge.mjs start   --binary <path> [--run-auto-analysis] [--idle <sec>] [--timeout <sec>]
//   node bridge.mjs stop    --binary <path>
//   node bridge.mjs status  --binary <path>
//   node bridge.mjs stop-all

import { createHash } from 'node:crypto';
import { openSync, closeSync, existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync, realpathSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import * as net from 'node:net';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────────────────────
// Paths
// ─────────────────────────────────────────────────────────────────────────────
const BIN_DIR = resolve(process.env.IDA_SKILL_BIN_DIR || join(__dirname, '..', 'bin'));
const RUNTIME_STATE = join(BIN_DIR, 'runtime');

// Map Node's process.platform to the runtime folder suffix used by setup.mjs.
const HOST_PLATFORM_KEY = process.platform === 'win32' ? 'windows'
  : process.platform === 'darwin' ? 'mac' : 'linux';

// Resolve the runtime directory. Preference order:
//   1. $IDA_RUNTIME_DIR (explicit override)
//   2. bin/ida-runtime-<host>/   (per-platform runtime, always suffixed)
function resolveRuntimeDir() {
  if (process.env.IDA_RUNTIME_DIR) return resolve(process.env.IDA_RUNTIME_DIR);
  return join(BIN_DIR, `ida-runtime-${HOST_PLATFORM_KEY}`);
}
const RUNTIME_DIR = resolveRuntimeDir();

// ─────────────────────────────────────────────────────────────────────────────
// Port / PID file management (keyed by binary path hash)
// ─────────────────────────────────────────────────────────────────────────────
function binaryHash(binaryPath) {
  // Use realpath to resolve symlinks (e.g. /tmp → /private/tmp on macOS)
  // Must match cli.py's os.path.realpath()
  const resolved = realpathSync(binaryPath);
  return createHash('md5').update(resolved).digest('hex').slice(0, 12);
}
function portFilePath(binaryPath) {
  return join(RUNTIME_STATE, `worker-${binaryHash(binaryPath)}.port`);
}
function pidFilePath(binaryPath) {
  return join(RUNTIME_STATE, `worker-${binaryHash(binaryPath)}.pid`);
}
function logFilePath(binaryPath) {
  return join(RUNTIME_STATE, `worker-${binaryHash(binaryPath)}.log`);
}
function lockFilePath(binaryPath) {
  return join(RUNTIME_STATE, `worker-${binaryHash(binaryPath)}.lock`);
}

// Atomically claim the start lock (O_CREAT|O_EXCL). Concurrent `start`
// invocations would otherwise both see "no worker" and spawn two idalib
// processes on the same database. A lock whose holder PID is dead is stale
// (crashed mid-start) and gets reclaimed.
function tryAcquireStartLock(binaryPath) {
  const lockFile = lockFilePath(binaryPath);
  const claim = () => {
    try {
      writeFileSync(lockFile, String(process.pid), { flag: 'wx' });
      return true;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      return false;
    }
  };
  if (claim()) return true;
  let holder = null;
  try { holder = parseInt(readFileSync(lockFile, 'utf8').trim(), 10); } catch {}
  if (!isPidAlive(holder)) {
    rmSync(lockFile, { force: true });
    return claim();
  }
  return false;
}

function readPort(binaryPath) {
  const f = portFilePath(binaryPath);
  if (!existsSync(f)) return null;
  const n = parseInt(readFileSync(f, 'utf8').trim(), 10);
  return Number.isNaN(n) ? null : n;
}
function readPid(binaryPath) {
  const f = pidFilePath(binaryPath);
  if (!existsSync(f)) return null;
  const n = parseInt(readFileSync(f, 'utf8').trim(), 10);
  return Number.isNaN(n) ? null : n;
}
function isPidAlive(pid) {
  if (!pid) return false;
  try { process.kill(pid, 0); return true; }
  catch { return false; }
}
function tcpProbe(port) {
  return new Promise(r => {
    const s = new net.Socket();
    s.setTimeout(2000);
    s.once('connect', () => { s.destroy(); r(true); });
    s.once('error', () => { s.destroy(); r(false); });
    s.once('timeout', () => { s.destroy(); r(false); });
    s.connect(port, '127.0.0.1');
  });
}
async function isWorkerRunning(binaryPath) {
  const port = readPort(binaryPath);
  if (!port) return false;
  const pid = readPid(binaryPath);
  if (!isPidAlive(pid)) return false;
  return tcpProbe(port);
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolve Python and worker script
// ─────────────────────────────────────────────────────────────────────────────
function findPython() {
  // IDA 9.4's native Python modules target CPython 3.13. A newer generic
  // `python3` can hard-crash while loading idapro, so prefer the matching
  // interpreter and allow an explicit override for other IDA releases.
  const candidates = [
    process.env.IDA_PYTHON,
    'python3.13', 'python3.12', 'python3.11', 'python3.10',
    'python3', 'python',
  ].filter((value, index, all) => value && all.indexOf(value) === index);
  for (const c of candidates) {
    try {
      const r = spawnSync(c, ['--version'], { stdio: ['ignore', 'pipe', 'pipe'] });
      if (r.status === 0) {
        const version = `${r.stdout?.toString() || ''}${r.stderr?.toString() || ''}`.trim();
        return { command: c, version };
      }
    } catch {}
  }
  console.error('ERROR: Python 3 not found. Install python3 and ensure it is on PATH.');
  process.exit(1);
}

function validateRuntime() {
  if (!existsSync(RUNTIME_DIR)) {
    console.error(`ERROR: Runtime not provisioned at ${RUNTIME_DIR}`);
    console.error('Run: node scripts/setup.mjs --ida-dir /path/to/ida');
    process.exit(1);
  }
  const core = process.platform === 'win32' ? 'idalib.dll'
    : process.platform === 'darwin' ? 'libidalib.dylib' : 'libidalib.so';
  const required = [core, 'ida.hlp', join('idalib', 'python', 'idapro'), 'python'];
  const missing = required.filter(path => !existsSync(join(RUNTIME_DIR, path)));
  if (missing.length) {
    console.error(`ERROR: Runtime is incomplete at ${RUNTIME_DIR}`);
    for (const path of missing) console.error(`  missing: ${path}`);
    console.error('Re-run setup with --force.');
    process.exit(1);
  }
}

function validateBinary(binaryPath) {
  if (!binaryPath || !existsSync(binaryPath)) {
    console.error(`ERROR: Binary not found: ${binaryPath || '(missing --binary)'}`);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// start
// ─────────────────────────────────────────────────────────────────────────────
async function cmdStart(opts) {
  validateRuntime();
  validateBinary(opts.binary);
  mkdirSync(RUNTIME_STATE, { recursive: true });

  if (await isWorkerRunning(opts.binary)) {
    const port = readPort(opts.binary);
    console.log(`Worker already running (port ${port}).`);
    return;
  }

  const timeoutMs = (opts.timeout || 300) * 1000;
  let acquired = tryAcquireStartLock(opts.binary);
  if (!acquired) {
    // Another process is starting this worker — wait for its result instead
    // of racing it onto the same database.
    console.log('Another start is already in progress for this binary; waiting...');
    const waitStart = Date.now();
    while (!acquired && Date.now() - waitStart < timeoutMs) {
      if (await isWorkerRunning(opts.binary)) {
        console.log(`Worker ready on port ${readPort(opts.binary)} (started by another process).`);
        return;
      }
      acquired = tryAcquireStartLock(opts.binary);
      if (!acquired) await new Promise(r => setTimeout(r, 1000));
    }
    if (!acquired) {
      console.error(`Timed out waiting for the concurrent start. Stale lock? ${lockFilePath(opts.binary)}`);
      process.exit(1);
    }
    // Lock taken over from a holder that died/finished without a worker.
    if (await isWorkerRunning(opts.binary)) {
      rmSync(lockFilePath(opts.binary), { force: true });
      console.log(`Worker already running (port ${readPort(opts.binary)}).`);
      return;
    }
  }
  // Release the lock on every exit path, including process.exit().
  process.on('exit', () => { try { rmSync(lockFilePath(opts.binary), { force: true }); } catch {} });

  // Clean stale files
  rmSync(portFilePath(opts.binary), { force: true });
  rmSync(pidFilePath(opts.binary), { force: true });

  const portFile = portFilePath(opts.binary);
  const logFile = logFilePath(opts.binary);
  const python = findPython();
  const workerScript = join(__dirname, 'worker.py');

  const workerArgs = [
    workerScript,
    '--port', '0',  // auto-assign
    '--port-file', portFile,
    '--binary', opts.binary,
  ];
  if (opts.autoAnalysis === false) {
    workerArgs.push('--no-run-auto-analysis');
  }
  const idleTimeout = opts.idle ?? 600;
  workerArgs.push('--idle-timeout', String(idleTimeout));
  if (opts.autosave !== undefined) {
    workerArgs.push('--autosave', String(opts.autosave));
  }
  if (opts.multiAgent) {
    workerArgs.push('--multi-agent');
  }

  // Build the child process environment
  const childEnv = { ...process.env, IDA_RUNTIME_DIR: RUNTIME_DIR };

  // Linux: libidalib.so and the _ida_*.so modules have RUNPATH=$ORIGIN but
  // some sub-modules (e.g. plugins/*.so) reference siblings that need
  // LD_LIBRARY_PATH to resolve. This must be set before Python starts —
  // os.environ['LD_LIBRARY_PATH'] from within Python is too late (ld.so
  // reads it only at process start).
  if (process.platform === 'linux') {
    const libPaths = [RUNTIME_DIR, join(RUNTIME_DIR, 'plugins')];
    childEnv.LD_LIBRARY_PATH = libPaths.join(':')
      + (process.env.LD_LIBRARY_PATH ? ':' + process.env.LD_LIBRARY_PATH : '');
  }

  const logFd = openSync(logFile, 'w');
  const child = spawn(python.command, workerArgs, {
    env: childEnv,
    stdio: ['ignore', logFd, logFd],
    detached: true,
  });
  closeSync(logFd);
  child.unref();

  writeFileSync(pidFilePath(opts.binary), String(child.pid));

  console.log(`Starting worker for ${opts.binary}`);
  console.log(`  PID: ${child.pid}`);
  console.log(`  Python: ${python.version} (${python.command})`);
  console.log(`  Log: ${logFile}`);
  console.log('Waiting for ready signal...');

  // Poll for the port file
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const port = readPort(opts.binary);
    if (port !== null) {
      if (await tcpProbe(port)) {
        console.log(`\nWorker ready on port ${port}.`);
        console.log(`  cli.py <cmd> --binary "${opts.binary}"`);
        return;
      }
    }
    if (child.exitCode !== null) {
      console.error(`\nWorker exited with code ${child.exitCode}. Check log: ${logFile}`);
      rmSync(portFilePath(opts.binary), { force: true });
      rmSync(pidFilePath(opts.binary), { force: true });
      process.exit(1);
    }
    process.stdout.write('.');
    await new Promise(r => setTimeout(r, 1000));
  }
  console.error(`\nTimeout after ${opts.timeout || 300}s. Check log: ${logFile}`);
  if (isPidAlive(child.pid)) {
    try { process.kill(child.pid, 'SIGTERM'); } catch {}
  }
  rmSync(portFilePath(opts.binary), { force: true });
  rmSync(pidFilePath(opts.binary), { force: true });
  process.exit(1);
}

async function requestDatabaseClose(port, timeoutMs = 300000) {
  if (!port) return false;
  const sock = new net.Socket();
  sock.setTimeout(timeoutMs);
  try {
    await new Promise((resolve, reject) => {
      let data = '';
      sock.once('connect', () => {
        sock.write(JSON.stringify({ cmd: 'close', args: { save: true } }) + '\n');
      });
      sock.on('data', chunk => {
        data += chunk.toString();
        if (!data.includes('\n')) return;
        try {
          const response = JSON.parse(data.slice(0, data.indexOf('\n')));
          if (response.status !== 'ok') reject(new Error(response.error || 'database close failed'));
          else resolve();
        } catch (error) {
          reject(error);
        }
      });
      sock.once('error', reject);
      sock.once('timeout', () => reject(new Error('database save timed out')));
      sock.connect(port, '127.0.0.1');
    });
    return true;
  } finally {
    sock.destroy();
  }
}

async function stopWorker(port, pid) {
  let closed = false;
  if (port && pid && isPidAlive(pid)) {
    try {
      closed = await requestDatabaseClose(port);
    } catch (error) {
      console.warn(`WARNING: graceful database close failed: ${error.message}`);
    }
  }
  if (pid && isPidAlive(pid)) {
    try { process.kill(pid, 'SIGTERM'); } catch {}
    for (let i = 0; i < 60; i++) {
      if (!isPidAlive(pid)) break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
  if (pid && isPidAlive(pid)) {
    console.warn(`WARNING: worker ${pid} did not exit; forcing termination.`);
    try { process.kill(pid, 'SIGKILL'); } catch {}
  }
  return closed;
}

// ─────────────────────────────────────────────────────────────────────────────
// stop
// ─────────────────────────────────────────────────────────────────────────────
async function cmdStop(opts) {
  const port = readPort(opts.binary);
  const pid = readPid(opts.binary);

  await stopWorker(port, pid);

  rmSync(portFilePath(opts.binary), { force: true });
  rmSync(pidFilePath(opts.binary), { force: true });
  console.log('Worker stopped.');
}

// ─────────────────────────────────────────────────────────────────────────────
// stop-all
// ─────────────────────────────────────────────────────────────────────────────
async function cmdStopAll() {
  mkdirSync(RUNTIME_STATE, { recursive: true });
  const files = readdirSync(RUNTIME_STATE).filter(f => f.startsWith('worker-') && f.endsWith('.port'));
  if (files.length === 0) {
    console.log('No workers running.');
    return;
  }
  let stopped = 0;
  for (const f of files) {
    const portFile = join(RUNTIME_STATE, f);
    const pidFile = portFile.replace('.port', '.pid');
    const port = parseInt(readFileSync(portFile, 'utf8').trim(), 10);
    const pidStr = existsSync(pidFile) ? readFileSync(pidFile, 'utf8').trim() : null;
    const pid = pidStr ? parseInt(pidStr, 10) : null;

    await stopWorker(port, pid);
    rmSync(portFile, { force: true });
    rmSync(pidFile, { force: true });
    stopped++;
    console.log(`Stopped worker (port ${port}, pid ${pid}).`);
  }
  console.log(`${stopped} worker(s) stopped.`);
}

// ─────────────────────────────────────────────────────────────────────────────
// status
// ─────────────────────────────────────────────────────────────────────────────
async function cmdStatus(opts) {
  const port = readPort(opts.binary);
  const pid = readPid(opts.binary);
  const alive = pid !== null && isPidAlive(pid);
  const reachable = port !== null && alive && await tcpProbe(port);

  // Also query the worker for database info
  let dbInfo = null;
  if (reachable) {
    try {
      const sock = new net.Socket();
      sock.setTimeout(5000);
      dbInfo = await new Promise((res, rej) => {
        let data = '';
        sock.once('connect', () => {
          sock.write(JSON.stringify({ cmd: 'info', args: {} }) + '\n');
        });
        sock.on('data', d => {
          data += d.toString();
          if (data.includes('\n')) {
            try { res(JSON.parse(data.trim())); } catch { res(null); }
            sock.destroy();
          }
        });
        sock.once('error', rej);
        sock.once('timeout', () => { sock.destroy(); rej(new Error('timeout')); });
        sock.connect(port, '127.0.0.1');
      });
    } catch { /* ignore */ }
  }

  console.log(JSON.stringify({
    running: reachable,
    pid,
    port,
    pid_alive: alive,
    port_reachable: reachable,
    database: dbInfo?.result || null,
  }, null, 2));
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────
function parseArgs() {
  const [cmd, ...rest] = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--binary') opts.binary = rest[++i];
    else if (rest[i] === '--idle') opts.idle = parseInt(rest[++i], 10);
    else if (rest[i] === '--autosave') opts.autosave = parseInt(rest[++i], 10);
    else if (rest[i] === '--multi-agent') opts.multiAgent = true;
    else if (rest[i] === '--timeout') opts.timeout = parseInt(rest[++i], 10);
    else if (rest[i] === '--no-run-auto-analysis') opts.autoAnalysis = false;
    else if (rest[i] === '--run-auto-analysis') opts.autoAnalysis = true;
  }
  return { cmd, opts };
}

const { cmd, opts } = parseArgs();
if (cmd !== 'stop-all' && !opts.binary) {
  console.error('--binary <path> is required.');
  process.exit(1);
}

switch (cmd) {
  case 'start':    await cmdStart(opts); break;
  case 'stop':     await cmdStop(opts); break;
  case 'stop-all': await cmdStopAll(); break;
  case 'status':   await cmdStatus(opts); break;
  default:
    console.error('Usage: bridge.mjs <start|stop|stop-all|status> --binary <path> [options]');
    console.error('');
    console.error('Commands:');
    console.error('  start     Start a worker for --binary (auto-imports + analyzes)');
    console.error('  stop      Stop the worker and save the database');
    console.error('  stop-all  Stop all running workers');
    console.error('  status    Check if worker is running and get database info');
    console.error('');
    console.error('Options:');
    console.error('  --binary <path>          Binary file to analyze');
    console.error('  --idle <sec>             Idle auto-shutdown timeout (default: 600, 0=disable)');
    console.error('  --autosave <sec>         Save this long after unsaved changes accumulate (default: 300, 0=disable)');
    console.error('  --multi-agent            Block undo/redo/restore-snapshot (unsafe with concurrent clients)');
    console.error('  --timeout <sec>          Startup timeout (default: 300)');
    console.error('  --no-run-auto-analysis   Skip auto-analysis on first open');
    process.exit(1);
}
