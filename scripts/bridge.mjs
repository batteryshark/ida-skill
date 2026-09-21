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

import { createHash, randomUUID } from 'node:crypto';
import { openSync, closeSync, existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync, realpathSync, renameSync } from 'node:fs';
import { join, resolve, dirname, isAbsolute, basename } from 'node:path';
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
function pathHash(path) {
  return createHash('md5').update(path).digest('hex').slice(0, 12);
}
function paths(stem) {
  return Object.fromEntries(['pid', 'port', 'json', 'log', 'lock'].map(ext => [ext, `${stem}.${ext}`]));
}
function binaryPaths(binary) {
  return paths(join(RUNTIME_STATE, `worker-${pathHash(realpathSync(binary))}`));
}
const delay = ms => new Promise(resolveDelay => setTimeout(resolveDelay, ms));
function isPidAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code !== 'ESRCH'; }
}
function validPort(port) {
  return Number.isSafeInteger(port) && port > 0 && port <= 65535;
}
function readPort(p) {
  if (!existsSync(p.port)) return null;
  const text = readFileSync(p.port, 'utf8').trim();
  const port = Number(text);
  if (!/^[1-9][0-9]*$/.test(text) || !validPort(port)) throw new Error('Invalid port metadata; state preserved');
  return port;
}
function readState(p, requestedPath) {
  if (!existsSync(p.json)) {
    if (existsSync(p.pid) || existsSync(p.port)) {
      throw new Error('Legacy or incomplete worker metadata cannot verify ownership; state preserved. Stop legacy workers with the pre-upgrade bridge.');
    }
    return null;
  }
  let state;
  try { state = JSON.parse(readFileSync(p.json, 'utf8')); }
  catch { throw new Error(`Invalid worker state at ${p.json}; state preserved`); }
  if (!state || state.protocol !== 1 || !Number.isSafeInteger(state.pid) || state.pid <= 0
      || (state.port !== null && !validPort(state.port))
      || typeof state.session_id !== 'string' || !state.session_id
      || typeof state.requested_path !== 'string' || !isAbsolute(state.requested_path)
      || basename(p.json) !== `worker-${pathHash(state.requested_path)}.json`
      || (requestedPath && state.requested_path !== requestedPath)) {
    throw new Error(`Invalid worker identity metadata at ${p.json}; state preserved`);
  }
  return state;
}
function writeState(p, state) {
  const temporary = `${p.json}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    renameSync(temporary, p.json);
  } catch (error) {
    try { rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}
function removeSession(p, captured) {
  const current = readState(p);
  if (!current || current.session_id !== captured.session_id || current.pid !== captured.pid) {
    throw new Error('Worker session changed during lifecycle operation; replacement state preserved');
  }
  rmSync(p.port, { force: true });
  rmSync(p.pid, { force: true });
  rmSync(p.json);
}
async function withLifecycleLock(p, timeoutSeconds, operation) {
  mkdirSync(RUNTIME_STATE, { recursive: true });
  const lock = { contents: JSON.stringify({ pid: process.pid, token: randomUUID() }), retain: false };
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (true) {
    try { writeFileSync(p.lock, lock.contents, { flag: 'wx', mode: 0o600 }); break; }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    if (Date.now() >= deadline) {
      throw new Error(`Lifecycle lock still exists at ${p.lock}; state preserved. Inspect its owner before manually recovering a stale lock.`);
    }
    await delay(100);
  }
  try { return await operation(lock); }
  finally {
    if (!lock.retain) {
      if (readFileSync(p.lock, 'utf8') !== lock.contents) {
        throw new Error(`Lifecycle lock ownership changed at ${p.lock}; lock preserved`);
      }
      rmSync(p.lock);
    }
  }
}
function tcpProbe(port) {
  if (!port) return Promise.resolve(false);
  return new Promise(resolveProbe => {
    const socket = new net.Socket();
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); resolveProbe(true); });
    socket.once('error', () => { socket.destroy(); resolveProbe(false); });
    socket.once('timeout', () => { socket.destroy(); resolveProbe(false); });
    socket.connect(port, '127.0.0.1');
  });
}
async function request(port, cmd, sessionId, timeoutMs = 5000, args = {}) {
  const socket = new net.Socket();
  let deadline;
  try {
    return await new Promise((resolveRequest, reject) => {
      let data = '';
      deadline = setTimeout(() => reject(new Error(`${cmd} timed out`)), timeoutMs);
      socket.once('connect', () => {
        const message = { cmd, args };
        if (sessionId !== undefined) message.session_id = sessionId;
        socket.write(`${JSON.stringify(message)}\n`);
      });
      socket.on('data', chunk => {
        data += chunk.toString();
        const newline = data.indexOf('\n');
        if (newline < 0) return;
        try {
          const response = JSON.parse(data.slice(0, newline));
          if (response.status !== 'ok') throw new Error(response.error || `${cmd} failed`);
          resolveRequest(response.result);
        } catch (error) { reject(error); }
      });
      socket.once('error', reject);
      socket.once('end', () => reject(new Error(`worker disconnected before acknowledging ${cmd}`)));
      socket.once('close', () => reject(new Error(`worker connection closed before acknowledging ${cmd}`)));
      socket.connect(port, '127.0.0.1');
    });
  } finally {
    clearTimeout(deadline);
    socket.destroy();
  }
}
async function verifyIdentity(p, state, timeoutMs = 5000) {
  if (!isPidAlive(state.pid)) throw new Error('Recorded worker PID is not alive; state preserved');
  const port = state.port ?? readPort(p);
  if (!port) throw new Error(`Worker ${state.pid} is still alive but not ready; state preserved`);
  const identity = await request(port, 'worker-identity', undefined, timeoutMs);
  if (!identity || identity.protocol !== 1 || identity.pid !== state.pid
      || identity.session_id !== state.session_id || identity.requested_path !== state.requested_path
      || !['ready', 'stopping'].includes(identity.state)) {
    throw new Error('Worker identity mismatch (protocol, PID, session, or requested path); state preserved');
  }
  return { port, identity };
}
async function assertDeadAndUnreachable(p, state) {
  if (isPidAlive(state.pid) || await tcpProbe(state.port ?? readPort(p))) {
    throw new Error('Worker PID or endpoint is still active; state preserved');
  }
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
  throw new Error('Python 3 not found. Install python3 and ensure it is on PATH.');
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
  const requestedPath = realpathSync(opts.binary);
  const p = binaryPaths(opts.binary);
  await withLifecycleLock(p, opts.timeout ?? 300, async lock => {
    let state = readState(p, requestedPath);
    if (state) {
      if (isPidAlive(state.pid)) {
        const { port, identity } = await verifyIdentity(p, state, (opts.timeout ?? 300) * 1000);
        if (identity.state !== 'ready') throw new Error('Worker is stopping; state preserved');
        if (state.port === null) writeState(p, { ...state, port });
        console.log(`Worker already running (port ${port}).`);
        return;
      }
      await assertDeadAndUnreachable(p, state);
      removeSession(p, state);
    }

    const python = findPython();
    const sessionId = randomUUID();
    const workerArgs = [
      join(__dirname, 'worker.py'), '--port', '0', '--port-file', p.port,
      '--binary', requestedPath, '--session-id', sessionId,
      '--idle-timeout', String(opts.idle ?? 600),
    ];
    if (opts.autoAnalysis === false) workerArgs.push('--no-run-auto-analysis');
    if (opts.autosave !== undefined) workerArgs.push('--autosave', String(opts.autosave));
    if (opts.multiAgent) workerArgs.push('--multi-agent');
    const childEnv = { ...process.env, IDA_RUNTIME_DIR: RUNTIME_DIR };
    if (process.platform === 'linux') {
      childEnv.LD_LIBRARY_PATH = [RUNTIME_DIR, join(RUNTIME_DIR, 'plugins'), process.env.LD_LIBRARY_PATH].filter(Boolean).join(':');
    }
    const logFd = openSync(p.log, 'w');
    let child;
    try { child = spawn(python.command, workerArgs, { env: childEnv, stdio: ['ignore', logFd, logFd], detached: true }); }
    finally { closeSync(logFd); }
    await new Promise((resolveSpawn, reject) => { child.once('spawn', resolveSpawn); child.once('error', reject); });
    child.unref();
    state = { protocol: 1, pid: child.pid, port: null, session_id: sessionId, requested_path: requestedPath };
    try { writeState(p, state); }
    catch (error) {
      // A durable PID-only marker blocks another start. If even that fails,
      // retain our lock so an untracked live worker cannot be duplicated.
      try { writeFileSync(p.pid, String(child.pid)); }
      catch { lock.retain = true; }
      throw new Error(`Could not publish worker state: ${error.message}; live worker PID ${child.pid}, session ${sessionId}, log ${p.log}; ${lock.retain ? 'lifecycle lock retained for manual recovery' : 'PID metadata preserved'}`);
    }
    writeFileSync(p.pid, String(child.pid));
    console.log(`Starting worker for ${requestedPath}\n  PID: ${child.pid}\n  Python: ${python.version} (${python.command})\n  Log: ${p.log}`);
    const deadline = Date.now() + (opts.timeout ?? 300) * 1000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null || child.signalCode !== null || !isPidAlive(child.pid)) {
        throw new Error(`Worker exited before readiness; state and log preserved at ${p.log}`);
      }
      if (readPort(p) !== null) {
        const { port, identity } = await verifyIdentity(p, state, Math.max(1, deadline - Date.now()));
        if (identity.state !== 'ready') throw new Error('New worker is stopping; state preserved');
        writeState(p, { ...state, port });
        console.log(`Worker ready on port ${port}.`);
        return;
      }
      await delay(100);
    }
    throw new Error(`Startup timed out; worker ${child.pid} and its state were preserved. Check log: ${p.log}`);
  });
}

async function stopSession(p, opts, requestedPath) {
  await withLifecycleLock(p, opts.timeout ?? 300, async () => {
    const state = readState(p, requestedPath);
    if (!state) return;
    if (isPidAlive(state.pid)) {
      const { port, identity } = await verifyIdentity(p, state, (opts.timeout ?? 300) * 1000);
      if (identity.state === 'ready') {
        const receipt = await request(port, 'worker-shutdown', state.session_id, (opts.timeout ?? 300) * 1000);
        if (!receipt || receipt.status !== 'stopping' || receipt.session_id !== state.session_id) {
          throw new Error('Worker shutdown acknowledgement did not match the session; state preserved');
        }
      }
      const deadline = Date.now() + (opts.timeout ?? 30) * 1000;
      while (isPidAlive(state.pid) && Date.now() < deadline) await delay(100);
      if (isPidAlive(state.pid)) throw new Error(`Worker ${state.pid} did not exit after shutdown; process and state preserved`);
    }
    await assertDeadAndUnreachable(p, state);
    removeSession(p, state);
  });
}
async function cmdStop(opts) {
  await stopSession(binaryPaths(opts.binary), opts, realpathSync(opts.binary));
  console.log('Worker stopped.');
}
async function cmdStopAll(opts) {
  mkdirSync(RUNTIME_STATE, { recursive: true });
  const stems = [...new Set(readdirSync(RUNTIME_STATE)
    .filter(name => /^worker-[0-9a-f]{12}\.(json|pid|port|lock)$/.test(name))
    .map(name => name.replace(/\.(json|pid|port|lock)$/, '')))];
  let stopped = 0;
  let failed = 0;
  for (const stem of stems) {
    try { await stopSession(paths(join(RUNTIME_STATE, stem)), opts); stopped++; }
    catch (error) { console.error(`ERROR: ${error.message}`); failed++; }
  }
  console.log(`${stopped} worker(s) stopped.`);
  if (failed) throw new Error(`${failed} worker(s) could not be stopped; their state was preserved`);
}
async function cmdStatus(opts) {
  const p = binaryPaths(opts.binary);
  const result = { running: false, identity_verified: false, pid: null, port: null, pid_alive: false, port_reachable: false, identity: null, database: null, error: null };
  try {
    const state = readState(p, realpathSync(opts.binary));
    if (state) {
      result.pid = state.pid;
      result.port = state.port ?? readPort(p);
      result.pid_alive = isPidAlive(state.pid);
      result.port_reachable = await tcpProbe(result.port);
      const { port, identity } = await verifyIdentity(p, state, Math.min(5000, (opts.timeout ?? 5) * 1000));
      if (readState(p)?.session_id !== state.session_id) throw new Error('Worker session changed during status');
      result.identity = identity;
      result.identity_verified = true;
      result.running = identity.state === 'ready';
      if (result.running) {
        try { result.database = await request(port, 'worker-command', state.session_id, Math.min(5000, (opts.timeout ?? 5) * 1000), { cmd: 'info', args: {} }); }
        catch (error) { result.error = error.message; }
      }
    }
  } catch (error) { result.error = error.message; }
  console.log(JSON.stringify(result, null, 2));
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
if (opts.timeout !== undefined && (!Number.isFinite(opts.timeout) || opts.timeout <= 0)) {
  console.error('--timeout must be a positive number of seconds.');
  process.exit(1);
}
if (cmd !== 'stop-all' && !opts.binary) {
  console.error('--binary <path> is required.');
  process.exit(1);
}

try {
  switch (cmd) {
    case 'start':    await cmdStart(opts); break;
    case 'stop':     await cmdStop(opts); break;
    case 'stop-all': await cmdStopAll(opts); break;
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
      console.error('  --timeout <sec>          Start/save timeout (default: 300); also overrides the 30s stop wait');
      console.error('  --no-run-auto-analysis   Skip auto-analysis on first open');
      process.exit(1);
  }
} catch (error) {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
}
