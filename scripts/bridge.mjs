#!/usr/bin/env node
// Persistent idalib worker lifecycle manager. Normal lifecycle operations
// never force-kill workers or delete IDA database sidecars.

import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync,
  realpathSync, renameSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import * as net from 'node:net';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BIN_DIR = join(__dirname, '..', 'bin');
const RUNTIME_STATE = process.env.IDA_SKILL_STATE_DIR || join(BIN_DIR, 'runtime');
const HOST_PLATFORM_KEY = process.platform === 'win32' ? 'windows'
  : process.platform === 'darwin' ? 'mac' : 'linux';
const RUNTIME_DIR = process.env.IDA_RUNTIME_DIR || join(BIN_DIR, `ida-runtime-${HOST_PLATFORM_KEY}`);
const WORKER_SCRIPT = process.env.IDA_SKILL_WORKER_SCRIPT || join(__dirname, 'worker.py');

function canonical(path) {
  return realpathSync(resolve(path));
}

function normalized(path) {
  try { return canonical(path); } catch { return resolve(path); }
}

function binaryHash(path) {
  return createHash('md5').update(canonical(path)).digest('hex').slice(0, 12);
}

function paths(binary) {
  const stem = join(RUNTIME_STATE, `worker-${binaryHash(binary)}`);
  return {
    port: `${stem}.port`, pid: `${stem}.pid`, state: `${stem}.json`,
    lineage: `${stem}.lineage.json`, log: `${stem}.log`, lock: `${stem}.lock`,
  };
}

function readNumber(path) {
  if (!existsSync(path)) return null;
  const value = Number.parseInt(readFileSync(path, 'utf8').trim(), 10);
  return Number.isNaN(value) ? null : value;
}

function readCanonicalPositiveDecimal(path) {
  if (!existsSync(path)) return { present: false, bytes: null, value: null };
  const bytes = readFileSync(path);
  const text = bytes.toString('utf8');
  if (!/^[1-9][0-9]*$/.test(text)) return { present: true, bytes, value: null };
  const value = Number(text);
  return { present: true, bytes, value: Number.isSafeInteger(value) ? value : null };
}

function artifactUnchanged(path, initial) {
  const current = readCanonicalPositiveDecimal(path);
  return current.present === initial.present
    && (!initial.present || (current.value !== null && current.bytes.equals(initial.bytes)));
}

function readState(binary) {
  const p = paths(binary);
  let state = {};
  try { state = JSON.parse(readFileSync(p.state, 'utf8')); } catch {}
  return { ...state, pid: state.pid ?? readNumber(p.pid), port: state.port ?? readNumber(p.port) };
}

function writeState(binary, state) {
  const p = paths(binary);
  const temporary = `${p.state}.${process.pid}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, p.state);
}

function processState(pid) {
  if (!pid) return { alive: false, permission_ambiguous: false };
  try {
    process.kill(pid, 0);
    let command_line = null;
    let owner_uid = null;
    if (process.platform === 'linux') {
      try { command_line = readFileSync(`/proc/${pid}/cmdline`).toString().replaceAll('\0', ' ').trim(); } catch {}
      try { owner_uid = statSync(`/proc/${pid}`).uid; } catch {}
    }
    return { alive: true, permission_ambiguous: false, command_line, owner_uid };
  } catch (error) {
    return { alive: error.code === 'EPERM', permission_ambiguous: error.code !== 'ESRCH' };
  }
}

function tcpProbe(port, timeout = 2000) {
  return new Promise(resolveProbe => {
    if (!port) return resolveProbe(false);
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.once('connect', () => { socket.destroy(); resolveProbe(true); });
    socket.once('error', () => { socket.destroy(); resolveProbe(false); });
    socket.once('timeout', () => { socket.destroy(); resolveProbe(false); });
    socket.connect(port, '127.0.0.1');
  });
}

function request(port, cmd, args = {}, timeoutMs = 300000) {
  return new Promise((resolveRequest, reject) => {
    if (!port) return reject(new Error('worker has no RPC port'));
    const socket = new net.Socket();
    let data = '';
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => socket.write(`${JSON.stringify({ cmd, args })}\n`));
    socket.on('data', chunk => {
      data += chunk.toString();
      const newline = data.indexOf('\n');
      if (newline < 0) return;
      socket.destroy();
      try {
        const response = JSON.parse(data.slice(0, newline));
        if (response.status !== 'ok') reject(new Error(`[${response.error_type || 'Error'}] ${response.error || 'request failed'}`));
        else resolveRequest(response.result);
      } catch (error) { reject(error); }
    });
    socket.once('error', reject);
    socket.once('timeout', () => { socket.destroy(); reject(new Error(`${cmd} timed out`)); });
    socket.connect(port, '127.0.0.1');
  });
}

function sha256(path) {
  if (!path || !existsSync(path)) return null;
  const fd = openSync(path, 'r');
  try {
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let offset = 0;
    const before = fstatSync(fd);
    const size = before.size;
    while (offset < size) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
      if (!count) break;
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
    const digest = hash.digest('hex');
    const after = fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      throw new Error(`file changed while hashing: ${path}`);
    }
    return digest;
  } finally { closeSync(fd); }
}

function databaseCandidates(binary) {
  const path = canonical(binary);
  const extension = extname(path).toLowerCase();
  if (extension === '.i64' || extension === '.idb') return [path];
  return [`${path}.i64`, `${path}.idb`];
}

function sidecars(databasePath) {
  if (!databasePath) return [];
  const extension = extname(databasePath).toLowerCase();
  const root = extension === '.i64' || extension === '.idb'
    ? databasePath.slice(0, -extension.length) : databasePath;
  return ['.id0', '.id1', '.id2', '.nam', '.til'].map(suffix => root + suffix).filter(existsSync);
}

function validateRuntime() {
  if (process.env.IDA_SKILL_WORKER_SCRIPT) return;
  if (!existsSync(RUNTIME_DIR)) throw new Error(`Runtime not provisioned at ${RUNTIME_DIR}`);
  const core = process.platform === 'win32' ? 'idalib.dll'
    : process.platform === 'darwin' ? 'libidalib.dylib' : 'libidalib.so';
  for (const item of [core, 'ida.hlp', join('idalib', 'python', 'idapro'), 'python']) {
    if (!existsSync(join(RUNTIME_DIR, item))) throw new Error(`Runtime is incomplete: missing ${item}`);
  }
}

function findPython() {
  const candidates = [process.env.IDA_PYTHON, 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3', 'python']
    .filter((value, index, all) => value && all.indexOf(value) === index);
  for (const command of candidates) {
    const result = spawnSync(command, ['--version'], { stdio: ['ignore', 'pipe', 'pipe'] });
    if (result.status === 0) return command;
  }
  throw new Error('Python 3 not found');
}

function acquireLock(binary) {
  const lock = paths(binary).lock;
  try { writeFileSync(lock, String(process.pid), { flag: 'wx' }); return lock; } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const holder = readNumber(lock);
  const processInfo = processState(holder);
  if (processInfo.alive || processInfo.permission_ambiguous) {
    throw new Error(`another lifecycle operation owns ${lock} (pid ${holder})`);
  }
  rmSync(lock, { force: true });
  writeFileSync(lock, String(process.pid), { flag: 'wx' });
  return lock;
}

function releaseLock(lock) {
  if (readCanonicalPositiveDecimal(lock).value === process.pid) rmSync(lock, { force: true });
}

function acquireCleanupLock(requested) {
  const path = paths(requested).lock;
  const token = Buffer.from(String(process.pid));
  try { writeFileSync(path, token, { flag: 'wx' }); }
  catch (error) {
    if (error.code === 'EEXIST') throw new Error('lifecycle lock exists; stale cleanup is unsafe');
    throw error;
  }
  return { path, token };
}

function cleanupReleaseError(lock, artifacts, cause) {
  let observed = null;
  try { observed = readFileSync(lock.path).toString('utf8'); }
  catch (error) {
    if (error.code !== 'ENOENT') cause = error;
  }
  return new Error(
    `cleanup lock release failed: ${cause.message}; lock=${JSON.stringify(lock.path)}; `
    + `owner=${JSON.stringify(lock.token.toString('utf8'))}; observed=${JSON.stringify(observed)}; `
    + `remaining=${JSON.stringify(artifacts.filter(existsSync))}`,
  );
}

function releaseCleanupLock(lock, artifacts) {
  if (process.env.IDA_SKILL_TEST_STALE_RELEASE_FAULT === 'replace') {
    writeFileSync(lock.path, 'replacement');
  } else if (process.env.IDA_SKILL_TEST_STALE_RELEASE_FAULT === 'remove') {
    rmSync(lock.path);
  }
  let observed;
  try { observed = readFileSync(lock.path); }
  catch (error) { throw cleanupReleaseError(lock, artifacts, error); }
  if (!observed.equals(lock.token)) {
    throw cleanupReleaseError(lock, artifacts, new Error('lock owner token changed'));
  }
  try { rmSync(lock.path); }
  catch (error) { throw cleanupReleaseError(lock, artifacts, error); }
}

async function inspect(binary) {
  const requested = canonical(binary);
  const state = readState(binary);
  const proc = processState(state.pid);
  const reachable = proc.alive && await tcpProbe(state.port);
  let worker = null;
  let identity_error = null;
  if (reachable) {
    try { worker = await request(state.port, 'identity', {}, 5000); }
    catch (error) { identity_error = error.message; }
  }
  const nonce_match = !worker || !state.nonce || worker.nonce === state.nonce;
  const pid_match = !worker || worker.worker_pid === state.pid;
  const legacyState = state.version !== 2;
  const lineage = worker?.lineage || null;
  const source = lineage?.source || worker?.source || null;
  const database = lineage?.database || worker?.database || null;
  const currentSourceHash = source?.path ? sha256(source.path) : null;
  const source_identity_match = !worker || (legacyState
    ? Boolean(state.input_sha256)
      && worker.input_sha256 === state.input_sha256
      && sha256(worker.input_path) === state.input_sha256
    : source?.ida_sha256 === state.source?.ida_sha256
      && (!currentSourceHash || currentSourceHash === source.ida_sha256));
  const target_match = !worker || [worker.requested_path, worker.input_path, worker.database_path]
    .filter(Boolean).map(path => { try { return canonical(path); } catch { return resolve(path); } }).includes(requested);
  const databasePath = worker?.database_path || databaseCandidates(binary).find(existsSync) || databaseCandidates(binary)[0];
  const currentDatabaseHash = sha256(databasePath);
  const database_lineage_match = !worker || (legacyState
    ? source_identity_match && currentDatabaseHash === state.database_sha256
    : database?.path && state.database?.path
      && normalized(database.path) === normalized(state.database.path)
      && Number.isInteger(database.generation)
      && database.generation >= (state.database.generation ?? 0)
      && database.confirmed_sha256 === currentDatabaseHash
      && !['checkpointing', 'save_failed', 'recovery_required'].includes(database.save_state));
  return {
    requested_path: requested,
    running: reachable && Boolean(worker) && nonce_match && pid_match && source_identity_match && database_lineage_match && target_match,
    pid: state.pid || null,
    port: state.port || null,
    pid_alive: proc.alive,
    permission_ambiguous: proc.permission_ambiguous,
    port_reachable: reachable,
    command_line: proc.command_line || null,
    owner_uid: proc.owner_uid,
    state,
    worker,
    nonce_match,
    pid_match,
    input_match: legacyState ? source_identity_match : null,
    source_identity_match,
    database_lineage_match,
    source,
    database,
    external_change_suspected: Boolean(worker) && (!source_identity_match || !database_lineage_match),
    target_match,
    identity_error,
    database_path: databasePath,
    database_sha256: sha256(databasePath),
    sidecars: sidecars(databasePath),
    lock_artifact: existsSync(paths(binary).lock) ? paths(binary).lock : null,
  };
}

function assertSafeExisting(status, requireWritable = null) {
  if (!status.pid_alive) throw new Error('recorded worker is not alive');
  if (!status.port_reachable || !status.worker) throw new Error('worker is alive but unresponsive; preserve it and escalate');
  if (!status.nonce_match || !status.pid_match || !status.source_identity_match || !status.database_lineage_match || !status.target_match) {
    throw new Error('worker, state, source, database lineage, or target identity mismatch; escalate');
  }
  if (status.permission_ambiguous) throw new Error('worker ownership is ambiguous; escalate');
  if (status.owner_uid !== null && typeof process.getuid === 'function' && status.owner_uid !== process.getuid()) {
    throw new Error(`worker belongs to uid ${status.owner_uid}; possible concurrent use`);
  }
  if (status.state.owner_uid !== null && status.state.owner_uid !== undefined
      && typeof process.getuid === 'function' && status.state.owner_uid !== process.getuid()) {
    throw new Error(`worker state belongs to uid ${status.state.owner_uid}; possible concurrent use`);
  }
  if (requireWritable !== null && Boolean(status.worker.writable) !== requireWritable) {
    throw new Error(`worker mode mismatch: expected writable=${requireWritable}`);
  }
}

async function cmdStart(opts, quiet = false) {
  validateRuntime();
  if (!opts.binary || !existsSync(opts.binary)) throw new Error(`Binary not found: ${opts.binary || '(missing)'}`);
  mkdirSync(RUNTIME_STATE, { recursive: true });
  const lock = acquireLock(opts.binary);
  try {
    const before = await inspect(opts.binary);
    if (before.pid_alive) {
      assertSafeExisting(before);
      throw new Error(`worker already running for this database (pid ${before.pid}, writable=${before.worker.writable})`);
    }
    if (before.sidecars.length) {
      throw new Error(`IDA sidecars exist without a responsive managed worker: ${before.sidecars.join(', ')}; preserve them and escalate`);
    }

    const p = paths(opts.binary);
    const nonce = randomUUID();
    const python = findPython();
    const args = [
      WORKER_SCRIPT, '--port', '0', '--port-file', p.port,
      '--binary', canonical(opts.binary), '--nonce', nonce, '--lineage-file', p.lineage,
    ];
    if (opts.autoAnalysis === false) args.push('--no-run-auto-analysis');
    if (opts.readOnly) args.push('--read-only');
    args.push('--idle-timeout', String(opts.idle ?? 600));
    if (opts.autosave !== undefined) args.push('--autosave', String(opts.autosave));
    if (opts.multiAgent) args.push('--multi-agent');
    const childEnv = { ...process.env, IDA_RUNTIME_DIR: RUNTIME_DIR };
    if (process.platform === 'linux') childEnv.LD_LIBRARY_PATH = [RUNTIME_DIR, join(RUNTIME_DIR, 'plugins'), process.env.LD_LIBRARY_PATH].filter(Boolean).join(':');
    const logFd = openSync(p.log, 'w');
    const child = spawn(python, args, { env: childEnv, stdio: ['ignore', logFd, logFd], detached: true });
    closeSync(logFd);
    child.unref();
    writeFileSync(p.pid, String(child.pid));
    writeState(opts.binary, {
      version: 2, pid: child.pid, port: null, nonce,
      owner_uid: typeof process.getuid === 'function' ? process.getuid() : null,
      requested_path: canonical(opts.binary), writable: !opts.readOnly,
      started_at: new Date().toISOString(), log: p.log,
    });

    const deadline = Date.now() + (opts.timeout ?? 300) * 1000;
    while (Date.now() < deadline) {
      const port = readNumber(p.port);
      if (port && await tcpProbe(port)) {
        const identity = await request(port, 'identity', {}, 5000);
        if (identity.worker_pid !== child.pid || identity.nonce !== nonce) throw new Error('new worker identity mismatch');
        writeState(opts.binary, {
          ...readState(opts.binary), port, database_path: identity.database_path,
          source: identity.lineage?.source,
          database: {
            ...identity.lineage?.database,
            generation: 0,
            confirmed_sha256: identity.lineage?.database?.open_sha256,
          },
        });
        const result = { status: 'started', pid: child.pid, port, writable: !opts.readOnly, identity };
        if (!quiet) console.log(JSON.stringify(result, null, 2));
        return result;
      }
      await new Promise(resolveWait => setTimeout(resolveWait, 250));
    }
    throw new Error(`startup timed out; worker state and log preserved at ${p.state} and ${p.log}`);
  } finally { releaseLock(lock); }
}

async function waitForExit(pid, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (processState(pid).alive && Date.now() < deadline) await new Promise(resolveWait => setTimeout(resolveWait, 250));
  return !processState(pid).alive;
}

async function finalizeUnlocked(binary, save, timeoutSeconds = 60) {
  const before = await inspect(binary);
  if (!before.pid_alive && !before.state.pid) {
    return { status: 'already_closed', worker_stopped: true, database_path: before.database_path, database_sha256: before.database_sha256, sidecars: before.sidecars };
  }
  assertSafeExisting(before, save ? true : null);
  const response = await request(before.port, 'finalize', { save, nonce: before.state.nonce }, timeoutSeconds * 1000);
  const stopped = await waitForExit(before.pid, timeoutSeconds);
  const after = await inspect(binary);
  if (!stopped) throw new Error(`worker ${before.pid} remained alive after finalization; state preserved`);
  const databasePath = response.database_path;
  if (!databasePath) throw new Error('worker close receipt did not identify the database path');
  if (save && !existsSync(databasePath)) throw new Error('packed database does not exist after save-and-close');
  const finalHash = sha256(databasePath);
  const finalDatabase = response.lineage?.database;
  if (save && (!finalDatabase || finalDatabase.confirmed_sha256 !== finalHash
      || finalDatabase.generation <= (before.database?.generation ?? -1))) {
    throw new Error('worker finalization receipt does not match the packed database generation');
  }
  if (!save && finalHash !== before.database?.confirmed_sha256) {
    throw new Error('close-no-save changed the last committed packed database');
  }
  const remainingSidecars = [...new Set([...(response.sidecars || []), ...sidecars(databasePath)])].filter(existsSync);
  if (save && remainingSidecars.length) throw new Error(`analysis sidecars remain after worker exit: ${remainingSidecars.join(', ')}`);
  const result = {
    status: save ? 'saved_and_closed' : 'closed_without_save',
    worker_stopped: true,
    repacking_completed: save,
    database_path: databasePath,
    database_sha256: finalHash,
    lineage: response.lineage || null,
    sidecars: remainingSidecars,
  };
  const p = paths(binary);
  rmSync(p.port, { force: true });
  rmSync(p.pid, { force: true });
  rmSync(p.state, { force: true });
  rmSync(p.lineage, { force: true });
  return result;
}

async function finalize(binary, save, timeoutSeconds = 60) {
  const lock = acquireLock(binary);
  try {
    return await finalizeUnlocked(binary, save, timeoutSeconds);
  } finally { releaseLock(lock); }
}

async function cmdRecover(opts) {
  const lock = acquireLock(opts.binary);
  try {
  const initial = await inspect(opts.binary);
  assertSafeExisting(initial, true);
  if (initial.worker.multi_agent) throw new Error('worker permits concurrent clients; active use is ambiguous and recovery requires escalation');
  if (!initial.sidecars.length && initial.database_sha256) throw new Error('database has no live sidecars; abandoned-session recovery is not indicated');
  const saved = await finalizeUnlocked(opts.binary, true, opts.timeout ?? 60);
  const packedHash = saved.database_sha256;
  await cmdStart({ ...opts, binary: saved.database_path, readOnly: true, autoAnalysis: false, idle: 0 }, true);
  const verificationStatus = await inspect(saved.database_path);
  assertSafeExisting(verificationStatus, false);
  const database = await request(verificationStatus.port, 'info', {}, 300000);
  const verification = await finalize(saved.database_path, false, opts.timeout ?? 60);
  const stable = packedHash === verification.database_sha256;
  if (!stable) throw new Error(`no-save verification changed packed hash (${packedHash} -> ${verification.database_sha256})`);
  console.log(JSON.stringify({ status: 'recovered', saved, verification: { database, ...verification, hash_stable: true } }, null, 2));
  } finally { releaseLock(lock); }
}

async function cmdStatus(opts) {
  console.log(JSON.stringify(await inspect(opts.binary), null, 2));
}

async function clearStaleReadOnlyLocked(opts, requested, p) {
    const bookkeeping = [p.port, p.pid, p.lineage, p.state];
    const present = bookkeeping.filter(existsSync);
    const requiredPresent = [p.pid, p.lineage, p.state].filter(existsSync);
    if (!present.length) {
      return { status: 'already_absent_unverifiable', target: requested,
        present, missing: bookkeeping };
    }
    if (requiredPresent.length !== 3) {
      const missing = bookkeeping.filter(path => !existsSync(path));
      throw new Error(`read-only runtime metadata is incomplete; present=${JSON.stringify(present)}; missing=${JSON.stringify(missing)}`);
    }
    for (const artifact of [p.pid, p.state, p.lineage]) {
      if (!existsSync(artifact)) throw new Error('read-only runtime metadata is incomplete');
    }
    const pidArtifact = readCanonicalPositiveDecimal(p.pid);
    const portArtifact = readCanonicalPositiveDecimal(p.port);
    if (pidArtifact.value === null || (portArtifact.present && (portArtifact.value === null || portArtifact.value > 65535))) {
      throw new Error('PID or port artifact is not canonical positive decimal');
    }
    const stateBytes = readFileSync(p.state);
    const lineageBytes = readFileSync(p.lineage);
    let stateRecord;
    let lineage;
    try { stateRecord = JSON.parse(stateBytes.toString('utf8')); lineage = JSON.parse(lineageBytes.toString('utf8')); }
    catch { throw new Error('read-only runtime metadata is invalid'); }
    const state = readState(opts.binary);
    if (state.version !== 2 || !Number.isInteger(state.pid) || state.pid <= 0
        || !Number.isInteger(state.port) || state.port <= 0 || state.port > 65535
        || state.writable !== false || stateRecord.pid !== pidArtifact.value
        || (portArtifact.present && stateRecord.port !== portArtifact.value)
        || state.database?.generation !== 0 || state.database?.save_state !== 'open_clean') {
      throw new Error('recorded state is uncertain or not read-only');
    }
    const proc = processState(state.pid);
    if (proc.alive || proc.permission_ambiguous) throw new Error('recorded PID is alive or its state is uncertain');
    if (await tcpProbe(state.port)) throw new Error('recorded RPC port is reachable');
    const ownerMatches = typeof process.getuid === 'function'
      ? Number.isInteger(state.owner_uid) && state.owner_uid === process.getuid()
      : state.owner_uid === null;
    if (lineage.version !== 2 || lineage.writable !== false || lineage.worker_pid !== state.pid
        || typeof state.nonce !== 'string' || !state.nonce || lineage.nonce !== state.nonce
        || !ownerMatches) {
      throw new Error('state and lineage identities do not match');
    }
    if (!state.requested_path || normalized(state.requested_path) !== requested
        || !state.log || normalized(state.log) !== normalized(p.log)) {
      throw new Error('requested target or runtime identity does not match');
    }
    const source = lineage.source;
    const requestedIsDatabase = ['.i64', '.idb'].includes(extname(requested).toLowerCase());
    if (!source?.path || normalized(source.path) !== normalized(state.source?.path)
        || source.ida_sha256 !== opts.sourceSha256 || source.file_sha256 !== opts.sourceSha256
        || source.file_status !== 'matched' || state.source?.ida_sha256 !== opts.sourceSha256
        || state.source?.file_sha256 !== opts.sourceSha256 || state.source?.file_status !== 'matched'
        || (!requestedIsDatabase && normalized(source.path) !== requested)
        || sha256(source.path) !== opts.sourceSha256) {
      throw new Error('source identity or hash does not match');
    }
    const database = lineage.database;
    if (!database?.path || !state.database?.path || normalized(database.path) !== normalized(state.database.path)
        || !state.database_path || normalized(database.path) !== normalized(state.database_path)
        || !databaseCandidates(requested).map(normalized).includes(normalized(database.path))
        || database.open_sha256 !== opts.databaseSha256 || database.confirmed_sha256 !== opts.databaseSha256
        || state.database.open_sha256 !== opts.databaseSha256 || state.database.confirmed_sha256 !== opts.databaseSha256
        || database.generation !== 0 || state.database.generation !== 0
        || database.save_state !== 'closed' || state.database.save_state !== 'open_clean'
        || sha256(database.path) !== opts.databaseSha256) throw new Error('database identity or packed hash does not match');
    if (sidecars(database.path).length) throw new Error('IDA sidecars exist; stale cleanup is unsafe');
    if (process.env.IDA_SKILL_TEST_STALE_READY) {
      writeFileSync(process.env.IDA_SKILL_TEST_STALE_READY, 'ready', { flag: 'wx' });
    }
    if (process.env.IDA_SKILL_TEST_STALE_BARRIER) {
      const deadline = Date.now() + 5000;
      while (!existsSync(process.env.IDA_SKILL_TEST_STALE_BARRIER) && Date.now() < deadline) {
        await new Promise(resolveDelay => setTimeout(resolveDelay, 10));
      }
      if (!existsSync(process.env.IDA_SKILL_TEST_STALE_BARRIER)) {
        throw new Error('test stale-cleanup barrier timed out');
      }
    }
    const testDelay = Number(process.env.IDA_SKILL_TEST_STALE_DELAY_MS || 0);
    if (Number.isFinite(testDelay) && testDelay > 0) {
      await new Promise(resolveDelay => setTimeout(resolveDelay, testDelay));
    }
    const rechecked = processState(state.pid);
    if (rechecked.alive || rechecked.permission_ambiguous || await tcpProbe(state.port)
        || !readFileSync(p.state).equals(stateBytes) || !readFileSync(p.lineage).equals(lineageBytes)
        || !artifactUnchanged(p.pid, pidArtifact) || !artifactUnchanged(p.port, portArtifact)
        || sha256(source.path) !== opts.sourceSha256 || sha256(database.path) !== opts.databaseSha256
        || sidecars(database.path).length) {
      throw new Error('external change or concurrent use is suspected; stale cleanup is unsafe');
    }
    const removed = [];
    const removalOrder = [p.pid, p.lineage, ...(portArtifact.present ? [p.port] : []), p.state];
    const failAfter = Number(process.env.IDA_SKILL_TEST_STALE_FAIL_AFTER || 0);
    try {
      for (const artifact of removalOrder) {
        rmSync(artifact);
        removed.push(artifact);
        if (Number.isInteger(failAfter) && failAfter === removed.length) {
          throw new Error('injected unlink failure');
        }
      }
    } catch (error) {
      const remaining = removalOrder.filter(existsSync);
      throw new Error(`stale cleanup interrupted: ${error.message}; removed=${JSON.stringify(removed)}; remaining=${JSON.stringify(remaining)}`);
    }
    return { status: 'cleared_stale_read_only', pid: state.pid, target: requested,
      source_sha256: opts.sourceSha256, database_path: normalized(database.path), database_sha256: opts.databaseSha256,
      removed };
}

async function cmdClearStaleReadOnly(opts) {
  const requested = canonical(opts.binary);
  const p = paths(requested);
  const lock = acquireCleanupLock(requested);
  const artifacts = [p.port, p.pid, p.lineage, p.state];
  let receipt = null;
  let primaryError = null;
  try { receipt = await clearStaleReadOnlyLocked(opts, requested, p); }
  catch (error) { primaryError = error; }
  try { releaseCleanupLock(lock, artifacts); }
  catch (releaseError) {
    if (primaryError) {
      throw new Error(`${primaryError.message}; secondary release failure: ${releaseError.message}`, { cause: primaryError });
    }
    throw releaseError;
  }
  if (primaryError) throw primaryError;
  console.log(JSON.stringify(receipt, null, 2));
}

function parseArgs() {
  const [cmd, ...rest] = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--binary') opts.binary = rest[++i];
    else if (rest[i] === '--idle') opts.idle = Number.parseInt(rest[++i], 10);
    else if (rest[i] === '--autosave') opts.autosave = Number.parseInt(rest[++i], 10);
    else if (rest[i] === '--timeout') opts.timeout = Number.parseInt(rest[++i], 10);
    else if (rest[i] === '--multi-agent') opts.multiAgent = true;
    else if (rest[i] === '--read-only') opts.readOnly = true;
    else if (rest[i] === '--no-run-auto-analysis') opts.autoAnalysis = false;
    else if (rest[i] === '--run-auto-analysis') opts.autoAnalysis = true;
    else if (rest[i] === '--source-sha256') opts.sourceSha256 = rest[++i];
    else if (rest[i] === '--database-sha256') opts.databaseSha256 = rest[++i];
  }
  return { cmd, opts };
}

async function main() {
  const { cmd, opts } = parseArgs();
  if (!opts.binary) throw new Error('--binary <path> is required');
  if (cmd === 'start') await cmdStart(opts);
  else if (cmd === 'status') await cmdStatus(opts);
  else if (cmd === 'save-and-close' || cmd === 'stop') console.log(JSON.stringify(await finalize(opts.binary, true, opts.timeout), null, 2));
  else if (cmd === 'close-no-save') console.log(JSON.stringify(await finalize(opts.binary, false, opts.timeout), null, 2));
  else if (cmd === 'recover-unclosed-database') await cmdRecover(opts);
  else if (cmd === 'clear-stale-read-only') {
    const sha256Pattern = /^[0-9a-f]{64}$/;
    if (!sha256Pattern.test(opts.sourceSha256 || '') || !sha256Pattern.test(opts.databaseSha256 || '')) {
      throw new Error('--source-sha256 and --database-sha256 must be lowercase SHA-256 values');
    }
    await cmdClearStaleReadOnly(opts);
  }
  else throw new Error('Usage: bridge.mjs <start|status|save-and-close|close-no-save|recover-unclosed-database|clear-stale-read-only> --binary <path>');
}

main().catch(error => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
