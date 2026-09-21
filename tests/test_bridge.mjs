import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const BRIDGE = join(dirname(dirname(fileURLToPath(import.meta.url))), 'scripts', 'bridge.mjs');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'ida-bridge-'));
  mkdirSync(join(root, 'runtime'));
  t.after(() => {
    const births = join(root, 'fixture-births');
    if (existsSync(births)) {
      for (const pid of readFileSync(births, 'utf8').trim().split('\n').map(Number)) {
        if (Number.isInteger(pid) && pid > 0) { try { process.kill(pid, 'SIGKILL'); } catch {} }
      }
    }
    rmSync(root, { recursive: true, force: true });
  });
  return root;
}
function artifacts(root, name = 'fixture.bin') {
  const binary = join(root, name);
  writeFileSync(binary, 'fixture');
  const requestedPath = realpathSync(binary);
  const hash = createHash('md5').update(requestedPath).digest('hex').slice(0, 12);
  const stem = join(root, 'runtime', `worker-${hash}`);
  return { binary, requestedPath, ...Object.fromEntries(['pid', 'port', 'json', 'lock', 'requests', 'signals', 'closing'].map(ext => [ext, `${stem}.${ext}`])) };
}

const WORKER = String.raw`
const net = require('node:net');
const fs = require('node:fs');
const opts = JSON.parse(process.argv[1]);
if (opts.births) fs.appendFileSync(opts.births, process.pid + '\n');
let state = 'ready';
const identity = () => ({protocol: 1, pid: process.pid, session_id: opts.session,
  requested_path: opts.requestedPath, current_path: opts.requestedPath,
  idb_path: opts.requestedPath + '.i64', state});
process.on('SIGTERM', () => fs.appendFileSync(opts.signals, 'SIGTERM\n'));
const server = net.createServer(socket => {
  let buffer = '';
  socket.on('data', data => {
    buffer += data;
    if (!buffer.includes('\n')) return;
    const request = JSON.parse(buffer.slice(0, buffer.indexOf('\n')));
    fs.appendFileSync(opts.requests, request.cmd + '\n');
    const reply = (result, callback) => socket.end(JSON.stringify({status: 'ok', result}) + '\n', callback);
    const error = message => socket.end(JSON.stringify({status: 'error', error: message}) + '\n');
    if (request.session_id !== undefined && request.session_id !== opts.session) return error('SessionMismatch');
    if (request.cmd === 'worker-identity') return reply(identity());
    if (request.cmd === 'worker-command' && request.args.cmd === 'info') return reply({file_path: opts.requestedPath});
    if (request.cmd !== 'worker-shutdown' || request.session_id !== opts.session) return error('Unexpected request');
    fs.writeFileSync(opts.closing, 'closing');
    if (opts.mode === 'disconnect') return socket.end();
    if (opts.mode === 'timeout') return;
    if (opts.mode === 'failure') return error('save refused');
    if (opts.mode === 'bad-ack') return reply({status: 'stopping', session_id: 'wrong-session'});
    state = 'stopping';
    setTimeout(() => {
      if (opts.mode === 'replace-state') {
        const replacement = JSON.parse(fs.readFileSync(opts.json, 'utf8'));
        replacement.session_id = 'replacement-session';
        fs.writeFileSync(opts.json, JSON.stringify(replacement));
      }
      reply({status: 'stopping', session_id: opts.session, close: {status: 'closed', saved: true}}, () => {
        if (opts.mode !== 'refuse-exit') setTimeout(() => process.exit(0), 10);
      });
    }, opts.closeDelay || 0);
  });
});
setTimeout(() => server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  if (opts.port) fs.writeFileSync(opts.port, String(port));
  console.log(port);
}), opts.readyDelay || 0);
`;

async function fakeWorker(t, root, mode = 'success', name, options = {}) {
  const files = artifacts(root, name);
  const session = randomUUID();
  const child = spawn(process.execPath, ['-e', WORKER, JSON.stringify({ ...files, mode, session, ...options })], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', data => { stderr += data; });
  const exited = once(child, 'exit');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
  });
  const port = await Promise.race([
    once(child.stdout, 'data').then(([data]) => Number(String(data).trim())),
    exited.then(() => { throw new Error(`Fixture worker exited: ${stderr}`); }),
  ]);
  const state = { protocol: 1, pid: child.pid, port, session_id: session, requested_path: files.requestedPath };
  writeFileSync(files.pid, String(child.pid));
  writeFileSync(files.json, JSON.stringify(state));
  return { ...files, child, exited, state };
}
function spawnBridge(root, args, bridge = BRIDGE, env = {}) {
  const child = spawn(process.execPath, [bridge, ...args], {
    env: { ...process.env, IDA_SKILL_BIN_DIR: root, ...env }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  return { child, done: once(child, 'close').then(([code]) => ({ code, stdout, stderr })) };
}
async function runBridge(...args) { return spawnBridge(...args).done; }
function assertPreserved(worker) {
  assert.doesNotThrow(() => process.kill(worker.child.pid, 0));
  for (const file of [worker.pid, worker.port, worker.json]) assert.ok(existsSync(file), file);
  assert.equal(existsSync(worker.signals), false, 'bridge must never signal a recorded PID');
}
async function waitFor(path) {
  const deadline = Date.now() + 5000;
  while (!existsSync(path) && Date.now() < deadline) await delay(10);
  assert.ok(existsSync(path), `Timed out waiting for ${path}`);
}
function startupFixture(root, files, readyDelay = 0) {
  const scripts = join(root, 'scripts');
  mkdirSync(scripts);
  const bridge = join(scripts, 'bridge.mjs');
  copyFileSync(BRIDGE, bridge);
  // Node stands in for Python: the bridge passes the real worker arguments,
  // but these fixtures never load IDA or need a licensed runtime.
  const options = { ...files, mode: 'success', readyDelay, births: join(root, 'fixture-births') };
  writeFileSync(join(scripts, 'worker.py'), `
    const args = process.argv.slice(2);
    const options = ${JSON.stringify(options)};
    options.session = args[args.indexOf('--session-id') + 1];
    options.port = args[args.indexOf('--port-file') + 1];
    process.argv[1] = JSON.stringify(options);
    ${WORKER}
  `);
  const runtime = join(root, 'fake-ida');
  mkdirSync(join(runtime, 'idalib', 'python', 'idapro'), { recursive: true });
  mkdirSync(join(runtime, 'python'));
  const core = process.platform === 'win32' ? 'idalib.dll' : process.platform === 'darwin' ? 'libidalib.dylib' : 'libidalib.so';
  writeFileSync(join(runtime, core), 'fixture');
  writeFileSync(join(runtime, 'ida.hlp'), 'fixture');
  return { bridge, env: { IDA_RUNTIME_DIR: runtime, IDA_PYTHON: process.execPath } };
}

for (const [mode, message] of [
  ['failure', /save refused/], ['disconnect', /disconnected before acknowledging/],
  ['timeout', /worker-shutdown timed out/], ['refuse-exit', /did not exit/],
  ['bad-ack', /acknowledgement did not match/],
]) {
  test(`stop preserves worker/state without signals on ${mode}`, { timeout: 10000 }, async t => {
    const root = fixture(t);
    const worker = await fakeWorker(t, root, mode);
    const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '1']);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, message);
    assertPreserved(worker);
    assert.doesNotMatch(result.stdout, /Worker stopped/);
  });
}

test('verified shutdown saves, exits itself, and removes the captured state', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const worker = await fakeWorker(t, root);
  const status = await runBridge(root, ['status', '--binary', worker.binary]);
  assert.equal(JSON.parse(status.stdout).identity_verified, true);
  assert.equal(JSON.parse(status.stdout).running, true);
  const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '2']);
  assert.equal(result.code, 0, result.stderr);
  await worker.exited;
  for (const file of [worker.pid, worker.port, worker.json, worker.lock, worker.signals]) assert.equal(existsSync(file), false, file);
});

for (const field of ['pid', 'port', 'session_id', 'requested_path']) {
  test(`mismatched ${field} refuses status/attach/stop without closing or signalling`, { timeout: 10000 }, async t => {
    const root = fixture(t);
    const worker = await fakeWorker(t, root, 'success', 'original.bin');
    const other = await fakeWorker(t, root, 'success', 'other.bin');
    const changed = { ...worker.state, [field]: other.state[field] };
    writeFileSync(worker.json, JSON.stringify(changed));
    const { bridge, env } = startupFixture(root, worker);
    const status = await runBridge(root, ['status', '--binary', worker.binary, '--timeout', '1']);
    assert.equal(JSON.parse(status.stdout).running, false);
    assert.equal(JSON.parse(status.stdout).identity_verified, false);
    for (const cmd of ['start', 'stop']) {
      const result = await runBridge(root, [cmd, '--binary', worker.binary, '--timeout', '1'], bridge, env);
      assert.equal(result.code, 1, result.stderr);
    }
    for (const fixtureWorker of [worker, other]) {
      assertPreserved(fixtureWorker);
      assert.doesNotMatch(existsSync(fixtureWorker.requests) ? readFileSync(fixtureWorker.requests, 'utf8') : '', /worker-shutdown/);
    }
  });
}

test('legacy PID-only and corrupt state are preserved and reported unverified', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const worker = await fakeWorker(t, root);
  rmSync(worker.json);
  rmSync(worker.port);
  const legacy = await runBridge(root, ['stop-all', '--timeout', '1']);
  assert.equal(legacy.code, 1);
  assert.match(legacy.stderr, /Legacy or incomplete/);
  assert.ok(existsSync(worker.pid));
  writeFileSync(worker.json, '{broken');
  const status = await runBridge(root, ['status', '--binary', worker.binary]);
  assert.equal(JSON.parse(status.stdout).identity_verified, false);
  assert.match(JSON.parse(status.stdout).error, /Invalid worker state/);
  assert.equal(readFileSync(worker.json, 'utf8'), '{broken');
  assert.equal(existsSync(worker.signals), false);
});

test('stop-all continues after failed saves and reports partial failure', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const failed = await fakeWorker(t, root, 'failure', 'failed.bin');
  const successful = await fakeWorker(t, root, 'success', 'success.bin');
  const result = await runBridge(root, ['stop-all', '--timeout', '2']);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stdout, /1 worker\(s\) stopped/);
  assert.match(result.stderr, /1 worker\(s\) could not be stopped/);
  assertPreserved(failed);
  for (const file of [successful.pid, successful.port, successful.json]) assert.equal(existsSync(file), false);
});

test('stop never deletes metadata belonging to a replacement session', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const worker = await fakeWorker(t, root, 'replace-state');
  const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '2']);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /replacement state preserved/);
  assert.equal(JSON.parse(readFileSync(worker.json, 'utf8')).session_id, 'replacement-session');
  assert.ok(existsSync(worker.pid));
  assert.ok(existsSync(worker.port));
});

test('concurrent start waits for stop and retains replacement tracking', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const worker = await fakeWorker(t, root, 'success', undefined, { closeDelay: 500 });
  const { bridge, env } = startupFixture(root, worker);
  const stopping = spawnBridge(root, ['stop', '--binary', worker.binary, '--timeout', '3']);
  await waitFor(worker.closing);
  const starting = await runBridge(root, ['start', '--binary', worker.binary, '--timeout', '3'], bridge, env);
  assert.equal((await stopping.done).code, 0);
  assert.equal(starting.code, 0, starting.stderr);
  assert.doesNotMatch(starting.stdout, /already running/);
  const replacement = JSON.parse(readFileSync(worker.json, 'utf8'));
  assert.notEqual(replacement.session_id, worker.state.session_id);
  assert.notEqual(replacement.pid, worker.child.pid);
  assert.ok(existsSync(worker.pid));
  assert.ok(existsSync(worker.port));
  const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '2']);
  assert.equal(result.code, 0, result.stderr);
});

test('startup timeout preserves identity, then ready recovery publishes the same session', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const files = artifacts(root);
  const { bridge, env } = startupFixture(root, files, 1500);
  const first = await runBridge(root, ['start', '--binary', files.binary, '--timeout', '1'], bridge, env);
  assert.equal(first.code, 1, first.stderr);
  assert.match(first.stderr, /state were preserved/);
  const initial = JSON.parse(readFileSync(files.json, 'utf8'));
  assert.equal(initial.port, null);
  const early = await runBridge(root, ['start', '--binary', files.binary, '--timeout', '1'], bridge, env);
  assert.equal(early.code, 1, early.stderr);
  assert.match(early.stderr, /still alive but not ready/);
  await waitFor(files.port);
  const recovered = await runBridge(root, ['start', '--binary', files.binary, '--timeout', '2'], bridge, env);
  assert.equal(recovered.code, 0, recovered.stderr);
  const ready = JSON.parse(readFileSync(files.json, 'utf8'));
  assert.equal(ready.pid, initial.pid);
  assert.equal(ready.session_id, initial.session_id);
  assert.ok(Number.isInteger(ready.port));
  assert.equal((await runBridge(root, ['stop', '--binary', files.binary, '--timeout', '2'])).code, 0);
});

test('an existing lifecycle lock is never reclaimed or removed by another operation', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const worker = await fakeWorker(t, root);
  const token = JSON.stringify({ pid: 999999999, token: 'stale-owner' });
  writeFileSync(worker.lock, token);
  const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '1']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /manually recovering a stale lock/);
  assert.equal(readFileSync(worker.lock, 'utf8'), token);
  assertPreserved(worker);
});

for (const failPid of [false, true]) {
  test(`failed initial state publication preserves ${failPid ? 'the owned lock' : 'a durable PID marker'}`, { timeout: 10000 }, async t => {
    const root = fixture(t);
    const files = artifacts(root);
    const { bridge, env } = startupFixture(root, files);
    const hook = join(root, 'publish-fault.mjs');
    writeFileSync(hook, `
      import fs from 'node:fs';
      import { syncBuiltinESMExports } from 'node:module';
      const rename = fs.renameSync;
      const write = fs.writeFileSync;
      fs.renameSync = (from, to) => {
        if (String(to).endsWith('.json')) throw new Error('injected state publication failure');
        return rename(from, to);
      };
      fs.writeFileSync = (path, ...args) => {
        if (${failPid} && String(path).endsWith('.pid')) throw new Error('injected PID publication failure');
        return write(path, ...args);
      };
      syncBuiltinESMExports();
      process.env.NODE_OPTIONS = ''; // Keep the fault inside the bridge process.
    `);
    const result = await runBridge(root, ['start', '--binary', files.binary, '--timeout', '1'], bridge,
      { ...env, NODE_OPTIONS: `--import=${pathToFileURL(hook).href}` });
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, /Could not publish worker state/);
    assert.match(result.stderr, /live worker PID [1-9][0-9]*, session/);
    await waitFor(join(root, 'fixture-births'));
    assert.equal(existsSync(files.lock), failPid);
    assert.equal(existsSync(files.pid), !failPid);
    const retry = await runBridge(root, ['start', '--binary', files.binary, '--timeout', '1'], bridge, env);
    assert.equal(retry.code, 1, retry.stderr);
    assert.match(retry.stderr, failPid ? /Lifecycle lock still exists/ : /Legacy or incomplete/);
    assert.equal(readFileSync(join(root, 'fixture-births'), 'utf8').trim().split('\n').length, 1);
  });
}

test('spawn failures never publish an undefined PID and release the owned lock', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const files = artifacts(root);
  const { bridge, env } = startupFixture(root, files);
  const hook = join(root, 'spawn-fault.mjs');
  writeFileSync(hook, `
    import childProcess from 'node:child_process';
    import { syncBuiltinESMExports } from 'node:module';
    const spawn = childProcess.spawn;
    childProcess.spawn = (command, args, options) => spawn(${JSON.stringify(join(root, 'missing-executable'))}, args, options);
    syncBuiltinESMExports();
  `);
  const result = await runBridge(root, ['start', '--binary', files.binary, '--timeout', '1'], bridge,
    { ...env, NODE_OPTIONS: `--import=${pathToFileURL(hook).href}` });
  assert.equal(result.code, 1);
  assert.match(result.stderr, /ENOENT/);
  for (const file of [files.pid, files.json, files.lock]) assert.equal(existsSync(file), false, file);
});

test('malformed identity fields cannot trigger RPCs or process signals', { timeout: 10000 }, async t => {
  const root = fixture(t);
  const worker = await fakeWorker(t, root);
  for (const state of [[], { ...worker.state, pid: -1 }, { ...worker.state, pid: 1.5 },
    { ...worker.state, port: '1234' }, { ...worker.state, port: 0 },
    { ...worker.state, session_id: '' }, { ...worker.state, requested_path: 'relative.bin' }]) {
    writeFileSync(worker.json, JSON.stringify(state));
    const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '1']);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, /Invalid worker identity metadata/);
  }
  assert.equal(existsSync(worker.requests), false);
  assertPreserved(worker);
});
