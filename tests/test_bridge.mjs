import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const BRIDGE = join(dirname(dirname(fileURLToPath(import.meta.url))), 'scripts', 'bridge.mjs');

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'ida-bridge-'));
  const runtime = join(root, 'runtime');
  mkdirSync(runtime);
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, runtime };
}

function artifacts(root, name = 'fixture.bin') {
  const binary = join(root, name);
  writeFileSync(binary, 'fixture');
  const hash = createHash('md5').update(realpathSync(binary)).digest('hex').slice(0, 12);
  const stem = join(root, 'runtime', `worker-${hash}`);
  return { binary, pid: `${stem}.pid`, port: `${stem}.port` };
}

async function fakeWorker(t, root, mode, name) {
  const files = artifacts(root, name);
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import net from 'node:net';
    const mode = process.argv[1];
    process.on('SIGTERM', () => { if (mode !== 'refuse-exit') process.exit(0); });
    const server = net.createServer(socket => socket.once('data', data => {
      const request = JSON.parse(data);
      if (request.cmd !== 'close' || request.args.save !== true) process.exit(2);
      if (mode === 'disconnect') return socket.end();
      if (mode === 'timeout') return;
      socket.end(JSON.stringify(mode === 'failure'
        ? {status: 'error', error: 'save refused'}
        : {status: 'ok', result: {status: 'closed', saved: true}}) + '\\n');
    }));
    server.listen(0, '127.0.0.1', () => console.log(server.address().port));
  `, mode], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', data => { stderr += data; });
  const exited = once(child, 'exit');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
  });
  const ready = await Promise.race([
    once(child.stdout, 'data').then(([data]) => Number(String(data).trim())),
    exited.then(() => { throw new Error(`Fixture worker exited: ${stderr}`); }),
  ]);
  writeFileSync(files.pid, String(child.pid));
  writeFileSync(files.port, String(ready));
  return { ...files, child, exited };
}

async function runBridge(root, args, bridge = BRIDGE, env = {}) {
  const child = spawn(process.execPath, [bridge, ...args], {
    env: { ...process.env, IDA_SKILL_BIN_DIR: root, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', data => { stdout += data; });
  child.stderr.on('data', data => { stderr += data; });
  const [code] = await once(child, 'close');
  return { code, stdout, stderr };
}

for (const [mode, message] of [
  ['failure', /save refused/],
  ['disconnect', /disconnected before acknowledging/],
  ['timeout', /save timed out/],
]) {
  test(`stop preserves a live worker and its state on ${mode}`, { timeout: 10000 }, async t => {
    const { root } = fixture(t);
    const worker = await fakeWorker(t, root, mode);
    const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '1']);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stderr, message);
    assert.doesNotThrow(() => process.kill(worker.child.pid, 0));
    assert.ok(existsSync(worker.pid));
    assert.ok(existsSync(worker.port));
    assert.doesNotMatch(result.stdout, /Worker stopped/);
  });
}

test('stop removes state only after a successful save and worker exit', { timeout: 10000 }, async t => {
  const { root } = fixture(t);
  const worker = await fakeWorker(t, root, 'success');
  const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '2']);
  assert.equal(result.code, 0, result.stderr);
  await worker.exited;
  assert.equal(existsSync(worker.pid), false);
  assert.equal(existsSync(worker.port), false);
});

test('stop does not force-kill a worker that remains alive after close', {
  timeout: 10000, skip: process.platform === 'win32',
}, async t => {
  const { root } = fixture(t);
  const worker = await fakeWorker(t, root, 'refuse-exit');
  const result = await runBridge(root, ['stop', '--binary', worker.binary, '--timeout', '1']);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /did not exit/);
  assert.doesNotThrow(() => process.kill(worker.child.pid, 0));
  assert.ok(existsSync(worker.pid));
  assert.ok(existsSync(worker.port));
});

test('stop-all continues after failed saves and reports partial failure', { timeout: 10000 }, async t => {
  const { root } = fixture(t);
  const failed = await fakeWorker(t, root, 'failure', 'failed.bin');
  const successful = await fakeWorker(t, root, 'success', 'success.bin');
  const result = await runBridge(root, ['stop-all', '--timeout', '2']);
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stdout, /1 worker\(s\) stopped/);
  assert.match(result.stderr, /1 worker\(s\) could not be stopped/);
  assert.doesNotThrow(() => process.kill(failed.child.pid, 0));
  assert.ok(existsSync(failed.pid));
  assert.ok(existsSync(failed.port));
  assert.equal(existsSync(successful.pid), false);
  assert.equal(existsSync(successful.port), false);
});

test('startup timeout preserves the worker and a retry cannot start a second one', { timeout: 10000 }, async t => {
  const { root } = fixture(t);
  const files = artifacts(root);
  const scripts = join(root, 'scripts');
  mkdirSync(scripts);
  const bridge = join(scripts, 'bridge.mjs');
  copyFileSync(BRIDGE, bridge);
  writeFileSync(join(scripts, 'worker.py'), 'import time\ntime.sleep(60)\n');
  const runtime = join(root, 'fake-ida');
  mkdirSync(join(runtime, 'idalib', 'python', 'idapro'), { recursive: true });
  mkdirSync(join(runtime, 'python'));
  const core = process.platform === 'win32' ? 'idalib.dll'
    : process.platform === 'darwin' ? 'libidalib.dylib' : 'libidalib.so';
  writeFileSync(join(runtime, core), 'fixture');
  writeFileSync(join(runtime, 'ida.hlp'), 'fixture');
  const env = { IDA_RUNTIME_DIR: runtime, IDA_PYTHON: process.platform === 'win32' ? 'python' : 'python3' };
  let pid;
  t.after(() => { if (pid) { try { process.kill(pid, 'SIGTERM'); } catch {} } });
  const args = ['start', '--binary', files.binary, '--timeout', '1'];
  const first = await runBridge(root, args, bridge, env);
  assert.equal(first.code, 1, first.stderr);
  assert.match(first.stderr, /state were preserved/);
  pid = Number(readFileSync(files.pid, 'utf8'));
  assert.doesNotThrow(() => process.kill(pid, 0));
  const second = await runBridge(root, args, bridge, env);
  assert.equal(second.code, 1, second.stderr);
  assert.match(second.stderr, /still alive but not ready/);
  assert.equal(Number(readFileSync(files.pid, 'utf8')), pid);
  const stop = await runBridge(root, ['stop-all', '--timeout', '1']);
  assert.equal(stop.code, 1, stop.stderr);
  assert.match(stop.stderr, /No worker RPC port recorded/);
  assert.doesNotThrow(() => process.kill(pid, 0));
  assert.ok(existsSync(files.pid));
});
