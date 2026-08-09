import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SETUP = join(ROOT, 'scripts', 'setup.mjs');

function write(path, value = 'fixture') {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, value);
}

function makeIdaInstall(root, target) {
  const libraries = {
    mac: ['libida.dylib', 'libidalib.dylib'],
    linux: ['libida.so', 'libidalib.so'],
    windows: ['ida.dll', 'idalib.dll'],
  }[target];
  for (const library of libraries) write(join(root, library));
  for (const file of ['ida.hlp', 'ida.int', 'license.txt']) write(join(root, file));
  write(join(root, 'python', 'idaapi.py'));
  write(join(root, 'idalib', 'python', 'idapro', '__init__.py'));
  write(join(root, 'dbgsrv', 'debug-server'));
  return root;
}

function makeLicenseDir(root, target) {
  write(join(root, 'idapro.hexlic'), 'private-license-fixture');
  if (target !== 'windows') write(join(root, 'ida.reg'), 'eula-fixture');
  write(join(root, 'ida-config.json'), '{}');
  return root;
}

function runSetup(temp, args) {
  return spawnSync(process.execPath, [SETUP, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: join(temp, 'empty-home'),
      USERPROFILE: join(temp, 'empty-home'),
      APPDATA: join(temp, 'empty-appdata'),
    },
  });
}

function assertSuccess(result) {
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
}

test('provisions private portable runtimes for macOS, Linux, and Windows', () => {
  const temp = mkdtempSync(join(tmpdir(), 'ida-skill-setup-'));
  try {
    for (const target of ['mac', 'linux', 'windows']) {
      const source = makeIdaInstall(join(temp, `source-${target}`), target);
      const license = makeLicenseDir(join(temp, `license-${target}`), target);
      const bundle = join(temp, `bundle-${target}`);
      const result = runSetup(temp, [
        '--ida-dir', source,
        '--license-dir', license,
        '--bundle-dir', bundle,
        '--target-platform', target,
        '--include-license',
      ]);
      assertSuccess(result);

      const runtime = join(bundle, `ida-runtime-${target}`);
      assert.ok(existsSync(join(runtime, 'license', 'idapro.hexlic')));
      if (target !== 'windows') assert.ok(existsSync(join(runtime, 'license', 'ida.reg')));
      assert.ok(existsSync(join(bundle, 'dbgsrv', 'debug-server')));

      const marker = JSON.parse(readFileSync(join(runtime, '.provisioned'), 'utf8'));
      assert.equal(marker.platform, target);
      assert.equal(marker.licenseIncluded, true);
      assert.equal('idaSource' in marker, false);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('keeps license state out unless explicitly requested', () => {
  const temp = mkdtempSync(join(tmpdir(), 'ida-skill-unlicensed-'));
  try {
    const source = makeIdaInstall(join(temp, 'source'), 'linux');
    const bundle = join(temp, 'bundle');
    const result = runSetup(temp, [
      '--ida-dir', source,
      '--bundle-dir', bundle,
      '--target-platform', 'linux',
    ]);
    assertSuccess(result);
    assert.equal(existsSync(join(bundle, 'ida-runtime-linux', 'license', 'idapro.hexlic')), false);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('full mode copies installation content and private license state', () => {
  const temp = mkdtempSync(join(tmpdir(), 'ida-skill-full-'));
  try {
    const source = makeIdaInstall(join(temp, 'source'), 'linux');
    const license = makeLicenseDir(join(temp, 'license'), 'linux');
    const bundle = join(temp, 'bundle');
    write(join(source, 'docs', 'guide.txt'), 'full-mode-fixture');

    const result = runSetup(temp, [
      '--ida-dir', source,
      '--license-dir', license,
      '--bundle-dir', bundle,
      '--target-platform', 'linux',
      '--include-license',
      '--full',
    ]);
    assertSuccess(result);
    assert.equal(
      readFileSync(join(bundle, 'ida-runtime-linux', 'docs', 'guide.txt'), 'utf8'),
      'full-mode-fixture',
    );
    assert.equal(
      readFileSync(join(bundle, 'ida-runtime-linux', 'license', 'idapro.hexlic'), 'utf8'),
      'private-license-fixture',
    );
    assert.equal(
      readFileSync(join(bundle, 'ida-runtime-linux', 'license', 'ida.reg'), 'utf8'),
      'eula-fixture',
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test('an invalid explicit installation never falls back to another IDA', () => {
  const temp = mkdtempSync(join(tmpdir(), 'ida-skill-bad-path-'));
  try {
    const missing = join(temp, 'missing');
    const result = runSetup(temp, [
      '--ida-dir', missing,
      '--bundle-dir', join(temp, 'bundle'),
      '--target-platform', 'linux',
    ]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Explicit --ida-dir does not exist/);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
