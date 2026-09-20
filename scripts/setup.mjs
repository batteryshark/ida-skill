#!/usr/bin/env node
// setup.mjs
// Provisions a minimal portable idalib runtime from the user's licensed
// IDA Pro installation. Pure Node.js stdlib (Node >= 18). No npm deps.
//
// Unlike the ghidra-skill (which downloads from the internet), IDA is
// proprietary — this script trims the user's LOCAL installation in-place.
//
// CRITICAL (macOS arm64): uses `ditto` instead of `cp` to preserve
// code-signing extended attributes. Binaries copied with `cp` segfault.
//
// Run:  node setup.mjs [--ida-dir /path/to/ida] [--force]
// Re-run safe: skips steps already completed.

import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync,
  rmSync, readdirSync, statSync,
} from 'node:fs';
import { platform, arch, homedir } from 'node:os';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
const BIN_DIR = join(__dirname, '..', 'bin');

// plat and RUNTIME_DIR are set in main() based on --target-platform
let plat = null;
let RUNTIME_DIR = null;
let PLATFORM_KEY = null;

// ─────────────────────────────────────────────────────────────────────────────
// Platform detection
// ─────────────────────────────────────────────────────────────────────────────
const HOST_PLATFORM_KEY = `${platform()}-${arch()}`;
const PLATFORM_INFO = {
  'darwin-arm64': { os: 'mac', arch: 'arm64', libExt: '.dylib', copyCmd: 'ditto' },
  'darwin-x64':   { os: 'mac', arch: 'x64',  libExt: '.dylib', copyCmd: 'ditto' },
  'linux-x64':    { os: 'linux', arch: 'x64', libExt: '.so',   copyCmd: 'cp'   },
  'linux-arm64':  { os: 'linux', arch: 'arm64', libExt: '.so', copyCmd: 'cp'   },
  'win32-x64':    { os: 'windows', arch: 'x64', libExt: '.dll', copyCmd: 'robocopy' },
};

// Target platform can be overridden via --target-platform for cross-trimming
// (e.g. trimming a Windows IDA from macOS).
let _targetOs = null;
function getTargetPlatform(targetArg) {
  if (targetArg) {
    const map = {
      'windows': { os: 'windows', libExt: '.dll', copyCmd: 'cp' }, // cp when cross-trimming
      'mac':     { os: 'mac',     libExt: '.dylib' },
      'linux':   { os: 'linux',   libExt: '.so' },
    };
    const t = map[targetArg];
    if (!t) {
      console.error(`Unknown --target-platform: ${targetArg}. Use: windows, mac, linux`);
      process.exit(1);
    }
    return t;
  }
  // Default: use the host platform
  return PLATFORM_INFO[HOST_PLATFORM_KEY];
}

// ─────────────────────────────────────────────────────────────────────────────
// Files to keep (everything else is trimmed)
// ─────────────────────────────────────────────────────────────────────────────

// Core libraries — platform-specific names.
// macOS/Linux: libida.dylib/.so, libidalib.dylib/.so, libclpx.dylib/.so
// Windows:     ida.dll, idalib.dll, clp64.dll (no libclpx)
const CORE_LIBS_BY_PLATFORM = {
  windows: ['ida', 'ida32', 'idalib', 'idalib32', 'libclang', 'libz3', 'libdwarf', 'clp64', 'libSwiftDemangle', 'librustdemangle'],
  mac:     ['libida', 'libida32', 'libidalib', 'libidalib32', 'libclang', 'libz3', 'libdwarf', 'libclpx', 'libSwiftDemangle', 'librustdemangle'],
  linux:   ['libida', 'libida32', 'libidalib', 'libidalib32', 'libclang', 'libz3', 'libdwarf', 'libclpx', 'libSwiftDemangle', 'librustdemangle'],
};
function getCoreLibs(os) {
  return CORE_LIBS_BY_PLATFORM[os] || CORE_LIBS_BY_PLATFORM.linux;
}

// Python native binding extension: .pyd (Windows), .so (macOS/Linux)
function getPydExt(os) {
  return os === 'windows' ? '.pyd' : '.so';
}

// Required non-library files
const REQUIRED_FILES = ['ida.hlp', 'ida.int', 'license.txt'];

// Decompiler plugins (one per architecture)
const KEEP_PLUGINS = [
  'hexx64', 'hexarm', 'hexmips', 'hexppc', 'hexrv', 'hexarc',
  'dbg', 'idapython3', 'pdb', 'dwarf', 'eh_parse',
  'objc', 'swift', 'rtti', 'strings',
  'golang', 'rust', 'coff', 'elf', 'objc', 'idaclang',
];

// Processor modules to keep (metapc/pc is built into libida)
const KEEP_PROCS = ['arm', 'mips', 'ppc', 'riscv', 'arc', 'wasm', 'pc'];

// Loaders to keep
const KEEP_LOADERS = ['pe', 'elf', 'macho', 'coff', 'bin'];

// TIL subdirectories to keep
const KEEP_TIL_DIRS = ['pc', 'arm'];

// TIL files (in til/pc) to keep — everything else trimmed
const KEEP_TIL_PC = [
  'gnulnx_x64.til', 'gnulnx_x86.til', 'gnuwin.til',
  'ntapi64_win10.til', 'ntapi_win10.til',
  'uefi64.til', 'mscor.til',
];

// TIL files (in til/arm) to keep
const KEEP_TIL_ARM = [
  'gnulnx_arm.til', 'gnulnx_arm64.til', 'android_arm64.til', 'armv12.til',
];

// Directories to skip entirely
const SKIP_DIRS = new Set([
  'docs', 'tools', 'sig', 'dbgsrv', 'themes', 'idc', 'ids',
  'include', '__pycache__',
]);

// ─────────────────────────────────────────────────────────────────────────────
// IDA installation discovery
// ─────────────────────────────────────────────────────────────────────────────

function findIdaDir(explicit) {
  if (explicit && existsSync(explicit)) return resolveIdaDir(explicit);

  // IDADIR env var
  const envIdadir = process.env.IDADIR;
  if (envIdadir && existsSync(envIdadir)) return resolveIdaDir(envIdadir);

  // Platform defaults
  const candidates = platformDefaults();
  for (const c of candidates) {
    if (existsSync(c)) return resolveIdaDir(c);
  }
  return null;
}

function resolveIdaDir(dir) {
  // macOS .app bundle: point at Contents/MacOS
  if (platform() === 'darwin' && basename(dir).endsWith('.app')) {
    return join(dir, 'Contents', 'MacOS');
  }
  return dir;
}

function platformDefaults() {
  if (platform() === 'darwin') {
    return ['/Applications/IDA Professional 9.4.app', '/Applications/IDA Professional 9.3.app']
      .flatMap(d => [join(d, 'Contents', 'MacOS'), d]);
  }
  if (platform() === 'win32') {
    return [
      'C:\\Program Files\\IDA Professional 9.4',
      'C:\\Program Files\\IDA Pro 9.4',
      'C:\\Program Files\\IDA Professional 9.3',
    ];
  }
  // Linux
  return ['/opt/ida-pro-9.4', '/opt/idapro-9.4', '/opt/ida-9.4',
          '/opt/ida-pro-9.3', '/opt/idapro-9.3'];
}

function validateIdaDir(dir) {
  const libExt = plat.libExt;
  // Check for the kernel library (platform-specific naming)
  const kernelNames = plat.os === 'windows'
    ? ['ida.dll', 'ida64.dll']
    : [`libida${libExt}`, `libida64${libExt}`];
  for (const name of kernelNames) {
    if (existsSync(join(dir, name))) return true;
  }
  // Fallback: check for ida.hlp (always present)
  return existsSync(join(dir, 'ida.hlp'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Copy helpers (platform-specific)
// ─────────────────────────────────────────────────────────────────────────────

// HOST_COPY_CMD: copy tool on the HOST machine (not the target platform).
// plat.libExt/os are target-specific; the copy command must run on host.
const HOST_COPY_CMD = HOST_PLATFORM_KEY.startsWith('darwin') ? 'ditto'
  : HOST_PLATFORM_KEY.startsWith('win32') ? 'robocopy' : 'cp';

function copyFile(src, dest) {
  mkdirSync(dirname(dest), { recursive: true });
  if (HOST_COPY_CMD === 'ditto') {
    // ditto preserves code-signing extended attributes (CRITICAL on macOS arm64)
    spawnSync('ditto', [src, dest], { stdio: ['ignore', 'pipe', 'pipe'] });
  } else if (HOST_COPY_CMD === 'robocopy') {
    // robocopy /COPYALL preserves ACLs and alternate data streams
    spawnSync('robocopy', [dirname(src), dirname(dest), basename(src), '/COPY:DAT', '/NFL', '/NDL', '/NJH', '/NJS'],
      { stdio: ['ignore', 'pipe', 'pipe'] });
  } else {
    // Linux: cp -a preserves permissions and timestamps
    spawnSync('cp', ['-a', src, dest], { stdio: ['ignore', 'pipe', 'pipe'] });
  }
}

function copyDir(src, dest) {
  mkdirSync(dest, { recursive: true });
  if (HOST_COPY_CMD === 'ditto') {
    spawnSync('ditto', [src, dest], { stdio: ['ignore', 'pipe', 'pipe'] });
  } else if (HOST_COPY_CMD === 'robocopy') {
    spawnSync('robocopy', [src, dest, '/E', '/COPY:DAT', '/NFL', '/NDL', '/NJH', '/NJS'],
      { stdio: ['ignore', 'pipe', 'pipe'] });
  } else {
    spawnSync('cp', ['-a', `${src}/.`, dest], { stdio: ['ignore', 'pipe', 'pipe'] });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Provisioning steps
// ─────────────────────────────────────────────────────────────────────────────

function provisionCore(idaDir) {
  console.log('[core] Copying core libraries...');
  const libExt = plat.libExt;
  const coreLibs = getCoreLibs(plat.os);

  for (const base of coreLibs) {
    // Try the platform extension (and 64/32 variants)
    const candidates = [
      `${base}${libExt}`,
      `${base}64${libExt}`,
      `${base}32${libExt}`,
    ];

    for (const name of candidates) {
      const src = join(idaDir, name);
      if (existsSync(src)) {
        copyFile(src, join(RUNTIME_DIR, name));
      }
    }
  }

  // Required non-library files
  for (const f of REQUIRED_FILES) {
    const src = join(idaDir, f);
    if (existsSync(src)) {
      copyFile(src, join(RUNTIME_DIR, f));
    } else {
      console.warn(`[core] WARNING: ${f} not found in IDA installation`);
    }
  }
}

function provisionLicense(idaDir) {
  console.log('[license] Bundling license...');
  const destDir = join(RUNTIME_DIR, 'license');
  mkdirSync(destDir, { recursive: true });

  // 1. Copy idapro.hexlic (the actual license file)
  const hexlicCandidates = [
    join(idaDir, 'idapro.hexlic'),
    join(homedir(), '.idapro', 'idapro.hexlic'),
  ];
  if (process.env.APPDATA) {
    hexlicCandidates.push(join(process.env.APPDATA, 'Hex-Rays', 'IDA Pro', 'idapro.hexlic'));
  }
  for (const src of hexlicCandidates) {
    if (existsSync(src)) {
      copyFile(src, join(destDir, 'idapro.hexlic'));
      console.log(`[license] hexlic: ${src}`);
      break;
    }
  }

  // 2. Copy ida.reg (macOS/Linux EULA acceptance — makes runtime self-contained)
  const regCandidates = [
    join(homedir(), '.idapro', 'ida.reg'),
  ];
  for (const src of regCandidates) {
    if (existsSync(src)) {
      copyFile(src, join(destDir, 'ida.reg'));
      console.log(`[license] ida.reg: ${src}`);
      break;
    }
  }

  // 3. Copy ida-config.json if it exists (install dir pointer)
  const configCandidates = [
    join(homedir(), '.idapro', 'ida-config.json'),
    join(idaDir, 'ida-config.json'),
  ];
  for (const src of configCandidates) {
    if (existsSync(src)) {
      copyFile(src, join(destDir, 'ida-config.json'));
      console.log(`[license] ida-config.json: ${src}`);
      break;
    }
  }

  if (!existsSync(join(destDir, 'idapro.hexlic'))) {
    console.warn('[license] WARNING: idapro.hexlic not found anywhere.');
  }
}

function provisionPlugins(idaDir) {
  const srcDir = join(idaDir, 'plugins');
  if (!existsSync(srcDir)) { console.warn('[plugins] No plugins directory'); return; }

  console.log('[plugins] Copying decompiler + essential plugins...');
  const destDir = join(RUNTIME_DIR, 'plugins');
  mkdirSync(destDir, { recursive: true });

  for (const entry of readdirSync(srcDir)) {
    // Match platform-specific extension (.dll on Windows, .dylib on macOS, .so on Linux)
    const ext = entry.match(/\.(dll|dylib|so)$/);
    if (!ext) continue;
    const stem = entry.replace(/\.(dll|dylib|so)$/, '');
    if (KEEP_PLUGINS.includes(stem)) {
      copyFile(join(srcDir, entry), join(destDir, entry));
    }
  }
}

function provisionProcs(idaDir) {
  const srcDir = join(idaDir, 'procs');
  if (!existsSync(srcDir)) { console.warn('[procs] No procs directory'); return; }

  console.log('[procs] Copying processor modules...');
  const destDir = join(RUNTIME_DIR, 'procs');
  mkdirSync(destDir, { recursive: true });

  for (const entry of readdirSync(srcDir)) {
    const ext = entry.match(/\.(dll|dylib|so|py)$/);
    if (!ext) continue;
    const stem = entry.replace(/\.(dll|dylib|so|py)$/, '');
    if (KEEP_PROCS.includes(stem)) {
      copyFile(join(srcDir, entry), join(destDir, entry));
    }
  }
}

function provisionLoaders(idaDir) {
  const srcDir = join(idaDir, 'loaders');
  if (!existsSync(srcDir)) { console.warn('[loaders] No loaders directory'); return; }

  console.log('[loaders] Copying file format loaders...');
  const destDir = join(RUNTIME_DIR, 'loaders');
  mkdirSync(destDir, { recursive: true });

  for (const entry of readdirSync(srcDir)) {
    const ext = entry.match(/\.(dll|dylib|so)$/);
    if (!ext) continue;
    const stem = entry.replace(/\.(dll|dylib|so)$/, '');
    if (KEEP_LOADERS.some(l => stem.startsWith(l))) {
      copyFile(join(srcDir, entry), join(destDir, entry));
    }
  }
}

function provisionTil(idaDir) {
  const srcDir = join(idaDir, 'til');
  if (!existsSync(srcDir)) { console.warn('[til] No til directory'); return; }

  console.log('[til] Copying trimmed type libraries...');
  const destDir = join(RUNTIME_DIR, 'til');
  mkdirSync(destDir, { recursive: true });

  // gnucmn.til (shared base types — REQUIRED)
  const gnucmn = join(srcDir, 'gnucmn.til');
  if (existsSync(gnucmn)) copyFile(gnucmn, join(destDir, 'gnucmn.til'));

  // Per-directory trimming
  for (const sub of KEEP_TIL_DIRS) {
    const subSrc = join(srcDir, sub);
    if (!existsSync(subSrc)) continue;
    const subDest = join(destDir, sub);
    mkdirSync(subDest, { recursive: true });

    const keepList = sub === 'pc' ? KEEP_TIL_PC : sub === 'arm' ? KEEP_TIL_ARM : null;
    if (keepList) {
      for (const f of keepList) {
        const src = join(subSrc, f);
        if (existsSync(src)) copyFile(src, join(subDest, f));
      }
    } else {
      copyDir(subSrc, subDest);
    }
  }
}

function provisionCfg(idaDir) {
  const srcDir = join(idaDir, 'cfg');
  if (!existsSync(srcDir)) { console.warn('[cfg] No cfg directory'); return; }

  console.log('[cfg] Copying trimmed configuration...');
  const destDir = join(RUNTIME_DIR, 'cfg');
  mkdirSync(destDir, { recursive: true });

  for (const entry of readdirSync(srcDir)) {
    const src = join(srcDir, entry);
    const st = statSync(src);
    if (!st.isFile()) continue;

    // Keep .cfg files but skip localization (.clt) and huge obscure configs
    if (entry.endsWith('.cfg')) {
      // Skip configs for processors we don't support
      const skipPrefixes = ['pic', '78k', 'tri', '68', 'tms', 'h8', 'msp', 'avr', 'fr.', 'm32', 'c166'];
      if (skipPrefixes.some(p => entry.startsWith(p))) continue;
      // Skip configs larger than 1MB (obscure processors)
      if (st.size > 1_048_576) continue;
      copyFile(src, join(destDir, entry));
    }
  }
}

function provisionPython(idaDir) {
  // lib-dynload: native Python bindings (_ida_*.so/dylib/dll)
  const dynloadSrc = join(idaDir, 'python', 'lib-dynload');
  if (existsSync(dynloadSrc)) {
    console.log('[python] Copying native bindings (lib-dynload)...');
    copyDir(dynloadSrc, join(RUNTIME_DIR, 'python', 'lib-dynload'));
  }

  // Python .py stub files
  const pySrc = join(idaDir, 'python');
  if (existsSync(pySrc)) {
    console.log('[python] Copying Python stub modules...');
    const destPy = join(RUNTIME_DIR, 'python');
    for (const entry of readdirSync(pySrc)) {
      if (!entry.endsWith('.py')) continue;
      copyFile(join(pySrc, entry), join(destPy, entry));
    }
  }

  // idapro wheel + config
  const idalibPySrc = join(idaDir, 'idalib', 'python');
  if (existsSync(idalibPySrc)) {
    console.log('[python] Copying idapro wheel...');
    copyDir(idalibPySrc, join(RUNTIME_DIR, 'idalib', 'python'));
  }
}

function provisionDbgsrv(idaDir) {
  // The dbgsrv folder is shared across all platforms (contains remote debug
  // servers for every target OS). Copy it once into bin/dbgsrv/.
  const srcDir = join(idaDir, 'dbgsrv');
  const destDir = join(BIN_DIR, 'dbgsrv');
  if (!existsSync(srcDir)) {
    console.warn('[dbgsrv] No dbgsrv/ folder in IDA installation — skipping');
    return;
  }
  mkdirSync(destDir, { recursive: true });
  for (const name of readdirSync(srcDir)) {
    copyFile(join(srcDir, name), join(destDir, name));
  }
  const count = readdirSync(destDir).length;
  console.log(`[dbgsrv] Copied ${count} remote debug servers to bin/dbgsrv/`);
}

function provisionComplete(idaDir) {
  // Just copy everything (for --full mode)
  console.log('[full] Copying entire IDA installation (untrimmed)...');
  for (const entry of readdirSync(idaDir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const src = join(idaDir, entry);
    if (statSync(src).isDirectory()) copyDir(src, join(RUNTIME_DIR, entry));
    else copyFile(src, join(RUNTIME_DIR, entry));
  }
}

function writeMarker(idaDir) {
  const marker = join(RUNTIME_DIR, '.provisioned');
  writeFileSync(marker, JSON.stringify({
    schema: 2,
    platform: PLATFORM_KEY,
    runtime: basename(RUNTIME_DIR),
    idaSource: idaDir,
    timestamp: new Date().toISOString(),
  }, null, 2));
}

function dirSize(dir) {
  let total = 0;
  function walk(d) {
    for (const entry of readdirSync(d)) {
      const p = join(d, entry);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else total += st.size;
    }
  }
  if (existsSync(dir)) walk(dir);
  return total;
}

function trustMacRuntime() {
  if (platform() !== 'darwin' || plat.os !== 'mac' || !existsSync(RUNTIME_DIR)) return;
  // Archives and browser downloads can quarantine every copied dylib and
  // _ida_*.so independently. Gatekeeper may then SIGKILL Python during
  // `import idapro`, before it can produce a useful exception. This runtime
  // is built exclusively from the user's already-licensed local IDA install,
  // so clear quarantine recursively after copying the complete bundle.
  const result = spawnSync(
    'xattr', ['-dr', 'com.apple.quarantine', RUNTIME_DIR],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (result.status === 0) {
    console.log(`[macOS] Trusted portable runtime (cleared quarantine): ${RUNTIME_DIR}`);
  } else {
    const detail = result.stderr?.toString().trim();
    console.warn(`[macOS] WARNING: could not clear runtime quarantine${detail ? `: ${detail}` : ''}`);
    console.warn(`[macOS] Run: xattr -dr com.apple.quarantine "${RUNTIME_DIR}"`);
  }
}

function validateProvisionedRuntime() {
  const core = plat.os === 'windows' ? 'idalib.dll'
    : plat.os === 'mac' ? 'libidalib.dylib' : 'libidalib.so';
  const required = [
    core,
    'ida.hlp',
    join('idalib', 'python', 'idapro'),
    join('python'),
    join('license', 'idapro.hexlic'),
  ];
  if (plat.os !== 'windows') required.push(join('license', 'ida.reg'));
  return required.filter(path => !existsSync(join(RUNTIME_DIR, path)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  const force = args.includes('--force');
  const fullMode = args.includes('--full');
  let explicitIda = null;
  let targetPlatformArg = null;

  const idaIdx = args.indexOf('--ida-dir');
  if (idaIdx !== -1 && args[idaIdx + 1]) explicitIda = args[idaIdx + 1];

  const tpIdx = args.indexOf('--target-platform');
  if (tpIdx !== -1 && args[tpIdx + 1]) targetPlatformArg = args[tpIdx + 1];

  // Determine target platform (host platform by default, or --target-platform for cross-trimming)
  plat = getTargetPlatform(targetPlatformArg);
  PLATFORM_KEY = targetPlatformArg || HOST_PLATFORM_KEY;
  // Keep runtime folder names stable and identical to bridge.mjs/worker.py.
  // Architecture is implicit in the host build; cross-trimming already uses
  // the same mac/windows/linux key.
  const runtimeName = `ida-runtime-${targetPlatformArg || plat.os}`;
  RUNTIME_DIR = join(BIN_DIR, runtimeName);

  console.log('ida-skill setup');
  console.log(`  host     : ${HOST_PLATFORM_KEY}`);
  console.log(`  target   : ${targetPlatformArg || HOST_PLATFORM_KEY} (${plat.os})`);
  console.log(`  runtime  : ${RUNTIME_DIR}`);
  console.log(`  mode     : ${fullMode ? 'full (untrimmed)' : 'trimmed'}`);
  console.log('');

  // Validate runtime already exists
  const marker = join(RUNTIME_DIR, '.provisioned');
  if (existsSync(marker) && !force) {
    const missing = validateProvisionedRuntime();
    if (missing.length) {
      console.error(`ERROR: Existing runtime is incomplete: ${RUNTIME_DIR}`);
      for (const path of missing) console.error(`  missing: ${path}`);
      console.error('Re-run setup with --force to repair it.');
      process.exit(1);
    }
    // Trust approvals and licenses can change after initial provisioning.
    // Refresh the small per-user state without recopying the 200+ MB runtime.
    provisionLicense(RUNTIME_DIR);
    trustMacRuntime();
    console.log(`Runtime already provisioned -> ${RUNTIME_DIR}`);
    console.log('License/EULA state refreshed. Use --force to fully re-provision.');
    return;
  }

  // Find IDA installation
  const idaDir = findIdaDir(explicitIda);
  if (!idaDir) {
    console.error('ERROR: IDA Pro installation not found.');
    console.error('');
    console.error('Specify your IDA installation directory:');
    console.error('  node setup.mjs --ida-dir "/path/to/ida" [--target-platform windows]');
    console.error('');
    console.error('Or set the IDADIR environment variable.');
    process.exit(1);
  }

  if (!validateIdaDir(idaDir)) {
    console.error(`ERROR: ${idaDir} does not look like a valid IDA installation.`);
    console.error(`Expected (${plat.os}): ${plat.os === 'windows' ? 'ida.dll' : 'libida' + plat.libExt} + ida.hlp + ida.int`);
    process.exit(1);
  }

  console.log(`  ida dir  : ${idaDir}`);
  console.log('');

  // Wipe and recreate
  if (force || !existsSync(marker)) {
    rmSync(RUNTIME_DIR, { recursive: true, force: true });
  }
  mkdirSync(RUNTIME_DIR, { recursive: true });

  // Provision
  if (fullMode) {
    provisionComplete(idaDir);
    provisionLicense(idaDir);
    provisionDbgsrv(idaDir);
  } else {
    provisionCore(idaDir);
    provisionLicense(idaDir);
    provisionPlugins(idaDir);
    provisionProcs(idaDir);
    provisionLoaders(idaDir);
    provisionTil(idaDir);
    provisionCfg(idaDir);
    provisionPython(idaDir);
    provisionDbgsrv(idaDir);
  }

  trustMacRuntime();
  writeMarker(idaDir);

  const missing = validateProvisionedRuntime();
  if (missing.length) {
    console.error(`ERROR: Provisioned runtime is incomplete: ${missing.join(', ')}`);
    process.exit(1);
  }

  const sizeMB = Math.round(dirSize(RUNTIME_DIR) / 1048576);
  console.log('');
  console.log(`Done. Runtime size: ${sizeMB} MB`);
  console.log(`  ${RUNTIME_DIR}`);
  if (targetPlatformArg) {
    console.log('');
    console.log('NOTE: This is a cross-trimmed runtime for a different platform.');
    console.log('The runtime is at: ' + RUNTIME_DIR);
  }
  console.log('');
  console.log('Next steps:');
  console.log('  Start worker:  python3 scripts/cli.py worker start --binary /path/to/binary');
  console.log('  Query:         python3 scripts/cli.py functions --binary /path/to/binary');
  console.log('  Finalize:      python3 scripts/cli.py worker save-and-close --binary /path/to/binary');
}

main();
