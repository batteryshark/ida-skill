#!/usr/bin/env node
// setup.mjs
// Provisions a minimal portable idalib runtime from the user's licensed
// IDA Pro installation. Pure Node.js stdlib (Node >= 22). No npm deps.
//
// IDA is proprietary: copy only from the user's local installation into an
// ignored private bundle. Never modify the source installation or download IDA.
//
// CRITICAL (macOS arm64): uses `ditto` instead of `cp` to preserve
// code-signing extended attributes. Binaries copied with `cp` segfault.
//
// Run: node scripts/setup.mjs --ida-dir /path/to/ida [--include-license] [--full]
// Re-run safe: skips steps already completed.

import {
  existsSync, mkdirSync, readFileSync, writeFileSync,
  rmSync, readdirSync, statSync,
} from 'node:fs';
import { platform, arch, homedir } from 'node:os';
import { join, dirname, basename, resolve, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
const DEFAULT_BIN_DIR = join(__dirname, '..', 'bin');
let BIN_DIR = DEFAULT_BIN_DIR;

// plat and RUNTIME_DIR are set in main() based on --target-platform
let plat = null;
let RUNTIME_DIR = null;
let PLATFORM_KEY = null;

// ─────────────────────────────────────────────────────────────────────────────
// Platform detection
// ─────────────────────────────────────────────────────────────────────────────
const HOST_PLATFORM_KEY = `${platform()}-${arch()}`;
const PLATFORM_INFO = {
  'darwin-arm64': { os: 'mac', libExt: '.dylib' },
  'darwin-x64':   { os: 'mac', libExt: '.dylib' },
  'linux-x64':    { os: 'linux', libExt: '.so' },
  'linux-arm64':  { os: 'linux', libExt: '.so' },
  'win32-x64':    { os: 'windows', libExt: '.dll' },
};

// Target platform can be overridden via --target-platform for cross-trimming
// (e.g. trimming a Windows IDA from macOS).
function getTargetPlatform(targetArg) {
  if (targetArg) {
    const map = {
      'windows': { os: 'windows', libExt: '.dll' },
      'mac':     { os: 'mac', libExt: '.dylib' },
      'linux':   { os: 'linux', libExt: '.so' },
    };
    const t = map[targetArg];
    if (!t) throw new Error(`Unknown --target-platform: ${targetArg}. Use: windows, mac, linux`);
    return t;
  }
  const host = PLATFORM_INFO[HOST_PLATFORM_KEY];
  if (!host) {
    throw new Error(`Unsupported host platform: ${HOST_PLATFORM_KEY}. Use --target-platform with a readable IDA installation.`);
  }
  return host;
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

// ─────────────────────────────────────────────────────────────────────────────
// IDA installation discovery
// ─────────────────────────────────────────────────────────────────────────────

function findIdaDir(explicit) {
  if (explicit) return existsSync(explicit) ? resolveIdaDir(explicit) : null;

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
  if (basename(dir).endsWith('.app')) {
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
  return kernelNames.some(name => existsSync(join(dir, name)))
    && existsSync(join(dir, 'ida.hlp'))
    && existsSync(join(dir, 'ida.int'));
}

// ─────────────────────────────────────────────────────────────────────────────
// Copy helpers (platform-specific)
// ─────────────────────────────────────────────────────────────────────────────

// HOST_COPY_CMD: copy tool on the HOST machine (not the target platform).
// plat.libExt/os are target-specific; the copy command must run on host.
const HOST_COPY_CMD = HOST_PLATFORM_KEY.startsWith('darwin') ? 'ditto'
  : HOST_PLATFORM_KEY.startsWith('win32') ? 'robocopy' : 'cp';

function runCopy(command, args, robocopy = false) {
  const result = spawnSync(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const ok = robocopy
    ? result.status !== null && result.status >= 0 && result.status <= 7
    : result.status === 0;
  if (ok) return;
  const detail = result.error?.message || result.stderr?.toString().trim() || `exit ${result.status}`;
  throw new Error(`${command} failed: ${detail}`);
}

function copyFile(src, dest) {
  mkdirSync(dirname(dest), { recursive: true });
  if (HOST_COPY_CMD === 'ditto') {
    // ditto preserves code-signing extended attributes (CRITICAL on macOS arm64)
    runCopy('ditto', [src, dest]);
  } else if (HOST_COPY_CMD === 'robocopy') {
    // Preserve file data, attributes, and timestamps without requiring admin rights.
    runCopy('robocopy', [dirname(src), dirname(dest), basename(src), '/COPY:DAT', '/NFL', '/NDL', '/NJH', '/NJS'], true);
  } else {
    // Linux: cp -a preserves permissions and timestamps
    runCopy('cp', ['-a', src, dest]);
  }
}

function copyDir(src, dest) {
  mkdirSync(dest, { recursive: true });
  if (HOST_COPY_CMD === 'ditto') {
    runCopy('ditto', [src, dest]);
  } else if (HOST_COPY_CMD === 'robocopy') {
    runCopy('robocopy', [src, dest, '/E', '/COPY:DAT', '/NFL', '/NDL', '/NJH', '/NJS'], true);
  } else {
    runCopy('cp', ['-a', `${src}/.`, dest]);
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

function provisionLicense(idaDir, explicitLicenseDir) {
  console.log('[license] Bundling license...');
  const destDir = join(RUNTIME_DIR, 'license');
  mkdirSync(destDir, { recursive: true });

  const sourceDirs = [explicitLicenseDir, idaDir, join(homedir(), '.idapro')].filter(Boolean);
  if (process.env.APPDATA) {
    sourceDirs.push(join(process.env.APPDATA, 'Hex-Rays', 'IDA Pro'));
  }
  const uniqueDirs = [...new Set(sourceDirs.map(dir => resolve(dir)))];

  const hexlic = uniqueDirs.map(dir => join(dir, 'idapro.hexlic')).find(existsSync);
  if (!hexlic) {
    throw new Error('idapro.hexlic not found. Pass --license-dir /path/to/your/IDA/user-config directory.');
  }
  copyFile(hexlic, join(destDir, 'idapro.hexlic'));
  console.log('[license] Copied idapro.hexlic');

  // macOS/Linux keep EULA state in ida.reg. Windows applies the equivalent
  // per-user registry value when the licensed worker starts.
  if (plat.os !== 'windows') {
    const reg = uniqueDirs.map(dir => join(dir, 'ida.reg')).find(existsSync);
    if (!reg) {
      throw new Error('ida.reg not found. Start IDA once and accept its EULA, then pass --license-dir if needed.');
    }
    copyFile(reg, join(destDir, 'ida.reg'));
    console.log('[license] Copied ida.reg');
  }

  const config = uniqueDirs.map(dir => join(dir, 'ida-config.json')).find(existsSync);
  if (config) {
    copyFile(config, join(destDir, 'ida-config.json'));
    console.log('[license] Copied ida-config.json');
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
  console.log(`[dbgsrv] Copied ${count} remote debug servers to ${destDir}`);
}

function provisionComplete(idaDir, includeLicense) {
  // Copy the untrimmed product installation. Personal license/EULA state is
  // still opt-in even if it happens to live in the installation directory.
  console.log('[full] Copying entire IDA installation (untrimmed)...');
  const privateState = new Set(['idapro.hexlic', 'ida.reg', 'ida-config.json', 'license']);
  for (const entry of readdirSync(idaDir)) {
    if (!includeLicense && privateState.has(entry.toLowerCase())) continue;
    const src = join(idaDir, entry);
    if (statSync(src).isDirectory()) copyDir(src, join(RUNTIME_DIR, entry));
    else copyFile(src, join(RUNTIME_DIR, entry));
  }
}

function writeMarker(fullMode, licenseIncluded) {
  const marker = join(RUNTIME_DIR, '.provisioned');
  writeFileSync(marker, JSON.stringify({
    schema: 3,
    platform: PLATFORM_KEY,
    runtime: basename(RUNTIME_DIR),
    mode: fullMode ? 'full' : 'trimmed',
    licenseIncluded,
    timestamp: new Date().toISOString(),
  }, null, 2));
}

function isWithin(parent, child) {
  const rel = relative(resolve(parent), resolve(child));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
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

function validateProvisionedRuntime(requireLicense = false) {
  const core = plat.os === 'windows' ? 'idalib.dll'
    : plat.os === 'mac' ? 'libidalib.dylib' : 'libidalib.so';
  const required = [
    core,
    'ida.hlp',
    join('idalib', 'python', 'idapro'),
    join('python'),
  ];
  if (requireLicense) {
    required.push(join('license', 'idapro.hexlic'));
    if (plat.os !== 'windows') required.push(join('license', 'ida.reg'));
  }
  return required.filter(path => !existsSync(join(RUNTIME_DIR, path)));
}

function usage() {
  console.log(`Usage: node scripts/setup.mjs [options]

Copy a locally installed, licensed IDA Pro runtime into a private portable bundle.

Options:
  --ida-dir <path>          IDA installation or macOS .app bundle
  --target-platform <os>   mac, linux, or windows (defaults to this host)
  --bundle-dir <path>       Private payload root (default: ./bin)
  --license-dir <path>      Directory containing idapro.hexlic and ida.reg
  --include-license         Copy private license/EULA state into the bundle
  --full                    Copy the complete installation instead of trimming
  --force                   Replace the selected runtime
  --help                    Show this help

Set IDA_SKILL_BIN_DIR to the same --bundle-dir when starting the bridge.`);
}

function parseArgs(args) {
  const options = {
    force: false,
    fullMode: false,
    includeLicense: false,
    idaDir: null,
    targetPlatform: null,
    bundleDir: null,
    licenseDir: null,
    help: false,
  };
  const values = new Set(['--ida-dir', '--target-platform', '--bundle-dir', '--license-dir']);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--force') options.force = true;
    else if (arg === '--full') options.fullMode = true;
    else if (arg === '--include-license') options.includeLicense = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (values.has(arg)) {
      const value = args[++i];
      if (!value) throw new Error(`${arg} requires a value`);
      if (arg === '--ida-dir') options.idaDir = value;
      else if (arg === '--target-platform') options.targetPlatform = value;
      else if (arg === '--bundle-dir') options.bundleDir = value;
      else options.licenseDir = value;
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  return options;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    usage();
    return;
  }
  if (options.idaDir && !existsSync(options.idaDir)) {
    throw new Error(`Explicit --ida-dir does not exist: ${options.idaDir}`);
  }
  if (options.licenseDir && !existsSync(options.licenseDir)) {
    throw new Error(`Explicit --license-dir does not exist: ${options.licenseDir}`);
  }

  // Determine target platform (host platform by default, or --target-platform for cross-trimming)
  plat = getTargetPlatform(options.targetPlatform);
  PLATFORM_KEY = options.targetPlatform || HOST_PLATFORM_KEY;
  BIN_DIR = resolve(options.bundleDir || process.env.IDA_SKILL_BIN_DIR || DEFAULT_BIN_DIR);
  // Keep runtime folder names stable and identical to bridge.mjs/worker.py.
  // Architecture is implicit in the host build; cross-trimming already uses
  // the same mac/windows/linux key.
  const runtimeName = `ida-runtime-${options.targetPlatform || plat.os}`;
  RUNTIME_DIR = join(BIN_DIR, runtimeName);

  console.log('ida-skill setup');
  console.log(`  host     : ${HOST_PLATFORM_KEY}`);
  console.log(`  target   : ${options.targetPlatform || HOST_PLATFORM_KEY} (${plat.os})`);
  console.log(`  bundle   : ${BIN_DIR}`);
  console.log(`  runtime  : ${RUNTIME_DIR}`);
  console.log(`  mode     : ${options.fullMode ? 'full (untrimmed)' : 'trimmed'}`);
  console.log(`  license  : ${options.includeLicense ? 'included (private)' : 'system configuration'}`);
  console.log('');

  // Validate runtime already exists
  const marker = join(RUNTIME_DIR, '.provisioned');
  if (existsSync(marker) && !options.force) {
    let previous = {};
    try { previous = JSON.parse(readFileSync(marker, 'utf8')); } catch {}
    if (options.fullMode && previous.mode && previous.mode !== 'full') {
      throw new Error('Existing runtime is trimmed. Re-run with --full --force to replace it.');
    }
    const missing = validateProvisionedRuntime();
    if (missing.length) {
      console.error(`ERROR: Existing runtime is incomplete: ${RUNTIME_DIR}`);
      for (const path of missing) console.error(`  missing: ${path}`);
      console.error('Re-run setup with --force to repair it.');
      process.exit(1);
    }
    if (options.includeLicense) {
      const licenseIdaDir = options.idaDir ? resolveIdaDir(options.idaDir) : findIdaDir(null);
      provisionLicense(licenseIdaDir, options.licenseDir);
      const licenseMissing = validateProvisionedRuntime(true);
      if (licenseMissing.length) throw new Error(`Bundled license state is incomplete: ${licenseMissing.join(', ')}`);
    }
    trustMacRuntime();
    writeMarker(
      previous.mode === 'full',
      options.includeLicense || existsSync(join(RUNTIME_DIR, 'license', 'idapro.hexlic')),
    );
    console.log(`Runtime already provisioned -> ${RUNTIME_DIR}`);
    console.log(options.includeLicense
      ? 'License/EULA state refreshed. Use --force to fully re-provision.'
      : 'Use --include-license to add private portable license state, or --force to re-provision.');
    return;
  }

  // Find IDA installation
  const idaDir = findIdaDir(options.idaDir);
  if (!idaDir) {
    console.error('ERROR: IDA Pro installation not found.');
    console.error('');
    console.error('Specify your IDA installation directory:');
    console.error('  node scripts/setup.mjs --ida-dir "/path/to/ida" [--include-license]');
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

  if (isWithin(idaDir, RUNTIME_DIR) || isWithin(RUNTIME_DIR, idaDir)) {
    throw new Error('IDA source and runtime destination must not overlap. Choose a separate --bundle-dir.');
  }

  // Wipe and recreate
  if (options.force || !existsSync(marker)) {
    rmSync(RUNTIME_DIR, { recursive: true, force: true });
  }
  mkdirSync(RUNTIME_DIR, { recursive: true });

  // Provision
  if (options.fullMode) {
    provisionComplete(idaDir, options.includeLicense);
    if (options.includeLicense) provisionLicense(idaDir, options.licenseDir);
    provisionDbgsrv(idaDir);
  } else {
    provisionCore(idaDir);
    if (options.includeLicense) provisionLicense(idaDir, options.licenseDir);
    provisionPlugins(idaDir);
    provisionProcs(idaDir);
    provisionLoaders(idaDir);
    provisionTil(idaDir);
    provisionCfg(idaDir);
    provisionPython(idaDir);
    provisionDbgsrv(idaDir);
  }

  trustMacRuntime();
  writeMarker(options.fullMode, options.includeLicense);

  const missing = validateProvisionedRuntime(options.includeLicense);
  if (missing.length) {
    console.error(`ERROR: Provisioned runtime is incomplete: ${missing.join(', ')}`);
    process.exit(1);
  }

  const sizeMB = Math.round(dirSize(RUNTIME_DIR) / 1048576);
  console.log('');
  console.log(`Done. Runtime size: ${sizeMB} MB`);
  console.log(`  ${RUNTIME_DIR}`);
  if (options.targetPlatform) {
    console.log('');
    console.log('NOTE: This runtime uses the explicit target platform layout.');
    console.log('The runtime is at: ' + RUNTIME_DIR);
  }
  console.log('');
  if (!options.includeLicense) {
    console.log('License was not copied. The worker will use this machine\'s normal IDA configuration.');
    console.log('Re-run with --include-license for a private self-contained bundle.');
    console.log('');
  }
  console.log('Next steps:');
  console.log('  Start worker:  node scripts/bridge.mjs start --binary /path/to/binary');
  console.log('  Query:         python3 scripts/cli.py functions --binary /path/to/binary');
  console.log('  Stop:          node scripts/bridge.mjs stop --binary /path/to/binary');
}

try {
  main();
} catch (error) {
  console.error(`ERROR: ${error.message}`);
  process.exit(1);
}
