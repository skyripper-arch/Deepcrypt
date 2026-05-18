'use strict';

const { spawnSync, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const https = require('https');

const BINARY_DIR = path.join(__dirname, '..', 'binaries');

const PLATFORM_MAP = {
  win32:  { prefix: 'dpc-win',    ext: '.exe' },
  linux:  { prefix: 'dpc-linux',  ext: ''     },
  darwin: { prefix: 'dpc-darwin', ext: ''     },
  android:{ prefix: 'dpc-linux',  ext: ''     }, // Termux (node reports 'linux', but guard android too)
};

// Maps Node.js arch names → Go arch names used in binary filenames.
const ARCH_MAP = {
  x64:   'amd64',
  arm64: 'arm64',
  arm:   'arm',   // 32-bit ARM — Termux on older devices
  ia32:  '386',
};

// Detect Termux: it sets TERMUX_VERSION and its PREFIX lives under /data/data/.
function isTermux() {
  return (
    process.env.TERMUX_VERSION !== undefined ||
    (process.env.PREFIX || '').includes('com.termux')
  );
}

function resolveBinary() {
  const rawPlatform = os.platform();
  // Termux identifies itself as 'linux', but let's be explicit.
  const platform = isTermux() ? 'linux' : rawPlatform;
  const arch = os.arch();
  const plat = PLATFORM_MAP[platform];

  if (!plat) {
    fatal(`Unsupported platform: ${platform}`);
  }

  const mappedArch = ARCH_MAP[arch] || arch;
  const name = `${plat.prefix}-${mappedArch}${plat.ext}`;
  const fullPath = path.join(BINARY_DIR, name);

  if (!fs.existsSync(fullPath)) {
    const hint = isTermux()
      ? '  On Termux: pkg install nodejs && npm install -g deepcrypt'
      : '  Run build/build.ps1 (Windows) or build/build.sh (Unix) to compile.';
    fatal(
      `Binary not found: ${fullPath}\n` +
      `  Platform detected: ${platform}/${mappedArch}\n` +
      hint +
      '\n  Or run: dpc update'
    );
  }
  return fullPath;
}

// PowerShell / Termux drag-and-drop may wrap paths in quotes — strip them.
function sanitizeArg(arg) {
  if (arg.startsWith('-')) return arg;
  return arg.replace(/^["']|["']$/g, '').trim();
}

function fatal(msg) {
  process.stderr.write(`[dpc] Error: ${msg}\n`);
  process.exit(1);
}

const GITHUB_RAW_PKG =
  'https://raw.githubusercontent.com/skyripper/deepcrypt/main/package.json';

function fetchLatestVersion() {
  return new Promise((resolve, reject) => {
    const req = https.get(GITHUB_RAW_PKG, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(data).version);
        } catch {
          reject(new Error('Failed to parse remote package.json'));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
  });
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
  }
  return 0;
}

async function handleUpdate() {
  const pkg = require('../package.json');
  console.log(`[dpc] Installed version : ${pkg.version}`);
  console.log('[dpc] Checking GitHub for updates...');

  let latest;
  try {
    latest = await fetchLatestVersion();
  } catch (err) {
    console.error(`[dpc] Could not reach GitHub: ${err.message}`);
    process.exit(1);
  }

  console.log(`[dpc] Latest version    : ${latest}`);

  if (compareVersions(latest, pkg.version) <= 0) {
    console.log('[dpc] Already up to date.');
    return;
  }

  console.log(`[dpc] Updating ${pkg.version} → ${latest} ...`);
  try {
    execSync('npm install -g skyripper/deepcrypt', { stdio: 'inherit' });
    console.log('[dpc] Update complete. Run "dpc --version" to confirm.');
  } catch {
    console.error('[dpc] Update failed. Try running the command yourself:');
    console.error('      npm install -g skyripper/deepcrypt');
    process.exit(1);
  }
}

function run(args) {
  if (args[0] === 'update') {
    handleUpdate().catch((err) => {
      process.stderr.write(`[dpc] Unexpected error: ${err.message}\n`);
      process.exit(1);
    });
    return;
  }

  const binary = resolveBinary();
  const sanitized = args.map(sanitizeArg);

  const result = spawnSync(binary, sanitized, {
    stdio: 'inherit',
    windowsHide: false,
  });

  if (result.error) {
    fatal(`Engine launch failed: ${result.error.message}`);
  }
  process.exit(result.status ?? 0);
}

module.exports = { run };
