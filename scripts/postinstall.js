'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const BINARY_DIR = path.join(__dirname, '..', 'binaries');

function run() {
  if (os.platform() === 'win32') {
    console.log('[deepcrypt] Windows detected — no chmod required.');
    return;
  }

  let files;
  try {
    files = fs.readdirSync(BINARY_DIR);
  } catch {
    console.warn('[deepcrypt] Warning: binaries/ directory not found — skipping chmod.');
    return;
  }

  let count = 0;
  for (const file of files) {
    if (file === '.gitkeep' || file.endsWith('.exe')) continue;
    const p = path.join(BINARY_DIR, file);
    try {
      fs.chmodSync(p, 0o755);
      count++;
    } catch (err) {
      console.warn(`[deepcrypt] Warning: could not chmod ${file}: ${err.message}`);
    }
  }

  if (count > 0) {
    console.log(`[deepcrypt] Made ${count} binaries executable.`);
  } else {
    console.warn('[deepcrypt] No pre-built binaries found. Run build/build.sh to compile the Go engine.');
  }
}

run();
