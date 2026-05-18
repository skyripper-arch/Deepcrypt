 # Deepcrypt

  High-performance, ultra-secure file and folder encryption CLI. Built on a Go core with a Node.js install wrapper,
  deployable in seconds on Windows, Linux, macOS, and Termux (Android).

  ---

  ## Features

  - **Multi-algorithm encryption** — AES-256-GCM, ChaCha20-Poly1305, RSA-4096-OAEP, ECC Curve25519, and ML-KEM-768
  post-quantum cryptography
  - **HWID-bound keys** — derived from hardware identifiers via Argon2id, making keys machine-specific
  - **Cross-platform** — native Go binaries for Windows, Linux, macOS (x64 + ARM64), and 32-bit ARM (Termux)
  - **`.dpc` file format** — structured encrypted output with embedded algorithm metadata
  - **Base64 output** — optional `--b64` flag for text-safe encoded output
  - **Self-updating** — built-in `dpc update` command

  ---

  ## Installation universal git
git clone https://github.com/skyripper-arch/Deepcrypt
cd deepcrypt 
bash install.sh

  ### Windows

  Requires [Node.js 18+](https://nodejs.org).

  ```powershell
  npm install -g skyripper-arch/Deepcrypt

  Linux / macOS

  Requires Node.js 18+ (https://nodejs.org).

  sudo npm install -g skyripper-arch/Deepcrypt

  Termux (Android)
   cd deepcrypt
  git pull
  bash install.sh
  dpc --version

  pkg install nodejs
  npm install -g skyripper-arch/Deepcrypt

  ---
  Usage

  dpc encrypt <file>           Encrypt a file
  dpc decrypt <file>           Decrypt a .dpec file
  dpc encrypt <folder>         Encrypt an entire folder
  dpc decrypt <folder>         Decrypt an entire folder
  dpc update                   Check for updates and install the latest version

  Examples

  dpc encrypt secret.txt
  dpc decrypt secret.txt.dpec
  dpc encrypt --b64 document.pdf

  ---
  Updating

  dpc update

  This checks the latest version on GitHub, compares it to your installed version, and upgrades automatically if a newer
   release is available.

  You can also reinstall manually:

  # Windows
  npm install -g skyripper-arch/Deepcrypt

  # Linux / macOS
  sudo npm install -g skyripper-arch/Deepcrypt

  ---
  How It Works

  Deepcrypt ships precompiled Go binaries for each platform inside the npm package. The Node.js wrapper (dpc) detects
  your OS and architecture, picks the correct binary, and passes your arguments straight through — no compilation
  required on your machine.

  Encryption keys are derived using Argon2id from a combination of hardware identifiers (CPU ID, machine GUID, etc.),
  network info, and a CSPRNG seed. This means an encrypted file is bound to the machine it was encrypted on unless the
  key file is explicitly exported.

  Encrypted files use the .dpec format — a binary container with a 4-byte DPEC magic header, algorithm ID, nonce, and
  payload.

  ---
  Supported Platforms

  ┌─────────┬─────┬───────┬──────────────┐
  │   OS    │ x64 │ ARM64 │ ARM (32-bit) │
  ├─────────┼─────┼───────┼──────────────┤
  │ Windows │ ✅  │ ✅    │ —            │
  ├─────────┼─────┼───────┼──────────────┤
  │ Linux   │ ✅  │ ✅    │ ✅           │
  ├─────────┼─────┼───────┼──────────────┤
  │ macOS   │ ✅  │ ✅    │ —            │
  ├─────────┼─────┼───────┼──────────────┤
  │ Termux  │ ✅  │ ✅    │ ✅           │
  └─────────┴─────┴───────┴──────────────┘

  ---
  License

  Apache 2.0 — see LICENSE for details.
