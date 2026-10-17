# 🔐 enCPTO — Military-Grade Dual-Layer Encryption Tool

**Repo:** [nil-coder-sudo/enCPTO](https://github.com/nil-coder-sudo/enCPTO) · **Script:** [`enCPTO-v7.py`](https://github.com/nil-coder-sudo/enCPTO/blob/main/enCPTO-v7.py)

**enCPTO** is a desktop file & folder encryption application built with Python and PyQt6. It cascades two independent ciphers — **AES-256-CTR** and **XChaCha20-Poly1305** — under keys derived with **Argon2id + HKDF-SHA512**, seals the whole container with **HMAC-SHA512**, and offers optional GPU (OpenCL) acceleration, all in a single, self-contained, offline tool.

No cloud, no telemetry, no accounts. Your key never leaves your machine.

> **v7.0** removes the PIN / TOTP / recovery-code layer — the encryption password is now the only thing you need — and introduces the stronger **V7 container format**. Files made by v6.x and earlier still decrypt.

---

## ✨ Features

### 🔒 Cryptography (V7 format)
- **Argon2id** key derivation, raised to `t=4, m=256 MiB, p=4` with a **32-byte salt**; the parameters are stored in each file's header so they can be raised again later without breaking old files
- **HKDF-SHA512** splits the Argon2id output into independent sub-keys for each layer — no key is ever used for two purposes
- **Dual-layer cascade:** layer 1 **AES-256-CTR** (from-scratch OpenCL kernel on GPU, or CPU) → layer 2 **XChaCha20-Poly1305**. Reading your data means breaking *both* AES and ChaCha20
- Every 4 MiB chunk is authenticated and bound to the header, its index and a "final chunk" flag — chunks can't be reordered, dropped, truncated or spliced in from another file
- **HMAC-SHA512** over the header, metadata and every chunk; the whole file is verified before a single byte of plaintext is written
- **Encrypted metadata:** the original filename and file/folder type are encrypted and padded to a fixed size — nothing about the contents is visible without the password
- Wrong passwords are rejected in under a second (metadata check) before the full integrity pass
- Best-effort **secure memory wiping** of keys (`ctypes` + `mmap`) as soon as they're no longer needed

### 📦 File Handling
- Encrypt single files **or entire folders** (folders are streamed into a ZIP archive in memory before encryption, never written unencrypted to disk)
- Decrypt into a folder of your choice — the original name is restored automatically, and existing files are never overwritten (`name (1).ext`)
- Backward-compatible decryption of older containers (V1 / V2 / V3 / V4 / V6)
- Built-in **DoD 5220.22-M**–style 3-pass secure shredder to destroy source files/folders after encryption
- Drag-and-drop, with live preview for images, text, and encrypted-container info

### 🎨 Interface
- Bilingual UI (繁體中文 / English) with a single toggle
- Six themes: **Dark, Light, System, Auto, Army Green, Deep Hacker**
- Custom background image support with independent **background opacity** and **widget opacity** sliders
- Built-in **strong password generator** (configurable length, character sets, ambiguous-character exclusion)
- Non-blocking background worker thread with live progress reporting

---

## 🧱 Architecture at a Glance

```
Password ──► Argon2id (t=4, m=256 MiB, p=4, 32-byte salt) ──► 64-byte master
master   ──► HKDF-SHA512 (salt = SHA-512(header))
               ├── k_aes  (32 B)  layer 1  AES-256-CTR
               ├── k_xcc  (32 B)  layer 2  XChaCha20-Poly1305
               └── k_mac  (64 B)  HMAC-SHA512

Plaintext chunk i ──► AES-256-CTR(k_aes) ──► XChaCha20-Poly1305(k_xcc, AAD = header hash ‖ i ‖ final)
All chunks + header + metadata ──► HMAC-SHA512(k_mac) ──► V7 container (.dat)
```

**V7 container layout:**

| Field              | Size        | Description                                              |
|--------------------|-------------|----------------------------------------------------------|
| Magic              | 8 bytes     | `ENCPTO7\0`                                              |
| KDF id             | 1 byte      | `0x01` = Argon2id                                        |
| Argon2 t / m / p   | 4 + 4 + 1   | Time cost, memory (KiB), parallelism                     |
| Salt               | 32 bytes    |                                                          |
| AES IV prefix      | 8 bytes     | + 32-bit chunk index + 32-bit block counter              |
| XChaCha nonce prefix | 16 bytes  | + 64-bit chunk index                                     |
| Encrypted metadata | 528 bytes   | Flags, original filename, size — padded, then AEAD-sealed |
| Ciphertext chunks  | variable    | `ct (≤ 4 MiB) + 16-byte Poly1305 tag` per chunk          |
| HMAC-SHA512        | 64 bytes    | Over everything above                                    |

The header is public but authenticated: changing any byte (including the Argon2 parameters) changes the derived keys and fails verification. Absurd KDF parameters in an untrusted header are refused before any work is done.

---

## 📥 Installation

### Requirements
- Python 3.10+
- A GPU + OpenCL runtime is **optional** — the app falls back to a CPU implementation automatically
- About 256 MB of free RAM while encrypting/decrypting (Argon2id)

### Install dependencies

```bash
pip install PyQt6 pycryptodome argon2-cffi
```

Optional, for GPU acceleration:

```bash
pip install pyopencl numpy
```

### Download

```bash
curl -L -o enCPTO-v7.py https://raw.githubusercontent.com/nil-coder-sudo/enCPTO/main/enCPTO-v7.py
```

Or clone the repository:

```bash
git clone https://github.com/nil-coder-sudo/enCPTO.git
cd enCPTO
```

### Run

```bash
python enCPTO-v7.py
```

The app opens straight to the main window — there is no PIN, authenticator app or setup wizard.

---

## 🚀 Usage

1. **Select a file or folder** — via the buttons or by dragging it onto the window
2. **Enter a strong encryption key** — the app enforces length ≥ 8 and at least 3 of {uppercase, lowercase, digits, symbols}, or generate one in **Settings → Password Generator**
3. *(Optional)* Enable **secure shredding** to destroy the original after encryption
4. Click **Encrypt** and choose where to save the `.dat` file
5. To decrypt, select the `.dat` file, enter the key, click **Decrypt** and pick an output folder — the original file or folder is restored there under its original name

> ⚠️ The password is now the **only** key. There is no password recovery: if you forget it, the data is unrecoverable by design. Store it in a password manager.

### Upgrading from v6.x
- Your existing `.dat` files keep working — just open them in v7.
- New encryptions always use the V7 format, which v6.x cannot read.
- The old MFA settings file `~/.encpto/security.cfg` is no longer used; you can delete it.

---

## 🗂️ Project Structure

This is a single-file application (`enCPTO-v7.py`) organized into clearly separated sections:

- Secure memory helpers
- AES-256 key expansion + OpenCL kernel + `GpuManager`
- V7 primitives (header, Argon2id + HKDF, metadata) and the streaming encryption/decryption engine
- Legacy V1–V6 decryption
- Directory packing / secure shredding
- Password generator
- PyQt6 UI: themes, settings panel, main window

---

## 🔧 Configuration Files

enCPTO stores local state under `~/.encpto/`:

| File            | Contents                                       |
|-----------------|------------------------------------------------|
| `ui_prefs.cfg`  | Theme, background image path, opacity settings |

It is local-only and never transmitted anywhere.

---

## ⚠️ Security Notes & Disclaimer

- The GPU path uses a hand-written OpenCL AES-256 kernel (validated against PyCryptodome at start-up); the CPU path and XChaCha20-Poly1305 / HMAC layers use PyCryptodome. The project has **not** undergone a formal third-party security audit or side-channel analysis. For high-stakes/regulated use cases, prefer audited, widely-reviewed tools.
- Encryption strength is bounded by your password. Use a long, random one (the built-in generator is a good start).
- Secure shredding overwrites files before deletion but cannot guarantee data is unrecoverable on SSDs, journaling filesystems, or systems with wear-leveling/snapshots.
- Use at your own risk. Always keep independent backups of anything important.

---

## 🤝 Contributing

Issues and pull requests are welcome — particularly around:
- Cross-platform testing (Windows / macOS / Linux)
- Additional language localizations
- Security review and hardening
- Packaging into standalone binaries (PyInstaller / Nuitka)

---

## 📄 License

See [LICENSE](LICENSE).

---

## 🙏 Acknowledgements

Built with [PyQt6](https://www.riverbankcomputing.com/software/pyqt/), [PyCryptodome](https://www.pycryptodome.org/), [argon2-cffi](https://github.com/hynek/argon2-cffi), and [PyOpenCL](https://documen.tician.de/pyopencl/).
