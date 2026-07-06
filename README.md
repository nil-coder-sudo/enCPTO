# 🔐 enCPTO — Military-Grade Dual-Layer Encryption Tool

**Repo:** [nil-coder-sudo/enCPTO](https://github.com/nil-coder-sudo/enCPTO) · **Script:** [`enCPTO-v6-2.py`](https://github.com/nil-coder-sudo/enCPTO/blob/main/enCPTO-v6-2.py)

**enCPTO** is a desktop file & folder encryption application built with Python and PyQt6. It combines a from-scratch AES-256 implementation, Argon2id key derivation, HMAC-SHA256 integrity verification, TOTP-based multi-factor authentication, and optional GPU (OpenCL) acceleration into a single, self-contained, offline tool.

No cloud, no telemetry, no accounts. Your key never leaves your machine.

> **v6.2** adds a dedicated Settings panel, a live background-transparency slider, and per-widget opacity control — on top of the v6 security core (PIN + TOTP + recovery codes) and v6.1 theming system.

---

## ✨ Features

### 🔒 Cryptography
- **AES-256**, implemented from scratch (custom S-box, key schedule, and round functions) — both a pure-Python/NumPy CPU path and a hand-written **OpenCL kernel** for GPU acceleration
- **Argon2id** key derivation (`t=3, m=64MB, p=4`) for file passwords, with a lighter Argon2id profile for the local PIN
- **AES-256-CTR** (GPU-accelerated path) or **AES-256-GCM** (CPU path) for bulk data encryption
- **HMAC-SHA256** integrity tag covers the header *and* every ciphertext chunk — tampering or a wrong password is always detected before any plaintext is written to disk
- Chunked streaming pipeline (4 MB blocks) so multi-gigabyte files never need to fit in RAM
- Best-effort **secure memory wiping** of keys (`ctypes` + `mmap`) as soon as they're no longer needed

### 🛡️ Multi-Factor Authentication
- First-run **Setup Wizard**: PIN creation → TOTP secret + QR code (Google Authenticator / Authy compatible) → one-time-display **recovery codes**
- App-unlock **PIN gate** with attempt limiting and timed lockout
- **TOTP confirmation** required before every encrypt/decrypt operation
- Single-use **recovery codes** as a TOTP fallback
- MFA state is itself stored in an AES-256-GCM–encrypted config file, keyed to a machine-derived secret

### 📦 File Handling
- Encrypt single files **or entire folders** (folders are streamed into a ZIP archive before encryption, with no full folder ever written unencrypted to disk)
- Original filename is embedded in the encrypted container and restored automatically on decrypt
- Backward-compatible decryption of older container versions (V2 / V3 / V4 / V6)
- Built-in **DoD 5220.22-M**–style 3-pass secure shredder to destroy source files/folders after encryption
- Drag-and-drop, with live preview for images, text, and encrypted-container metadata

### 🎨 Interface
- Bilingual UI (繁體中文 / English) with a single toggle
- Six themes: **Dark, Light, System, Auto, Army Green, Deep Hacker**
- Custom background image support with independent **background opacity** and **widget opacity** sliders
- Built-in **strong password generator** (configurable length, character sets, ambiguous-character exclusion)
- Non-blocking background worker thread with live progress reporting

---

## 🧱 Architecture at a Glance

```
Password ──► Argon2id (t=3, m=64MB, p=4) ──► 64-byte key material
                                               ├── AES-256 key   (bytes 0–32)
                                               └── HMAC-SHA256 key (bytes 32–64)

Plaintext ──► [chunk 1][chunk 2]...[chunk N] ──► AES-256-CTR (GPU) or AES-256-GCM (CPU)
                                               └──► HMAC-SHA256 over header + all ciphertext
                                                    └──► V6 container (.dat)
```

**V6 container layout:**

| Field           | Size            | Description                          |
|-----------------|-----------------|---------------------------------------|
| Magic           | 8 bytes         | `ENCPTO6\0`                            |
| Mode            | 1 byte          | `0x01` CTR (GPU) / `0x02` GCM (CPU)    |
| Flags           | 1 byte          | `0x00` single file / `0x01` ZIP folder |
| Name length     | 2 bytes         | Length of embedded original filename   |
| Original name   | variable        | UTF-8 filename, restored on decrypt    |
| Argon2 salt     | 16 bytes        |                                        |
| Base nonce      | 12 bytes        |                                        |
| HMAC-SHA256     | 32 bytes        | Over header + full ciphertext          |
| Ciphertext      | remainder       | 4 MB chunks, each independently nonced |

Decryption re-derives the key, verifies the HMAC over the *entire* file before writing a single byte of plaintext, and only then decrypts — so a wrong password or a corrupted/tampered file fails safely.

---

## 📥 Installation

### Requirements
- Python 3.10+
- A GPU + OpenCL runtime is **optional** — the app falls back to a CPU implementation automatically

### Install dependencies

```bash
pip install PyQt6 pycryptodome argon2-cffi pyotp qrcode[pil] Pillow
```

Optional, for GPU acceleration:

```bash
pip install pyopencl numpy
```

### Download

```bash
curl -L -o enCPTO-v6-2.py https://raw.githubusercontent.com/nil-coder-sudo/enCPTO/main/enCPTO-v6-2.py
```

Or clone the repository:

```bash
git clone https://github.com/nil-coder-sudo/enCPTO.git
cd enCPTO
```

### Run

```bash
python enCPTO-v6-2.py
```

On first launch you'll be guided through the **Security Setup Wizard**: choose a PIN, scan the generated QR code into an authenticator app, and save your one-time recovery codes somewhere safe. From then on, every launch starts with a PIN prompt, and every encrypt/decrypt action requires a TOTP code.

---

## 🚀 Usage

1. **Select a file or folder** — via the buttons or by dragging it onto the window
2. **Enter a strong encryption key** — the app enforces length ≥ 8 and at least 3 of {uppercase, lowercase, digits, symbols}, or generate one in **Settings → Password Generator**
3. *(Optional)* Enable **secure shredding** to destroy the original after encryption
4. Click **Encrypt** or **Decrypt**, confirm with your TOTP code, and choose where to save the output
5. Adjust **theme, background, and opacity** any time from the Settings tab

> ⚠️ There is no password recovery for encrypted files. If you forget the encryption key, the data is unrecoverable by design — that's what "military-grade" means. (This is separate from the app's own PIN/TOTP lock, which *does* have recovery codes.)

---

## 🗂️ Project Structure

This is currently a single-file application (`enCPTO-v6-2.py`) organized into clearly separated sections:

- Secure memory helpers
- AES-256 key expansion + OpenCL kernel + `GpuManager`
- Core streaming encryption/decryption engine (V2–V6 formats)
- Directory packing / secure shredding
- `SecurityManager` (PIN, TOTP, recovery codes, encrypted config)
- Password generator
- PyQt6 UI: themes, settings panel, dialogs, main window

---

## 🔧 Configuration Files

enCPTO stores local state under `~/.encpto/`:

| File              | Contents                                                        |
|-------------------|------------------------------------------------------------------|
| `security.cfg`    | AES-256-GCM–encrypted PIN hash, TOTP secret, recovery code hashes |
| `ui_prefs.cfg`     | Theme, background image path, opacity settings                   |

Both are local-only and never transmitted anywhere.

---

## ⚠️ Security Notes & Disclaimer

- This project implements its own AES-256 (including a hand-written OpenCL kernel) for educational and performance purposes. It has **not** undergone formal third-party security audit or side-channel analysis. For high-stakes/regulated use cases, prefer audited, widely-reviewed cryptographic libraries.
- Losing your encryption password **and** your MFA recovery codes at the same time means permanent data/access loss — there is no backdoor.
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

Specify your chosen license here (e.g., MIT, Apache-2.0, GPL-3.0).

---

## 🙏 Acknowledgements

Built with [PyQt6](https://www.riverbankcomputing.com/software/pyqt/), [PyCryptodome](https://www.pycryptodome.org/), [argon2-cffi](https://github.com/hynek/argon2-cffi), [PyOTP](https://github.com/pyauth/pyotp), and [PyOpenCL](https://documen.tician.de/pyopencl/).
