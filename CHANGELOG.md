# Changelog

## 8.0.0

A native C++ rewrite. Containers stay in the V7 format: files made by v7.0 open in 8.0 and vice versa.

### New
- Native apps for Windows, macOS and Linux, built and packaged by GitHub Actions — no Python or pip needed.
- `encpto-cli` command-line tool (`encrypt`, `decrypt`, `info`, `genpass`).
- Redesigned interface: drop zone with previews, a single clear action (switches to Decrypt for containers),
  live progress with speed and Cancel, results shown inline with "Show in folder".
- Password generator page; the clipboard is cleared 30 seconds after copying.
- Thread-count setting.

### Faster
- Chunks are encrypted and decrypted on all CPU cores; HMAC-SHA512 and disk writes run alongside.
- Folders are compressed in parallel (libdeflate); photos, video and archives are stored without recompressing.
- About 1.6–2.5× faster on a 2-core machine, more on machines with more cores.

### Safer
- Output is written to a temporary file and renamed only on success; cancelling or failing leaves nothing behind.
- Keys live in locked, guard-paged memory; plaintext buffers are wiped.
- Empty folders survive a folder round-trip.
- Shredded files are renamed before deletion so their names don't linger in the directory.

### Changed
- The OpenCL GPU path is gone: AES-NI on the CPU is faster than copying chunks to a GPU and back.
- V1–V6 containers are no longer read; decrypt them once with `legacy/enCPTO-v7.py`.
- The Python app moved to `legacy/`.

## 7.0.0
- Removed PIN / TOTP / recovery codes; the password is the only key.
- V7 container: Argon2id (t=4, 256 MiB, p=4) + HKDF-SHA512, AES-256-CTR ⊕ XChaCha20-Poly1305, HMAC-SHA512, encrypted file names.
