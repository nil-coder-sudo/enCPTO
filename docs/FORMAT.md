# enCPTO V7 container format

Used by enCPTO v7.0 (Python) and v8.x (C++). All integers are big-endian.
Reference implementations: [`src/core/format.cpp`](../src/core/format.cpp) (C++),
[`tests/compat/v7_reference.py`](../tests/compat/v7_reference.py) (Python).

## Key derivation

```
master  = Argon2id v1.3(password_utf8, salt, t, m_kib, p, length = 64)
okm     = HKDF-SHA512(ikm = master, salt = SHA-512(header), info = "enCPTO-v7 subkeys", L = 128)

k_aes = okm[0:32]     layer 1: AES-256-CTR
k_xcc = okm[32:64]    layer 2: XChaCha20-Poly1305 (IETF)
k_mac = okm[64:128]   HMAC-SHA512 over the whole container
```

Because the HKDF salt is the hash of the entire header, changing any header byte —
including the Argon2 parameters — yields different keys and authentication fails.

## Layout

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | magic `ENCPTO7\0` |
| 8 | 1 | KDF id, `0x01` = Argon2id |
| 9 | 4 | Argon2 time cost `t` |
| 13 | 4 | Argon2 memory `m` in KiB |
| 17 | 1 | Argon2 parallelism `p` |
| 18 | 32 | salt |
| 50 | 8 | AES IV prefix |
| 58 | 16 | XChaCha20 nonce prefix |
| 74 | 528 | metadata: 512 bytes ciphertext + 16-byte Poly1305 tag |
| 602 | … | chunks: `ciphertext (≤ 4 MiB) ‖ tag (16)`, at least one |
| end − 64 | 64 | HMAC-SHA512(k_mac, everything before it) |

Readers must reject headers with `t ∉ [1, 64]`, `p ∉ [1, 64]`, `m ∉ [65536, 4 GiB]` or `m < 8·p`
before doing any work (denial-of-service protection).

## Metadata block

Plaintext (512 bytes, zero padded):

```
version (1) = 1 ‖ flags (1) ‖ name_len (2) ‖ name (UTF-8, ≤ 255) ‖ payload_size (8) ‖ zeros
```

`flags`: `0x00` single file, `0x01` folder (payload is a ZIP whose entries start with `<folder name>/`).

Sealed with XChaCha20-Poly1305 under `k_xcc`:
nonce = `xcc_prefix ‖ 0xFFFFFFFFFFFFFFFF`, AAD = `SHA-512(header) ‖ "meta"`.

## Chunks

The payload is split into 4 MiB chunks (an empty payload is one empty chunk). For chunk `i`:

```
s1  = AES-256-CTR(k_aes, counter block = aes_prefix ‖ uint32(i) ‖ uint32(0))  XOR  plaintext
ct, tag = XChaCha20-Poly1305(k_xcc, nonce = xcc_prefix ‖ uint64(i),
                             AAD = SHA-512(header) ‖ uint64(i) ‖ uint8(final))
```

`final` is 1 for the last chunk only, so chunks cannot be reordered, dropped, truncated or
spliced from another file. The chunk index must stay below 2³² − 1.

## Decryption order

1. Parse and sanity-check the header; derive keys.
2. Open the metadata block (wrong password fails here, in well under a second).
3. Verify the HMAC over the whole file. **No plaintext may be written before this succeeds.**
4. Open every chunk (each tag verified), undo AES-CTR, check the total equals `payload_size`.
