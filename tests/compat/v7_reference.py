#!/usr/bin/env python3
"""
Independent Python reference implementation of the enCPTO V7 container.

It mirrors the engine of legacy/enCPTO-v7.py (PyCryptodome + argon2-cffi)
without any GUI dependency, so CI can prove that the C++ build and the
original Python tool read and write byte-compatible files.

    python v7_reference.py encrypt <file|folder> <out.dat> <password>
    python v7_reference.py decrypt <in.dat> <out_dir> <password>

Requires:  pip install pycryptodome argon2-cffi
"""
import hashlib
import hmac
import io
import os
import struct
import sys
import zipfile

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes

MAGIC = b"ENCPTO7\x00"
HEADER_FMT = ">8sBIIB"
HEADER_SIZE = struct.calcsize(HEADER_FMT) + 32 + 8 + 16      # 74
META_PLAIN, TAG, MAC = 512, 16, 64
META_SIZE = META_PLAIN + TAG
META_INDEX = 0xFFFFFFFFFFFFFFFF
CHUNK = 4 * 1024 * 1024
FLAG_FILE, FLAG_ZIP = 0, 1
T, M_KIB, P = 4, 256 * 1024, 4


def _keys(pwd: bytes, hdr: bytes):
    _, _, t, m, p = struct.unpack(HEADER_FMT, hdr[:18])
    salt = hdr[18:50]
    master = hash_secret_raw(pwd, salt, time_cost=t, memory_cost=m, parallelism=p,
                             hash_len=64, type=Type.ID)
    okm = b"".join(HKDF(master, 32, hashlib.sha512(hdr).digest(), SHA512,
                        num_keys=4, context=b"enCPTO-v7 subkeys"))
    return okm[0:32], okm[32:64], okm[64:128]


def _xnonce(prefix: bytes, idx: int) -> bytes:
    return prefix + struct.pack(">Q", idx)


def _aad(hh: bytes, idx: int, final: bool) -> bytes:
    return hh + struct.pack(">QB", idx, 1 if final else 0)


def encrypt_bytes(data: bytes, name: str, flags: int, pwd: bytes,
                  salt=None, aes_prefix=None, xcc_prefix=None) -> bytes:
    salt = salt or get_random_bytes(32)
    aes_prefix = aes_prefix or get_random_bytes(8)
    xcc_prefix = xcc_prefix or get_random_bytes(16)
    hdr = struct.pack(HEADER_FMT, MAGIC, 1, T, M_KIB, P) + salt + aes_prefix + xcc_prefix
    hh = hashlib.sha512(hdr).digest()
    k_aes, k_xcc, k_mac = _keys(pwd, hdr)

    nb = name.encode("utf-8")[:255].decode("utf-8", "ignore").encode("utf-8")
    meta = struct.pack(">BBH", 1, flags, len(nb)) + nb + struct.pack(">Q", len(data))
    meta += b"\x00" * (META_PLAIN - len(meta))
    c = ChaCha20_Poly1305.new(key=k_xcc, nonce=_xnonce(xcc_prefix, META_INDEX))
    c.update(hh + b"meta")
    ct, tag = c.encrypt_and_digest(meta)
    out = bytearray(hdr + ct + tag)

    chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
    for idx, chunk in enumerate(chunks):
        final = idx == len(chunks) - 1
        s1 = AES.new(k_aes, AES.MODE_CTR, nonce=aes_prefix + struct.pack(">I", idx),
                     initial_value=0).encrypt(chunk)
        c = ChaCha20_Poly1305.new(key=k_xcc, nonce=_xnonce(xcc_prefix, idx))
        c.update(_aad(hh, idx, final))
        ct, tag = c.encrypt_and_digest(s1)
        out += ct + tag
    out += hmac.new(k_mac, bytes(out), hashlib.sha512).digest()
    return bytes(out)


def decrypt_bytes(blob: bytes, pwd: bytes):
    """Returns (flags, name, plaintext)."""
    hdr, meta_blob = blob[:HEADER_SIZE], blob[HEADER_SIZE:HEADER_SIZE + META_SIZE]
    if hdr[:8] != MAGIC:
        raise ValueError("not a V7 container")
    hh = hashlib.sha512(hdr).digest()
    aes_prefix, xcc_prefix = hdr[50:58], hdr[58:74]
    k_aes, k_xcc, k_mac = _keys(pwd, hdr)

    c = ChaCha20_Poly1305.new(key=k_xcc, nonce=_xnonce(xcc_prefix, META_INDEX))
    c.update(hh + b"meta")
    meta = c.decrypt_and_verify(meta_blob[:-TAG], meta_blob[-TAG:])
    if not hmac.compare_digest(hmac.new(k_mac, blob[:-MAC], hashlib.sha512).digest(), blob[-MAC:]):
        raise ValueError("HMAC mismatch")
    _, flags, nlen = struct.unpack(">BBH", meta[:4])
    name = meta[4:4 + nlen].decode("utf-8", "replace")
    size = struct.unpack(">Q", meta[4 + nlen:12 + nlen])[0]

    body = blob[HEADER_SIZE + META_SIZE:-MAC]
    out, idx, pos = bytearray(), 0, 0
    while pos < len(body):
        n = min(CHUNK + TAG, len(body) - pos)
        piece = body[pos:pos + n]
        pos += n
        c = ChaCha20_Poly1305.new(key=k_xcc, nonce=_xnonce(xcc_prefix, idx))
        c.update(_aad(hh, idx, pos == len(body)))
        s1 = c.decrypt_and_verify(piece[:-TAG], piece[-TAG:])
        out += AES.new(k_aes, AES.MODE_CTR, nonce=aes_prefix + struct.pack(">I", idx),
                       initial_value=0).encrypt(s1)
        idx += 1
    if len(out) != size:
        raise ValueError("size mismatch")
    return flags, name, bytes(out)


def _zip_dir(path: str) -> bytes:
    buf = io.BytesIO()
    base = os.path.dirname(os.path.abspath(path))
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for f in sorted(files):
                fp = os.path.join(root, f)
                zf.write(fp, os.path.relpath(fp, base))
    return buf.getvalue()


def main(argv):
    if len(argv) != 5 or argv[1] not in ("encrypt", "decrypt"):
        print(__doc__)
        return 2
    cmd, src, dst, pwd = argv[1], argv[2], argv[3], argv[4].encode("utf-8")
    if cmd == "encrypt":
        src = src.rstrip("/\\")
        if os.path.isdir(src):
            data, flags = _zip_dir(src), FLAG_ZIP
        else:
            with open(src, "rb") as f:
                data, flags = f.read(), FLAG_FILE
        with open(dst, "wb") as f:
            f.write(encrypt_bytes(data, os.path.basename(src), flags, pwd))
    else:
        with open(src, "rb") as f:
            flags, name, data = decrypt_bytes(f.read(), pwd)
        os.makedirs(dst, exist_ok=True)
        if flags == FLAG_ZIP:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(dst)
        else:
            with open(os.path.join(dst, os.path.basename(name)), "wb") as f:
                f.write(data)
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
