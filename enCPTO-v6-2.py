#!/usr/bin/env python3
"""
enCPTO v6.2 — AES-256 + SHA-256 HMAC + OpenCL GPU Booster + MFA + Themes + Settings Panel
═══════════════════════════════════════════════════════════════════════════════════════════
升級摘要 (v6.1 → v6.2):
  ① [NEW] 獨立設定頁面 (Settings Panel)
  ② [NEW] 透明度滑桿控制背景可見度 (0%=背景完全可見, 100%=純主題色)
  ③ [NEW] 元件不透明度控制 (0%=完全透明, 100%=完全不透明)
  ④ [FIX] 所有子 widget 使用 rgba 半透明背景，讓背景圖片/顏色透出

繼承自 v6.1:
  ① 自定義背景圖片 (Custom Background Image)
  ② 六種主題 (Dark / Light / System / Auto / Army Green / Deep Hacker)

繼承自 v6:
  ① 原始檔名自動嵌入加密檔 (V6 Header)
  ② PIN 碼鎖定 + TOTP 驗證 + 緊急救援碼
  ③ 資料夾批量加密 (Directory Archive Mode)
  ④ DoD 5220.22-M 安全粉碎機
  ⑤ Argon2id + AES-256-CTR/GCM + HMAC-SHA256
  ⑥ GPU OpenCL 加速

Install:
  pip install pyopencl numpy argon2-cffi pycryptodome PyQt6 pyotp qrcode[pil] Pillow
"""

import sys, os, re, struct, hashlib, ctypes, mmap, secrets, string, io, zipfile, shutil
import json, time, base64, tempfile
import hmac as hmac_mod
from typing import Iterator

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox,
    QCheckBox, QStatusBar, QStackedWidget, QTextEdit, QGroupBox,
    QProgressBar, QSlider, QDialog, QDialogButtonBox, QFrame,
    QScrollArea, QComboBox, QTabWidget, QSizePolicy, QSpacerItem,
)
from PyQt6.QtGui import (
    QPixmap, QFont, QDragEnterEvent, QDropEvent, QImage,
    QPalette, QColor, QPainter, QBrush,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QTime

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False

try:
    import pyotp
    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False

try:
    import qrcode
    from PIL import Image as PILImage
    _QRCODE_AVAILABLE = True
except ImportError:
    _QRCODE_AVAILABLE = False


# ═══════════════════════════════════════════════════════════
#  Secure memory helpers
# ═══════════════════════════════════════════════════════════

def _secure_zero_bytes(buf: bytes) -> None:
    try:
        size = len(buf)
        if size == 0:
            return
        data_ptr = ctypes.cast(
            id(buf) + (ctypes.sizeof(ctypes.c_ssize_t) * 4 + ctypes.sizeof(ctypes.c_int)),
            ctypes.POINTER(ctypes.c_char)
        )
        ctypes.memset(data_ptr, 0, size)
    except Exception:
        pass


def _secure_zero_bytearray(ba: bytearray) -> None:
    try:
        if len(ba) == 0:
            return
        ptr = (ctypes.c_char * len(ba)).from_buffer(ba)
        ctypes.memset(ptr, 0, len(ba))
    except Exception:
        ba[:] = b'\x00' * len(ba)


class _SecureKey:
    def __init__(self, key_bytes: bytes):
        self._len = len(key_bytes)
        self._mm = None
        try:
            self._mm = mmap.mmap(-1, max(self._len, mmap.PAGESIZE))
            self._mm.write(key_bytes)
            self._mm.seek(0)
            self.buf = memoryview(self._mm)[:self._len].cast('B')
        except Exception:
            self.buf = bytearray(key_bytes)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._wipe()

    def _wipe(self):
        try:
            if self._mm is not None:
                self._mm.seek(0)
                self._mm.write(b'\x00' * self._len)
                self._mm.close()
                self._mm = None
            elif isinstance(self.buf, bytearray):
                _secure_zero_bytearray(self.buf)
        except Exception:
            pass

    def slice(self, start: int, stop: int) -> bytes:
        return bytes(self.buf[start:stop])


# ═══════════════════════════════════════════════════════════
#  AES-256 Key Expansion
# ═══════════════════════════════════════════════════════════
_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _sw(w):
    return ((_SBOX[(w>>24)&0xff]<<24)|(_SBOX[(w>>16)&0xff]<<16)|
            (_SBOX[(w>>8) &0xff]<< 8)| _SBOX[w      &0xff])

def _rw(w): return ((w<<8)&0xffffffff)|(w>>24)

def aes256_expand(key: bytes) -> bytes:
    ks = [int.from_bytes(key[4*i:4*i+4],'big') for i in range(8)]
    for i in range(8, 60):
        t = ks[i-1]
        if   i%8 == 0: t = (_sw(_rw(t))^(_RCON[i//8]<<24)) & 0xffffffff
        elif i%8 == 4: t = _sw(t)
        ks.append((ks[i-8]^t) & 0xffffffff)
    return b''.join(w.to_bytes(4,'big') for w in ks)

def cpu_ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    ecb = AES.new(key, AES.MODE_ECB)
    nb  = (len(data)+15)//16
    blks = b''.join(nonce + struct.pack('>I', i) for i in range(nb))
    ks   = ecb.encrypt(blks)[:len(data)]
    try:
        import numpy as np
        return (np.frombuffer(data,np.uint8)^np.frombuffer(ks,np.uint8)).tobytes()
    except ImportError:
        return bytes(a^b for a,b in zip(data,ks))


# ═══════════════════════════════════════════════════════════
#  OpenCL AES-256-CTR Kernel
# ═══════════════════════════════════════════════════════════
_CL_KERNEL = r"""
__constant uchar SB[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
uchar xt(uchar x){return(x<<1)^((x&0x80)?0x1b:0);}
void aes_sub(uchar s[16]){for(int i=0;i<16;i++)s[i]=SB[s[i]];}
void aes_shr(uchar s[16]){
    uchar t;
    t=s[1];s[1]=s[5];s[5]=s[9];s[9]=s[13];s[13]=t;
    t=s[2];s[2]=s[10];s[10]=t; t=s[6];s[6]=s[14];s[14]=t;
    t=s[15];s[15]=s[11];s[11]=s[7];s[7]=s[3];s[3]=t;
}
void aes_mix(uchar s[16]){
    for(int c=0;c<4;c++){
        uchar a=s[4*c],b=s[4*c+1],cc=s[4*c+2],d=s[4*c+3];
        s[4*c  ]=xt(a)^xt(b)^b   ^cc ^d;
        s[4*c+1]=a   ^xt(b)^xt(cc)^cc^d;
        s[4*c+2]=a   ^b   ^xt(cc)^xt(d)^d;
        s[4*c+3]=xt(a)^a  ^b    ^cc   ^xt(d);
    }
}
void aes_ark(__global const uchar* ks, int round, uchar s[16]){
    for(int i=0;i<16;i++) s[i]^=ks[round*16+i];
}
void aes256_ecb(uchar b[16], __global const uchar* ks){
    uchar s[16]; for(int i=0;i<16;i++) s[i]=b[i];
    aes_ark(ks,0,s);
    for(int r=1;r<14;r++){aes_sub(s);aes_shr(s);aes_mix(s);aes_ark(ks,r,s);}
    aes_sub(s); aes_shr(s); aes_ark(ks,14,s);
    for(int i=0;i<16;i++) b[i]=s[i];
}
__kernel void aes256_ctr(
    __global const uchar* in,
    __global       uchar* out,
    __global const uchar* ks,
    __global const uchar* iv,
    ulong n_bytes
){
    ulong bid = get_global_id(0);
    ulong off = bid * 16;
    if(off >= n_bytes) return;
    uchar ctr[16];
    for(int i=0;i<12;i++) ctr[i]=iv[i];
    ctr[12]=(uchar)(bid>>24);
    ctr[13]=(uchar)(bid>>16);
    ctr[14]=(uchar)(bid>> 8);
    ctr[15]=(uchar) bid;
    aes256_ecb(ctr, ks);
    ulong blk = (off+16<=n_bytes) ? 16 : n_bytes-off;
    for(ulong i=0;i<blk;i++) out[off+i]=in[off+i]^ctr[i];
}
"""

# ═══════════════════════════════════════════════════════════
#  GPU Manager  (OpenCL)
# ═══════════════════════════════════════════════════════════
class GpuManager:
    available: bool = False
    name:      str  = ""
    _ctx  = None
    _q    = None
    _prg  = None

    def __init__(self):
        self._probe()

    def _probe(self):
        try:
            import pyopencl as cl
            import numpy as np
        except ImportError:
            return
        for plat in cl.get_platforms():
            try:
                devs = plat.get_devices(cl.device_type.GPU)
            except Exception:
                continue
            for dev in devs:
                try:
                    ctx = cl.Context([dev])
                    q   = cl.CommandQueue(ctx)
                    prg = cl.Program(ctx, _CL_KERNEL).build()
                    self._validate(cl, np, ctx, q, prg)
                    self._ctx, self._q, self._prg = ctx, q, prg
                    self.available = True
                    self.name      = dev.name.strip()
                    return
                except Exception:
                    continue

    def _validate(self, cl, np, ctx, q, prg):
        key   = bytes(range(32))
        nonce = bytes(range(12))
        pt    = bytes(range(64))
        ks_bytes = aes256_expand(key)
        mf  = cl.mem_flags
        ib  = cl.Buffer(ctx, mf.READ_ONLY|mf.COPY_HOST_PTR, hostbuf=np.frombuffer(pt,      np.uint8))
        ob  = cl.Buffer(ctx, mf.WRITE_ONLY, size=64)
        ksb = cl.Buffer(ctx, mf.READ_ONLY|mf.COPY_HOST_PTR, hostbuf=np.frombuffer(ks_bytes, np.uint8))
        ivb = cl.Buffer(ctx, mf.READ_ONLY|mf.COPY_HOST_PTR, hostbuf=np.frombuffer(nonce,   np.uint8))
        prg.aes256_ctr(q, (4,), None, ib, ob, ksb, ivb, np.uint64(64))
        gpu_out = np.empty(64, np.uint8)
        cl.enqueue_copy(q, gpu_out, ob); q.finish()
        ecb = AES.new(key, AES.MODE_ECB)
        ref_ks = b''.join(ecb.encrypt(nonce + struct.pack('>I', i)) for i in range(4))
        expected = bytes(a^b for a,b in zip(pt, ref_ks))
        if bytes(gpu_out) != expected:
            raise RuntimeError("GPU AES-256 validation failed — output mismatch")

    def process(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        import pyopencl as cl
        import numpy as np
        ks_bytes = aes256_expand(key)
        da      = np.frombuffer(data,     np.uint8).copy()
        ksb_arr = np.frombuffer(ks_bytes, np.uint8)
        ivb_arr = np.frombuffer(nonce,    np.uint8)
        mf  = cl.mem_flags
        ib  = cl.Buffer(self._ctx, mf.READ_ONLY|mf.COPY_HOST_PTR, hostbuf=da)
        ob  = cl.Buffer(self._ctx, mf.WRITE_ONLY, size=da.nbytes)
        ksb = cl.Buffer(self._ctx, mf.READ_ONLY|mf.COPY_HOST_PTR, hostbuf=ksb_arr)
        ivb = cl.Buffer(self._ctx, mf.READ_ONLY|mf.COPY_HOST_PTR, hostbuf=ivb_arr)
        nb  = (len(data)+15)//16
        self._prg.aes256_ctr(self._q, (nb,), None, ib, ob, ksb, ivb, np.uint64(len(data)))
        res = np.empty(len(data), np.uint8)
        cl.enqueue_copy(self._q, res, ob); self._q.finish()
        return res.tobytes()


GPU = GpuManager()


# ═══════════════════════════════════════════════════════════
#  Crypto constants
# ═══════════════════════════════════════════════════════════
MAGIC_V6   = b"ENCPTO6\x00"
MAGIC_V4   = b"ENCPTO4\x00"
MAGIC_V3   = b"ENCPTO3\x00"
MAGIC_V2   = b"ENCPTO2\x00"
MODE_CTR   = 0x01
MODE_GCM   = 0x02
FLAG_FILE  = 0x00
FLAG_ZIP   = 0x01
CHUNK_SIZE = 4 * 1024 * 1024

ARGON2_TIME    = 3
ARGON2_MEM_KB  = 65536
ARGON2_PAR     = 4
ARGON2_HASH_LEN= 64
ARGON2_SALT_LEN= 16

PIN_ARGON2_TIME   = 2
PIN_ARGON2_MEM_KB = 8192
PIN_ARGON2_PAR    = 2
PIN_ARGON2_LEN    = 32

PBKDF2_ITERS = 1_000_000

HEADER_SIZE_V4 = 8 + 1 + 1 + ARGON2_SALT_LEN + 12 + 32  # = 70

CONFIG_DIR   = os.path.join(os.path.expanduser("~"), ".encpto")
CONFIG_FILE  = os.path.join(CONFIG_DIR, "security.cfg")
UI_PREF_FILE = os.path.join(CONFIG_DIR, "ui_prefs.cfg")

MAX_PIN_ATTEMPTS    = 3
PIN_LOCKOUT_SECONDS = 60

RECOVERY_CODE_COUNT  = 5
RECOVERY_CODE_LENGTH = 16

MAX_EMBEDDED_NAME_BYTES = 255

# ═══════════════════════════════════════════════════════════
#  Theme Definitions
# ═══════════════════════════════════════════════════════════

THEME_NAMES = ["Dark", "Light", "System", "Auto", "Army Green", "Deep Hacker"]

_THEME_DATA = {
    "Dark": {
        "bg":          "#1e1e2e",
        "bg2":         "#16213e",
        "bg3":         "#0d0d1a",
        "fg":          "#e0e0e0",
        "fg2":         "#cccccc",
        "accent":      "#80cbc4",
        "accent2":     "#4db6ac",
        "border":      "#555555",
        "border2":     "#0f3460",
        "btn_bg":      "#2b2b3b",
        "btn_hover":   "#3a3a4a",
        "status_bg":   "#16213e",
        "status_fg":   "#80cbc4",
        "group_fg":    "#cccccc",
        "input_bg":    "#2b2b3b",
        "input_fg":    "#e0e0e0",
        "enc_btn":     "#8b0000",
        "dec_btn":     "#006400",
        "warning_bg":  "#1a0a0a",
        "warning_fg":  "#fca5a5",
        "warning_br":  "#7f1d1d",
        "tab_bg":      "#16213e",
        "tab_sel":     "#80cbc4",
        "tab_sel_bg":  "#0f3460",
        "overlay_rgb": (30, 30, 46),
    },
    "Light": {
        "bg":          "#f0f2f5",
        "bg2":         "#ffffff",
        "bg3":         "#e4e8ed",
        "fg":          "#1a1a2e",
        "fg2":         "#333344",
        "accent":      "#006064",
        "accent2":     "#00838f",
        "border":      "#b0bec5",
        "border2":     "#90a4ae",
        "btn_bg":      "#e0e4e8",
        "btn_hover":   "#cfd8dc",
        "status_bg":   "#e0e4e8",
        "status_fg":   "#006064",
        "group_fg":    "#333344",
        "input_bg":    "#ffffff",
        "input_fg":    "#1a1a2e",
        "enc_btn":     "#c62828",
        "dec_btn":     "#2e7d32",
        "warning_bg":  "#fff3e0",
        "warning_fg":  "#b71c1c",
        "warning_br":  "#ef9a9a",
        "tab_bg":      "#e0e4e8",
        "tab_sel":     "#006064",
        "tab_sel_bg":  "#b2dfdb",
        "overlay_rgb": (240, 242, 245),
    },
    "Army Green": {
        "bg":          "#1a2010",
        "bg2":         "#1f2b14",
        "bg3":         "#111a08",
        "fg":          "#c8d4a0",
        "fg2":         "#b0c080",
        "accent":      "#8bc34a",
        "accent2":     "#a5d650",
        "border":      "#4a5a2a",
        "border2":     "#3a4a1a",
        "btn_bg":      "#2a3a1a",
        "btn_hover":   "#3a4a2a",
        "status_bg":   "#111a08",
        "status_fg":   "#8bc34a",
        "group_fg":    "#b0c080",
        "input_bg":    "#1f2b14",
        "input_fg":    "#c8d4a0",
        "enc_btn":     "#4e2000",
        "dec_btn":     "#1b4a00",
        "warning_bg":  "#1a1a08",
        "warning_fg":  "#c8d4a0",
        "warning_br":  "#4a5a2a",
        "tab_bg":      "#111a08",
        "tab_sel":     "#8bc34a",
        "tab_sel_bg":  "#2a3a1a",
        "overlay_rgb": (26, 32, 16),
    },
    "Deep Hacker": {
        "bg":          "#000000",
        "bg2":         "#001200",
        "bg3":         "#000800",
        "fg":          "#00ff41",
        "fg2":         "#00cc33",
        "accent":      "#00ff41",
        "accent2":     "#39ff14",
        "border":      "#004400",
        "border2":     "#006600",
        "btn_bg":      "#001a00",
        "btn_hover":   "#003300",
        "status_bg":   "#000800",
        "status_fg":   "#00ff41",
        "group_fg":    "#00cc33",
        "input_bg":    "#001200",
        "input_fg":    "#00ff41",
        "enc_btn":     "#1a0000",
        "dec_btn":     "#001a00",
        "warning_bg":  "#0a0000",
        "warning_fg":  "#ff4400",
        "warning_br":  "#440000",
        "tab_bg":      "#000800",
        "tab_sel":     "#00ff41",
        "tab_sel_bg":  "#001a00",
        "overlay_rgb": (0, 0, 0),
    },
}

def _resolve_theme_name(name: str) -> str:
    if name == "System":
        try:
            palette = QApplication.palette()
            bg = palette.color(QPalette.ColorRole.Window)
            brightness = (bg.red() * 299 + bg.green() * 587 + bg.blue() * 114) // 1000
            return "Light" if brightness > 128 else "Dark"
        except Exception:
            return "Dark"
    elif name == "Auto":
        hour = QTime.currentTime().hour()
        return "Light" if 7 <= hour < 19 else "Dark"
    return name

def get_theme(name: str) -> dict:
    resolved = _resolve_theme_name(name)
    return _THEME_DATA.get(resolved, _THEME_DATA["Dark"])


def _hex_to_rgb(hex_color: str) -> str:
    """Convert #rrggbb to 'r,g,b' string for use in rgba()."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"{r},{g},{b}"


# ═══════════════════════════════════════════════════════════
#  UI Preferences Manager
# ═══════════════════════════════════════════════════════════

class UiPrefsManager:
    """Stores theme + background image path + opacity in ~/.encpto/ui_prefs.cfg."""

    _DEFAULT = {
        "theme":          "Dark",
        "bg_image":       "",
        "bg_opacity":     60,   # 0=overlay fully transparent (image fully visible), 100=fully opaque (no image)
        "widget_opacity": 80,   # 0=widgets fully transparent, 100=widgets fully opaque
    }

    def __init__(self):
        self._prefs: dict = dict(self._DEFAULT)
        self._load()

    def _load(self):
        try:
            if os.path.exists(UI_PREF_FILE):
                with open(UI_PREF_FILE, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                self._prefs.update({k: v for k, v in loaded.items()
                                    if k in self._DEFAULT})
        except Exception:
            self._prefs = dict(self._DEFAULT)

    def _save(self):
        try:
            os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
            tmp = UI_PREF_FILE + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self._prefs, f, ensure_ascii=False, indent=2)
            os.replace(tmp, UI_PREF_FILE)
        except Exception:
            pass

    @property
    def theme(self) -> str:
        return self._prefs.get("theme", "Dark")

    @theme.setter
    def theme(self, val: str):
        if val in THEME_NAMES:
            self._prefs["theme"] = val
            self._save()

    @property
    def bg_image(self) -> str:
        path = self._prefs.get("bg_image", "")
        return path if path and os.path.isfile(path) else ""

    @bg_image.setter
    def bg_image(self, val: str):
        self._prefs["bg_image"] = val
        self._save()

    def clear_bg_image(self):
        self._prefs["bg_image"] = ""
        self._save()

    @property
    def bg_opacity(self) -> int:
        """
        Overlay opacity percentage.
        0  = overlay fully transparent → background image / colour fully visible
        100 = overlay fully opaque     → pure theme colour, image hidden
        """
        v = self._prefs.get("bg_opacity", 60)
        return max(0, min(100, int(v)))

    @bg_opacity.setter
    def bg_opacity(self, val: int):
        self._prefs["bg_opacity"] = max(0, min(100, int(val)))
        self._save()

    @property
    def widget_opacity(self) -> int:
        v = self._prefs.get("widget_opacity", 80)
        return max(0, min(100, int(v)))

    @widget_opacity.setter
    def widget_opacity(self, val: int):
        self._prefs["widget_opacity"] = max(0, min(100, int(val)))
        self._save()


ui_prefs = UiPrefsManager()


# ═══════════════════════════════════════════════════════════
#  KDF helpers
# ═══════════════════════════════════════════════════════════

def _v6_header_size(name_len: int) -> int:
    return 8 + 1 + 1 + 2 + name_len + ARGON2_SALT_LEN + 12 + 32


def _kdf_argon2(pwd: bytes, salt: bytes) -> '_SecureKey':
    if not _ARGON2_AVAILABLE:
        raise RuntimeError("argon2-cffi not installed.\nRun:  pip install argon2-cffi")
    raw = hash_secret_raw(
        secret=pwd, salt=salt,
        time_cost=ARGON2_TIME, memory_cost=ARGON2_MEM_KB,
        parallelism=ARGON2_PAR, hash_len=ARGON2_HASH_LEN,
        type=Argon2Type.ID,
    )
    sk = _SecureKey(raw)
    _secure_zero_bytes(raw)
    return sk


def _kdf_argon2_pin(pin: bytes, salt: bytes) -> bytes:
    if not _ARGON2_AVAILABLE:
        raise RuntimeError("argon2-cffi not installed.")
    raw = hash_secret_raw(
        secret=pin, salt=salt,
        time_cost=PIN_ARGON2_TIME, memory_cost=PIN_ARGON2_MEM_KB,
        parallelism=PIN_ARGON2_PAR, hash_len=PIN_ARGON2_LEN,
        type=Argon2Type.ID,
    )
    return raw


def _kdf_pbkdf2_legacy(pwd: bytes, salt: bytes) -> bytes:
    from Crypto.Protocol.KDF import PBKDF2
    return PBKDF2(pwd, salt, dkLen=64, count=PBKDF2_ITERS)


def _chunk_nonce(base_nonce: bytes, chunk_idx: int) -> bytes:
    n = bytearray(base_nonce)
    idx_bytes = struct.pack('>I', chunk_idx)
    for i in range(4):
        n[8 + i] ^= idx_bytes[i]
    return bytes(n)


def _cfg_encrypt(data: bytes, key: bytes) -> bytes:
    nonce  = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ct


def _cfg_decrypt(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("Config blob too short.")
    nonce  = blob[:12]
    tag    = blob[12:28]
    ct     = blob[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


# ═══════════════════════════════════════════════════════════
#  Directory helpers
# ═══════════════════════════════════════════════════════════

def pack_directory_to_zip(dir_path: str, progress_cb=None) -> io.BytesIO:
    all_files = []
    for root, dirs, files in os.walk(dir_path):
        dirs.sort()
        for fname in sorted(files):
            all_files.append(os.path.join(root, fname))
    buf = io.BytesIO()
    base = os.path.dirname(os.path.abspath(dir_path))
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for idx, fpath in enumerate(all_files):
            arcname = os.path.relpath(fpath, base)
            zf.write(fpath, arcname)
            if progress_cb:
                progress_cb(idx + 1, len(all_files))
    buf.seek(0)
    return buf


def unpack_zip_to_directory(zip_bytes: bytes, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for member in zf.namelist():
            member_path = os.path.realpath(os.path.join(out_dir, member))
            if not member_path.startswith(os.path.realpath(out_dir)):
                raise ValueError(f"Unsafe ZIP path detected: {member}")
        zf.extractall(out_dir)


def _is_zip_bytes(data: bytes) -> bool:
    return data[:4] == b'PK\x03\x04'


# ═══════════════════════════════════════════════════════════
#  DoD 5220.22-M Secure Shredder
# ═══════════════════════════════════════════════════════════

def secure_shred_file(file_path: str, progress_cb=None) -> None:
    file_size  = os.path.getsize(file_path)
    total_work = file_size * 3
    passes = [
        lambda size: b'\x00' * size,
        lambda size: b'\xff' * size,
        lambda size: secrets.token_bytes(size),
    ]
    with open(file_path, 'r+b') as f:
        for pass_idx, pattern_fn in enumerate(passes):
            f.seek(0)
            offset = 0
            while offset < file_size:
                chunk_len = min(CHUNK_SIZE, file_size - offset)
                f.write(pattern_fn(chunk_len))
                f.flush()
                os.fsync(f.fileno())
                offset += chunk_len
                if progress_cb:
                    progress_cb(pass_idx * file_size + offset, total_work)
        f.truncate(0)
        f.flush()
        os.fsync(f.fileno())
    os.remove(file_path)


def secure_shred_directory(dir_path: str, progress_cb=None) -> None:
    all_files = []
    for root, _, files in os.walk(dir_path):
        for fname in files:
            all_files.append(os.path.join(root, fname))
    for idx, fpath in enumerate(all_files):
        secure_shred_file(fpath)
        if progress_cb:
            progress_cb(idx + 1, len(all_files))
    shutil.rmtree(dir_path, ignore_errors=True)


# ═══════════════════════════════════════════════════════════
#  Core encryption engine  (V6)
# ═══════════════════════════════════════════════════════════

def _encrypt_stream(source_stream, source_size, pwd, use_gpu, out_path,
                    flags=FLAG_FILE, progress_cb=None,
                    original_name: str = "") -> str:
    salt       = get_random_bytes(ARGON2_SALT_LEN)
    base_nonce = get_random_bytes(12)
    with _kdf_argon2(pwd, salt) as sk:
        aes_key  = sk.slice(0, 32)
        hmac_key = sk.slice(32, 64)
    mode = MODE_CTR if (use_gpu and GPU.available) else MODE_GCM

    name_bytes = original_name.encode('utf-8')[:MAX_EMBEDDED_NAME_BYTES]
    name_len   = len(name_bytes)

    hdr_body = (MAGIC_V6
                + bytes([mode])
                + bytes([flags])
                + struct.pack('>H', name_len)
                + name_bytes
                + salt
                + base_nonce)

    header_total = len(hdr_body) + 32

    h = hmac_mod.new(hmac_key, hdr_body, hashlib.sha256)
    bytes_done = 0
    _enc_ok = False
    try:
        with open(out_path, 'w+b') as out_f:
            out_f.write(b'\x00' * header_total)
            chunk_idx = 0
            while True:
                chunk = source_stream.read(CHUNK_SIZE)
                if not chunk:
                    break
                cn = _chunk_nonce(base_nonce, chunk_idx)
                if mode == MODE_CTR:
                    ct_section = (GPU.process(chunk, aes_key, cn)
                                  if GPU.available
                                  else cpu_ctr(chunk, aes_key, cn))
                else:
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=cn)
                    cipher.update(struct.pack('>Q', chunk_idx))
                    ct, tag = cipher.encrypt_and_digest(chunk)
                    ct_section = ct + tag
                h.update(ct_section)
                out_f.write(ct_section)
                chunk_idx  += 1
                bytes_done += len(chunk)
                if progress_cb:
                    progress_cb(bytes_done, source_size)
            final_mac = h.digest()
            final_hdr = hdr_body + final_mac
            out_f.seek(0)
            out_f.write(final_hdr)
            out_f.flush()
            os.fsync(out_f.fileno())
        _enc_ok = True
    except BaseException:
        if not _enc_ok:
            try:
                os.remove(out_path)
            except OSError:
                pass
        raise
    finally:
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
    return out_path


def do_encrypt(in_path, pwd, use_gpu, out_path, shred_after=False, progress_cb=None) -> str:
    file_size     = os.path.getsize(in_path)
    original_name = os.path.basename(in_path)
    with open(in_path, 'rb') as f:
        result = _encrypt_stream(f, file_size, pwd, use_gpu, out_path,
                                 flags=FLAG_FILE, progress_cb=progress_cb,
                                 original_name=original_name)
    if shred_after:
        secure_shred_file(in_path)
    return result


def do_encrypt_directory(dir_path, pwd, use_gpu, out_path, shred_after=False,
                         progress_cb=None, zip_progress_cb=None) -> str:
    original_name = os.path.basename(dir_path.rstrip('/\\'))
    zip_buf  = pack_directory_to_zip(dir_path, progress_cb=zip_progress_cb)
    zip_size = zip_buf.seek(0, 2)
    zip_buf.seek(0)
    result = _encrypt_stream(zip_buf, zip_size, pwd, use_gpu, out_path,
                             flags=FLAG_ZIP, progress_cb=progress_cb,
                             original_name=original_name)
    if shred_after:
        secure_shred_directory(dir_path)
    return result


def do_decrypt(in_path, pwd, out_path, progress_cb=None) -> str:
    with open(in_path, 'rb') as f:
        magic = f.read(8)
    if magic == MAGIC_V6:
        return _decrypt_v6(in_path, pwd, out_path, progress_cb)
    elif magic == MAGIC_V4:
        return _decrypt_v4(in_path, pwd, out_path, progress_cb)
    elif magic == MAGIC_V3:
        return _decrypt_v3_compat(in_path, pwd, out_path, progress_cb)
    else:
        return _decrypt_legacy(in_path, pwd, out_path)


def _tmp_path(out_path: str) -> str:
    return out_path + ".dec_tmp"

def _remove_tmp(tmp: str) -> None:
    try:
        os.remove(tmp)
    except OSError:
        pass


def _decrypt_v6(in_path, pwd, out_path, progress_cb=None) -> str:
    file_size = os.path.getsize(in_path)
    with open(in_path, 'rb') as f:
        magic      = f.read(8)
        mode       = ord(f.read(1))
        flags      = ord(f.read(1))
        name_len   = struct.unpack('>H', f.read(2))[0]
        name_bytes = f.read(name_len)
        original_name = name_bytes.decode('utf-8', errors='replace')
        salt       = f.read(ARGON2_SALT_LEN)
        base_nonce = f.read(12)
        hdr_body   = (magic + bytes([mode]) + bytes([flags])
                      + struct.pack('>H', name_len) + name_bytes
                      + salt + base_nonce)
        mac_stored = f.read(32)

    header_total = _v6_header_size(name_len)
    if file_size < header_total:
        raise ValueError("File too short — corrupted V6 format.")
    ct_start = header_total
    ct_size  = file_size - ct_start

    with _kdf_argon2(pwd, salt) as sk:
        aes_key  = sk.slice(0, 32)
        hmac_key = sk.slice(32, 64)

    h = hmac_mod.new(hmac_key, hdr_body, hashlib.sha256)
    with open(in_path, 'rb') as f:
        f.seek(ct_start)
        remaining = ct_size
        while remaining > 0:
            block = f.read(min(CHUNK_SIZE, remaining))
            if not block:
                break
            h.update(block)
            remaining -= len(block)
    if not hmac_mod.compare_digest(h.digest(), mac_stored):
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
        raise ValueError("HMAC-SHA256 mismatch — wrong password or file tampered.")

    if flags == FLAG_ZIP and original_name:
        real_out = os.path.join(out_path, original_name)
    else:
        real_out = out_path

    tmp_path_  = _tmp_path(real_out)
    bytes_done = 0
    try:
        collect_for_zip = (flags == FLAG_ZIP)
        plaintext_buf   = io.BytesIO() if collect_for_zip else None
        with open(in_path, 'rb') as f_in:
            ctx_out = None if collect_for_zip else open(tmp_path_, 'wb')
            try:
                f_in.seek(ct_start)
                chunk_idx = 0
                if mode == MODE_CTR:
                    while True:
                        ct_chunk = f_in.read(CHUNK_SIZE)
                        if not ct_chunk:
                            break
                        cn = _chunk_nonce(base_nonce, chunk_idx)
                        pt = (GPU.process(ct_chunk, aes_key, cn) if GPU.available
                              else cpu_ctr(ct_chunk, aes_key, cn))
                        (plaintext_buf if collect_for_zip else ctx_out).write(pt)
                        chunk_idx  += 1
                        bytes_done += len(ct_chunk)
                        if progress_cb:
                            progress_cb(bytes_done, ct_size)
                elif mode == MODE_GCM:
                    ct_chunk_size = CHUNK_SIZE + 16
                    while True:
                        ct_chunk = f_in.read(ct_chunk_size)
                        if not ct_chunk:
                            break
                        if len(ct_chunk) < 17:
                            raise ValueError("Truncated GCM chunk — file corrupted.")
                        ct, tag = ct_chunk[:-16], ct_chunk[-16:]
                        cn = _chunk_nonce(base_nonce, chunk_idx)
                        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=cn)
                        cipher.update(struct.pack('>Q', chunk_idx))
                        pt = cipher.decrypt_and_verify(ct, tag)
                        (plaintext_buf if collect_for_zip else ctx_out).write(pt)
                        chunk_idx  += 1
                        bytes_done += len(ct_chunk)
                        if progress_cb:
                            progress_cb(bytes_done, ct_size)
                else:
                    raise ValueError(f"Unknown mode byte 0x{mode:02x} in V6 file.")
                if ctx_out:
                    ctx_out.flush()
                    os.fsync(ctx_out.fileno())
            finally:
                if ctx_out:
                    ctx_out.close()
        if collect_for_zip:
            zip_data = plaintext_buf.getvalue()
            plaintext_buf.close()
            if not _is_zip_bytes(zip_data):
                raise ValueError("Decrypted payload is not a valid ZIP archive.")
            unpack_zip_to_directory(zip_data, real_out)
            return real_out
        os.replace(tmp_path_, real_out)
    except BaseException:
        _remove_tmp(tmp_path_)
        raise
    finally:
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
    return real_out


def peek_v6_header(dat_path: str) -> dict:
    with open(dat_path, 'rb') as f:
        magic = f.read(8)
        if magic != MAGIC_V6:
            raise ValueError("Not a V6 file.")
        mode     = ord(f.read(1))
        flags    = ord(f.read(1))
        name_len = struct.unpack('>H', f.read(2))[0]
        if name_len > MAX_EMBEDDED_NAME_BYTES:
            raise ValueError("Embedded name length out of range.")
        name_bytes    = f.read(name_len)
        original_name = name_bytes.decode('utf-8', errors='replace')
    return {
        "original_name": original_name,
        "flags":         flags,
        "mode":          mode,
        "is_zip":        flags == FLAG_ZIP,
    }


def peek_v4_flags(dat_path: str) -> dict:
    try:
        with open(dat_path, 'rb') as f:
            f.read(8)
            f.read(1)
            flags = ord(f.read(1))
        return {"is_zip": flags == FLAG_ZIP}
    except Exception:
        return {"is_zip": False}


def _decrypt_v4(in_path, pwd, out_path, progress_cb=None) -> str:
    HEADER_LEN = HEADER_SIZE_V4
    file_size  = os.path.getsize(in_path)
    if file_size < HEADER_LEN:
        raise ValueError("File too short — corrupted V4 format.")
    with open(in_path, 'rb') as f:
        hdr_body   = f.read(8 + 1 + 1 + ARGON2_SALT_LEN + 12)
        mac_stored = f.read(32)
    mode       = hdr_body[8]
    flags      = hdr_body[9]
    salt       = hdr_body[10 : 10 + ARGON2_SALT_LEN]
    base_nonce = hdr_body[10 + ARGON2_SALT_LEN : 10 + ARGON2_SALT_LEN + 12]
    with _kdf_argon2(pwd, salt) as sk:
        aes_key  = sk.slice(0, 32)
        hmac_key = sk.slice(32, 64)
    h = hmac_mod.new(hmac_key, hdr_body, hashlib.sha256)
    ct_start = HEADER_LEN
    ct_size  = file_size - ct_start
    with open(in_path, 'rb') as f:
        f.seek(ct_start)
        remaining = ct_size
        while remaining > 0:
            to_read = min(CHUNK_SIZE, remaining)
            block   = f.read(to_read)
            if not block:
                break
            h.update(block)
            remaining -= len(block)
    if not hmac_mod.compare_digest(h.digest(), mac_stored):
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
        raise ValueError("HMAC-SHA256 mismatch — wrong password or file tampered.")
    tmp_path_  = _tmp_path(out_path)
    bytes_done = 0
    try:
        collect_for_zip = (flags == FLAG_ZIP)
        if collect_for_zip:
            plaintext_buf = io.BytesIO()
        with open(in_path, 'rb') as f_in:
            ctx_out = (None if collect_for_zip else open(tmp_path_, 'wb'))
            try:
                f_in.seek(ct_start)
                chunk_idx = 0
                if mode == MODE_CTR:
                    while True:
                        ct_chunk = f_in.read(CHUNK_SIZE)
                        if not ct_chunk:
                            break
                        cn = _chunk_nonce(base_nonce, chunk_idx)
                        pt = (GPU.process(ct_chunk, aes_key, cn) if GPU.available
                              else cpu_ctr(ct_chunk, aes_key, cn))
                        if collect_for_zip:
                            plaintext_buf.write(pt)
                        else:
                            ctx_out.write(pt)
                        chunk_idx  += 1
                        bytes_done += len(ct_chunk)
                        if progress_cb:
                            progress_cb(bytes_done, ct_size)
                elif mode == MODE_GCM:
                    ct_chunk_size = CHUNK_SIZE + 16
                    while True:
                        ct_chunk = f_in.read(ct_chunk_size)
                        if not ct_chunk:
                            break
                        if len(ct_chunk) < 17:
                            raise ValueError("Truncated GCM chunk — file corrupted.")
                        ct, tag = ct_chunk[:-16], ct_chunk[-16:]
                        cn = _chunk_nonce(base_nonce, chunk_idx)
                        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=cn)
                        cipher.update(struct.pack('>Q', chunk_idx))
                        pt = cipher.decrypt_and_verify(ct, tag)
                        if collect_for_zip:
                            plaintext_buf.write(pt)
                        else:
                            ctx_out.write(pt)
                        chunk_idx  += 1
                        bytes_done += len(ct_chunk)
                        if progress_cb:
                            progress_cb(bytes_done, ct_size)
                else:
                    raise ValueError(f"Unknown mode byte 0x{mode:02x} in V4 file.")
                if not collect_for_zip:
                    ctx_out.flush()
                    os.fsync(ctx_out.fileno())
            finally:
                if ctx_out is not None:
                    ctx_out.close()
        if collect_for_zip:
            zip_data = plaintext_buf.getvalue()
            plaintext_buf.close()
            if not _is_zip_bytes(zip_data):
                raise ValueError("Decrypted payload is not a valid ZIP archive.")
            unpack_zip_to_directory(zip_data, out_path)
            return out_path
        os.replace(tmp_path_, out_path)
    except BaseException:
        _remove_tmp(tmp_path_)
        raise
    finally:
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
    return out_path


def _decrypt_v3_compat(in_path, pwd, out_path, progress_cb=None) -> str:
    HEADER_LEN = 8 + 1 + ARGON2_SALT_LEN + 12 + 32
    file_size  = os.path.getsize(in_path)
    if file_size < HEADER_LEN:
        raise ValueError("File too short — corrupted V3 format.")
    with open(in_path, 'rb') as f:
        hdr_body   = f.read(8 + 1 + ARGON2_SALT_LEN + 12)
        mac_stored = f.read(32)
    mode       = hdr_body[8]
    salt       = hdr_body[9 : 9 + ARGON2_SALT_LEN]
    base_nonce = hdr_body[9 + ARGON2_SALT_LEN : 9 + ARGON2_SALT_LEN + 12]
    with _kdf_argon2(pwd, salt) as sk:
        aes_key  = sk.slice(0, 32)
        hmac_key = sk.slice(32, 64)
    h = hmac_mod.new(hmac_key, hdr_body, hashlib.sha256)
    ct_start = HEADER_LEN
    ct_size  = file_size - ct_start
    with open(in_path, 'rb') as f:
        f.seek(ct_start)
        remaining = ct_size
        while remaining > 0:
            to_read = min(CHUNK_SIZE, remaining)
            block   = f.read(to_read)
            if not block:
                break
            h.update(block)
            remaining -= len(block)
    if not hmac_mod.compare_digest(h.digest(), mac_stored):
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
        raise ValueError("HMAC-SHA256 mismatch — wrong password or file tampered.")
    tmp_path_  = _tmp_path(out_path)
    bytes_done = 0
    try:
        with open(in_path, 'rb') as f_in, open(tmp_path_, 'wb') as f_out:
            f_in.seek(ct_start)
            chunk_idx = 0
            if mode == MODE_CTR:
                while True:
                    ct_chunk = f_in.read(CHUNK_SIZE)
                    if not ct_chunk:
                        break
                    cn = _chunk_nonce(base_nonce, chunk_idx)
                    pt = (GPU.process(ct_chunk, aes_key, cn) if GPU.available
                          else cpu_ctr(ct_chunk, aes_key, cn))
                    f_out.write(pt)
                    chunk_idx  += 1
                    bytes_done += len(ct_chunk)
                    if progress_cb:
                        progress_cb(bytes_done, ct_size)
            elif mode == MODE_GCM:
                ct_chunk_size = CHUNK_SIZE + 16
                while True:
                    ct_chunk = f_in.read(ct_chunk_size)
                    if not ct_chunk:
                        break
                    if len(ct_chunk) < 17:
                        raise ValueError("Truncated GCM chunk — file corrupted.")
                    ct, tag = ct_chunk[:-16], ct_chunk[-16:]
                    cn = _chunk_nonce(base_nonce, chunk_idx)
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=cn)
                    cipher.update(struct.pack('>Q', chunk_idx))
                    pt = cipher.decrypt_and_verify(ct, tag)
                    f_out.write(pt)
                    chunk_idx  += 1
                    bytes_done += len(ct_chunk)
                    if progress_cb:
                        progress_cb(bytes_done, ct_size)
            else:
                raise ValueError(f"Unknown mode byte 0x{mode:02x} in V3 file.")
            f_out.flush()
            os.fsync(f_out.fileno())
        os.replace(tmp_path_, out_path)
    except BaseException:
        _remove_tmp(tmp_path_)
        raise
    finally:
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
    return out_path


def _decrypt_legacy(in_path, pwd, out_path) -> str:
    from Crypto.Protocol.KDF import PBKDF2
    with open(in_path, 'rb') as f:
        file_data = f.read()
    tmp_path_ = _tmp_path(out_path)
    if file_data[:8] == MAGIC_V2:
        if len(file_data) < 85:
            raise ValueError("File too short — corrupted V2 format.")
        mode       = file_data[8]
        salt       = file_data[9:41]
        nonce      = file_data[41:53]
        mac_stored = file_data[53:85]
        ct_section = file_data[85:]
        raw      = _kdf_pbkdf2_legacy(pwd, salt)
        aes_key  = raw[:32]
        hmac_key = raw[32:]
        hdr = MAGIC_V2 + bytes([mode]) + salt + nonce
        if not hmac_mod.compare_digest(
            hmac_mod.new(hmac_key, hdr + ct_section, hashlib.sha256).digest(),
            mac_stored
        ):
            _secure_zero_bytes(aes_key)
            _secure_zero_bytes(hmac_key)
            raise ValueError("HMAC-SHA256 mismatch — wrong password or file tampered.")
        if mode == MODE_CTR:
            plaintext = (GPU.process(ct_section, aes_key, nonce) if GPU.available
                         else cpu_ctr(ct_section, aes_key, nonce))
        elif mode == MODE_GCM:
            ct, tag   = ct_section[:-16], ct_section[-16:]
            cipher    = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ct, tag)
        else:
            raise ValueError(f"Unknown mode byte 0x{mode:02x} in V2 file.")
        _secure_zero_bytes(aes_key)
        _secure_zero_bytes(hmac_key)
    else:
        if len(file_data) < 64:
            raise ValueError("File too short — not a valid encrypted file.")
        salt       = file_data[:32]
        nonce      = file_data[32:48]
        tag        = file_data[48:64]
        ciphertext = file_data[64:]
        aes_key    = PBKDF2(pwd, salt, dkLen=32, count=PBKDF2_ITERS)
        cipher     = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise ValueError("Wrong password or corrupted file (V1 GCM).")
        finally:
            _secure_zero_bytes(aes_key)
    try:
        with open(tmp_path_, 'wb') as f:
            f.write(plaintext)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path_, out_path)
    except BaseException:
        _remove_tmp(tmp_path_)
        raise
    return out_path


# ═══════════════════════════════════════════════════════════
#  Background worker thread
# ═══════════════════════════════════════════════════════════
class CryptoWorker(QThread):
    finished   = pyqtSignal(str)
    failed     = pyqtSignal(str)
    progress   = pyqtSignal(int)
    status_msg = pyqtSignal(str)

    def __init__(self, task):
        super().__init__()
        self._task = task

    def run(self):
        try:
            self.finished.emit(self._task())
        except Exception as e:
            self.failed.emit(str(e))


# ═══════════════════════════════════════════════════════════
#  Strong Password Generator
# ═══════════════════════════════════════════════════════════
_AMBIGUOUS = set("0O1lI")

def generate_password(length=20, use_upper=True, use_lower=True,
                      use_digits=True, use_symbols=True,
                      avoid_ambiguous=False) -> str:
    pools: list[str] = []
    def _filtered(chars: str) -> str:
        if avoid_ambiguous:
            return ''.join(c for c in chars if c not in _AMBIGUOUS)
        return chars
    if use_upper:
        p = _filtered(string.ascii_uppercase)
        if p: pools.append(p)
    if use_lower:
        p = _filtered(string.ascii_lowercase)
        if p: pools.append(p)
    if use_digits:
        p = _filtered(string.digits)
        if p: pools.append(p)
    if use_symbols:
        syms = ''.join(c for c in string.punctuation if c not in r'\`')
        p = _filtered(syms)
        if p: pools.append(p)
    if not pools:
        raise ValueError("At least one character set must be selected.")
    min_len = len(pools)
    if length < max(min_len, 8):
        raise ValueError(f"Length must be ≥ {max(min_len, 8)} for the selected pools.")
    full_pool = ''.join(pools)
    mandatory = [secrets.choice(p) for p in pools]
    remainder = [secrets.choice(full_pool) for _ in range(length - len(mandatory))]
    chars = mandatory + remainder
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return ''.join(chars)


# ═══════════════════════════════════════════════════════════
#  Recovery Code Generator
# ═══════════════════════════════════════════════════════════
_RC_CHARSET = string.ascii_uppercase + string.digits

def _generate_recovery_code() -> str:
    charset = ''.join(c for c in _RC_CHARSET if c not in _AMBIGUOUS)
    groups = [''.join(secrets.choice(charset) for _ in range(4)) for _ in range(4)]
    return '-'.join(groups)

def _generate_recovery_codes() -> list[str]:
    return [_generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]


# ═══════════════════════════════════════════════════════════
#  SecurityManager
# ═══════════════════════════════════════════════════════════
_CFG_MAGIC      = b"ENCPTOCFG1"
_CFG_APP_CONST  = b"enCPTO_v5_security_config_2025"

class SecurityManager:
    def __init__(self):
        self._cfg_key     = self._derive_config_key()
        self._cfg: dict   = {}
        self._initialized = False
        self._load_config()

    def _derive_config_key(self) -> bytes:
        machine_id = self._get_machine_id()
        from Crypto.Protocol.KDF import PBKDF2
        salt = hashlib.sha256(_CFG_APP_CONST).digest()[:16]
        key  = PBKDF2(machine_id + _CFG_APP_CONST, salt, dkLen=32, count=100_000)
        return key

    def _get_machine_id(self) -> bytes:
        try:
            if sys.platform == "linux":
                with open("/etc/machine-id", 'rb') as f:
                    return f.read().strip()
            elif sys.platform == "darwin":
                import subprocess
                result = subprocess.run(
                    ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                    capture_output=True, text=True
                )
                for line in result.stdout.splitlines():
                    if "IOPlatformUUID" in line:
                        uuid = line.split('"')[-2]
                        return uuid.encode()
            elif sys.platform == "win32":
                import subprocess
                result = subprocess.run(
                    ["wmic", "csproduct", "get", "UUID"],
                    capture_output=True, text=True
                )
                lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                if len(lines) > 1:
                    return lines[1].encode()
        except Exception:
            pass
        import platform, getpass
        fallback = platform.node() + getpass.getuser() + "enCPTO_v5_fallback"
        return fallback.encode()

    def _load_config(self):
        if not os.path.exists(CONFIG_FILE):
            self._cfg         = {}
            self._initialized = False
            return
        try:
            with open(CONFIG_FILE, 'rb') as f:
                blob = f.read()
            if not blob.startswith(_CFG_MAGIC):
                self._cfg         = {}
                self._initialized = False
                return
            encrypted  = blob[len(_CFG_MAGIC):]
            json_bytes = _cfg_decrypt(encrypted, self._cfg_key)
            self._cfg  = json.loads(json_bytes.decode('utf-8'))
            self._initialized = True
        except Exception:
            self._cfg         = {}
            self._initialized = False

    def _save_config(self):
        os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
        json_bytes = json.dumps(self._cfg).encode('utf-8')
        encrypted  = _cfg_encrypt(json_bytes, self._cfg_key)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, 'wb') as f:
            f.write(_CFG_MAGIC)
            f.write(encrypted)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CONFIG_FILE)
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except Exception:
            pass

    @property
    def is_initialized(self) -> bool:
        return self._initialized and bool(self._cfg)

    def setup(self, pin: str) -> tuple[str, list[str]]:
        if not _ARGON2_AVAILABLE:
            raise RuntimeError("argon2-cffi is required for security setup.")
        if not _PYOTP_AVAILABLE:
            raise RuntimeError("pyotp is required for TOTP setup.\npip install pyotp")

        pin_b    = pin.encode('utf-8')
        pin_salt = get_random_bytes(ARGON2_SALT_LEN)
        pin_hash = _kdf_argon2_pin(pin_b, pin_salt)
        _secure_zero_bytes(pin_b)

        totp_secret    = pyotp.random_base32()
        recovery_codes = _generate_recovery_codes()

        rc_hashed = []
        for code in recovery_codes:
            normalized = code.replace('-', '').upper()
            h = hashlib.sha256(normalized.encode()).hexdigest()
            rc_hashed.append({"hash": h, "used": False})

        self._cfg = {
            "pin_salt":       pin_salt.hex(),
            "pin_hash":       pin_hash.hex(),
            "totp_secret":    totp_secret,
            "recovery_codes": rc_hashed,
            "fail_count":     0,
            "lockout_until":  0.0,
        }
        self._save_config()
        self._initialized = True
        _secure_zero_bytes(pin_hash)

        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name="enCPTO User",
            issuer_name="enCPTO v6"
        )
        return totp_uri, recovery_codes

    def is_locked_out(self) -> tuple[bool, float]:
        until     = self._cfg.get("lockout_until", 0.0)
        remaining = until - time.time()
        if remaining > 0:
            return True, remaining
        return False, 0.0

    def verify_pin(self, pin: str) -> bool:
        locked, _ = self.is_locked_out()
        if locked:
            return False
        pin_b = pin.encode('utf-8')
        try:
            pin_salt = bytes.fromhex(self._cfg["pin_salt"])
            expected = bytes.fromhex(self._cfg["pin_hash"])
            computed = _kdf_argon2_pin(pin_b, pin_salt)
            ok       = hmac_mod.compare_digest(computed, expected)
            _secure_zero_bytes(computed)
        except Exception:
            ok = False
        finally:
            _secure_zero_bytes(pin_b)

        if ok:
            self._cfg["fail_count"]    = 0
            self._cfg["lockout_until"] = 0.0
            self._save_config()
            return True
        else:
            count = self._cfg.get("fail_count", 0) + 1
            self._cfg["fail_count"] = count
            if count >= MAX_PIN_ATTEMPTS:
                self._cfg["lockout_until"] = time.time() + PIN_LOCKOUT_SECONDS
                self._cfg["fail_count"]    = 0
            self._save_config()
            return False

    def remaining_pin_attempts(self) -> int:
        count = self._cfg.get("fail_count", 0)
        return max(0, MAX_PIN_ATTEMPTS - count)

    def verify_totp(self, code: str) -> bool:
        if not _PYOTP_AVAILABLE:
            return False
        secret = self._cfg.get("totp_secret", "")
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)

    def get_totp_secret(self) -> str:
        return self._cfg.get("totp_secret", "")

    def verify_recovery_code(self, code: str) -> bool:
        normalized = code.replace('-', '').replace(' ', '').upper()
        h     = hashlib.sha256(normalized.encode()).hexdigest()
        codes = self._cfg.get("recovery_codes", [])
        for entry in codes:
            if not entry.get("used", False) and hmac_mod.compare_digest(entry["hash"], h):
                entry["used"] = True
                self._save_config()
                return True
        return False

    def remaining_recovery_codes(self) -> int:
        codes = self._cfg.get("recovery_codes", [])
        return sum(1 for c in codes if not c.get("used", False))

    def reset(self):
        self._cfg         = {}
        self._initialized = False
        try:
            secure_shred_file(CONFIG_FILE)
        except Exception:
            try:
                os.remove(CONFIG_FILE)
            except Exception:
                pass


security = SecurityManager()


# ═══════════════════════════════════════════════════════════
#  QR Code helper
# ═══════════════════════════════════════════════════════════

def _generate_qr_pixmap(uri: str, size: int = 280) -> QPixmap | None:
    if not _QRCODE_AVAILABLE:
        return None
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,
                           box_size=4, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qimg = QImage()
        qimg.loadFromData(buf.getvalue(), 'PNG')
        px = QPixmap.fromImage(qimg).scaled(size, size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        return px
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════
#  Dialog: First-time Setup Wizard
# ═══════════════════════════════════════════════════════════

class SetupWizardDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("enCPTO v6 — 安全設定精靈 / Security Setup Wizard")
        self.resize(600, 700)
        self.setMinimumSize(500, 600)
        self.setModal(True)
        self._totp_uri       = ""
        self._recovery_codes = []
        self._setup_done     = False
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet("""
            QDialog { background: #1a1a2e; color: #e0e0e0; }
            QLabel  { color: #e0e0e0; }
            QLineEdit {
                background: #16213e; color: #e0e0e0;
                border: 1px solid #0f3460; border-radius: 4px;
                padding: 6px; font-size: 13px;
            }
            QPushButton {
                background: #0f3460; color: #e0e0e0;
                border: none; border-radius: 4px;
                padding: 8px 16px; font-weight: bold;
            }
            QPushButton:hover  { background: #1a4a80; }
            QPushButton:pressed { background: #0a2040; }
            QTextEdit {
                background: #0d0d1a; color: #a0ffa0;
                border: 1px solid #0f3460; border-radius: 4px;
                font-family: Consolas, monospace; font-size: 12px;
                padding: 6px;
            }
        """)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet("QScrollArea { background: transparent; }")

        self.container = QWidget()
        layout = QVBoxLayout(self.container)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("🔐  enCPTO v6 MFA 安全設定精靈")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #80cbc4; margin-bottom: 6px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #0f3460;")
        layout.addWidget(sep)

        step1_label = QLabel("步驟 1 / Step 1 — 設定 PIN 碼 (至少 6 位)")
        step1_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        step1_label.setStyleSheet("color: #ffcc80;")
        layout.addWidget(step1_label)

        pin_row = QHBoxLayout()
        self.pin_input   = QLineEdit()
        self.pin_input.setPlaceholderText("輸入 PIN 碼 (6-20 位數字或字母)")
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_confirm = QLineEdit()
        self.pin_confirm.setPlaceholderText("再次輸入 PIN 碼確認")
        self.pin_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        pin_row.addWidget(self.pin_input)
        pin_row.addWidget(self.pin_confirm)
        layout.addLayout(pin_row)

        self.pin_status = QLabel("")
        self.pin_status.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.pin_status)
        self.pin_input.textChanged.connect(self._check_pin)
        self.pin_confirm.textChanged.connect(self._check_pin)

        self.btn_generate_setup = QPushButton(
            "⚡ 產生 TOTP 密鑰與救援碼 / Generate TOTP & Recovery Codes")
        self.btn_generate_setup.setStyleSheet(
            "QPushButton { background: #006064; font-size: 12px; padding: 10px; }"
            "QPushButton:hover { background: #00838f; }"
            "QPushButton:disabled { background: #333; color: #666; }"
        )
        self.btn_generate_setup.clicked.connect(self._do_generate)
        self.btn_generate_setup.setEnabled(False)
        layout.addWidget(self.btn_generate_setup)

        step2_label = QLabel("步驟 2 / Step 2 — 掃描 QR Code 至 Google Authenticator / Authy")
        step2_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        step2_label.setStyleSheet("color: #ffcc80;")
        layout.addWidget(step2_label)

        self.qr_label = QLabel("尚未產生 QR Code\n(請先完成步驟 1)")
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_label.setMinimumHeight(200)
        self.qr_label.setStyleSheet(
            "background: #0d1117; border: 2px dashed #0f3460; border-radius: 4px; color: #666;")
        layout.addWidget(self.qr_label)

        self.totp_secret_label = QLabel("")
        self.totp_secret_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totp_secret_label.setStyleSheet(
            "color: #80cbc4; font-family: Consolas, monospace; font-size: 11px;")
        self.totp_secret_label.setWordWrap(True)
        layout.addWidget(self.totp_secret_label)

        step3_label = QLabel("步驟 3 / Step 3 — 抄寫並妥善保管救援碼 ⚠️ 僅顯示一次")
        step3_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        step3_label.setStyleSheet("color: #f87171;")
        layout.addWidget(step3_label)

        self.recovery_display = QTextEdit()
        self.recovery_display.setReadOnly(True)
        self.recovery_display.setMaximumHeight(120)
        self.recovery_display.setPlaceholderText(
            "救援碼將在此顯示 / Recovery codes will appear here")
        layout.addWidget(self.recovery_display)

        warn_label = QLabel(
            "⚠️  請將上方救援碼列印或抄寫後存放於安全、不與電腦相連的位置。\n"
            "    These codes bypass TOTP. Store them offline, away from this device.")
        warn_label.setStyleSheet(
            "color: #fca5a5; font-size: 10px; background: #1a0a0a; "
            "border: 1px solid #7f1d1d; border-radius: 3px; padding: 6px;")
        warn_label.setWordWrap(True)
        layout.addWidget(warn_label)

        self.chk_confirm = QCheckBox(
            "我已抄寫救援碼，並了解無法復原的風險 / I have saved recovery codes")
        self.chk_confirm.setEnabled(False)
        self.chk_confirm.setStyleSheet("color: #ccc; font-size: 11px;")
        self.chk_confirm.stateChanged.connect(self._on_confirm_change)
        layout.addWidget(self.chk_confirm)

        self.btn_finish = QPushButton("✅ 完成設定 / Finish Setup")
        self.btn_finish.setEnabled(False)
        self.btn_finish.setStyleSheet(
            "QPushButton { background: #1b5e20; font-size: 13px; font-weight: bold; padding: 10px; }"
            "QPushButton:hover { background: #2e7d32; }"
            "QPushButton:disabled { background: #333; color: #666; }"
        )
        self.btn_finish.clicked.connect(self.accept)
        layout.addWidget(self.btn_finish)

        self.scroll.setWidget(self.container)
        main_layout.addWidget(self.scroll)

    def _check_pin(self):
        p1 = self.pin_input.text()
        p2 = self.pin_confirm.text()
        if len(p1) < 6:
            self.pin_status.setText("PIN 太短，至少 6 碼")
            self.pin_status.setStyleSheet("color: red; font-size: 11px;")
            self.btn_generate_setup.setEnabled(False)
        elif p1 != p2 and p2:
            self.pin_status.setText("兩次輸入不一致")
            self.pin_status.setStyleSheet("color: orange; font-size: 11px;")
            self.btn_generate_setup.setEnabled(False)
        elif p1 == p2 and len(p1) >= 6:
            self.pin_status.setText("✅ PIN 符合要求")
            self.pin_status.setStyleSheet("color: green; font-size: 11px;")
            self.btn_generate_setup.setEnabled(True)
        else:
            self.pin_status.setText("")
            self.btn_generate_setup.setEnabled(False)

    def _do_generate(self):
        pin = self.pin_input.text()
        if not pin or len(pin) < 6:
            return
        try:
            totp_uri, recovery_codes = security.setup(pin)
            self._totp_uri       = totp_uri
            self._recovery_codes = recovery_codes
            self._setup_done     = True

            px = _generate_qr_pixmap(totp_uri, size=240)
            if px:
                self.qr_label.setPixmap(px)
                self.qr_label.setStyleSheet(
                    "background: white; border: 2px solid #80cbc4; border-radius: 4px;")
            else:
                secret = security.get_totp_secret()
                self.qr_label.setText(
                    f"無法產生 QR Code (請安裝 qrcode + Pillow)\n\n"
                    f"手動輸入 Secret:\n{secret}")

            secret = security.get_totp_secret()
            self.totp_secret_label.setText(f"手動輸入 Secret (備用): {secret}")

            rc_text = "救援碼 / Recovery Codes (各僅可使用一次):\n\n"
            for i, code in enumerate(recovery_codes, 1):
                rc_text += f"  [{i}]  {code}\n"
            self.recovery_display.setText(rc_text)

            self.chk_confirm.setEnabled(True)
            self.btn_generate_setup.setEnabled(False)
            self.pin_input.setEnabled(False)
            self.pin_confirm.setEnabled(False)

        except Exception as e:
            QMessageBox.critical(self, "設定失敗 / Setup Failed", str(e))

    def _on_confirm_change(self, state):
        self.btn_finish.setEnabled(state == Qt.CheckState.Checked.value)

    def get_result(self) -> tuple[str, list[str]]:
        return self._totp_uri, self._recovery_codes


# ═══════════════════════════════════════════════════════════
#  Dialog: PIN Entry
# ═══════════════════════════════════════════════════════════

class PinDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("enCPTO v6 — PIN 驗證 / PIN Verification")
        self.setFixedSize(380, 280)
        self.setModal(True)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)
        self._verified      = False
        self._lockout_timer = QTimer(self)
        self._lockout_timer.timeout.connect(self._update_lockout)
        self._build_ui()
        self._update_status()

    def _build_ui(self):
        self.setStyleSheet("""
            QDialog { background: #1a1a2e; color: #e0e0e0; }
            QLabel  { color: #e0e0e0; }
            QLineEdit {
                background: #16213e; color: #e0e0e0;
                border: 1px solid #0f3460; border-radius: 4px;
                padding: 8px; font-size: 16px; letter-spacing: 2px;
            }
            QPushButton {
                background: #0f3460; color: #e0e0e0;
                border: none; border-radius: 4px;
                padding: 10px; font-weight: bold; font-size: 13px;
            }
            QPushButton:hover   { background: #1a4a80; }
            QPushButton:pressed { background: #0a2040; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        icon_label = QLabel("🔒")
        icon_label.setFont(QFont("Arial", 32))
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)

        title = QLabel("請輸入 PIN 碼以解鎖 enCPTO\nEnter PIN to unlock enCPTO")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 11))
        layout.addWidget(title)

        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("PIN")
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pin_input.returnPressed.connect(self._verify)
        layout.addWidget(self.pin_input)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.status_label)

        self.btn_verify = QPushButton("解鎖 / Unlock")
        self.btn_verify.clicked.connect(self._verify)
        layout.addWidget(self.btn_verify)

        layout.addStretch()

    def _update_status(self):
        locked, remaining = security.is_locked_out()
        if locked:
            self.pin_input.setEnabled(False)
            self.btn_verify.setEnabled(False)
            self.status_label.setText(
                f"🔒 已鎖定 {remaining:.0f} 秒 / Locked for {remaining:.0f}s")
            self.status_label.setStyleSheet("color: #f87171;")
            self._lockout_timer.start(1000)
        else:
            self._lockout_timer.stop()
            self.pin_input.setEnabled(True)
            self.btn_verify.setEnabled(True)
            attempts = security.remaining_pin_attempts()
            if attempts < MAX_PIN_ATTEMPTS:
                self.status_label.setText(
                    f"⚠️  剩餘嘗試次數: {attempts} / Remaining attempts: {attempts}")
                self.status_label.setStyleSheet("color: orange;")
            else:
                self.status_label.setText(
                    f"剩餘嘗試次數: {MAX_PIN_ATTEMPTS} 次 / {MAX_PIN_ATTEMPTS} attempts")
                self.status_label.setStyleSheet("color: gray; font-size: 11px;")

    def _update_lockout(self):
        locked, remaining = security.is_locked_out()
        if locked:
            self.status_label.setText(
                f"🔒 已鎖定 {remaining:.0f} 秒 / Locked for {remaining:.0f}s")
        else:
            self._lockout_timer.stop()
            self._update_status()

    def _verify(self):
        locked, _ = security.is_locked_out()
        if locked:
            return
        pin = self.pin_input.text()
        if not pin:
            return
        pin_bytes = pin.encode('utf-8')
        ok        = security.verify_pin(pin)
        _secure_zero_bytes(pin_bytes)
        self.pin_input.clear()

        if ok:
            self._verified = True
            self.accept()
        else:
            self._update_status()
            locked_now, _ = security.is_locked_out()
            if locked_now:
                QMessageBox.warning(self, "已鎖定 / Locked",
                    f"PIN 錯誤次數過多，已鎖定 {PIN_LOCKOUT_SECONDS} 秒。\n"
                    f"Too many failed attempts. Locked for {PIN_LOCKOUT_SECONDS}s.")
            else:
                remain = security.remaining_pin_attempts()
                self.status_label.setText(
                    f"❌ PIN 錯誤，剩餘 {remain} 次 / Wrong PIN, {remain} tries left")
                self.status_label.setStyleSheet("color: #f87171;")

    @property
    def verified(self) -> bool:
        return self._verified

    def closeEvent(self, event):
        if not self._verified:
            event.ignore()


# ═══════════════════════════════════════════════════════════
#  Dialog: TOTP Verification
# ═══════════════════════════════════════════════════════════

class TOTPDialog(QDialog):
    def __init__(self, operation: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("enCPTO v6 — TOTP 驗證 / TOTP Verification")
        self.setFixedSize(450, 350)
        self.setModal(True)
        self._verified  = False
        self._operation = operation
        self._build_ui()

    def _build_ui(self):
        self.setStyleSheet("""
            QDialog { background: #1a1a2e; color: #e0e0e0; }
            QLabel  { color: #e0e0e0; }
            QLineEdit {
                background: #16213e; color: #80cbc4;
                border: 1px solid #0f3460; border-radius: 4px;
                padding: 10px; font-size: 24px; letter-spacing: 6px;
                text-align: center;
            }
            QPushButton {
                background: #0f3460; color: #e0e0e0;
                border: none; border-radius: 4px;
                padding: 10px; font-weight: bold; font-size: 13px;
            }
            QPushButton:hover   { background: #1a4a80; }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        icon = QLabel("🔐")
        icon.setFont(QFont("Arial", 28))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        op_text = f"操作: {self._operation}" if self._operation else ""
        title   = QLabel(
            f"請輸入驗證器 6 位數碼以確認操作\n"
            f"Enter 6-digit TOTP code to confirm\n{op_text}"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 10))
        layout.addWidget(title)

        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("000000")
        self.totp_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.totp_input.setMaxLength(6)
        self.totp_input.returnPressed.connect(self._verify)
        layout.addWidget(self.totp_input)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(self.status_label)

        btn_row    = QHBoxLayout()
        self.btn_verify = QPushButton("✅ 驗證 / Verify")
        self.btn_verify.clicked.connect(self._verify)
        btn_cancel = QPushButton("❌ 取消 / Cancel")
        btn_cancel.setStyleSheet(
            "QPushButton { background: #4a1010; }"
            "QPushButton:hover { background: #6a1515; }")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(self.btn_verify)
        btn_row.addWidget(btn_cancel)
        layout.addLayout(btn_row)

        self.btn_use_recovery = QPushButton(
            f"🆘 使用救援碼 / Use Recovery Code  "
            f"(剩餘 {security.remaining_recovery_codes()} 組)")
        self.btn_use_recovery.setStyleSheet(
            "QPushButton { background: #3d1f00; color: #ffa07a; font-size: 11px; }"
            "QPushButton:hover { background: #5a2e00; }")
        self.btn_use_recovery.clicked.connect(self._use_recovery)
        layout.addWidget(self.btn_use_recovery)

    def _verify(self):
        code = self.totp_input.text().strip()
        if len(code) != 6 or not code.isdigit():
            self.status_label.setText("請輸入 6 位數字 / Enter 6 digits")
            self.status_label.setStyleSheet("color: orange;")
            return
        if security.verify_totp(code):
            self._verified = True
            self.accept()
        else:
            self.totp_input.clear()
            self.status_label.setText("❌ 驗證碼錯誤或已過期 / Invalid or expired code")
            self.status_label.setStyleSheet("color: #f87171;")

    def _use_recovery(self):
        code, ok = _input_dialog_secure(
            self,
            "使用救援碼 / Use Recovery Code",
            "請輸入救援碼 (格式: XXXX-XXXX-XXXX-XXXX)\nEnter recovery code:"
        )
        if not ok or not code:
            return
        if security.verify_recovery_code(code):
            remaining = security.remaining_recovery_codes()
            QMessageBox.information(
                self, "救援碼有效 / Recovery Code Valid",
                f"✅ 救援碼已接受並標記為已使用。\n"
                f"剩餘可用救援碼: {remaining} 組\n\n"
                f"Recovery code accepted and marked as used.\n"
                f"Remaining codes: {remaining}"
            )
            self._verified = True
            self.accept()
        else:
            QMessageBox.warning(
                self, "無效救援碼 / Invalid Recovery Code",
                "此救援碼無效或已被使用。\nThis code is invalid or already used."
            )

    @property
    def verified(self) -> bool:
        return self._verified


def _input_dialog_secure(parent, title: str, prompt: str) -> tuple[str, bool]:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setFixedSize(420, 160)
    dlg.setStyleSheet("""
        QDialog { background: #1a1a2e; color: #e0e0e0; }
        QLabel  { color: #e0e0e0; }
        QLineEdit {
            background: #16213e; color: #80cbc4;
            border: 1px solid #0f3460; border-radius: 4px;
            padding: 8px; font-size: 13px; font-family: Consolas, monospace;
        }
        QPushButton {
            background: #0f3460; color: #e0e0e0;
            border: none; border-radius: 4px; padding: 8px 16px; font-weight: bold;
        }
        QPushButton:hover { background: #1a4a80; }
    """)
    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.addWidget(QLabel(prompt))
    edit = QLineEdit()
    edit.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addWidget(edit)
    btns = QDialogButtonBox(
        QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    btns.accepted.connect(dlg.accept)
    btns.rejected.connect(dlg.reject)
    layout.addWidget(btns)
    result = dlg.exec()
    text   = edit.text()
    edit.clear()
    return text, result == QDialog.DialogCode.Accepted


# ═══════════════════════════════════════════════════════════
#  Language strings
# ═══════════════════════════════════════════════════════════
LANGUAGES = {
    "TW": {
        "app_title":            "enCPTO v6.2 - Argon2id + AES-256 + HMAC-SHA256 + MFA + GPU + 設定頁面",
        "btn_lang":             "🌐 Switch to English",
        "title_label":          "軍規級雙層加密工具 v6.2",
        "tab_main":             "🔐 加密 / 解密",
        "tab_settings":         "⚙ 設定",
        "btn_select_input":     "📂 選擇檔案",
        "btn_select_dir":       "📁 選擇資料夾",
        "input_empty":          "輸入: 尚未選擇",
        "input_loaded":         "檔案: {0}",
        "input_dir_loaded":     "資料夾: {0}",
        "pwd_label":            "加密金鑰 (要求高強度):",
        "chk_show_pwd":         "顯示密碼",
        "str_req":              "強度: 必須填寫 (最少 8 碼)",
        "str_short":            "強度: 太短 (最少 8 碼)",
        "str_weak":             "強度: 弱 (需混合大小寫、數字或符號)",
        "str_ok":               "強度: 安全 ✅",
        "out_empty":            "輸出: 尚未設定",
        "out_loaded":           "輸出: {0}",
        "chk_shred":            "🗑 加密後以 DoD 5220.22-M 安全粉碎原始檔案",
        "shred_warn_title":     "⚠️ 不可逆操作確認",
        "shred_warn_body":      ("您即將永久銷毀原始檔案！\n\n"
                                 "三階段覆寫 (0x00 → 0xFF → 亂數) 後無法還原。\n\n確定要繼續嗎？"),
        "btn_encrypt":          "🔥 加密 (Argon2id + AES-256 + HMAC)",
        "btn_decrypt":          "🔑 解密還原",
        "preview_title":        "檔案預覽",
        "preview_drop":         "請將檔案或資料夾拖放到此處\n或點擊左側選擇",
        "preview_enc":          "[ 已加密的 DAT 檔案 ]\n內容無法預覽",
        "preview_enc_v6":       "[ V6 加密檔案 ]\n原始檔名: {0}\n內容無法預覽",
        "preview_dir":          "[ 資料夾已選取 ]\n{0}\n共 {1} 個檔案，約 {2}",
        "preview_unk":          "[ 不支援預覽的檔案格式 ]\n{0}",
        "status_ready":         "就緒。  MFA: ✅ 已啟用  |  V6 格式 (自動嵌入檔名)",
        "status_zip_run":       "⏳ 打包資料夾中…",
        "status_enc_run":       "⏳ Argon2id 金鑰推導 + AES-256 加密中…",
        "status_enc_ok":        "加密完成！",
        "status_enc_fail":      "加密失敗。",
        "status_dec_run":       "⏳ 驗證 HMAC 與解密中…",
        "status_dec_ok":        "解密成功！",
        "status_dec_fail":      "解密失敗。",
        "msg_warn":             "警告",
        "msg_err":              "錯誤",
        "msg_succ":             "成功",
        "err_no_file":          "請先選擇要處理的檔案或資料夾。",
        "err_weak_pwd":         ("拒絕弱密碼！\n\n密碼必須：\n1. 長度超過 8 碼\n"
                                 "2. 包含大小寫字母、數字、特殊符號中的至少三種。"),
        "err_not_dat":          "請選擇一個有效的 .dat 加密檔案。",
        "err_no_pwd":           "請輸入解密金鑰。",
        "err_wrong_pwd":        "解密失敗！密碼錯誤、HMAC 不符，或檔案已遭竄改。",
        "err_no_argon2":        "請先安裝 argon2-cffi：\npip install argon2-cffi",
        "err_totp_cancel":      "操作已取消：未通過 TOTP 驗證。",
        "succ_enc":             "檔案已使用 Argon2id + AES-256 + HMAC-SHA256 保護！\n儲存至：{0}",
        "succ_enc_dir":         "資料夾已打包加密！\n儲存至：{0}",
        "succ_dec":             "解密成功！\n儲存至：{0}",
        "succ_dec_dir":         "ZIP 已解密並還原至：\n{0}",
        # Settings tab
        "sect_appearance":      "🎨 外觀",
        "theme_label":          "主題:",
        "bg_image_label":       "背景圖片:",
        "btn_select_bg":        "🖼 選擇圖片",
        "btn_clear_bg":         "✖ 清除",
        "bg_opacity_label":     "背景透明度: {0}%",
        "bg_opacity_hint":      "0% = 背景完全可見（無遮罩）  |  100% = 純主題色（完全遮蓋）",
        "widget_opacity_label": "元件不透明度: {0}%",
        "widget_opacity_hint":  "0% = 元件完全透明  |  100% = 元件完全不透明 (建議 70~90%)",
        "bg_current":           "目前: {0}",
        "bg_none":              "未設定背景圖片",
        "bg_set_ok":            "背景圖片已設定！",
        "bg_clear_ok":          "背景圖片已清除。",
        "sect_gpu":             "⚡ GPU 加速 (OpenCL)",
        "gpu_found":            "✅ 已偵測到 GPU: {0}",
        "gpu_none":             "❌ 未偵測到 GPU (需安裝 pyopencl + numpy)",
        "chk_gpu":              "啟用 GPU 加速 (AES-256-CTR on GPU)",
        "gpu_mode_on":          "模式: AES-256-CTR + HMAC [GPU ⚡] + Argon2id",
        "gpu_mode_off":         "模式: AES-256-GCM + HMAC [CPU] + Argon2id",
        "kdf_label":            "KDF: Argon2id (t=3, m=64MB, p=4)",
        "chunk_label":          "分塊: 4 MB/區塊  |  安全歸零: ctypes + mmap",
        "sect_shred":           "🗑 安全粉碎 (DoD 5220.22-M)",
        "shred_desc":           "加密/解密後粉碎來源檔案 (三階段覆寫，不可逆)",
        "sect_gen":             "🔑 強密碼產生器",
        "gen_length":           "長度: {0} 碼",
        "gen_upper":            "大寫 A-Z",
        "gen_lower":            "小寫 a-z",
        "gen_digits":           "數字 0-9",
        "gen_symbols":          "符號 !@#…",
        "gen_no_ambig":         "排除易混淆字元 (0/O/l/1/I)",
        "btn_generate":         "⚡ 產生密碼",
        "btn_copy_pwd":         "📋 複製至密碼欄",
        "gen_copied":           "密碼已複製到主介面密碼欄！",
        "gen_err_pool":         "請至少勾選一個字元集。",
        "sect_mfa":             "🔐 MFA 狀態",
        "mfa_status_ok":        "✅ MFA 已啟用 (PIN + TOTP)",
        "mfa_rc_remain":        "救援碼剩餘: {0} 組",
        "btn_reset_mfa":        "⚙️ 重設 MFA (危險操作)",
        "mfa_reset_warn":       ("⚠️ 重設 MFA 將清除所有 PIN、TOTP 設定與救援碼！\n\n"
                                 "下次啟動需重新完成設定精靈。\n確定要繼續嗎？"),
    },
    "EN": {
        "app_title":            "enCPTO v6.2 - Argon2id + AES-256 + HMAC-SHA256 + MFA + GPU + Settings",
        "btn_lang":             "🌐 切換至中文",
        "title_label":          "Military-Grade Dual-Layer Encryption v6.2",
        "tab_main":             "🔐 Encrypt / Decrypt",
        "tab_settings":         "⚙ Settings",
        "btn_select_input":     "📂 Select File",
        "btn_select_dir":       "📁 Select Folder",
        "input_empty":          "Input: Not selected",
        "input_loaded":         "File: {0}",
        "input_dir_loaded":     "Folder: {0}",
        "pwd_label":            "Encryption Key (Strong required):",
        "chk_show_pwd":         "Show Password",
        "str_req":              "Strength: Required (Min 8 chars)",
        "str_short":            "Strength: Too Short (< 8 chars)",
        "str_weak":             "Strength: Weak (Mix case/num/sym)",
        "str_ok":               "Strength: Secure ✅",
        "out_empty":            "Output: Not set",
        "out_loaded":           "Output: {0}",
        "chk_shred":            "🗑 Securely shred source file(s) after encryption (DoD 5220.22-M)",
        "shred_warn_title":     "⚠️ Irreversible Operation",
        "shred_warn_body":      ("You are about to permanently destroy the source file(s)!\n\n"
                                 "Three-pass overwrite makes recovery impossible.\n\nContinue?"),
        "btn_encrypt":          "🔥 Encrypt (Argon2id + AES-256 + HMAC)",
        "btn_decrypt":          "🔑 Decrypt File",
        "preview_title":        "File Preview",
        "preview_drop":         "Drag & Drop file or folder here\nor click select button",
        "preview_enc":          "[ Encrypted DAT File ]\nPreview unavailable",
        "preview_enc_v6":       "[ V6 Encrypted File ]\nOriginal filename: {0}\nPreview unavailable",
        "preview_dir":          "[ Folder Selected ]\n{0}\n{1} files, approx. {2}",
        "preview_unk":          "[ Unsupported Preview Format ]\n{0}",
        "status_ready":         "Ready.  MFA: ✅ Enabled  |  Format: V6 (auto filename embed)",
        "status_zip_run":       "⏳ Packing folder into ZIP stream…",
        "status_enc_run":       "⏳ Argon2id key derivation + AES-256 encryption…",
        "status_enc_ok":        "Encryption complete!",
        "status_enc_fail":      "Encryption failed.",
        "status_dec_run":       "⏳ Verifying HMAC and decrypting…",
        "status_dec_ok":        "Decryption complete!",
        "status_dec_fail":      "Decryption failed.",
        "msg_warn":             "Warning",
        "msg_err":              "Error",
        "msg_succ":             "Success",
        "err_no_file":          "Please select a file or folder first.",
        "err_weak_pwd":         ("Weak passwords are rejected!\n\nPassword must:\n"
                                 "1. Be > 8 chars\n2. Contain ≥3 of: upper, lower, numbers, symbols."),
        "err_not_dat":          "Please select a valid .dat encrypted file.",
        "err_no_pwd":           "Please enter the decryption key.",
        "err_wrong_pwd":        "Decryption failed!\nWrong password, HMAC mismatch, or tampered file.",
        "err_no_argon2":        "Please install argon2-cffi first:\npip install argon2-cffi",
        "err_totp_cancel":      "Operation cancelled: TOTP verification failed.",
        "succ_enc":             "File secured with Argon2id + AES-256 + HMAC-SHA256!\nSaved to: {0}",
        "succ_enc_dir":         "Folder packed and encrypted!\nSaved to: {0}",
        "succ_dec":             "File decrypted!\nSaved to: {0}",
        "succ_dec_dir":         "ZIP decrypted and extracted to:\n{0}",
        # Settings tab
        "sect_appearance":      "🎨 Appearance",
        "theme_label":          "Theme:",
        "bg_image_label":       "Background Image:",
        "btn_select_bg":        "🖼 Select Image",
        "btn_clear_bg":         "✖ Clear",
        "bg_opacity_label":     "Background Opacity: {0}%",
        "bg_opacity_hint":      "0% = background fully visible (no overlay)  |  100% = solid theme colour",
        "widget_opacity_label": "Widget Opacity: {0}%",
        "widget_opacity_hint":  "0% = fully transparent  |  100% = fully opaque (recommended 70-90%)",
        "bg_current":           "Current: {0}",
        "bg_none":              "No background image set",
        "bg_set_ok":            "Background image set!",
        "bg_clear_ok":          "Background image cleared.",
        "sect_gpu":             "⚡ GPU Booster (OpenCL)",
        "gpu_found":            "✅ GPU detected: {0}",
        "gpu_none":             "❌ No GPU found (install pyopencl + numpy)",
        "chk_gpu":              "Enable GPU Acceleration (AES-256-CTR on GPU)",
        "gpu_mode_on":          "Mode: AES-256-CTR + HMAC [GPU ⚡] + Argon2id",
        "gpu_mode_off":         "Mode: AES-256-GCM + HMAC [CPU] + Argon2id",
        "kdf_label":            "KDF: Argon2id (t=3, m=64MB, p=4)",
        "chunk_label":          "Chunk: 4 MB/block  |  Secure wipe: ctypes + mmap",
        "sect_shred":           "🗑 Secure Shredder (DoD 5220.22-M)",
        "shred_desc":           "Shred source files after encrypt/decrypt (3-pass overwrite, irreversible)",
        "sect_gen":             "🔑 Strong Password Generator",
        "gen_length":           "Length: {0} chars",
        "gen_upper":            "Uppercase A-Z",
        "gen_lower":            "Lowercase a-z",
        "gen_digits":           "Digits 0-9",
        "gen_symbols":          "Symbols !@#…",
        "gen_no_ambig":         "Exclude ambiguous chars (0/O/l/1/I)",
        "btn_generate":         "⚡ Generate Password",
        "btn_copy_pwd":         "📋 Copy to Password Field",
        "gen_copied":           "Password copied to the main password field!",
        "gen_err_pool":         "Please select at least one character set.",
        "sect_mfa":             "🔐 MFA Status",
        "mfa_status_ok":        "✅ MFA Active (PIN + TOTP)",
        "mfa_rc_remain":        "Recovery codes remaining: {0}",
        "btn_reset_mfa":        "⚙️ Reset MFA (Dangerous)",
        "mfa_reset_warn":       ("⚠️ Resetting MFA will erase all PIN, TOTP settings and recovery codes!\n\n"
                                 "You will need to complete setup again on next launch.\nContinue?"),
    },
}


# ═══════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════

def _count_dir_files(dir_path: str) -> tuple[int, int]:
    total_files = 0
    total_bytes = 0
    for root, _, files in os.walk(dir_path):
        for fname in files:
            total_files += 1
            try:
                total_bytes += os.path.getsize(os.path.join(root, fname))
            except OSError:
                pass
    return total_files, total_bytes


def _human_size(n: int) -> str:
    for unit in ('B','KB','MB','GB','TB'):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ═══════════════════════════════════════════════════════════
#  ThemedCentralWidget
#  ─────────────────────────────────────────────────────────
#  Key design:
#   • Always paints the background itself in paintEvent.
#   • opacity slider controls the OVERLAY alpha:
#       0%  → overlay alpha = 0   → background fully visible
#       100%→ overlay alpha = 255 → only theme colour visible
#   • All child widgets use rgba() so the painted background
#     shows through.
# ═══════════════════════════════════════════════════════════

class ThemedCentralWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # overlay colour — set from theme
        self._overlay_r   = 30
        self._overlay_g   = 30
        self._overlay_b   = 46
        # solid bg colour used when no image is set
        self._bg_r        = 30
        self._bg_g        = 30
        self._bg_b        = 46
        self._bg_pixmap: QPixmap | None = None
        self._overlay_alpha = 0      # computed from ui_prefs.bg_opacity
        self.reload_background()
        self._sync_alpha()
        # Must paint background ourselves; children are transparent
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

    # ── background image ─────────────────────────────────────

    def reload_background(self):
        path = ui_prefs.bg_image
        if path:
            px = QPixmap(path)
            if not px.isNull():
                self._bg_pixmap = px
                return
        self._bg_pixmap = None

    # ── overlay colour (set when theme changes) ───────────────

    def set_overlay_rgb(self, r: int, g: int, b: int):
        self._overlay_r = r
        self._overlay_g = g
        self._overlay_b = b
        self._bg_r      = r
        self._bg_g      = g
        self._bg_b      = b

    # ── opacity sync ─────────────────────────────────────────

    def _sync_alpha(self):
        """
        ui_prefs.bg_opacity is 0-100.
          0  → overlay alpha 0   (fully transparent → image/bg fully visible)
          100→ overlay alpha 255 (fully opaque → pure theme colour)
        """
        self._overlay_alpha = int(ui_prefs.bg_opacity * 255 / 100)

    def set_opacity(self, pct: int):
        """Called live when the slider moves."""
        ui_prefs.bg_opacity = pct
        self._sync_alpha()
        self.update()

    # ── painting ─────────────────────────────────────────────

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

        if self._bg_pixmap and not self._bg_pixmap.isNull():
            # 1. Draw the background image, scaled to fill
            scaled = self._bg_pixmap.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = (self.width()  - scaled.width())  // 2
            y = (self.height() - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)
            # 2. Draw semi-transparent theme-colour overlay
            if self._overlay_alpha > 0:
                overlay = QColor(
                    self._overlay_r, self._overlay_g, self._overlay_b,
                    self._overlay_alpha,
                )
                painter.fillRect(self.rect(), overlay)
        else:
            # No image: fill with solid theme colour tinted by opacity
            # opacity=0 → nearly transparent grey; opacity=100 → full theme colour
            # For usability we always show the theme bg when no image is set
            painter.fillRect(
                self.rect(),
                QColor(self._bg_r, self._bg_g, self._bg_b, 255),
            )


# ═══════════════════════════════════════════════════════════
#  Main Application
# ═══════════════════════════════════════════════════════════
class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.input_file_path  = ""
        self.input_dir_path   = ""
        self.output_file_path = ""
        self.current_lang     = "TW"
        self._worker          = None

        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(self._check_auto_theme)
        self._auto_timer.start(60_000)

        self.init_ui()
        self._apply_theme(ui_prefs.theme)
        self.update_ui_language()

    def gt(self, key, *args):
        t = LANGUAGES[self.current_lang].get(key, key)
        return t.format(*args) if args else t

    # ── Theme application ────────────────────────────────────

    def _apply_theme(self, theme_name: str):
        t = get_theme(theme_name)

        # Update the central widget's overlay colour
        try:
            rgb = t["overlay_rgb"]
            self._central.set_overlay_rgb(*rgb)
            self._central._sync_alpha()
            self._central.update()
        except Exception:
            pass

        mono_font = ""
        if _resolve_theme_name(theme_name) == "Deep Hacker":
            mono_font = "font-family: 'Courier New', monospace;"

        # ── rgba values for semi-transparent child backgrounds ──
        bg_rgb      = _hex_to_rgb(t['bg'])
        bg2_rgb     = _hex_to_rgb(t['bg2'])
        bg3_rgb     = _hex_to_rgb(t['bg3'])
        input_rgb   = _hex_to_rgb(t['input_bg'])
        tab_rgb     = _hex_to_rgb(t['tab_bg'])
        tab_sel_rgb = _hex_to_rgb(t['tab_sel_bg'])
        btn_rgb     = _hex_to_rgb(t['btn_bg'])
        btn_hov_rgb = _hex_to_rgb(t['btn_hover'])
        warn_rgb    = _hex_to_rgb(t.get('warning_bg', '#1a0a0a'))

        # 從 ui_prefs 讀取使用者的元件不透明度設定 (0~100 轉換為 0~255)
        child_a = int(ui_prefs.widget_opacity * 255 / 100)

        qss = f"""
        QMainWindow, QWidget {{
            background-color: transparent;
            color: {t['fg']};
            {mono_font}
        }}
        QTabWidget::pane {{
            border: 1px solid {t['border']};
            border-radius: 4px;
            background: rgba({bg_rgb}, {child_a});
        }}
        QTabBar::tab {{
            background: rgba({tab_rgb}, {child_a});
            color: {t['fg2']};
            padding: 8px 20px;
            border: 1px solid {t['border']};
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
            font-weight: bold;
        }}
        QTabBar::tab:selected {{
            background: rgba({tab_sel_rgb}, {child_a});
            color: {t['tab_sel']};
            border-bottom: 2px solid {t['tab_sel']};
        }}
        QTabBar::tab:hover:!selected {{
            background: rgba({btn_hov_rgb}, {child_a});
        }}
        QGroupBox {{
            color: {t['group_fg']};
            border: 1px solid {t['border']};
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 6px;
            background: rgba({bg2_rgb}, {child_a});
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 8px;
            color: {t['accent']};
            font-weight: bold;
        }}
        QLabel {{ color: {t['fg2']}; background: transparent; }}
        QLineEdit {{
            background: rgba({input_rgb}, {child_a});
            color: {t['input_fg']};
            border: 1px solid {t['border']};
            border-radius: 3px;
            padding: 4px;
        }}
        QTextEdit {{
            background: rgba({bg3_rgb}, {child_a});
            color: {t['fg']};
            border: 1px solid {t['border']};
            border-radius: 3px;
            padding: 4px;
        }}
        QPushButton {{
            background: rgba({btn_rgb}, {child_a});
            color: {t['fg']};
            border: 1px solid {t['border']};
            border-radius: 4px;
            padding: 6px;
        }}
        QPushButton:hover {{ background: rgba({btn_hov_rgb}, {child_a}); }}
        QCheckBox {{ color: {t['fg2']}; background: transparent; }}
        QComboBox {{
            background: rgba({input_rgb}, {child_a});
            color: {t['input_fg']};
            border: 1px solid {t['border']};
            border-radius: 3px;
            padding: 3px 6px;
        }}
        QComboBox::drop-down {{ border: none; width: 18px; }}
        QComboBox QAbstractItemView {{
            background: rgba({bg2_rgb}, 240);
            color: {t['fg']};
            border: 1px solid {t['border2']};
            selection-background-color: {t['border2']};
        }}
        QScrollArea {{ background: transparent; border: none; }}
        QScrollBar:vertical {{
            background: rgba({bg3_rgb}, 180);
            width: 8px;
            border-radius: 4px;
        }}
        QScrollBar::handle:vertical {{
            background: {t['border']};
            border-radius: 4px;
            min-height: 20px;
        }}
        QStatusBar {{
            background: rgba({_hex_to_rgb(t['status_bg'])}, 220);
            color: {t['status_fg']};
        }}
        QProgressBar {{
            border: 1px solid {t['border']};
            border-radius: 3px;
            background: rgba({bg3_rgb}, 180);
            color: #fff;
            text-align: center;
        }}
        QProgressBar::chunk {{
            background: {t['accent2']};
            border-radius: 3px;
        }}
        QSlider::groove:horizontal {{
            height: 4px;
            background: {t['border']};
            border-radius: 2px;
        }}
        QSlider::handle:horizontal {{
            width: 14px; height: 14px;
            margin: -5px 0;
            background: {t['accent']};
            border-radius: 7px;
        }}
        QSlider::sub-page:horizontal {{
            background: {t['accent2']};
            border-radius: 2px;
        }}
        QStackedWidget {{
            background: rgba({bg3_rgb}, {child_a});
            border: 2px dashed {t['border']};
            border-radius: 6px;
        }}
        """

        QApplication.instance().setStyleSheet(qss)

        try:
            self.btn_encrypt.setStyleSheet(
                f"background-color:rgba({_hex_to_rgb(t['enc_btn'])},{child_a});"
                "color:white;padding:12px;font-weight:bold;border-radius:5px;font-size:13px;")
            self.btn_decrypt.setStyleSheet(
                f"background-color:rgba({_hex_to_rgb(t['dec_btn'])},{child_a});"
                "color:white;padding:12px;font-weight:bold;border-radius:5px;font-size:13px;")
        except AttributeError:
            pass

    def _check_auto_theme(self):
        if ui_prefs.theme == "Auto":
            self._apply_theme("Auto")

    # ── Busy state ───────────────────────────────────────────

    def _set_busy(self, busy: bool):
        self.btn_encrypt.setEnabled(not busy)
        self.btn_decrypt.setEnabled(not busy)
        self.btn_select_input.setEnabled(not busy)
        self.btn_select_dir.setEnabled(not busy)
        self.progress_bar.setVisible(busy)
        if not busy:
            self.progress_bar.setValue(0)

    def _require_totp(self, operation: str) -> bool:
        dlg = TOTPDialog(operation=operation, parent=self)
        dlg.exec()
        return dlg.verified

    # ── UI construction ──────────────────────────────────────

    def init_ui(self):
        self.resize(1020, 760)
        self.setMinimumSize(820, 600)
        self.setAcceptDrops(True)

        self._central = ThemedCentralWidget()
        self.setCentralWidget(self._central)

        root_layout = QVBoxLayout(self._central)
        root_layout.setContentsMargins(8, 8, 8, 0)
        root_layout.setSpacing(4)

        # ── Top bar ───────────────────────────────────────────
        top_bar = QHBoxLayout()
        self.btn_toggle_lang = QPushButton()
        self.btn_toggle_lang.clicked.connect(self.toggle_language)
        self.btn_toggle_lang.setMaximumWidth(180)
        self.btn_toggle_lang.setStyleSheet(
            "QPushButton{background:#4a4a4a;color:#fff;padding:5px 10px;"
            "border-radius:4px;font-weight:bold;border:none;}"
            "QPushButton:hover{background:#5e5e5e;}")
        self.title_label = QLabel()
        self.title_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top_bar.addWidget(self.btn_toggle_lang)
        top_bar.addWidget(self.title_label, 1)
        top_bar.addSpacing(180)
        root_layout.addLayout(top_bar)

        # ── Tab widget ────────────────────────────────────────
        self.tabs = QTabWidget()
        root_layout.addWidget(self.tabs, 1)

        self._build_main_tab()
        self._build_settings_tab()

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    # ── Main tab ─────────────────────────────────────────────

    def _build_main_tab(self):
        main_widget = QWidget()
        main_widget.setStyleSheet("background: transparent;")
        main_h = QHBoxLayout(main_widget)
        main_h.setContentsMargins(4, 8, 4, 8)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFixedWidth(420)
        left_scroll.setFrameShape(QFrame.Shape.NoFrame)
        left_inner = QWidget()
        left_inner.setStyleSheet("background: transparent;")
        left = QVBoxLayout(left_inner)
        left.setSpacing(8)
        left.setContentsMargins(4, 4, 4, 4)

        input_row = QHBoxLayout()
        self.btn_select_input = QPushButton()
        self.btn_select_input.clicked.connect(self.select_input_file)
        self.btn_select_dir   = QPushButton()
        self.btn_select_dir.clicked.connect(self.select_input_directory)
        self.btn_select_dir.setStyleSheet(
            "QPushButton{background:#1565c0;color:#fff;padding:6px 10px;"
            "border-radius:4px;font-weight:bold;border:none;}"
            "QPushButton:hover{background:#1976d2;}")
        input_row.addWidget(self.btn_select_input)
        input_row.addWidget(self.btn_select_dir)
        left.addLayout(input_row)

        self.input_label = QLabel()
        self.input_label.setWordWrap(True)
        self.input_label.setStyleSheet("font-size:11px;background:transparent;")
        left.addWidget(self.input_label)

        self.pwd_label = QLabel()
        self.pwd_entry = QLineEdit()
        self.pwd_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_entry.textChanged.connect(self.check_password_strength)

        chk_row = QHBoxLayout()
        self.chk_show_pwd = QCheckBox()
        self.chk_show_pwd.stateChanged.connect(self.toggle_password_visibility)
        self.strength_label = QLabel()
        self.strength_label.setStyleSheet("color:gray;font-size:11px;background:transparent;")
        chk_row.addWidget(self.chk_show_pwd)
        chk_row.addWidget(self.strength_label, 1)

        left.addWidget(self.pwd_label)
        left.addWidget(self.pwd_entry)
        left.addLayout(chk_row)

        self.output_label = QLabel()
        self.output_label.setWordWrap(True)
        self.output_label.setStyleSheet("font-size:11px;background:transparent;")
        left.addWidget(self.output_label)

        shred_box = QGroupBox()
        shred_box.setStyleSheet(
            "QGroupBox{border:1px solid #7f1d1d;border-radius:4px;"
            "margin-top:6px;padding-top:6px;background:rgba(26,10,10,160);}"
            "QGroupBox::title{subcontrol-origin:margin;left:8px;color:#f87171;font-weight:bold;}")
        shred_lay = QVBoxLayout(shred_box)
        shred_lay.setContentsMargins(8, 14, 8, 8)
        self.chk_shred = QCheckBox()
        self.chk_shred.setStyleSheet(
            "QCheckBox{color:#fca5a5;font-size:11px;background:transparent;}"
            "QCheckBox::indicator:checked{background:#dc2626;border:2px solid #ef4444;border-radius:3px;}"
            "QCheckBox::indicator:unchecked{background:transparent;border:2px solid #7f1d1d;border-radius:3px;}")
        shred_lay.addWidget(self.chk_shred)
        self._shred_box = shred_box
        left.addWidget(shred_box)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(16)
        left.addWidget(self.progress_bar)

        self.btn_encrypt = QPushButton()
        self.btn_encrypt.setMinimumHeight(44)
        self.btn_encrypt.clicked.connect(self.encrypt_action)
        self.btn_decrypt = QPushButton()
        self.btn_decrypt.setMinimumHeight(44)
        self.btn_decrypt.clicked.connect(self.decrypt_action)
        left.addWidget(self.btn_encrypt)
        left.addWidget(self.btn_decrypt)
        left.addStretch()

        left_scroll.setWidget(left_inner)
        main_h.addWidget(left_scroll)

        right = QVBoxLayout()
        right.setSpacing(4)
        self.preview_title = QLabel()
        self.preview_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.preview_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.preview_stack = QStackedWidget()
        self.preview_stack.setMinimumSize(540, 480)

        self.image_preview = QLabel()
        self.image_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_preview.setStyleSheet("background:transparent;font-size:14px;")
        self.image_preview.setWordWrap(True)

        self.text_preview = QTextEdit()
        self.text_preview.setReadOnly(True)
        self.text_preview.setFont(QFont("Consolas", 10))

        self.preview_stack.addWidget(self.image_preview)
        self.preview_stack.addWidget(self.text_preview)

        right.addWidget(self.preview_title)
        right.addWidget(self.preview_stack, 1)
        main_h.addLayout(right, 1)

        self.tabs.addTab(main_widget, "")

    # ── Settings tab ─────────────────────────────────────────

    def _build_settings_tab(self):
        settings_scroll = QScrollArea()
        settings_scroll.setWidgetResizable(True)
        settings_scroll.setFrameShape(QFrame.Shape.NoFrame)

        sw = QWidget()
        sw.setStyleSheet("background: transparent;")
        sv = QVBoxLayout(sw)
        sv.setSpacing(10)
        sv.setContentsMargins(12, 12, 12, 12)

        # ── Appearance ───────────────────────────────────────
        self._sect_appearance = QGroupBox()
        ap = QVBoxLayout(self._sect_appearance)
        ap.setSpacing(8)
        ap.setContentsMargins(10, 16, 10, 10)

        # Theme
        theme_row = QHBoxLayout()
        self.theme_label_w = QLabel()
        self.theme_label_w.setFixedWidth(90)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(THEME_NAMES)
        self.theme_combo.setCurrentText(ui_prefs.theme)
        self.theme_combo.currentTextChanged.connect(self._on_theme_changed)
        theme_row.addWidget(self.theme_label_w)
        theme_row.addWidget(self.theme_combo, 1)
        ap.addLayout(theme_row)

        # BG image row
        bg_lbl_row = QHBoxLayout()
        self.bg_image_label_w = QLabel()
        self.bg_image_label_w.setFixedWidth(90)
        self.bg_current_label = QLabel()
        self.bg_current_label.setStyleSheet("font-size:10px;background:transparent;")
        self.bg_current_label.setWordWrap(True)
        bg_lbl_row.addWidget(self.bg_image_label_w)
        bg_lbl_row.addWidget(self.bg_current_label, 1)
        ap.addLayout(bg_lbl_row)

        bg_btn_row = QHBoxLayout()
        self.btn_select_bg = QPushButton()
        self.btn_select_bg.setFixedHeight(28)
        self.btn_select_bg.clicked.connect(self._select_background)
        self.btn_clear_bg = QPushButton()
        self.btn_clear_bg.setFixedHeight(28)
        self.btn_clear_bg.clicked.connect(self._clear_background)
        self.btn_clear_bg.setStyleSheet(
            "QPushButton{background:#4a1010;color:#fca5a5;font-size:11px;"
            "border-radius:3px;border:1px solid #7f1d1d;}"
            "QPushButton:hover{background:#6a1515;}")
        bg_btn_row.addWidget(self.btn_select_bg)
        bg_btn_row.addWidget(self.btn_clear_bg)
        bg_btn_row.addStretch()
        ap.addLayout(bg_btn_row)

        # ── Opacity slider ───────────────────────────────────
        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #555;")
        ap.addWidget(sep)

        # Background Opacity slider
        opacity_row = QHBoxLayout()
        self.opacity_value_label = QLabel()
        self.opacity_value_label.setFixedWidth(210)
        self.opacity_value_label.setStyleSheet("background:transparent;")
        self.opacity_slider = QSlider(Qt.Orientation.Horizontal)
        self.opacity_slider.setRange(0, 100)
        self.opacity_slider.setValue(ui_prefs.bg_opacity)
        self.opacity_slider.setTickInterval(10)
        self.opacity_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.opacity_slider.valueChanged.connect(self._on_opacity_changed)
        opacity_row.addWidget(self.opacity_value_label)
        opacity_row.addWidget(self.opacity_slider, 1)
        ap.addLayout(opacity_row)

        self.opacity_hint_label = QLabel()
        self.opacity_hint_label.setStyleSheet(
            "color:gray;font-size:10px;margin-left:2px;background:transparent;")
        ap.addWidget(self.opacity_hint_label)

        # Widget Opacity slider
        w_opacity_row = QHBoxLayout()
        self.w_opacity_value_label = QLabel()
        self.w_opacity_value_label.setFixedWidth(210)
        self.w_opacity_value_label.setStyleSheet("background:transparent;")
        self.w_opacity_slider = QSlider(Qt.Orientation.Horizontal)
        self.w_opacity_slider.setRange(0, 100)
        self.w_opacity_slider.setValue(ui_prefs.widget_opacity)
        self.w_opacity_slider.setTickInterval(10)
        self.w_opacity_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.w_opacity_slider.valueChanged.connect(self._on_widget_opacity_changed)
        w_opacity_row.addWidget(self.w_opacity_value_label)
        w_opacity_row.addWidget(self.w_opacity_slider, 1)
        ap.addLayout(w_opacity_row)

        self.w_opacity_hint_label = QLabel()
        self.w_opacity_hint_label.setStyleSheet(
            "color:gray;font-size:10px;margin-left:2px;background:transparent;")
        ap.addWidget(self.w_opacity_hint_label)

        sv.addWidget(self._sect_appearance)

        # ── GPU ──────────────────────────────────────────────
        self._sect_gpu = QGroupBox()
        gp = QVBoxLayout(self._sect_gpu)
        gp.setContentsMargins(10, 16, 10, 10)
        gp.setSpacing(4)

        self.gpu_status_label = QLabel()
        self.gpu_status_label.setWordWrap(True)
        self.chk_gpu = QCheckBox()
        self.chk_gpu.setEnabled(GPU.available)
        self.chk_gpu.stateChanged.connect(self._update_gpu_mode_label)
        self.gpu_mode_label = QLabel()
        self.gpu_mode_label.setStyleSheet("font-size:11px;background:transparent;")
        self.kdf_label_w   = QLabel()
        self.kdf_label_w.setStyleSheet("color:#ff9800;font-size:10px;background:transparent;")
        self.chunk_label_w = QLabel()
        self.chunk_label_w.setStyleSheet("font-size:10px;background:transparent;")

        gp.addWidget(self.gpu_status_label)
        gp.addWidget(self.chk_gpu)
        gp.addWidget(self.gpu_mode_label)
        gp.addWidget(self.kdf_label_w)
        gp.addWidget(self.chunk_label_w)
        sv.addWidget(self._sect_gpu)

        # ── Password Generator ───────────────────────────────
        self._sect_gen = QGroupBox()
        gen_lay = QVBoxLayout(self._sect_gen)
        gen_lay.setContentsMargins(10, 16, 10, 10)
        gen_lay.setSpacing(6)

        len_row = QHBoxLayout()
        self.gen_length_label = QLabel()
        self.gen_length_label.setFixedWidth(120)
        self.gen_length_label.setStyleSheet("background:transparent;")
        self.gen_slider = QSlider(Qt.Orientation.Horizontal)
        self.gen_slider.setRange(8, 64)
        self.gen_slider.setValue(20)
        self.gen_slider.setTickInterval(4)
        self.gen_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.gen_slider.valueChanged.connect(self._on_gen_slider)
        len_row.addWidget(self.gen_length_label)
        len_row.addWidget(self.gen_slider, 1)
        gen_lay.addLayout(len_row)

        chk_row1 = QHBoxLayout()
        chk_row2 = QHBoxLayout()
        _cs = "QCheckBox{font-size:11px;background:transparent;}"
        self.chk_gen_upper   = QCheckBox(); self.chk_gen_upper.setChecked(True);   self.chk_gen_upper.setStyleSheet(_cs)
        self.chk_gen_lower   = QCheckBox(); self.chk_gen_lower.setChecked(True);   self.chk_gen_lower.setStyleSheet(_cs)
        self.chk_gen_digits  = QCheckBox(); self.chk_gen_digits.setChecked(True);  self.chk_gen_digits.setStyleSheet(_cs)
        self.chk_gen_symbols = QCheckBox(); self.chk_gen_symbols.setChecked(True); self.chk_gen_symbols.setStyleSheet(_cs)
        chk_row1.addWidget(self.chk_gen_upper)
        chk_row1.addWidget(self.chk_gen_lower)
        chk_row2.addWidget(self.chk_gen_digits)
        chk_row2.addWidget(self.chk_gen_symbols)
        gen_lay.addLayout(chk_row1)
        gen_lay.addLayout(chk_row2)

        self.chk_gen_no_ambig = QCheckBox()
        self.chk_gen_no_ambig.setStyleSheet(_cs)
        gen_lay.addWidget(self.chk_gen_no_ambig)

        pwd_disp_row = QHBoxLayout()
        self.gen_pwd_display = QLineEdit()
        self.gen_pwd_display.setReadOnly(True)
        self.gen_pwd_display.setPlaceholderText("—")
        self.gen_pwd_display.setStyleSheet(
            "QLineEdit{font-family:Consolas,monospace;font-size:12px;padding:4px 8px;}")
        self.btn_copy_pwd = QPushButton()
        self.btn_copy_pwd.setFixedWidth(140)
        self.btn_copy_pwd.setFixedHeight(30)
        self.btn_copy_pwd.clicked.connect(self._copy_generated_pwd)
        pwd_disp_row.addWidget(self.gen_pwd_display)
        pwd_disp_row.addWidget(self.btn_copy_pwd)
        gen_lay.addLayout(pwd_disp_row)

        self.btn_generate = QPushButton()
        self.btn_generate.setFixedHeight(34)
        self.btn_generate.clicked.connect(self._do_generate_password)
        self.btn_generate.setStyleSheet(
            "QPushButton{background:#00695c;color:#fff;font-weight:bold;"
            "border-radius:4px;border:none;font-size:12px;}"
            "QPushButton:hover{background:#00796b;}")
        gen_lay.addWidget(self.btn_generate)
        sv.addWidget(self._sect_gen)

        # ── MFA ──────────────────────────────────────────────
        self._sect_mfa = QGroupBox()
        mfa_lay = QVBoxLayout(self._sect_mfa)
        mfa_lay.setContentsMargins(10, 16, 10, 10)
        mfa_lay.setSpacing(4)

        self.mfa_status_label = QLabel()
        self.mfa_rc_label = QLabel()
        self.mfa_rc_label.setStyleSheet("font-size:10px;background:transparent;")
        self.btn_reset_mfa = QPushButton()
        self.btn_reset_mfa.setFixedHeight(28)
        self.btn_reset_mfa.setStyleSheet(
            "QPushButton{background:#4a1010;color:#fca5a5;font-size:11px;"
            "border:1px solid #7f1d1d;border-radius:3px;}"
            "QPushButton:hover{background:#6a1515;}")
        self.btn_reset_mfa.clicked.connect(self._reset_mfa)

        mfa_lay.addWidget(self.mfa_status_label)
        mfa_lay.addWidget(self.mfa_rc_label)
        mfa_lay.addWidget(self.btn_reset_mfa)
        sv.addWidget(self._sect_mfa)

        sv.addStretch()
        settings_scroll.setWidget(sw)
        self.tabs.addTab(settings_scroll, "")

    # ── Settings handlers ────────────────────────────────────

    def _on_theme_changed(self, theme_name: str):
        ui_prefs.theme = theme_name
        self._apply_theme(theme_name)

    def _select_background(self):
        fp, _ = QFileDialog.getOpenFileName(
            self, "Select Background Image", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.webp);;All Files (*.*)"
        )
        if fp:
            ui_prefs.bg_image = fp
            self._central.reload_background()
            self._central._sync_alpha()
            self._central.update()
            self._refresh_bg_label()
            # Re-apply theme so child_alpha updates for has_bg
            self._apply_theme(ui_prefs.theme)
            self.status_bar.showMessage(self.gt("bg_set_ok"), 3000)

    def _clear_background(self):
        ui_prefs.clear_bg_image()
        self._central.reload_background()
        self._central._sync_alpha()
        self._central.update()
        self._refresh_bg_label()
        self._apply_theme(ui_prefs.theme)
        self.status_bar.showMessage(self.gt("bg_clear_ok"), 3000)

    def _refresh_bg_label(self):
        path = ui_prefs.bg_image
        if path:
            self.bg_current_label.setText(self.gt("bg_current", os.path.basename(path)))
        else:
            self.bg_current_label.setText(self.gt("bg_none"))

    def _on_opacity_changed(self, value: int):
        """Live update while dragging the slider."""
        self.opacity_value_label.setText(self.gt("bg_opacity_label", value))
        self._central.set_opacity(value)   # saves prefs + repaints central widget
        # Also re-apply theme so QSS child_alpha follows if needed
        # (only re-apply if has_bg changes; here just update label live)

    def _on_widget_opacity_changed(self, value: int):
        self.w_opacity_value_label.setText(self.gt("widget_opacity_label", value))
        ui_prefs.widget_opacity = value
        self._apply_theme(ui_prefs.theme)

    def _update_gpu_mode_label(self):
        if GPU.available and self.chk_gpu.isChecked():
            self.gpu_mode_label.setText(self.gt("gpu_mode_on"))
            self.gpu_mode_label.setStyleSheet(
                "color:#4fc3f7;font-size:11px;font-weight:bold;background:transparent;")
        else:
            self.gpu_mode_label.setText(self.gt("gpu_mode_off"))
            self.gpu_mode_label.setStyleSheet("font-size:11px;background:transparent;")

    def _on_gen_slider(self, value: int):
        self.gen_length_label.setText(self.gt("gen_length", value))

    def _do_generate_password(self):
        try:
            pwd = generate_password(
                length          = self.gen_slider.value(),
                use_upper       = self.chk_gen_upper.isChecked(),
                use_lower       = self.chk_gen_lower.isChecked(),
                use_digits      = self.chk_gen_digits.isChecked(),
                use_symbols     = self.chk_gen_symbols.isChecked(),
                avoid_ambiguous = self.chk_gen_no_ambig.isChecked(),
            )
        except ValueError as e:
            QMessageBox.warning(self, self.gt("msg_warn"), str(e))
            return
        self.gen_pwd_display.setText(pwd)

    def _copy_generated_pwd(self):
        txt = self.gen_pwd_display.text()
        if not txt or txt == "—":
            return
        self.pwd_entry.setText(txt)
        QApplication.clipboard().setText(txt)
        self.status_bar.showMessage(self.gt("gen_copied"), 3000)
        self.tabs.setCurrentIndex(0)

    def _reset_mfa(self):
        result = QMessageBox.warning(
            self,
            self.gt("btn_reset_mfa"),
            self.gt("mfa_reset_warn"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if result == QMessageBox.StandardButton.Yes:
            security.reset()
            QMessageBox.information(self, "MFA Reset",
                "MFA 設定已清除。請重新啟動程式完成設定。\n"
                "MFA settings cleared. Please restart to complete setup.")
            QApplication.quit()

    # ── Language ─────────────────────────────────────────────

    def toggle_language(self):
        self.current_lang = "EN" if self.current_lang == "TW" else "TW"
        self.update_ui_language()

    def update_ui_language(self):
        self.setWindowTitle(self.gt("app_title"))
        self.btn_toggle_lang.setText(self.gt("btn_lang"))
        self.title_label.setText(self.gt("title_label"))

        self.tabs.setTabText(0, self.gt("tab_main"))
        self.tabs.setTabText(1, self.gt("tab_settings"))

        self.btn_select_input.setText(self.gt("btn_select_input"))
        self.btn_select_dir.setText(self.gt("btn_select_dir"))
        self.pwd_label.setText(self.gt("pwd_label"))
        self.chk_show_pwd.setText(self.gt("chk_show_pwd"))
        self.btn_encrypt.setText(self.gt("btn_encrypt"))
        self.btn_decrypt.setText(self.gt("btn_decrypt"))
        self.preview_title.setText(self.gt("preview_title"))
        self.chk_shred.setText(self.gt("chk_shred"))
        self._shred_box.setTitle(self.gt("sect_shred"))

        self._sect_appearance.setTitle(self.gt("sect_appearance"))
        self.theme_label_w.setText(self.gt("theme_label"))
        self.bg_image_label_w.setText(self.gt("bg_image_label"))
        self.btn_select_bg.setText(self.gt("btn_select_bg"))
        self.btn_clear_bg.setText(self.gt("btn_clear_bg"))
        
        self.opacity_value_label.setText(
            self.gt("bg_opacity_label", self.opacity_slider.value()))
        self.opacity_hint_label.setText(self.gt("bg_opacity_hint"))
        
        self.w_opacity_value_label.setText(
            self.gt("widget_opacity_label", self.w_opacity_slider.value()))
        self.w_opacity_hint_label.setText(self.gt("widget_opacity_hint"))
        
        self._refresh_bg_label()

        self._sect_gpu.setTitle(self.gt("sect_gpu"))
        if GPU.available:
            self.gpu_status_label.setText(self.gt("gpu_found", GPU.name))
            self.gpu_status_label.setStyleSheet(
                "color:#4caf50;font-size:11px;background:transparent;")
        else:
            self.gpu_status_label.setText(self.gt("gpu_none"))
            self.gpu_status_label.setStyleSheet(
                "color:gray;font-size:11px;background:transparent;")
        self.chk_gpu.setText(self.gt("chk_gpu"))
        self.kdf_label_w.setText(self.gt("kdf_label"))
        self.chunk_label_w.setText(self.gt("chunk_label"))
        self._update_gpu_mode_label()

        self._sect_gen.setTitle(self.gt("sect_gen"))
        self.chk_gen_upper.setText(self.gt("gen_upper"))
        self.chk_gen_lower.setText(self.gt("gen_lower"))
        self.chk_gen_digits.setText(self.gt("gen_digits"))
        self.chk_gen_symbols.setText(self.gt("gen_symbols"))
        self.chk_gen_no_ambig.setText(self.gt("gen_no_ambig"))
        self.btn_generate.setText(self.gt("btn_generate"))
        self.btn_copy_pwd.setText(self.gt("btn_copy_pwd"))
        self._on_gen_slider(self.gen_slider.value())

        self._sect_mfa.setTitle(self.gt("sect_mfa"))
        self.mfa_status_label.setText(self.gt("mfa_status_ok"))
        self.mfa_rc_label.setText(
            self.gt("mfa_rc_remain", security.remaining_recovery_codes()))
        self.btn_reset_mfa.setText(self.gt("btn_reset_mfa"))

        self._refresh_input_label()
        self.output_label.setText(
            self.gt("out_empty") if not self.output_file_path
            else self.gt("out_loaded", os.path.basename(self.output_file_path)))
        self.check_password_strength(self.pwd_entry.text())
        self.status_bar.showMessage(self.gt("status_ready"))
        self._apply_theme(ui_prefs.theme)

    # ── Input helpers ────────────────────────────────────────

    def _refresh_input_label(self):
        if self.input_dir_path:
            self.input_label.setText(
                self.gt("input_dir_loaded", os.path.basename(self.input_dir_path)))
        elif self.input_file_path:
            self.input_label.setText(
                self.gt("input_loaded", os.path.basename(self.input_file_path)))
        else:
            self.input_label.setText(self.gt("input_empty"))
            self.image_preview.setText(self.gt("preview_drop"))

    def toggle_password_visibility(self):
        self.pwd_entry.setEchoMode(
            QLineEdit.EchoMode.Normal if self.chk_show_pwd.isChecked()
            else QLineEdit.EchoMode.Password)

    def is_password_strong(self, pwd: str) -> bool:
        if len(pwd) < 8:
            return False
        cats = sum([bool(re.search(r"[a-z]", pwd)), bool(re.search(r"[A-Z]", pwd)),
                    bool(re.search(r"\d",    pwd)), bool(re.search(r'[!@#$%^&*(),.?\":{}|<>]', pwd))])
        return cats >= 3

    def check_password_strength(self, text: str):
        if   len(text) == 0:                    txt, col = self.gt("str_req"),   "gray"
        elif len(text) < 8:                     txt, col = self.gt("str_short"), "red"
        elif not self.is_password_strong(text): txt, col = self.gt("str_weak"),  "orange"
        else:                                   txt, col = self.gt("str_ok"),    "#4caf50"
        self.strength_label.setText(txt)
        self.strength_label.setStyleSheet(f"color:{col};font-size:11px;background:transparent;")

    # ── Drag & Drop ──────────────────────────────────────────

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            fp = url.toLocalFile()
            if os.path.isdir(fp):
                self.load_input_directory(fp)
                break
            elif os.path.isfile(fp):
                self.load_input_file(fp)
                break

    # ── File loading ─────────────────────────────────────────

    def load_input_file(self, fp: str):
        self.input_file_path = fp
        self.input_dir_path  = ""
        self.input_label.setText(self.gt("input_loaded", os.path.basename(fp)))
        ext = fp.lower().rsplit('.', 1)[-1] if '.' in fp else ""

        if ext in ('png','jpg','jpeg','bmp','gif','webp','ico'):
            self.preview_stack.setCurrentIndex(0)
            px = QPixmap(fp).scaled(self.preview_stack.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation)
            self.image_preview.setPixmap(px)

        elif ext in ('txt','csv','json','md','py','js','html','css','xml','log','ini'):
            self.preview_stack.setCurrentIndex(1)
            try:
                with open(fp, 'r', encoding='utf-8') as f:
                    content = f.read(50 * 1024)
                    if len(content) == 50 * 1024:
                        content += "\n\n... [truncated] ..."
                self.text_preview.setText(content)
            except Exception:
                self.preview_stack.setCurrentIndex(0)
                self.image_preview.clear()
                self.image_preview.setText(self.gt("preview_unk", ext))

        elif ext == 'dat':
            self.preview_stack.setCurrentIndex(0)
            self.image_preview.clear()
            try:
                info = peek_v6_header(fp)
                self.image_preview.setText(self.gt("preview_enc_v6", info["original_name"]))
            except Exception:
                self.image_preview.setText(self.gt("preview_enc"))

        else:
            self.preview_stack.setCurrentIndex(0)
            self.image_preview.clear()
            self.image_preview.setText(self.gt("preview_unk", ext))

    def load_input_directory(self, dp: str):
        self.input_dir_path  = dp
        self.input_file_path = ""
        dn = os.path.basename(dp)
        self.input_label.setText(self.gt("input_dir_loaded", dn))
        self.preview_stack.setCurrentIndex(0)
        self.image_preview.clear()
        try:
            fc, fs = _count_dir_files(dp)
            self.image_preview.setText(self.gt("preview_dir", dn, fc, _human_size(fs)))
        except Exception:
            self.image_preview.setText(self.gt("input_dir_loaded", dn))

    def select_input_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*.*)")
        if fp:
            self.load_input_file(fp)

    def select_input_directory(self):
        dp = QFileDialog.getExistingDirectory(self, "Select Folder", "")
        if dp:
            self.load_input_directory(dp)

    def select_output_file(self, default_ext: str, suggested_name: str = "") -> bool:
        initial_path = ""
        if suggested_name:
            base_dir     = (os.path.dirname(self.input_file_path)
                            if self.input_file_path else "")
            initial_path = os.path.join(base_dir, suggested_name)
        fp, _ = QFileDialog.getSaveFileName(
            self, "Save File", initial_path,
            f"Files (*{default_ext});;All Files (*.*)" if default_ext else "All Files (*.*)"
        )
        if fp:
            if default_ext and not fp.lower().endswith(default_ext):
                fp += default_ext
            self.output_file_path = fp
            self.output_label.setText(self.gt("out_loaded", os.path.basename(fp)))
            return True
        return False

    def select_output_directory(self) -> bool:
        dp = QFileDialog.getExistingDirectory(self, "Select Output Folder", "")
        if dp:
            self.output_file_path = dp
            self.output_label.setText(self.gt("out_loaded", os.path.basename(dp)))
            return True
        return False

    def _make_progress_cb(self, multiplier: float = 1.0):
        def cb(done, total):
            if total > 0:
                pct = int(done * 100 / total * multiplier)
                self._worker.progress.emit(min(pct, 100))
        return cb

    # ── Encrypt ──────────────────────────────────────────────

    def encrypt_action(self):
        if not _ARGON2_AVAILABLE:
            QMessageBox.critical(self, self.gt("msg_err"), self.gt("err_no_argon2"))
            return

        pwd         = self.pwd_entry.text()
        is_dir_mode = bool(self.input_dir_path)
        is_file_mode= bool(self.input_file_path)

        if not is_dir_mode and not is_file_mode:
            QMessageBox.warning(self, self.gt("msg_warn"), self.gt("err_no_file"))
            return
        if not self.is_password_strong(pwd):
            QMessageBox.critical(self, self.gt("msg_warn"), self.gt("err_weak_pwd"))
            return
        if not self.select_output_file(".dat"):
            return

        if not self._require_totp("加密 / Encrypt"):
            QMessageBox.warning(self, self.gt("msg_warn"), self.gt("err_totp_cancel"))
            return

        shred_after = self.chk_shred.isChecked()
        if shred_after:
            res = QMessageBox.warning(
                self, self.gt("shred_warn_title"), self.gt("shred_warn_body"),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if res != QMessageBox.StandardButton.Yes:
                return

        use_gpu  = GPU.available and self.chk_gpu.isChecked()
        out_path = self.output_file_path
        pwd_b    = pwd.encode('utf-8')

        self.status_bar.showMessage(self.gt("status_enc_run"))
        self._set_busy(True)

        if is_dir_mode:
            dir_path   = self.input_dir_path
            worker_ref = [None]

            def task():
                def zip_cb(done, total):
                    if total > 0:
                        worker_ref[0].progress.emit(int(done * 30 / total))
                        worker_ref[0].status_msg.emit(self.gt("status_zip_run"))
                def enc_cb(done, total):
                    if total > 0:
                        pct = 30 + int(done * 70 / total)
                        worker_ref[0].progress.emit(min(pct, 100))
                        worker_ref[0].status_msg.emit(self.gt("status_enc_run"))
                return do_encrypt_directory(
                    dir_path, pwd_b, use_gpu, out_path,
                    shred_after=shred_after,
                    progress_cb=enc_cb,
                    zip_progress_cb=zip_cb,
                )

            self._worker    = CryptoWorker(task)
            worker_ref[0]   = self._worker
            self._worker.finished.connect(self._on_enc_dir_done)
        else:
            in_path = self.input_file_path

            def task():
                return do_encrypt(in_path, pwd_b, use_gpu, out_path,
                                  shred_after=shred_after,
                                  progress_cb=self._make_progress_cb())

            self._worker = CryptoWorker(task)
            self._worker.finished.connect(self._on_enc_done)

        self._worker.failed.connect(self._on_failed)
        self._worker.progress.connect(self.progress_bar.setValue)
        self._worker.status_msg.connect(self.status_bar.showMessage)
        self._worker.start()

    def _on_enc_done(self, out_path: str):
        self._set_busy(False)
        self.status_bar.showMessage(self.gt("status_enc_ok"))
        QMessageBox.information(self, self.gt("msg_succ"), self.gt("succ_enc", out_path))
        self.load_input_file(out_path)

    def _on_enc_dir_done(self, out_path: str):
        self._set_busy(False)
        self.status_bar.showMessage(self.gt("status_enc_ok"))
        QMessageBox.information(self, self.gt("msg_succ"), self.gt("succ_enc_dir", out_path))
        self.input_dir_path = ""
        self.load_input_file(out_path)

    # ── Decrypt ──────────────────────────────────────────────

    def decrypt_action(self):
        pwd = self.pwd_entry.text()
        if not self.input_file_path or not self.input_file_path.lower().endswith('.dat'):
            QMessageBox.warning(self, self.gt("msg_warn"), self.gt("err_not_dat"))
            return
        if not pwd:
            QMessageBox.warning(self, self.gt("msg_warn"), self.gt("err_no_pwd"))
            return

        is_zip_archive = False
        suggested_name = ""
        try:
            with open(self.input_file_path, 'rb') as f:
                magic = f.read(8)
            if magic == MAGIC_V6:
                info = peek_v6_header(self.input_file_path)
                is_zip_archive = info["is_zip"]
                suggested_name = info["original_name"]
            elif magic == MAGIC_V4:
                info           = peek_v4_flags(self.input_file_path)
                is_zip_archive = info["is_zip"]
        except Exception:
            pass

        if is_zip_archive:
            if not self.select_output_directory():
                return
        else:
            if not self.select_output_file("", suggested_name=suggested_name):
                return

        if not self._require_totp("解密 / Decrypt"):
            QMessageBox.warning(self, self.gt("msg_warn"), self.gt("err_totp_cancel"))
            return

        in_path  = self.input_file_path
        out_path = self.output_file_path
        pwd_b    = pwd.encode('utf-8')

        self.status_bar.showMessage(self.gt("status_dec_run"))
        self._set_busy(True)

        def task():
            return do_decrypt(in_path, pwd_b, out_path,
                              progress_cb=self._make_progress_cb())

        self._worker = CryptoWorker(task)
        self._worker.finished.connect(
            self._on_dec_dir_done if is_zip_archive else self._on_dec_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.progress.connect(self.progress_bar.setValue)
        self._worker.start()

    def _on_dec_done(self, out_path: str):
        self._set_busy(False)
        self.status_bar.showMessage(self.gt("status_dec_ok"))
        QMessageBox.information(self, self.gt("msg_succ"), self.gt("succ_dec", out_path))
        self.load_input_file(out_path)

    def _on_dec_dir_done(self, out_path: str):
        self._set_busy(False)
        self.status_bar.showMessage(self.gt("status_dec_ok"))
        QMessageBox.information(self, self.gt("msg_succ"), self.gt("succ_dec_dir", out_path))
        self.load_input_directory(out_path)

    def _on_failed(self, msg: str):
        self._set_busy(False)
        cur = self.status_bar.currentMessage()
        if "enc" in cur.lower() or "加密" in cur:
            self.status_bar.showMessage(self.gt("status_enc_fail"))
        else:
            self.status_bar.showMessage(self.gt("status_dec_fail"))
        if ("hmac" in msg.lower() or "wrong" in msg.lower() or "mismatch" in msg.lower()
                or "gcm" in msg.lower() or "tampered" in msg.lower()):
            QMessageBox.critical(self, self.gt("msg_err"), self.gt("err_wrong_pwd"))
        elif "argon2" in msg.lower():
            QMessageBox.critical(self, self.gt("msg_err"), self.gt("err_no_argon2"))
        else:
            QMessageBox.critical(self, self.gt("msg_err"), msg)


# ═══════════════════════════════════════════════════════════
#  Application startup — MFA bootstrap
# ═══════════════════════════════════════════════════════════

def _run_startup_mfa(app: QApplication) -> bool:
    if not _ARGON2_AVAILABLE:
        QMessageBox.critical(None, "依賴缺失 / Missing Dependency",
            "請安裝 argon2-cffi：\npip install argon2-cffi\n\n"
            "Please install argon2-cffi first.")
        return False

    if not _PYOTP_AVAILABLE:
        QMessageBox.critical(None, "依賴缺失 / Missing Dependency",
            "請安裝 pyotp：\npip install pyotp\n\nPlease install pyotp first.")
        return False

    if not security.is_initialized:
        QMessageBox.information(None, "enCPTO v6.2 — 首次啟動 / First Run",
            "歡迎使用 enCPTO v6.2！\n\n"
            "首次使用需完成安全設定精靈 (PIN + TOTP)。\n\n"
            "Welcome to enCPTO v6.2!\n"
            "Please complete the security setup wizard (PIN + TOTP) to continue.")
        wizard = SetupWizardDialog()
        result = wizard.exec()
        if result != QDialog.DialogCode.Accepted or not security.is_initialized:
            return False

    pin_dlg = PinDialog()
    pin_dlg.exec()
    if not pin_dlg.verified:
        return False

    return True


# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Minimal bootstrap stylesheet (overridden by _apply_theme after login)
    app.setStyleSheet("""
        QMainWindow, QWidget { background: #1e1e2e; color: #e0e0e0; }
        QLabel { color: #ccc; }
        QLineEdit {
            background: #2b2b3b; color: #e0e0e0;
            border: 1px solid #555; border-radius: 3px; padding: 4px;
        }
        QPushButton {
            background: #2b2b3b; color: #e0e0e0;
            border: 1px solid #555; border-radius: 4px; padding: 6px;
        }
        QPushButton:hover { background: #3a3a4a; }
        QCheckBox { color: #ccc; }
        QStatusBar { background: #16213e; color: #80cbc4; }
        QProgressBar { color: #fff; }
    """)

    if not _run_startup_mfa(app):
        sys.exit(0)

    win = CryptoApp()
    win.show()
    sys.exit(app.exec())