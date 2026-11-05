#!/usr/bin/env python3
"""
Cross-implementation check: encpto-cli (C++) ⇄ v7_reference.py (Python).

    python run_compat.py path/to/encpto-cli

Every payload is encrypted by one implementation and decrypted by the other,
in both directions, and the results are compared byte for byte.
"""
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import v7_reference as ref  # noqa: E402

PASSWORD = "Compat#Check2026 ✓"
MiB = 1024 * 1024


def cli(exe, *args):
    r = subprocess.run([exe, *args, "--password-stdin", "-q"], input=(PASSWORD + "\n").encode(),
                       capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"encpto-cli {' '.join(args)} failed:\n{r.stdout.decode()}{r.stderr.decode()}")


def same_tree(a, b):
    d = filecmp.dircmp(a, b)
    if d.left_only or d.right_only or d.funny_files:
        return False
    _, mismatch, errors = filecmp.cmpfiles(a, b, d.common_files, shallow=False)
    return not mismatch and not errors and all(
        same_tree(os.path.join(a, s), os.path.join(b, s)) for s in d.common_dirs)


def main():
    exe = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix="encpto-compat-")
    failures = 0
    try:
        src = os.path.join(work, "src")
        os.makedirs(src)
        files = {
            "empty.bin": b"",
            "one.bin": b"x",
            "exact-chunk.bin": os.urandom(4 * MiB),
            "multi-chunk.bin": os.urandom(9 * MiB + 7),
            "中文檔名 ✓.txt": "繁體中文內容\n".encode() * 1000,
        }
        for name, data in files.items():
            with open(os.path.join(src, name), "wb") as f:
                f.write(data)
        folder = os.path.join(src, "資料夾 Folder")
        os.makedirs(os.path.join(folder, "sub", "deeper"))
        os.makedirs(os.path.join(folder, "empty-dir"))
        for i in range(20):
            with open(os.path.join(folder, "sub", f"f{i}.txt"), "wb") as f:
                f.write(("line %d\n" % i).encode() * (i * 500))
        with open(os.path.join(folder, "sub", "deeper", "照片.jpg"), "wb") as f:
            f.write(os.urandom(300000))

        def check(label, ok):
            nonlocal failures
            print(("  ok    " if ok else "  FAIL  ") + label)
            failures += 0 if ok else 1

        # ── C++ encrypt → Python decrypt ──
        for name, data in files.items():
            dat = os.path.join(work, "cpp.dat")
            cli(exe, "encrypt", os.path.join(src, name), "-o", dat)
            with open(dat, "rb") as f:
                flags, got_name, plain = ref.decrypt_bytes(f.read(), PASSWORD.encode())
            check(f"C++ → Python  {name}", flags == 0 and got_name == name and plain == data)

        dat = os.path.join(work, "cpp-folder.dat")
        cli(exe, "encrypt", folder, "-o", dat)
        out = os.path.join(work, "py-out")
        ref.main(["", "decrypt", dat, out, PASSWORD])
        # Python's zipfile does not create empty folders unless they have an entry;
        # the C++ archive stores one, so the trees must match exactly.
        check("C++ → Python  folder", same_tree(folder, os.path.join(out, os.path.basename(folder))))

        # ── Python encrypt → C++ decrypt ──
        for name, data in files.items():
            dat = os.path.join(work, "py.dat")
            ref.main(["", "encrypt", os.path.join(src, name), dat, PASSWORD])
            out = os.path.join(work, "cpp-out-" + str(len(data)))
            cli(exe, "decrypt", dat, "-o", out)
            with open(os.path.join(out, name), "rb") as f:
                check(f"Python → C++  {name}", f.read() == data)

        shutil.rmtree(os.path.join(folder, "empty-dir"))  # Python's zipfile drops empty folders
        dat = os.path.join(work, "py-folder.dat")
        ref.main(["", "encrypt", folder, dat, PASSWORD])
        out = os.path.join(work, "cpp-folder-out")
        cli(exe, "decrypt", dat, "-o", out)
        check("Python → C++  folder", same_tree(folder, os.path.join(out, os.path.basename(folder))))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print(f"\n{'all compatible' if failures == 0 else f'{failures} failure(s)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
