# Legacy Python app (v7.0)

`enCPTO-v7.py` is the original Python/PyQt6 version. enCPTO 8 replaces it, but keep it around for one job:
**decrypting containers made by v6.x and older (formats V1–V6)**, which 8.0 no longer reads.

```bash
pip install PyQt6 pycryptodome argon2-cffi
python enCPTO-v7.py
```

Decrypt the old file, then encrypt the result again with enCPTO 8.
Files made by this tool in the V7 format open directly in enCPTO 8.
