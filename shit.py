"""
# shitcrypt

this shit is intentionally **not secure**. complete shit that 
shows how to: derive key-material from a passphrase, operate on 32-bit words, and
parallelize CPU-heavy work with ProcessPoolExecutor shit. SHIT.

**do NOT fucking use for real shit.**
if need secure, use shit like `cryptography` (AES-GCM)
or `pynacl`/libsodium (ChaCha20-Poly1305).

this shit has
- `shitcrypt` Python CLI that can encrypt/decrypt text or files.
- a custom shit cipher (word-level operations + rounds) — intentionally fucked.
- KDF based on repeated SHA-256 stretching (again: shit, do not rely on it).
- parallelization using ProcessPoolExecutor to test CPU-bound slicing.

usage ex
```bash
# encrypt a direct text value
python honest-crypto_encrypter.py --mode enc --text "hello world" --pass "p@ss"

# encrypt a file and save to outputs/
python honest-crypto_encrypter.py --mode enc --infile myfile.txt --pass "p@ss"

# decrypt a file from outputs/
python honest-crypto_encrypter.py --mode dec --infile outputs/enc_123456.txt --pass "p@ss"
```
the only shit that will survive the thermonuclear war.
"""

import os
import sys
import time
import argparse
import hashlib
import struct
from concurrent.futures import ProcessPoolExecutor
from math import ceil

# ---------------------- settings ----------------------
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# default round
DEFAULT_ROUNDS = 12000
KDF_ROUNDS = 4000

# multiplier (32-bit)
MUL = 0x9E3779B1
MASK32 = 0xFFFFFFFF

# workers default: number of CPU cores or 1
DEFAULT_WORKERS = max(1, (os.cpu_count() or 2))
# ------------------------------------------------------


def modinv(a, m):
    a0, m0 = a, m
    x0, x1 = 1, 0
    while m0 != 0:
        q = a0 // m0
        a0, m0, x0, x1 = m0, a0 - q * m0, x1, x0 - q * x1
    if a0 != 1:
        raise ValueError("no modular inverse")
    return x0 & (m - 1)

MUL_INV = modinv(MUL, 1 << 32)


def rotl32(x, r):
    r &= 31
    return ((x << r) & MASK32) | ((x & MASK32) >> (32 - r))


def rotr32(x, r):
    r &= 31
    return ((x & MASK32) >> r) | ((x << (32 - r)) & MASK32)


def bytes_to_words(b):
    orig = len(b)
    n = ceil(len(b) / 4)
    padded = b + b'\x00' * (n * 4 - len(b))
    words = list(struct.unpack('<' + 'I' * n, padded))
    return words, orig


def words_to_bytes(words, orig_byte_len):
    b = struct.pack('<' + 'I' * len(words), *words)
    return b[:orig_byte_len]


def derive_key_words(passphrase, kdf_rounds=KDF_ROUNDS):
    # deterministic surrogatepass encoding for arbitrary unicode
    h = passphrase.encode('utf-8', errors='surrogatepass')
    for i in range(kdf_rounds):
        h = hashlib.sha256(h + b'::' + str(i).encode()).digest()
    key_material = b''
    counter = 0
    # produce 4kib key material (enough shit)
    while len(key_material) < 4096:
        key_material += hashlib.sha256(h + b'::km::' + str(counter).encode()).digest()
        counter += 1
    words = [struct.unpack('<I', key_material[i:i+4])[0] for i in range(0, len(key_material), 4)]
    return words


# ---------------- worker funcs: each worker performs ALL rounds on its slice ----------------
def _worker_encrypt_full(args):
    # args: (words_slice, start_index, key_words, rounds)
    words_slice, start_index, key_words, rounds = args
    kwlen = len(key_words)
    out = list(words_slice)  # copy
    # do all rounds locally to minimize ipc and maximize CPU usage
    for r in range(rounds):
        kr = key_words[r % kwlen]
        add_base = (kr ^ ((r << 16) & MASK32)) & MASK32
        # process each element
        for i in range(len(out)):
            idx = start_index + i
            k1 = key_words[(idx + r) % kwlen]
            rot = ((k1 >> (r % 16)) & 31)
            w = out[i]
            w = (w ^ k1) & MASK32
            w = (w * MUL) & MASK32
            w = (w + (add_base & MASK32)) & MASK32
            w = rotl32(w, rot)
            out[i] = w
    return out


def _worker_decrypt_full(args):
    # args: (words_slice, start_index, key_words, rounds)
    words_slice, start_index, key_words, rounds = args
    kwlen = len(key_words)
    out = list(words_slice)
    # reverse rounds locally
    for r in range(rounds - 1, -1, -1):
        kr = key_words[r % kwlen]
        add_base = (kr ^ ((r << 16) & MASK32)) & MASK32
        for i in range(len(out)):
            idx = start_index + i
            k1 = key_words[(idx + r) % kwlen]
            rot = ((k1 >> (r % 16)) & 31)
            w = out[i]
            w = rotr32(w, rot)
            w = (w - (add_base & MASK32)) & MASK32
            w = (w * MUL_INV) & MASK32
            w = (w ^ k1) & MASK32
            out[i] = w
    return out


def chunkify_exact(lst, parts):
    n = len(lst)
    if n == 0:
        return []
    base = n // parts
    rem = n % parts
    chunks = []
    i = 0
    for p in range(parts):
        size = base + (1 if p < rem else 0)
        if size == 0:
            chunks.append(([], i))
        else:
            chunk = lst[i:i+size]
            chunks.append((chunk, i))
        i += size
    return chunks


def encrypt_words_parallel(words, key_words, rounds=DEFAULT_ROUNDS, workers=DEFAULT_WORKERS):
    arr = list(words)
    # make chunks equal to workers
    slices = chunkify_exact(arr, workers)
    args_list = [ (chunk, start, key_words, rounds) for (chunk, start) in slices ]
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = [ ex.submit(_worker_encrypt_full, a) for a in args_list ]
        results = [f.result() for f in futures]
    # combine in original order (slice order matches start indices)
    new_arr = []
    for res in results:
        new_arr.extend(res)
    return new_arr


def decrypt_words_parallel(words, key_words, rounds=DEFAULT_ROUNDS, workers=DEFAULT_WORKERS):
    arr = list(words)
    slices = chunkify_exact(arr, workers)
    args_list = [ (chunk, start, key_words, rounds) for (chunk, start) in slices ]
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = [ ex.submit(_worker_decrypt_full, a) for a in args_list ]
        results = [f.result() for f in futures]
    new_arr = []
    for res in results:
        new_arr.extend(res)
    return new_arr


# ---------------- file handling helpers (UTF fix) ----------------
def safe_read_text_file(path):
    """
    try read with utf-8, cp1254, latin-1; fall back to surrogatepass decoding from raw bytes
    """
    for enc in ('utf-8', 'cp1254', 'latin-1'):
        try:
            with open(path, 'r', encoding=enc) as f:
                return f.read(), enc
        except Exception:
            continue
    with open(path, 'rb') as f:
        raw = f.read()
    return raw.decode('utf-8', errors='surrogatepass'), 'surrogatepass'


# ---------------- file encrypt/decrypt ----------------
def encrypt_text_to_file(plain_text, passphrase, rounds=DEFAULT_ROUNDS, workers=DEFAULT_WORKERS, out_dir=OUTPUT_DIR):
    words, orig_bytes = bytes_to_words(plain_text.encode('utf-8', errors='surrogatepass'))
    key_words = derive_key_words(passphrase)
    print("[*] key derived, starting (CPU may load depending on rounds and workers)")
    t0 = time.time()
    enc_words = encrypt_words_parallel(words, key_words, rounds=rounds, workers=workers)
    t1 = time.time()
    enc_bytes = struct.pack('<' + 'I' * len(enc_words), *enc_words)
    # filename: enc_HHMMSS
    timestamp = time.strftime("%H%M%S")
    fname = f"enc_{timestamp}.txt"
    path = os.path.join(out_dir, fname)
    header = f"SCV1|rounds={rounds}|kdf={KDF_ROUNDS}|origlen={orig_bytes}\n"
    hexpayload = enc_bytes.hex().upper()
    with open(path, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write(hexpayload)
    print(f"[+] encrypted, file: {path}")
    print(f"[+] time: {t1-t0:.2f}s")
    return fname


def decrypt_file_to_text(filename, passphrase, workers=DEFAULT_WORKERS, out_dir=OUTPUT_DIR):
    path = filename if os.path.isabs(filename) or os.path.exists(filename) else os.path.join(out_dir, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, 'r', encoding='utf-8') as f:
        header = f.readline().strip()
        data = f.read().strip()
    if not header.startswith("SCV1|"):
        raise ValueError("unsupported file.")
    parts = header.split('|')
    kv = {}
    for p in parts[1:]:
        if '=' in p:
            k, v = p.split('=', 1); kv[k] = v
    rounds = int(kv.get('rounds', DEFAULT_ROUNDS))
    origlen = int(kv.get('origlen', 0))
    print(f"[*] found, rounds: {rounds} | origlen: {origlen}. deriving key...")
    key_words = derive_key_words(passphrase)
    enc_bytes = bytes.fromhex(data)
    nwords = len(enc_bytes) // 4
    words = list(struct.unpack('<' + 'I' * nwords, enc_bytes))
    print("[*] starting decryption (CPU will load based on round or workers)")
    t0 = time.time()
    dec_words = decrypt_words_parallel(words, key_words, rounds=rounds, workers=workers)
    t1 = time.time()
    out_bytes = words_to_bytes(dec_words, origlen)
    try:
        text = out_bytes.decode('utf-8', errors='surrogatepass')
    except Exception:
        text = out_bytes.decode('latin-1', errors='replace')
    print(f"[+] decrypted, time: {t1-t0:.2f}s")
    return text


# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description='honest-crypto : toy file/text encrypter (NOT SECURE)')
    p.add_argument('--mode', choices=('enc', 'dec'), required=True, help='enc=encrypt | dec=decrypt')
    p.add_argument('--text', help='text to encrypt (use with --mode enc)')
    p.add_argument('--infile', help='input filename (for enc: file to read; for dec: file in outputs/)')
    p.add_argument('--pass', dest='password', required=True, help='passphrase')
    p.add_argument('--rounds', type=int, default=DEFAULT_ROUNDS, help=f'round count (default {DEFAULT_ROUNDS})')
    p.add_argument('--workers', type=int, default=DEFAULT_WORKERS, help=f'parallel workers (default {DEFAULT_WORKERS})')
    return p.parse_args()


def main():
    args = parse_args()
    if args.mode == 'enc':
        if args.text:
            txt = args.text
        elif args.infile:
            if not os.path.exists(args.infile):
                print('infile not found')
                sys.exit(1)
            txt, enc = safe_read_text_file(args.infile)
            print(f"(detected encoding: {enc})")
        else:
            print('no text or infile provided')
            sys.exit(1)
        fname = encrypt_text_to_file(txt, args.password, rounds=args.rounds, workers=args.workers)
        print(f'output: {os.path.join(OUTPUT_DIR, fname)}')
    else:
        if not args.infile:
            print('infile required for decrypt mode')
            sys.exit(1)
        try:
            text = decrypt_file_to_text(args.infile, args.password, workers=args.workers)
            print('\n--- decrypted START ---\n')
            print(text)
            print('\n--- decrypted END ---\n')
        except FileNotFoundError:
            print('file not found')
            sys.exit(1)
        except Exception as e:
            print('error:', e)
            sys.exit(1)


if __name__ == '__main__':
    main()
