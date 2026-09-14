# XOR / AES Brute-Force Toolkit

A small collection of Python scripts for brute-forcing weak or partially-known
symmetric encryption keys against a ciphertext file. These were built for educational cryptanalysis — testing how quickly a
*weak* key (single repeating byte, short XOR key, or a password from a
wordlist) can be recovered when the underlying algorithm itself is not the
weak point.

## Repository structure

| File | Attack | Algorithm |
|---|---|---|
| `XOR_bruteforce.py` | Exhaustive key search | XOR, 1-byte and 2-byte repeating keys |
| `AES_bruteforce.py` | Exhaustive key search over a *weak key pattern* | AES-128 (ECB or CBC) |
| `bruteforce_worldlist.py` | Known-plaintext + wordlist | AES-128 (ECB or CBC) |

## Requirements

```bash
pip install cryptography pycryptodome
```

- `xor_bruteforce.py` — standard library only (`os`, `string`).
- `AES_bruteforce.py` — uses the [`cryptography`](https://cryptography.io/) package.
- `bruteforce_worldlist.py` — uses [`pycryptodome`](https://pycryptodome.readthedocs.io/) (`Crypto.Cipher`).

---

## 1. `xor_bruteforce.py` — XOR key brute force with scoring

Brute-forces every possible **1-byte** (256 combinations) and **2-byte**
(65,536 combinations) repeating XOR key against an encrypted `.bin` file,
scores each decrypted candidate by how much it looks like real text, and
saves the top candidates to disk for manual review.

### How it works

1. **`xor_decrypt(data, key)`** — XORs the ciphertext against the key,
   repeating the key cyclically (`key[i % key_len]`) across the whole file.
   This is the standard repeating-key XOR scheme.

2. **`score_plaintext(data)`** — heuristic scoring function combining:
   - `+1` per printable ASCII byte
   - `-5` for null bytes, `-3` for other control characters (penalizes
     binary/garbage output)
   - `+2` per occurrence of common English letters (`etaoinshrdlu` and
     uppercase)
   - `+20` per occurrence of common **Portuguese** function words (`" que "`,
     `" de "`, `" para "`, etc.) — tuned for Portuguese-language plaintext;
     swap this list out if your target text is in another language

   Higher score = more likely to be readable plaintext.

3. **`brute_force_one_byte(data)`** / **`brute_force_two_byte(data)`** — run
   the full keyspace, sort all candidates by score (descending), print the
   top `TOP_RESULTS` (default 20) with a preview of the first 100 bytes, and
   save each one to disk via `save_candidate()`.

4. **`save_candidate()`** — writes every top candidate to
   `XOR_results/xor_<keylen>byte_key_<hex>_score_<score>.bin`, so you can
   open and inspect the most promising ones without re-running the script.

### Usage

Edit the two path constants at the top of the file:

```python
INPUT_FILE = "path/to/your/encrypted_file.bin"
OUTPUT_DIR = "path/to/output/folder"
```

Then run:

```bash
python xor_bruteforce.py
```

### Notes / limitations

- Runs the **entire** keyspace for both 1-byte and 2-byte keys — the 2-byte
  pass (65,536 keys) will take noticeably longer on large files since it
  scores every byte of the file for every key.
- The scoring function is a heuristic, not a guarantee — always eyeball the
  top few candidates rather than trusting the single highest score blindly,
  especially on short files where a "lucky" garbage key can score well by
  chance.
- Only brute-forces **repeating-key XOR**, not more advanced schemes (XOR
  with a key as long as the plaintext, or keys derived from a KDF).

---

## 2. `AES_bruteforce.py` — weak AES key search

Assumes the AES-128 key is a **single byte value repeated 16 times**
(e.g. `\x2A` × 16) — a common weak-key pattern in beginner challenges —
and brute-forces all 256 possibilities.

### How it works

1. Reads the encrypted file and takes a 32-byte slice of ciphertext
   (`ciphertext[16:48]`) — two AES blocks — skipping the first 16 bytes
   (commonly a discarded/unused IV or header in the source challenge).
2. For each byte value `i` from `0` to `255`, builds the 16-byte key
   `[i]*16` and attempts an **AES-ECB** decryption.
3. Strips PKCS#7 padding from the result.
4. If **every** resulting byte falls within printable ASCII (or is a
   tab/newline/carriage-return), it's treated as a match, printed, and the
   loop stops.

### Usage

Set the file path:

```python
file_path = "path/to/your/encrypted_file.bin"
```

Run:

```bash
python AES_bruteforce.py
```

### Notes / limitations

- **This only works if the real key genuinely follows the "single byte
  repeated 16 times" pattern.** If the actual key doesn't match that
  assumption, all 256 attempts will fail (or throw a padding exception,
  which is caught and skipped). This is intentionally a very narrow guess,
  not a general AES key recovery method — real AES-128 has a 2^128 keyspace
  and cannot be brute-forced this way.
- There's a commented-out variant in the script for a **two-byte alternating
  pattern** (`[i, j, i, j, ...]`, 65,536 combinations) — uncomment it if the
  single-byte pattern doesn't yield a hit and you suspect a two-byte
  alternating key instead.
- The script is hardcoded to **AES-ECB**; a commented-out line shows how to
  switch to **AES-CBC** with an all-zero IV. Note the comment in the ECB branch about the IV being
  unused is only accurate for the ECB path — if you switch to CBC, the IV
  choice matters and an all-zero IV is only correct if that's what the
  target actually used.
- Stops at the **first** printable-only match. If your ciphertext block is
  short (2 blocks here) there's a real chance of false positives — random
  bytes occasionally decrypt to something that happens to fall in printable
  range. Verify any hit by decrypting more of the file with that key before
  trusting it.

---

## 3. `bruteforce_worldlist.py` — known-plaintext + wordlist attack

For cases where you already have **both** a known plaintext sample and its
corresponding ciphertext (a classic known-plaintext attack setup), and you
suspect the encryption key is a human-chosen password from a wordlist rather
than a random 128-bit key.

### How it works

1. Loads a known plaintext file, its matching ciphertext file, and a
   password wordlist (`passwords1.txt`).
2. Filters the wordlist to only passwords of 16 characters or fewer (so they
   fit in a single AES-128 key after padding).
3. Takes the first 32 bytes (2 blocks) of both plaintext and ciphertext as
   the test sample.
4. For each candidate password:
   - Encodes it as UTF-8 and right-pads with null bytes (`\x00`) to exactly
     16 bytes to form the AES key.
   - Encrypts the known plaintext sample using **AES-CBC with an all-zero
     IV**.
   - Compares the result to the real ciphertext sample — if they match, the
     password is printed and the loop stops.

### Usage

Set the three file paths:

```python
with open('PLAIN_TEXT_PATH', 'rb') as f:
    plaintext = f.read()

with open('CIPHER_TEXT_PATH', 'rb') as f:
    ciphertext = f.read()

with open('passwords1.txt') as f:
    passlist = f.read().splitlines()
```

Run:

```bash
python bruteforce_worldlist.py
```

### Notes / limitations

- **The IV must match what was actually used to produce the ciphertext.**
  This script assumes an all-zero IV; if the real ciphertext was produced
  with a random or otherwise non-zero IV, every comparison will fail even
  if the password is in your wordlist. If you don't know the IV, you either
  need it from elsewhere (e.g. it's often prepended to the ciphertext file)
  or you'll need to switch to ECB mode if that's genuinely what was used.
- Zero-padding a UTF-8-encoded password to 16 bytes (`.ljust(16, b'\x00')`)
  only reproduces the correct key if the target derived its key **exactly**
  this way. If the real system instead used a KDF (PBKDF2, scrypt, a hash
  digest, etc.) to turn the password into a key, this simple padding scheme
  will never match — this script only works for a very specific ("naive")
  key-derivation assumption.
- Only compares a 32-byte (2-block) sample for speed; once you find a
  candidate, re-encrypt the *entire* known plaintext and diff against the
  entire ciphertext to rule out a coincidental partial match.
- The commented-out ECB line is there if your target used ECB instead of
  CBC — try both if you're not sure which mode was used.

---

## General disclaimer

All three scripts rely on the target key being **weak, short, or guessable**
— none of them defeat AES or a properly-random XOR key. They're intended for
CTF challenges, learning exercises, and authorized security testing where
the "vulnerability" being exploited is a poor key choice, not the cipher
itself.
