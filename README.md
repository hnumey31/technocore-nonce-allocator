# Technocore Nonce Allocator

Standalone persistent nonce allocator for Technocore signed writes. Values increase independently for each DID and room, survive restarts, and are written atomically to a `0600` JSON file.

## Why ranges matter

A signed-write worker must never reuse a nonce for the same DID and room. Reserving a contiguous range lets a worker claim several nonces before signing a batch, while the allocator advances the durable high-water mark once. A process crash may leave unused nonces, which is safe; it cannot make a later worker reuse them.

Reservations are serialized with an advisory file lock. The state file is flushed with `fsync` before atomic replacement, and both the state and lock files use mode `0600`. This implementation targets Unix-like systems that provide `fcntl.flock`.

## Usage

Allocate one nonce from the CLI:

```bash
python3 nonce_allocator.py --state ~/.config/technocore/nonces.json \
  --did 'did:key:z6Mk...' --room lobby
```

Reserve a range from Python:

```python
from nonce_allocator import reserve_nonce_range

first, last = reserve_nonce_range(
    "~/.config/technocore/nonces.json",
    "did:key:z6Mk...",
    "lobby",
    count=32,
)
```

`reserve_nonce_range` returns an inclusive `(first, last)` pair as decimal strings. `count` must be a positive integer; booleans, zero, negatives, strings, and fractional values are rejected before state is changed. The final nonce must fit Technocore's 19-digit protocol cap.

## Canonical signature preflight

Technocore now requires an Ed25519 signature to have one canonical unpadded-base64url spelling. A 64-byte signature occupies 86 characters, but the final character carries four unused bits. Without a canonicality check, 16 different strings can decode to the same 64 bytes. The server therefore accepts only final characters `A`, `Q`, `g`, or `w`.

Use the dependency-free validator before constructing a signed-write URL:

```python
from signature_encoding import validate_canonical_signature

signature = validate_canonical_signature(signer.sign(message))
```

Or preflight from the command line:

```bash
python3 signature_encoding.py "$SIGNATURE"
```

The test suite generates a real 64-byte fixture, accepts its canonical encoding, derives all 15 alternate final-character spellings that decode to the same bytes, and rejects every alias. This mirrors the exact contract introduced by upstream commit [`b7ad42ed8f7759d29d7fc32d7aa6317e2ff707f8`](https://github.com/flop-labs/technocore-chat/commit/b7ad42ed8f7759d29d7fc32d7aa6317e2ff707f8).

Run the dependency-free test suite:

```bash
python3 -m unittest -v
```
