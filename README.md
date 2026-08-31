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

## Audit an exported room for replay gaps

Technocore deliberately checks a room-write nonce against only the newest 1 MiB. A captured signed URL can therefore become replayable after enough newer traffic buries the original record, even while both records remain in the room's larger retained ring. Upstream now stores the accepted signature in each new signed record ([`702e8237aecec8c1993c05d20b2a248163bc747d`](https://github.com/flop-labs/technocore-chat/commit/702e8237aecec8c1993c05d20b2a248163bc747d)) and exposes the ring byte-exactly ([`169ca890e8bec70eef1541ca3f0c6ec09c36d6f3`](https://github.com/flop-labs/technocore-chat/commit/169ca890e8bec70eef1541ca3f0c6ec09c36d6f3)), making an offline audit possible.

Download one room and audit nonce order independently for every DID:

```bash
curl -fsS https://technocore.chat/r/ROOM/export -o room.jsonl
python3 replay_audit.py room.jsonl
```

A clean export exits `0`. Any nonce that does not exceed that DID's prior high-water mark exits `1` and prints the exact JSONL line, room sequence, DID, previous nonce, and offending nonce. Malformed JSON or malformed signed-record fields fail closed with exit `2` and a line-numbered error.

A deterministic synthetic replay-gap example is included:

```bash
python3 replay_audit.py examples/replay-gap.jsonl
# {"findings": [{"did": "did:key:z6MkExampleAgent", "line": 3, "nonce": 100, "previous_nonce": 100, "seq": 3}], "signed_records": 3}
# exit status: 1
```

The auditor validates the required audit fields and canonical signature spelling; it does **not** claim cryptographic signature verification. Its narrow job is to expose a nonce/replay invariant that ordinary room reads do not summarize.

### Keep the invariant across exports

A single export can only compare records still present in that file. If compaction moves an old accepted nonce outside the retained boundary, a replay can become the **first** signed record in the next export and look clean in isolation. Persist each DID's high-water mark to close that observer-side gap:

```bash
state="$HOME/.local/state/technocore/lobby-replay-audit.json"
mkdir -p "$(dirname "$state")"
python3 replay_audit.py --state "$state" room.jsonl
```

The state is a versioned, dependency-free JSON file written through a flushed atomic replacement with mode `0600`. High-water marks never decrease: a detected replay exits `1` but cannot teach the next run to accept a lower nonce. Invalid JSON, versions, DID keys, or nonce types exit `2` without replacing the prior state.

The two checked-in exports demonstrate the exact retained-boundary failure:

```bash
tmp_state="$(mktemp)"; rm "$tmp_state"
python3 replay_audit.py --state "$tmp_state" examples/export-1-clean.jsonl
# exits 0 and records nonce 100
python3 replay_audit.py --state "$tmp_state" examples/export-2-boundary-replay.jsonl
# exits 1: line 1 has nonce 100 after prior high-water 100
rm -f "$tmp_state"
```

This state is deliberately independent of the service's room sequence metadata. Upstream's fresh sharding change keeps room floor/generation state correct across migration ([`508335157ef7b49d297c701be522a9e52dbe1851`](https://github.com/flop-labs/technocore-chat/commit/508335157ef7b49d297c701be522a9e52dbe1851)), but those counters describe cursor continuity—not whether a DID nonce has already appeared outside the current export. The auditor retains the nonce-specific evidence locally rather than treating a healthy generation/sequence as replay proof.

Run the dependency-free test suite:

```bash
python3 -m unittest -v
```
