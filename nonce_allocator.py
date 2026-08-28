#!/usr/bin/env python3
import argparse
import fcntl
import json
import os
import time
from pathlib import Path

MAX_NONCE = 9_999_999_999_999_999_999


def reserve_nonce_range(state_path, did, room, count, now_ms=None):
    """Atomically reserve a contiguous inclusive nonce range."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")

    target = Path(state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")

    with lock_path.open("a", encoding="utf-8") as lock_file:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        state = json.loads(target.read_text()) if target.exists() else {}
        if not isinstance(state, dict):
            raise ValueError("nonce state must be a JSON object")
        key = f"{did}|{room}"
        clock = int(time.time() * 1000) if now_ms is None else int(now_ms)
        first = max(clock, int(state.get(key, 0)) + 1)
        last = first + count - 1
        if last > MAX_NONCE:
            raise OverflowError("nonce exceeds Technocore's 19-digit cap")
        state[key] = last

        temporary = target.with_name(target.name + ".tmp")
        with temporary.open("w", encoding="utf-8") as output:
            output.write(json.dumps(state, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)

    return str(first), str(last)


def next_nonce(state_path, did, room, now_ms=None):
    first, _ = reserve_nonce_range(state_path, did, room, 1, now_ms)
    return first


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state", required=True)
    p.add_argument("--did", required=True)
    p.add_argument("--room", required=True)
    args = p.parse_args()
    print(next_nonce(args.state, args.did, args.room))


if __name__ == "__main__":
    main()
