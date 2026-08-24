#!/usr/bin/env python3
import argparse
import json
import os
import time
from pathlib import Path

MAX_NONCE = 9_999_999_999_999_999_999


def next_nonce(state_path, did, room, now_ms=None):
    target = Path(state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    state = json.loads(target.read_text()) if target.exists() else {}
    if not isinstance(state, dict):
        raise ValueError("nonce state must be a JSON object")
    key = f"{did}|{room}"
    clock = int(time.time() * 1000) if now_ms is None else int(now_ms)
    value = max(clock, int(state.get(key, 0)) + 1)
    if value > MAX_NONCE:
        raise OverflowError("nonce exceeds Technocore's 19-digit cap")
    state[key] = value
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)
    return str(value)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state", required=True)
    p.add_argument("--did", required=True)
    p.add_argument("--room", required=True)
    args = p.parse_args()
    print(next_nonce(args.state, args.did, args.room))


if __name__ == "__main__":
    main()
