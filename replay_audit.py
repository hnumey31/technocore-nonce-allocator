#!/usr/bin/env python3
"""Audit a Technocore room export for non-increasing signed-write nonces."""

import argparse
import json
import os
import tempfile

from signature_encoding import validate_canonical_signature


def _record(line, line_number):
    try:
        record = json.loads(line)
    except json.JSONDecodeError as error:
        raise ValueError(f"line {line_number}: invalid JSON: {error.msg}") from None
    if not isinstance(record, dict):
        raise ValueError(f"line {line_number}: record must be a JSON object")
    if "sig" not in record:
        return record
    if not isinstance(record.get("from"), str) or not record["from"].startswith("did:key:"):
        raise ValueError(f"line {line_number}: signed record must have a did:key sender")
    if isinstance(record.get("nonce"), bool) or not isinstance(record.get("nonce"), int):
        raise ValueError(f"line {line_number}: nonce must be an integer")
    if not isinstance(record.get("seq"), int):
        raise ValueError(f"line {line_number}: seq must be an integer")
    try:
        validate_canonical_signature(record["sig"])
    except ValueError as error:
        raise ValueError(f"line {line_number}: {error}") from None
    return record


def audit_export_state(lines, prior_high_water=None):
    """Return findings and updated per-DID nonce high-water marks."""
    high_water = dict(prior_high_water or {})
    findings = []
    for line_number, line in enumerate(lines, 1):
        record = _record(line, line_number)
        if "sig" not in record:
            continue
        did = record["from"]
        nonce = record["nonce"]
        previous = high_water.get(did)
        if previous is not None and nonce <= previous:
            findings.append(
                {
                    "line": line_number,
                    "seq": record["seq"],
                    "did": did,
                    "previous_nonce": previous,
                    "nonce": nonce,
                }
            )
        high_water[did] = max(previous, nonce) if previous is not None else nonce
    return findings, high_water


def audit_export(lines):
    """Return nonce regressions/replays found in one JSONL export."""
    findings, _ = audit_export_state(lines)
    return findings


def _newest_guard_nonce(raw_history, did, guard_bytes):
    """Return the newest nonce for ``did`` in the complete-line byte tail."""
    cutoff = max(0, len(raw_history) - guard_bytes)
    tail = raw_history[cutoff:]
    lines = tail.split(b"\n")
    if cutoff:
        lines = lines[1:]
    for raw in reversed(lines):
        if not raw:
            continue
        try:
            record = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if record.get("from") == did and isinstance(record.get("nonce"), int):
            return record["nonce"]
    return None


def analyze_replay_window(lines, guard_bytes=1 << 20):
    """Explain whether historical nonce reuse is inside the service guard window."""
    if isinstance(guard_bytes, bool) or not isinstance(guard_bytes, int) or guard_bytes <= 0:
        raise ValueError("guard_bytes must be a positive integer")
    high_water = {}
    raw_history = b""
    explanations = []
    for line_number, line in enumerate(lines, 1):
        record = _record(line, line_number)
        encoded = line.encode("utf-8") if isinstance(line, str) else line
        if not encoded.endswith(b"\n"):
            encoded += b"\n"
        if "sig" in record:
            did = record["from"]
            nonce = record["nonce"]
            previous = high_water.get(did)
            if previous is not None and nonce <= previous:
                guard_nonce = _newest_guard_nonce(raw_history, did, guard_bytes)
                explanations.append(
                    {
                        "line": line_number,
                        "seq": record["seq"],
                        "did": did,
                        "nonce": nonce,
                        "historical_high_water": previous,
                        "guard_nonce": guard_nonce,
                        "service_outcome": (
                            "refused"
                            if guard_nonce is not None and nonce <= guard_nonce
                            else "accepted"
                        ),
                    }
                )
            high_water[did] = max(previous, nonce) if previous is not None else nonce
        raw_history += encoded
    return explanations


def _positive_integer(value):
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _load_state(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as source:
            state = json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid audit state: {error}") from None
    if not isinstance(state, dict) or state.get("version") != 1:
        raise ValueError("invalid audit state: expected version 1 object")
    high_water = state.get("high_water")
    if not isinstance(high_water, dict):
        raise ValueError("invalid audit state: high_water must be an object")
    for did, nonce in high_water.items():
        if not isinstance(did, str) or not did.startswith("did:key:"):
            raise ValueError("invalid audit state: high_water keys must be did:key strings")
        if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
            raise ValueError(
                "invalid audit state: high_water nonces must be non-negative integers"
            )
    return high_water


def _save_state(path, high_water):
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=".replay-audit-", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump({"high_water": high_water, "version": 1}, target, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(
        description="Audit a Technocore room JSONL export for nonce replay gaps"
    )
    parser.add_argument(
        "--state", help="persist per-DID nonce high-water marks across exports"
    )
    parser.add_argument(
        "--explain-window",
        action="store_true",
        help="explain whether each in-export reuse is inside the service guard window",
    )
    parser.add_argument(
        "--guard-bytes",
        type=_positive_integer,
        default=1 << 20,
        help="service replay-guard byte window used by --explain-window (default: 1048576)",
    )
    parser.add_argument("export")
    args = parser.parse_args()

    with open(args.export, encoding="utf-8") as source:
        lines = source.readlines()
    try:
        prior_high_water = _load_state(args.state) if args.state else {}
        findings, high_water = audit_export_state(lines, prior_high_water)
        signed_records = sum(
            1 for line_number, line in enumerate(lines, 1) if "sig" in _record(line, line_number)
        )
        if args.state:
            _save_state(args.state, high_water)
    except ValueError as error:
        parser.error(str(error))
    payload = {"findings": findings, "signed_records": signed_records}
    if args.explain_window:
        payload["guard_bytes"] = args.guard_bytes
        payload["window_explanations"] = analyze_replay_window(lines, args.guard_bytes)
    print(json.dumps(payload, sort_keys=True))
    raise SystemExit(1 if findings else 0)


if __name__ == "__main__":
    main()
