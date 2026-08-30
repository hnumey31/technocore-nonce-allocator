#!/usr/bin/env python3
"""Audit a Technocore room export for non-increasing signed-write nonces."""

import argparse
import json

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


def audit_export(lines):
    """Return nonce regressions/replays found in JSONL records, grouped per DID."""
    high_water = {}
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
    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Audit a Technocore room JSONL export for nonce replay gaps"
    )
    parser.add_argument("export")
    args = parser.parse_args()

    with open(args.export, encoding="utf-8") as source:
        lines = source.readlines()
    try:
        findings = audit_export(lines)
        signed_records = sum(
            1 for line_number, line in enumerate(lines, 1) if "sig" in _record(line, line_number)
        )
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"findings": findings, "signed_records": signed_records}, sort_keys=True))
    raise SystemExit(1 if findings else 0)


if __name__ == "__main__":
    main()
