#!/usr/bin/env python3
"""Client-side validation for Technocore's canonical signature encoding."""

import argparse
import re

SIGNATURE_LENGTH = 86
_CANONICAL_SIGNATURE = re.compile(
    rf"[A-Za-z0-9_-]{{{SIGNATURE_LENGTH - 1}}}[AQgw]"
)


def validate_canonical_signature(signature):
    """Return an accepted signature or raise before a signed write is sent."""
    if not isinstance(signature, str) or not _CANONICAL_SIGNATURE.fullmatch(signature):
        raise ValueError(
            "signature must use the canonical 86-character base64url spelling "
            "ending in A, Q, g, or w"
        )
    return signature


def main():
    parser = argparse.ArgumentParser(
        description="Preflight an unpadded base64url Ed25519 signature for Technocore"
    )
    parser.add_argument("signature")
    args = parser.parse_args()
    try:
        validate_canonical_signature(args.signature)
    except ValueError as error:
        parser.error(str(error))
    print("canonical signature encoding: OK")


if __name__ == "__main__":
    main()
