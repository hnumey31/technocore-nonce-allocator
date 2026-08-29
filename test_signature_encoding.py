import base64
import subprocess
import sys
import unittest
from pathlib import Path

from signature_encoding import validate_canonical_signature


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class SignatureEncodingTests(unittest.TestCase):
    def test_accepts_one_spelling_and_rejects_fifteen_same_bytes_aliases(self):
        raw = bytes(range(64))
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        self.assertEqual(len(canonical), 86)
        self.assertEqual(validate_canonical_signature(canonical), canonical)

        aliases = [
            canonical[:-1] + char
            for char in ALPHABET
            if char != canonical[-1]
            and base64.urlsafe_b64decode(canonical[:-1] + char + "==") == raw
        ]
        self.assertEqual(len(aliases), 15)
        for alias in aliases:
            with self.subTest(last_character=alias[-1]):
                with self.assertRaisesRegex(ValueError, "canonical"):
                    validate_canonical_signature(alias)

    def test_cli_distinguishes_canonical_signature_from_same_bytes_alias(self):
        raw = bytes(range(64))
        canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        alias = next(
            canonical[:-1] + char
            for char in ALPHABET
            if char != canonical[-1]
            and base64.urlsafe_b64decode(canonical[:-1] + char + "==") == raw
        )
        script = Path(__file__).with_name("signature_encoding.py")

        accepted = subprocess.run(
            [sys.executable, script, canonical], capture_output=True, text=True, check=False
        )
        self.assertEqual(accepted.returncode, 0)
        self.assertEqual(accepted.stdout.strip(), "canonical signature encoding: OK")

        refused = subprocess.run(
            [sys.executable, script, alias], capture_output=True, text=True, check=False
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("canonical", refused.stderr)


if __name__ == "__main__":
    unittest.main()
