import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from replay_audit import audit_export


class ReplayAuditTests(unittest.TestCase):
    def test_reports_non_increasing_nonce_for_the_same_did(self):
        records = [
            {"seq": 10, "from": "did:key:z6MkAlice", "nonce": 100, "sig": "A" * 86, "text": "first"},
            {"seq": 11, "from": "did:key:z6MkBob", "nonce": 1, "sig": "A" * 86, "text": "other identity"},
            {"seq": 12, "from": "did:key:z6MkAlice", "nonce": 100, "sig": "A" * 86, "text": "captured replay"},
        ]
        lines = [json.dumps(record) for record in records]

        self.assertEqual(
            audit_export(lines),
            [
                {
                    "line": 3,
                    "seq": 12,
                    "did": "did:key:z6MkAlice",
                    "previous_nonce": 100,
                    "nonce": 100,
                }
            ],
        )

    def test_cli_reports_a_clean_export_deterministically(self):
        records = [
            {"seq": 1, "from": "did:key:z6MkAlice", "nonce": 100, "sig": "A" * 86, "text": "one"},
            {"seq": 2, "from": "did:key:z6MkAlice", "nonce": 101, "sig": "A" * 86, "text": "two"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "room.jsonl"
            export.write_text("".join(json.dumps(record) + "\n" for record in records))
            script = Path(__file__).with_name("replay_audit.py")
            command = [sys.executable, script, export]

            first = subprocess.run(command, capture_output=True, text=True, check=False)
            second = subprocess.run(command, capture_output=True, text=True, check=False)

        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stdout, '{"findings": [], "signed_records": 2}\n')
        self.assertEqual((second.returncode, second.stdout), (first.returncode, first.stdout))

    def test_cli_fails_closed_with_line_number_for_malformed_signed_record(self):
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "room.jsonl"
            export.write_text(
                json.dumps({"seq": 1, "from": "guest", "text": "unsigned"})
                + "\n"
                + json.dumps(
                    {"seq": 2, "from": "did:key:z6MkAlice", "nonce": "100", "sig": "A" * 86, "text": "bad nonce type"}
                )
                + "\n"
            )
            script = Path(__file__).with_name("replay_audit.py")
            result = subprocess.run(
                [sys.executable, script, export], capture_output=True, text=True, check=False
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("line 2", result.stderr)
        self.assertIn("nonce must be an integer", result.stderr)


if __name__ == "__main__":
    unittest.main()
