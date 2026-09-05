import fcntl
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from replay_audit import analyze_replay_window, audit_export, audit_export_state


class ReplayAuditTests(unittest.TestCase):
    def test_stateful_cli_waits_then_reloads_state_under_one_lock(self):
        script = Path(__file__).with_name("replay_audit.py")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            export = directory / "room.jsonl"
            state = directory / "audit-state.json"
            lock_path = state.with_name(state.name + ".lock")
            export.write_text(
                json.dumps(
                    {
                        "seq": 20,
                        "from": "did:key:z6MkAlice",
                        "nonce": 100,
                        "sig": "A" * 86,
                    }
                )
                + "\n"
            )
            state.write_text(
                json.dumps(
                    {"high_water": {"did:key:z6MkAlice": 50}, "version": 1}
                )
                + "\n"
            )

            with lock_path.open("a+") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                process = subprocess.Popen(
                    [sys.executable, script, "--state", state, export],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.wait(timeout=0.5)
                    state.write_text(
                        json.dumps(
                            {
                                "high_water": {"did:key:z6MkAlice": 100},
                                "version": 1,
                            }
                        )
                        + "\n"
                    )
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

            stdout, stderr = process.communicate(timeout=5)
            saved = json.loads(state.read_text())

        self.assertEqual(stderr, "")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(stdout)["findings"][0]["previous_nonce"], 100)
        self.assertEqual(saved["high_water"]["did:key:z6MkAlice"], 100)

    def test_window_explainer_marks_replay_inside_guard_as_refused(self):
        records = [
            {
                "seq": 1,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
                "text": "original",
            },
            {
                "seq": 2,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
                "text": "captured replay",
            },
        ]
        lines = [json.dumps(record, separators=(",", ":")) + "\n" for record in records]

        self.assertEqual(
            analyze_replay_window(lines, guard_bytes=4096),
            [
                {
                    "line": 2,
                    "seq": 2,
                    "did": "did:key:z6MkAlice",
                    "nonce": 7,
                    "historical_high_water": 7,
                    "guard_nonce": 7,
                    "service_outcome": "refused",
                }
            ],
        )

    def test_window_explainer_treats_iterable_items_as_logical_lines(self):
        records = [
            {
                "seq": 1,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
            },
            {"seq": 2, "from": "guest", "text": "filler"},
            {
                "seq": 3,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
            },
        ]
        lines_without_newlines = [json.dumps(record) for record in records]

        explanations = analyze_replay_window(lines_without_newlines, guard_bytes=4096)

        self.assertEqual(explanations[0]["guard_nonce"], 7)
        self.assertEqual(explanations[0]["service_outcome"], "refused")

    def test_window_explainer_marks_retained_reuse_outside_guard_as_accepted(self):
        records = [
            {
                "seq": 1,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
                "text": "original",
            },
            {"seq": 2, "from": "guest", "text": "x" * 300},
            {
                "seq": 3,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
                "text": "captured replay",
            },
        ]
        lines = [json.dumps(record, separators=(",", ":")) + "\n" for record in records]

        explanations = analyze_replay_window(lines, guard_bytes=256)

        self.assertEqual(explanations[0]["historical_high_water"], 7)
        self.assertIsNone(explanations[0]["guard_nonce"])
        self.assertEqual(explanations[0]["service_outcome"], "accepted")

    def test_cli_explain_window_emits_machine_readable_service_outcome(self):
        records = [
            {
                "seq": 1,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
            },
            {"seq": 2, "from": "guest", "text": "x" * 300},
            {
                "seq": 3,
                "from": "did:key:z6MkAlice",
                "nonce": 7,
                "sig": "A" * 86,
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "room.jsonl"
            export.write_text(
                "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records)
            )
            script = Path(__file__).with_name("replay_audit.py")

            result = subprocess.run(
                [
                    sys.executable,
                    script,
                    "--explain-window",
                    "--guard-bytes",
                    "256",
                    export,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["guard_bytes"], 256)
        self.assertEqual(payload["window_explanations"][0]["service_outcome"], "accepted")

    def test_prior_high_water_catches_replay_at_first_exported_line(self):
        lines = [
            json.dumps(
                {
                    "seq": 20,
                    "from": "did:key:z6MkAlice",
                    "nonce": 100,
                    "sig": "A" * 86,
                    "text": "captured replay at retained boundary",
                }
            )
        ]

        findings, high_water = audit_export_state(
            lines, {"did:key:z6MkAlice": 100}
        )

        self.assertEqual(
            findings,
            [
                {
                    "line": 1,
                    "seq": 20,
                    "did": "did:key:z6MkAlice",
                    "previous_nonce": 100,
                    "nonce": 100,
                }
            ],
        )
        self.assertEqual(high_water, {"did:key:z6MkAlice": 100})

    def test_cli_persists_high_water_and_catches_next_exports_first_line(self):
        script = Path(__file__).with_name("replay_audit.py")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            export = directory / "room.jsonl"
            state = directory / "audit-state.json"
            export.write_text(
                json.dumps(
                    {
                        "seq": 1,
                        "from": "did:key:z6MkAlice",
                        "nonce": 100,
                        "sig": "A" * 86,
                    }
                )
                + "\n"
            )
            first = subprocess.run(
                [sys.executable, script, "--state", state, export],
                capture_output=True,
                text=True,
                check=False,
            )
            export.write_text(
                json.dumps(
                    {
                        "seq": 20,
                        "from": "did:key:z6MkAlice",
                        "nonce": 100,
                        "sig": "A" * 86,
                    }
                )
                + "\n"
            )
            second = subprocess.run(
                [sys.executable, script, "--state", state, export],
                capture_output=True,
                text=True,
                check=False,
            )
            saved = json.loads(state.read_text())
            mode = state.stat().st_mode & 0o777

        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(
            json.loads(second.stdout)["findings"],
            [
                {
                    "did": "did:key:z6MkAlice",
                    "line": 1,
                    "nonce": 100,
                    "previous_nonce": 100,
                    "seq": 20,
                }
            ],
        )
        self.assertEqual(
            saved, {"high_water": {"did:key:z6MkAlice": 100}, "version": 1}
        )
        self.assertEqual(mode, 0o600)

    def test_cli_rejects_malformed_state_without_overwriting_it(self):
        script = Path(__file__).with_name("replay_audit.py")
        malformed = '{"high_water":{"did:key:z6MkAlice":"100"},"version":1}\n'
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            export = directory / "room.jsonl"
            state = directory / "audit-state.json"
            export.write_text(
                json.dumps(
                    {
                        "seq": 2,
                        "from": "did:key:z6MkAlice",
                        "nonce": 101,
                        "sig": "A" * 86,
                    }
                )
                + "\n"
            )
            state.write_text(malformed)
            result = subprocess.run(
                [sys.executable, script, "--state", state, export],
                capture_output=True,
                text=True,
                check=False,
            )
            after = state.read_text()

        self.assertEqual(result.returncode, 2)
        self.assertIn("high_water nonces must be non-negative integers", result.stderr)
        self.assertEqual(after, malformed)

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
