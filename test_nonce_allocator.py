import json
import tempfile
import unittest
from pathlib import Path
from nonce_allocator import next_nonce, reserve_nonce_range


class NonceTests(unittest.TestCase):
    def test_state_symlink_is_rejected_without_reading_or_replacing_it(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            path = directory / "state.json"
            sentinel = directory / "attacker-state.json"
            original = '{"did:key:zA|lobby": 7}\n'
            sentinel.write_text(original)
            sentinel.chmod(0o640)
            path.symlink_to(sentinel)

            with self.assertRaises(OSError):
                reserve_nonce_range(path, "did:key:zA", "lobby", 1, 1000)

            self.assertTrue(path.is_symlink())
            self.assertEqual(sentinel.read_text(), original)
            self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)

    def test_lock_symlink_is_rejected_without_touching_its_target(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            path = directory / "state.json"
            sentinel = directory / "sentinel.txt"
            sentinel.write_text("do not chmod or lock me\n")
            sentinel.chmod(0o640)
            path.with_name(path.name + ".lock").symlink_to(sentinel)

            rejected = False
            try:
                reserve_nonce_range(path, "did:key:zA", "lobby", 1, 1000)
            except OSError:
                rejected = True

            self.assertTrue(rejected, "a lock-file symlink must be rejected")
            self.assertEqual(sentinel.read_text(), "do not chmod or lock me\n")
            self.assertEqual(sentinel.stat().st_mode & 0o777, 0o640)
            self.assertFalse(path.exists())

    def test_predictable_temp_symlink_cannot_clobber_another_file(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            path = directory / "state.json"
            sentinel = directory / "sentinel.txt"
            sentinel.write_text("do not overwrite\n")
            path.with_name(path.name + ".tmp").symlink_to(sentinel)

            self.assertEqual(
                reserve_nonce_range(path, "did:key:zA", "lobby", 2, 1000),
                ("1000", "1001"),
            )

            self.assertEqual(sentinel.read_text(), "do not overwrite\n")
            self.assertFalse(path.is_symlink())
            self.assertEqual(json.loads(path.read_text()), {"did:key:zA|lobby": 1001})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(directory.glob(".state.json.*")), [])

    def test_monotonic_per_did_and_room(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            self.assertEqual(next_nonce(path, "did:key:zA", "lobby", 1000), "1000")
            self.assertEqual(next_nonce(path, "did:key:zA", "lobby", 1000), "1001")
            self.assertEqual(next_nonce(path, "did:key:zA", "other", 1000), "1000")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_reserves_contiguous_range_before_next_single_nonce(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            self.assertEqual(
                reserve_nonce_range(path, "did:key:zA", "lobby", 3, 1000),
                ("1000", "1002"),
            )
            self.assertEqual(next_nonce(path, "did:key:zA", "lobby", 1000), "1003")
            self.assertEqual(next_nonce(path, "did:key:zA", "other", 1000), "1000")

    def test_rejects_invalid_range_size_without_creating_state(self):
        for count in (True, 0, -1, 1.5, "2"):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as d:
                path = Path(d) / "state.json"
                with self.assertRaises(ValueError):
                    reserve_nonce_range(path, "did:key:zA", "lobby", count, 1000)
                self.assertFalse(path.exists())

    def test_protocol_cap(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OverflowError):
                next_nonce(Path(d) / "state.json", "did:key:zA", "lobby", 10**19)


if __name__ == "__main__":
    unittest.main()
