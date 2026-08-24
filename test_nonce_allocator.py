import tempfile
import unittest
from pathlib import Path
from nonce_allocator import next_nonce


class NonceTests(unittest.TestCase):
    def test_monotonic_per_did_and_room(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            self.assertEqual(next_nonce(path, "did:key:zA", "lobby", 1000), "1000")
            self.assertEqual(next_nonce(path, "did:key:zA", "lobby", 1000), "1001")
            self.assertEqual(next_nonce(path, "did:key:zA", "other", 1000), "1000")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_protocol_cap(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OverflowError):
                next_nonce(Path(d) / "state.json", "did:key:zA", "lobby", 10**19)


if __name__ == "__main__":
    unittest.main()
