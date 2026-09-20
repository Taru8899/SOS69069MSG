"""Runs without eth-account: python -m unittest discover tests"""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from cryptography.exceptions import InvalidTag
from sos69069_msg.crypto_utils import (MAX_PLAINTEXT_BYTES, derive_material, open_message,
                          random_payload_hash, seal_message)


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.key = derive_material(b"\x01" * 32, b"k", 32)

    def test_roundtrip(self):
        ph = random_payload_hash()
        m = seal_message(b"Hello from A", self.key, ph)
        self.assertLessEqual(len(m.encode()), 64)
        self.assertEqual(open_message(m, self.key, ph), b"Hello from A")

    def test_max_fits_exactly(self):
        ph = random_payload_hash()
        msg = b"x" * MAX_PLAINTEXT_BYTES
        m = seal_message(msg, self.key, ph)
        self.assertEqual(len(m), 64)
        self.assertEqual(open_message(m, self.key, ph), msg)

    def test_too_long_rejected_not_truncated(self):
        with self.assertRaises(ValueError):
            seal_message(b"x" * (MAX_PLAINTEXT_BYTES + 1), self.key, random_payload_hash())

    def test_wrong_key_or_hash_fails(self):
        ph = random_payload_hash()
        m = seal_message(b"secret", self.key, ph)
        with self.assertRaises(InvalidTag):
            open_message(m, derive_material(b"\x02" * 32, b"k", 32), ph)
        with self.assertRaises(InvalidTag):
            open_message(m, self.key, random_payload_hash())

    def test_empty_message(self):
        ph = random_payload_hash()
        self.assertEqual(open_message(seal_message(b"", self.key, ph), self.key, ph), b"")


if __name__ == "__main__":
    unittest.main()
