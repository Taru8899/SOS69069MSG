"""End-to-end flow tests for plain-metadata, random-D design."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg.address_factory import AddressFactory, generate_seed
from sos69069_msg.conversation import ConversationManager
from sos69069_msg.eip712 import record_struct_hash, verify_record
from sos69069_msg.message_engine import prepare_and_sign, short_code
from sos69069_msg.config import MAX_METADATA_LENGTH


class TestFlow(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.a = ConversationManager(AddressFactory(generate_seed(), os.path.join(tmp, "a.json")))
        self.b = ConversationManager(AddressFactory(generate_seed(), os.path.join(tmp, "b.json")))

    def test_two_parties_same_pasted_d(self):
        """Both parties use the same pasted D address."""
        d = "0x" + "cd" * 20
        ca = self.a.start_conversation(d=d)
        cb = self.b.start_conversation(d=d)
        self.assertEqual(ca.rendezvous_d.lower(), cb.rendezvous_d.lower())

    def test_random_d_are_different(self):
        ca = self.a.start_conversation()
        cb = self.b.start_conversation()
        self.assertNotEqual(ca.rendezvous_d.lower(), cb.rendezvous_d.lower())

    def test_sign_and_verify_plain(self):
        c = self.a.start_conversation()
        key = self.a.next_signer(c)
        ph, meta, sig = prepare_and_sign(key, c.rendezvous_d, "hello public")
        self.assertEqual(meta, "hello public")
        self.assertTrue(verify_record(key.address, c.rendezvous_d, ph, meta, sig))
        self.assertEqual(len(short_code("0x" + ph.hex())), 4)

    def test_reply_code_prefix(self):
        c = self.a.start_conversation()
        key = self.a.next_signer(c)
        ph, meta, sig = prepare_and_sign(key, c.rendezvous_d, "yes", reply_code="A3F2")
        self.assertTrue(meta.startswith("#A3F2 "))
        self.assertIn("yes", meta)
        self.assertTrue(verify_record(key.address, c.rendezvous_d, ph, meta, sig))

    def test_struct_hash_changes_with_metadata(self):
        c = self.a.start_conversation()
        s = self.a.next_signer(c).address
        ph = b"\x11" * 32
        base = record_struct_hash(s, c.rendezvous_d, ph, "m")
        self.assertNotEqual(base, record_struct_hash(s, c.rendezvous_d, ph, "n"))
        self.assertNotEqual(base, record_struct_hash(s, c.rendezvous_d, b"\x12" * 32, "m"))

    def test_too_long_rejected(self):
        c = self.a.start_conversation()
        key = self.a.next_signer(c)
        with self.assertRaises(ValueError):
            prepare_and_sign(key, c.rendezvous_d, "x" * (MAX_METADATA_LENGTH + 1))

    def test_one_time_signers_not_reused(self):
        c = self.a.start_conversation()
        k1 = self.a.next_signer(c)
        k2 = self.a.next_signer(c)
        self.assertNotEqual(k1.address, k2.address)


if __name__ == "__main__":
    unittest.main()
