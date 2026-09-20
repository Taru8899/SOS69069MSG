"""End-to-end client flow (no network)."""
import os, sys, tempfile, unittest, secrets
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from cryptography.exceptions import InvalidTag
from sos69069_msg.address_factory import AddressFactory, generate_seed
from sos69069_msg.conversation import ConversationManager
from sos69069_msg.eip712 import record_struct_hash, verify_record
from sos69069_msg.message_engine import prepare_and_sign, read_record
from sos69069_msg.submission import build_record_signature_call


class TestFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.secret = secrets.token_bytes(32)
        self.a = ConversationManager(AddressFactory(generate_seed(), os.path.join(self.tmp, "a.json")))
        self.b = ConversationManager(AddressFactory(generate_seed(), os.path.join(self.tmp, "b.json")))

    def test_same_d_and_roundtrip(self):
        ca, cb = self.a.start_conversation(self.secret), self.b.start_conversation(self.secret)
        self.assertEqual(ca.rendezvous_d, cb.rendezvous_d)
        key = self.a.next_signer(ca)
        ph, meta, sig = prepare_and_sign(key, ca.rendezvous_d, "Hello from A", self.secret)
        self.assertTrue(verify_record(key.address, ca.rendezvous_d, ph, meta, sig))
        self.assertEqual(read_record(meta, ph, self.secret), "Hello from A")
        call = build_record_signature_call(key.address, ca.rendezvous_d, ph, sig, meta)
        self.assertEqual(call["function"], "recordSignature")

    def test_tamper_and_wrong_secret(self):
        c = self.a.start_conversation(self.secret)
        key = self.a.next_signer(c)
        ph, meta, sig = prepare_and_sign(key, c.rendezvous_d, "hi", self.secret)
        self.assertFalse(verify_record(key.address, c.rendezvous_d, ph, meta + "x", sig))
        self.assertFalse(verify_record(key.address, self.b.start_conversation(secrets.token_bytes(32)).rendezvous_d, ph, meta, sig))
        with self.assertRaises(InvalidTag):
            read_record(meta, ph, secrets.token_bytes(32))

    def test_signers_are_one_time_and_persist(self):
        c = self.a.start_conversation(self.secret)
        addrs = {self.a.next_signer(c).address for _ in range(6)}  # exceeds prealloc of 3
        self.assertEqual(len(addrs), 6)
        seed = self.a.factory.master_seed
        again = AddressFactory(seed, os.path.join(self.tmp, "a.json"))  # "restart"
        self.assertNotIn(again.new_signer().address, addrs)

    def test_struct_hash_depends_on_every_field(self):
        c = self.a.start_conversation(self.secret)
        s = self.a.next_signer(c).address
        ph = b"\x11" * 32
        base = record_struct_hash(s, c.rendezvous_d, ph, "m")
        self.assertNotEqual(base, record_struct_hash(s, c.rendezvous_d, ph, "n"))
        self.assertNotEqual(base, record_struct_hash(s, c.rendezvous_d, b"\x12" * 32, "m"))

    def test_too_long_rejected(self):
        c = self.a.start_conversation(self.secret)
        key = self.a.next_signer(c)
        with self.assertRaises(ValueError):
            prepare_and_sign(key, c.rendezvous_d, "x" * 33, self.secret)
        with self.assertRaises(ValueError):
            prepare_and_sign(key, c.rendezvous_d, "x" * 65, self.secret, use_encryption=False)


if __name__ == "__main__":
    unittest.main()
