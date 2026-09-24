"""Pair protocol: self-posts + local My/Other merge."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg.conversation import ConversationStore, random_wallet, start_pair
from sos69069_msg.eip712 import verify_record
from sos69069_msg.message_engine import prepare_and_sign, short_code
from sos69069_msg.reader import Inbox, Message


class TestPairFlow(unittest.TestCase):
    def test_opposite_order_same_addresses(self):
        a = random_wallet()
        b = random_wallet()
        ca = start_pair(a, b.address)
        cb = start_pair(b, a.address)
        self.assertEqual(ca.my_address.lower(), a.address.lower())
        self.assertEqual(ca.other_address.lower(), b.address.lower())
        self.assertEqual(cb.my_address.lower(), b.address.lower())
        self.assertEqual(cb.other_address.lower(), a.address.lower())

    def test_self_post_intended_to_is_signer(self):
        a = random_wallet()
        ph, meta, sig = prepare_and_sign(a, "hello")
        self.assertTrue(verify_record(a.address, a.address, ph, meta, sig))
        self.assertEqual(meta, "hello")

    def test_store_save_load_clear(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "pair.json")
        store = ConversationStore(path)
        a = random_wallet()
        b = random_wallet()
        conv = start_pair(a, b.address)
        store.save(conv)
        loaded = store.load()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.my_address, conv.my_address)
        self.assertEqual(loaded.other_address, conv.other_address)
        store.clear()
        self.assertIsNone(store.load())

    def test_inbox_clear_wipes_link_cache(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "inbox.json")
        inbox = Inbox(path)
        inbox.add_pending("0x" + "ab" * 32, "pending text")
        self.assertTrue(inbox.pending())
        inbox.clear()
        self.assertEqual(inbox.pending(), [])
        self.assertEqual(inbox.messages, [])
        self.assertFalse(os.path.exists(path))

    def test_render_me_other(self):
        my = "0x" + "11" * 20
        other = "0x" + "22" * 20
        inbox = Inbox(os.path.join(tempfile.mkdtemp(), "i.json"))
        inbox.messages = [
            Message(1, 0, "0x" + "aa" * 32, 1700000000, my, my, "from me", "0x" + "11" * 32, my),
            Message(2, 0, "0x" + "bb" * 32, 1700000100, other, other, "from other", "0x" + "22" * 32, other),
        ]
        out = inbox.render(my)
        self.assertIn("Me", out)
        self.assertIn("Other", out)
        self.assertLess(out.index("from other"), out.index("from me"))  # newest first

    def test_reject_same_address(self):
        a = random_wallet()
        with self.assertRaises(ValueError):
            start_pair(a, a.address)


if __name__ == "__main__":
    unittest.main()
