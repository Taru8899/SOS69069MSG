"""CHECK-page list logic: entries(), reply prefix, pending / waiting cards, default key."""
import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg.config import DEFAULT_ETHERSCAN_KEY
from sos69069_msg.message_engine import prepare_and_sign, short_code
from sos69069_msg.reader import Inbox, Message, split_reply

ME = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
OTHER = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"


def msg(i, text, signer=OTHER, ph=None):
    return Message(block=100 + i, log_index=i, tx_hash="0x" + f"{i:064x}", timestamp=1700000000 + i * 60,
                   signer=signer, submitter=signer, text=text, payload_hash=ph or "0x" + f"{i:02x}" * 32)


class TestEntries(unittest.TestCase):
    def setUp(self):
        self.inbox = Inbox(os.path.join(tempfile.mkdtemp(), "i.json"))

    def test_default_key_is_preinserted(self):
        self.assertEqual(DEFAULT_ETHERSCAN_KEY, "RU99NEJZV9F2EWS7A97RWVHDJN1ZQ29Q99")

    def test_split_reply(self):
        self.assertEqual(split_reply("#a3f2 hello there"), ("A3F2", "hello there"))
        self.assertEqual(split_reply("hello #A3F2"), ("", "hello #A3F2"))
        self.assertEqual(split_reply("#XYZ1 nope"), ("", "#XYZ1 nope"))
        self.assertEqual(split_reply(""), ("", ""))

    def test_newest_first_with_code_tx_and_labels(self):
        self.inbox.merge([msg(i, f"m{i}", signer=ME if i == 2 else OTHER) for i in range(12)], 999)
        es = self.inbox.entries(mine={ME})
        self.assertEqual(len(es), 12)
        self.assertEqual([e["text"] for e in es[:3]], ["m11", "m10", "m9"])          # newest first
        self.assertTrue(all(e["tx"].startswith("0x") and len(e["tx"]) == 66 for e in es))   # link for each tx
        self.assertEqual(es[0]["code"], short_code("0x" + "0b" * 32))                 # short code of THAT message
        self.assertEqual([e["who"] for e in es if e["text"] == "m2"], ["you"])
        self.assertEqual(es[0]["who"], OTHER)
        self.assertEqual(es[0]["block"], 111)

    def test_reply_prefix_is_split_out(self):
        self.inbox.merge([msg(1, "#A3F2 yes, agreed")], 999)
        e = self.inbox.entries()[0]
        self.assertEqual((e["reply_to"], e["text"]), ("A3F2", "yes, agreed"))

    def test_reply_roundtrip_with_signing(self):
        # what the reply button does: code goes into SEND, signer prefixes the metadata,
        # and the reader later shows it as a reply to that code
        from sos69069_msg.address_factory import AddressFactory, generate_seed
        key = AddressFactory(generate_seed(), os.path.join(tempfile.mkdtemp(), "c.json")).new_signer()
        ph, meta, sig = prepare_and_sign(key, OTHER, "sounds good", reply_code="#0b0b")
        self.assertEqual(meta, "#0B0B sounds good")
        self.assertEqual(split_reply(meta), ("0B0B", "sounds good"))

    def test_waiting_cards_and_tx(self):
        ph1, ph2 = "0x" + "aa" * 32, "0x" + "bb" * 32
        self.inbox.add_pending(ph1, "not sent yet")
        self.inbox.add_pending(ph2, "in flight")
        self.inbox.mark_submitted(ph2, "0x" + "cd" * 32)
        es = self.inbox.entries()
        by = {e["text"]: e for e in es}
        self.assertTrue(by["not sent yet"]["pending"] and by["not sent yet"]["tx"] == "")
        self.assertIn("NOT submitted", by["not sent yet"]["status"])
        self.assertIn("waiting to be mined", by["in flight"]["status"])
        self.assertEqual(by["in flight"]["tx"], "0x" + "cd" * 32)                   # link available already
        self.assertEqual(by["not sent yet"]["code"], "AAAA")
        # once it lands on chain the waiting card is replaced by the real one
        self.inbox.merge([msg(5, "in flight", ph=ph2)], 999)
        es = self.inbox.entries()
        self.assertEqual([e["pending"] for e in es if e["text"] == "in flight"], [False])
        self.assertTrue(any(e["pending"] for e in es if e["text"] == "not sent yet"))

    def test_render_text_unchanged(self):
        self.inbox.merge([msg(1, "hello")], 999)
        self.assertIn("hello", self.inbox.render("0xD", ()))


if __name__ == "__main__":
    unittest.main()
