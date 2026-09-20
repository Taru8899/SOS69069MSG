"""RLP / tx / ABI / relayer / reader tests. Network is faked."""
import json, os, secrets, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg import rlp
from sos69069_msg.abi import (RECORD_SIGNATURE_SELECTOR, SIGNATURE_RECORDED_TOPIC,
                              decode_signature_recorded, encode_record_signature)
from sos69069_msg.address_factory import AddressFactory, generate_seed
from sos69069_msg.config import CONTRACT_ADDRESS
from sos69069_msg.conversation import ConversationManager
from sos69069_msg.eip712 import verify_record
from sos69069_msg.ethcrypto import (KeyPair, keccak256, normalize_address, parse_address,
                                    recover_address)
from sos69069_msg.message_engine import prepare_and_sign
from sos69069_msg.reader import Inbox, sync
from sos69069_msg.relayer import parse_record, submit
from sos69069_msg.rpc import RpcError, _check_url
from sos69069_msg.submission import build_record_signature_call


class TestRlp(unittest.TestCase):
    def test_spec_vectors(self):
        self.assertEqual(rlp.encode(b"dog").hex(), "83646f67")
        self.assertEqual(rlp.encode([b"cat", b"dog"]).hex(), "c88363617483646f67")
        self.assertEqual(rlp.encode(b"").hex(), "80")
        self.assertEqual(rlp.encode([]).hex(), "c0")
        self.assertEqual(rlp.encode(0).hex(), "80")
        self.assertEqual(rlp.encode(15).hex(), "0f")
        self.assertEqual(rlp.encode(1024).hex(), "820400")
        long = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"
        self.assertEqual(rlp.encode(long).hex(), "b838" + long.hex())

    def test_roundtrip(self):
        x = [b"a" * 60, [b"", b"\x01"], b"\x80"]
        self.assertEqual(rlp.decode(rlp.encode(x)), x)


class TestEIP155Vector(unittest.TestCase):
    """The worked example in EIP-155 validates rlp + keccak + recovery."""
    def test_signing_hash_and_sender(self):
        to = bytes.fromhex("35" * 20)
        unsigned = [9, 20 * 10**9, 21000, to, 10**18, b"", 1, 0, 0]
        digest = keccak256(rlp.encode(unsigned))
        self.assertEqual(digest.hex(), "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
        r = 18515461264373351373200002665853028612451056578545711640558177340181847433846
        s = 46948507304638947509940763649030358759909902576025900602547168820602576006531
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27])  # v=37 -> recid 0
        want = KeyPair.from_private_key(bytes.fromhex("46" * 32)).address
        self.assertEqual(recover_address(digest, sig), want)


class TestAbi(unittest.TestCase):
    def setUp(self):
        self.signer = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
        self.d = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"

    def test_calldata_layout(self):
        sig, meta, ph = b"\x11" * 65, "hello", b"\x22" * 32
        cd = encode_record_signature(self.signer, self.d, ph, sig, meta)
        self.assertEqual(cd[:4], RECORD_SIGNATURE_SELECTOR)
        body = cd[4:]
        self.assertEqual(body[12:32], parse_address(self.signer))
        self.assertEqual(body[44:64], parse_address(self.d))
        self.assertEqual(body[64:96], ph)
        self.assertEqual(int.from_bytes(body[96:128], "big"), 0xA0)
        self.assertEqual(int.from_bytes(body[128:160], "big"), 0xA0 + 32 + 96)  # 65B pads to 96
        self.assertEqual(int.from_bytes(body[0xA0:0xC0], "big"), 65)
        self.assertEqual(body[0xC0:0xC0 + 65], sig)
        m_off = 0xA0 + 32 + 96
        self.assertEqual(int.from_bytes(body[m_off:m_off + 32], "big"), 5)
        self.assertEqual(body[m_off + 32:m_off + 37], b"hello")
        self.assertEqual(len(body) % 32, 0)

    def test_event_data_decode(self):
        w = lambda n: n.to_bytes(32, "big")
        pad = lambda b: b + b"\0" * (-len(b) % 32)
        sig, meta = b"\x33" * 65, b"abc"
        data = (b"\x44" * 32 + w(128) + w(1700000000) + w(128 + 32 + 96)
                + w(65) + pad(sig) + w(3) + pad(meta))
        ph, s, ts, m = decode_signature_recorded(data)
        self.assertEqual((ph, s, ts, m), (b"\x44" * 32, sig, 1700000000, "abc"))

    def test_decode_rejects_garbage(self):
        with self.assertRaises(ValueError):
            decode_signature_recorded(b"\x00" * 10)
        with self.assertRaises(ValueError):
            decode_signature_recorded(b"\x00" * 31 + b"\x01" + (b"\xff" * 32) + b"\x00" * 64)


class FakeRpc:
    def __init__(self, **kw):
        self.chain, self.base, self.prio, self.gas = kw.get("chain", 1), kw.get("base", 10 * 10**9), 10**9, 100_000
        self.bal, self.n, self.sent, self.logs, self.head = kw.get("bal", 10**18), 7, [], [], 1000
        self.log_calls = []
    def chain_id(self): return self.chain
    def base_fee(self): return self.base
    def priority_fee(self): return self.prio
    def estimate_gas(self, f, t, d): return self.gas
    def balance(self, a): return self.bal
    def nonce(self, a): return self.n
    def send_raw(self, raw): self.sent.append(raw); return "0x" + keccak256(raw).hex()
    def block_number(self): return self.head
    def get_logs(self, flt):
        self.log_calls.append(flt)
        lo, hi = int(flt["fromBlock"], 16), int(flt["toBlock"], 16)
        return [l for l in self.logs if lo <= int(l["blockNumber"], 16) <= hi]


class TestRelayer(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.tmp = tmp
        self.secret = secrets.token_bytes(32)
        self.mgr = ConversationManager(AddressFactory(generate_seed(), os.path.join(tmp, "a.json")))
        self.conv = self.mgr.start_conversation(self.secret)
        key = self.mgr.next_signer(self.conv)
        self.ph, self.meta, self.sig = prepare_and_sign(key, self.conv.rendezvous_d, "hi there", self.secret)
        call = build_record_signature_call(key.address, self.conv.rendezvous_d, self.ph, self.sig, self.meta)
        self.key = key
        self.json = json.dumps({"to": call["to"], "chainId": 1, "signer": key.address,
                                "intendedTo": self.conv.rendezvous_d, "payloadHash": "0x" + self.ph.hex(),
                                "signature": "0x" + self.sig.hex(), "metadata": self.meta})
        self.relayer = self.mgr.factory.relayer_key()

    def test_submit_builds_valid_signed_tx(self):
        rpc = FakeRpc()
        txh = submit(rpc, self.relayer, parse_record(self.json))
        raw = rpc.sent[0]
        self.assertEqual(raw[0], 2)
        f = rlp.decode(raw[1:])
        self.assertEqual(int.from_bytes(f[0], "big"), 1)                       # chain
        self.assertEqual(int.from_bytes(f[1], "big"), 7)                       # nonce
        self.assertEqual(int.from_bytes(f[4], "big"), 120_000)                 # gas = est * 1.2
        self.assertEqual(f[5], parse_address(CONTRACT_ADDRESS))                # to = contract
        self.assertEqual(f[6], b"")                                            # value 0
        self.assertEqual(f[7][:4], RECORD_SIGNATURE_SELECTOR)
        digest = keccak256(b"\x02" + rlp.encode(f[:9]))
        sig = f[10].rjust(32, b"\0") + f[11].rjust(32, b"\0") + bytes([27 + int.from_bytes(f[9], "big")])
        self.assertEqual(recover_address(digest, sig), self.relayer.address)   # sender is relayer
        self.assertEqual(txh, "0x" + keccak256(raw).hex())

    def test_guards(self):
        rec = parse_record(self.json)
        with self.assertRaises(RpcError): submit(FakeRpc(chain=5), self.relayer, rec)
        with self.assertRaises(RpcError): submit(FakeRpc(base=100 * 10**9), self.relayer, rec)   # cap
        with self.assertRaises(RpcError): submit(FakeRpc(bal=1000), self.relayer, rec)           # unfunded

    def test_parse_rejects_bad_records(self):
        j = json.loads(self.json)
        for mutate in ({"metadata": "tampered"}, {"to": "0x" + "11" * 20}, {"chainId": 5},
                       {"signature": "0x" + "00" * 65}):
            with self.assertRaises(Exception):
                parse_record(json.dumps({**j, **mutate}))
        # `to` in the JSON is never used as the destination
        rpc = FakeRpc(); submit(rpc, self.relayer, parse_record(self.json))
        self.assertEqual(rlp.decode(rpc.sent[0][1:])[5], parse_address(CONTRACT_ADDRESS))

    def test_relayer_key_distinct_from_signers(self):
        self.assertNotIn(self.relayer.address, self.conv.my_signers)
        again = AddressFactory(self.mgr.factory.master_seed, os.path.join(self.tmp, "x.json"))
        self.assertEqual(again.relayer_key().address, self.relayer.address)

    # ---------------- reader ----------------
    def _log(self, block, idx, signer, d, ph, sig, ts, meta, submitter="0x" + "ab" * 20):
        w = lambda n: n.to_bytes(32, "big")
        pad = lambda b: b + b"\0" * (-len(b) % 32)
        m = meta.encode()
        data = ph + w(128) + w(ts) + w(128 + 32 + len(pad(sig))) + w(len(sig)) + pad(sig) + w(len(m)) + pad(m)
        t = lambda a: "0x" + parse_address(a).rjust(32, b"\0").hex()
        return {"blockNumber": hex(block), "logIndex": hex(idx), "transactionHash": "0x" + f"{block:064x}",
                "data": "0x" + data.hex(),
                "topics": ["0x" + SIGNATURE_RECORDED_TOPIC.hex(), t(signer), t(d), t(submitter)]}

    def test_sync_decrypts_ours_ignores_noise_and_is_incremental(self):
        rpc = FakeRpc()
        d = self.conv.rendezvous_d
        rpc.logs = [
            self._log(990, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta),
            self._log(991, 0, self.key.address, d, b"\x01" * 32, self.sig, 1700000001, "not-encrypted-spam"),
        ]
        inbox = Inbox(os.path.join(self.tmp, "inbox.json"))
        new, noise = sync(rpc, d, self.secret, inbox)
        self.assertEqual((new, noise), (1, 1))
        self.assertIn("hi there", inbox.render())
        self.assertEqual(inbox.last_block, 1000)
        # topic filter targets D; second sync only fetches new blocks
        self.assertEqual(rpc.log_calls[0]["topics"][2], "0x" + parse_address(d).rjust(32, b"\0").hex())
        rpc.head = 1010; rpc.log_calls.clear()
        new, _ = sync(rpc, d, self.secret, Inbox(os.path.join(self.tmp, "inbox.json")))
        self.assertEqual(new, 0)
        self.assertEqual(int(rpc.log_calls[0]["fromBlock"], 16), 1001)

    def test_inbox_render_newest_first_and_labels_you(self):
        rpc = FakeRpc(); d = self.conv.rendezvous_d
        k2 = self.mgr.next_signer(self.conv)
        ph2, meta2, sig2 = prepare_and_sign(k2, d, "second one", self.secret)
        rpc.logs = [
            self._log(990, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta),
            self._log(995, 0, k2.address, d, ph2, sig2, 1700000500, meta2),
        ]
        inbox = Inbox(os.path.join(self.tmp, "inbox2.json"))
        sync(rpc, d, self.secret, inbox)
        out = inbox.render(d, mine={self.key.address})
        self.assertLess(out.index("second one"), out.index("hi there"))          # newest first
        self.assertIn("from you", out)                                            # my signer labelled
        self.assertIn("from " + k2.address[:6], out)                              # other signer shown short
        self.assertIn("→ D", out)
        self.assertIn("Latest 2 of 2", out)
        self.assertEqual(inbox.render(d, limit=1).count("[") , 1)                 # limit works

    def test_my_signer_addresses(self):
        f = self.mgr.factory
        self.assertEqual(f.my_signer_addresses(), set(self.conv.my_signers))

    def test_rpc_url_must_be_https(self):
        with self.assertRaises(RpcError): _check_url("http://example.com")
        _check_url("https://example.com"); _check_url("http://127.0.0.1:8545")


if __name__ == "__main__":
    unittest.main()
